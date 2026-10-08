from __future__ import annotations
import asyncio
import re
import time
from typing import Dict, Any, List, Optional, Callable
from models.observation import Observation
from models.finding import Finding
from knowledge.retriever import KnowledgeRetriever
from session.manager import SessionManager
from storage.database import Database
from storage.findings import FindingsRepository
from storage.observations import ObservationRepository
from storage.audit import AuditRepository
from .protocol import LeaderPlan, GemmaActionDecision, DualAgentExchange
from .leader import TeamLeader
from .gemma_agent import GemmaSecurityAgent
from .executor import Executor
from .budget import BudgetManager
from .memory import AgentMemory
from .tool_registry import ToolRegistry


class DualAgentCoordinator:
    """
    Coordinates Team Leader (Gemini 3.5 Flash-Lite) and Security Researcher (Gemma 4 31B).
    Integrates Knowledge Retrieval, Session Management, and deterministic tool execution.
    """
    def __init__(
        self,
        assessment_id: str,
        target_url: str,
        leader: TeamLeader,
        researcher: GemmaSecurityAgent,
        executor: Executor,
        tool_registry: ToolRegistry,
        budget_manager: BudgetManager,
        db: Database,
        session_manager: Optional[SessionManager] = None,
        knowledge_retriever: Optional[KnowledgeRetriever] = None,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None
    ):
        self.assessment_id = assessment_id
        self.target_url = target_url
        self.leader = leader
        self.researcher = researcher
        self.executor = executor
        self.tool_registry = tool_registry
        self.budget_manager = budget_manager
        self.db = db
        self.session_manager = session_manager or SessionManager()
        self.knowledge_retriever = knowledge_retriever or KnowledgeRetriever()
        self.on_event = on_event

        self.memory = AgentMemory(assessment_id, db)
        self.findings_repo = FindingsRepository(db)
        self.obs_repo = ObservationRepository(db)
        self.audit_repo = AuditRepository(db)

        self.exchange_history: List[DualAgentExchange] = []
        self.recovered_flag: Optional[str] = None
        self.phase = "DISCOVERY"
        self.iteration = 0
        self.is_paused = False

    def _emit(self, event_type: str, data: Dict[str, Any]):
        self.audit_repo.record_event(self.assessment_id, event_type, data)
        if self.on_event:
            self.on_event(event_type, data)

    async def step(self) -> bool:
        """Executes one collaborative Dual-Agent iteration."""
        if self.is_paused:
            return False

        if not self.budget_manager.increment_iteration():
            self.phase = "COMPLETE"
            self._emit("assessment_completed", {"reason": "MAX_ITERATIONS_REACHED"})
            return False

        if not self.budget_manager.can_execute_http() or not self.budget_manager.can_call_llm():
            self.phase = "COMPLETE"
            self._emit("assessment_completed", {"reason": "BUDGET_EXHAUSTED"})
            return False

        self.iteration = self.budget_manager.current_iterations
        timestamp = time.time()

        # 1. BUILD COMPACT STATE FOR TEAM LEADER
        compact_state = self.memory.build_llm_context(
            phase=self.phase,
            current_objective=f"Assess {self.target_url}"
        )

        # 2. TEAM LEADER (Flash-Lite) PRODUCES STRATEGIC PLAN
        self._emit("leader_planning_started", {"iteration": self.iteration, "phase": self.phase})
        leader_plan = await self.leader.plan(
            objective=f"Authorized security assessment of {self.target_url}",
            phase=self.phase,
            compact_state=compact_state
        )
        self._emit("leader_plan_emitted", leader_plan.to_dict())

        # 3. KNOWLEDGE RETRIEVAL (Advisory Guidance)
        latest_obs = self.memory.last_observation or Observation(
            category="assessment_start",
            source="coordinator",
            endpoint=self.target_url,
            summary=f"Investigating {self.target_url} in phase {self.phase}"
        )
        advisory_snippets = self.knowledge_retriever.retrieve_relevant_snippets(latest_obs)
        if advisory_snippets:
            self._emit("knowledge_retrieved", {"count": len(advisory_snippets), "snippets": advisory_snippets})

        # 4. SECURITY RESEARCHER (Gemma 4 31B) FORMULATES HYPOTHESIS & SELECTS TOOL
        available_tools = self.tool_registry.get_llm_tool_declarations()
        self._emit("gemma_reasoning_started", {"mission": leader_plan.mission})
        gemma_decision = await self.researcher.decide_action(
            leader_plan=leader_plan,
            knowledge_snippets=advisory_snippets,
            compact_context=compact_state,
            available_tools=available_tools
        )
        self._emit("gemma_decision_made", gemma_decision.to_dict())

        # 5. DETERMINISTIC TOOL EXECUTION THROUGH SECURITY GATE
        from .decisions import AgentDecision
        exec_decision = AgentDecision(
            action=gemma_decision.action,
            tool=gemma_decision.tool,
            arguments=gemma_decision.arguments,
            reasoning_summary=gemma_decision.reasoning_summary,
            confidence=gemma_decision.confidence
        )

        success, obs, raw_result = await self.executor.execute(
            assessment_id=self.assessment_id,
            decision=exec_decision
        )

        # 6. PROCESS OBSERVATIONS & DYNAMIC TOKENS
        if obs:
            self.memory.record_observation(obs)
            self.obs_repo.save_observation(self.assessment_id, obs)
            self._emit("observation_recorded", obs.compact_for_llm())

            # Check for CTF Flag pattern in target response
            if obs.summary:
                flag_matches = re.findall(r'(FLAG\{[^}]+\}|ctf\{[^}]+\}|burp\{[^}]+\})', obs.summary, re.IGNORECASE)
                if flag_matches:
                    self.recovered_flag = flag_matches[0]
                    self._emit("ctf_flag_discovered", {"flag": self.recovered_flag})

        # 7. PROCESS FINDINGS & EVIDENCE
        if "findings" in raw_result:
            for f in raw_result["findings"]:
                self.memory.record_finding(f)
                self.findings_repo.save_finding(self.assessment_id, f)
                self._emit("finding_verified", f.to_dict())

        # 8. RECORD DUAL-AGENT EXCHANGE FOR AUDIT TRAIL
        exchange = DualAgentExchange(
            timestamp=timestamp,
            iteration=self.iteration,
            leader_plan=leader_plan,
            gemma_decision=gemma_decision,
            observation_summary=obs.summary if obs else "Tool executed",
            evidence_collected=[f.id for f in raw_result.get("findings", [])]
        )
        self.exchange_history.append(exchange)

        # 9. PHASE TRANSITIONS & COMPLETION
        if self.recovered_flag:
            self.phase = "COMPLETE"
            self._emit("assessment_completed", {"reason": "FLAG_RETRIEVED", "flag": self.recovered_flag})
            return False

        if self.phase == "DISCOVERY" and (self.iteration >= 2 or "crawl" in gemma_decision.tool):
            self.phase = "INVESTIGATION"
        elif self.phase == "INVESTIGATION" and len(self.memory.findings) > 0 and self.iteration >= 6:
            self.phase = "VERIFICATION"
        elif self.phase == "VERIFICATION" and self.iteration >= 8:
            self.phase = "REPORTING"
        elif self.phase == "REPORTING" or gemma_decision.action == "stop":
            self.phase = "COMPLETE"
            self._emit("assessment_completed", {"reason": "ASSESSMENT_FINISHED"})
            return False

        return True

    async def run(self, max_steps: int = 12):
        for _ in range(max_steps):
            active = await self.step()
            if not active:
                break
            await asyncio.sleep(0.05)
