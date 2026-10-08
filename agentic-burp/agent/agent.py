from __future__ import annotations
import asyncio
import time
from typing import Any, Callable, Dict, List, Optional

from models.endpoint import Endpoint
from models.finding import Finding
from models.observation import Observation
from models.request import HTTPRequest
from models.response import HTTPResponse
from storage.audit import AuditRepository
from storage.database import Database
from storage.findings import FindingsRepository
from storage.observations import ObservationRepository
from .budget import BudgetManager
from .executor import Executor
from .memory import AgentMemory
from .planner import Planner
from .state import AgentState
from .tool_registry import ToolRegistry


class Agent:
    """
    Central Orchestration State Machine for Agentic-Burp.
    Coordinates Planner, Executor, Memory, and Budgets through controlled assessment phases.
    """
    def __init__(
        self,
        assessment_id: str,
        target_url: str,
        planner: Planner,
        executor: Executor,
        tool_registry: ToolRegistry,
        budget_manager: BudgetManager,
        db: Database,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None
    ):
        self.assessment_id = assessment_id
        self.target_url = target_url
        self.planner = planner
        self.executor = executor
        self.tool_registry = tool_registry
        self.budget_manager = budget_manager
        self.db = db
        self.on_event = on_event

        self.memory = AgentMemory(assessment_id, db)
        self.state = AgentState(run_id=f"run_{assessment_id}", target=target_url)
        self.findings_repo = FindingsRepository(db)
        self.obs_repo = ObservationRepository(db)
        self.audit_repo = AuditRepository(db)

    def _emit_event(self, event_type: str, data: Dict[str, Any]):
        self.audit_repo.record_event(self.assessment_id, event_type, data)
        if self.on_event:
            self.on_event(event_type, data)

    async def step(self) -> bool:
        """Executes a single controlled agent iteration."""
        if self.state.paused:
            return False

        if not self.budget_manager.increment_iteration():
            self.state.phase = "COMPLETE"
            self.state.stop_reason = "MAX_ITERATIONS_REACHED"
            self._emit_event("assessment_completed", {"reason": self.state.stop_reason})
            return False

        if not self.budget_manager.can_execute_http() or not self.budget_manager.can_call_llm():
            self.state.phase = "COMPLETE"
            self.state.stop_reason = "BUDGET_EXHAUSTED"
            self._emit_event("assessment_completed", {"reason": self.state.stop_reason})
            return False

        self.state.iteration = self.budget_manager.current_iterations
        current_phase = self.state.phase

        # 1. BUILD COMPACT CONTEXT
        context = self.memory.build_llm_context(
            phase=current_phase,
            current_objective=f"Assess {self.target_url} in phase {current_phase}"
        )

        # 2. ASK PLANNER FOR DECISION
        available_tools = self.tool_registry.get_llm_tool_declarations()
        self._emit_event("llm_reasoning_started", {"phase": current_phase, "iteration": self.state.iteration})
        decision = await self.planner.decide(current_phase, context, available_tools)
        self._emit_event("llm_decision_made", decision.to_dict())

        # 3. EXECUTE APPROVED TOOL THROUGH SECURITY GATE
        success, obs, raw_result = await self.executor.execute(
            assessment_id=self.assessment_id,
            decision=decision
        )

        # 4. RECORD RESULTS TO MEMORY AND PERSISTENT STORAGE
        if obs:
            self.memory.record_observation(obs)
            self.obs_repo.save_observation(self.assessment_id, obs)
            self._emit_event("observation_created", obs.compact_for_llm())

        if "findings" in raw_result:
            for f in raw_result["findings"]:
                self.memory.record_finding(f)
                self.findings_repo.save_finding(self.assessment_id, f)
                self._emit_event("finding_discovered", f.to_dict())

        if "evidence" in raw_result:
            for ev in raw_result["evidence"]:
                self.findings_repo.save_evidence(
                    assessment_id=self.assessment_id,
                    evidence_id=ev.id,
                    evidence_type=ev.evidence_type,
                    description=ev.description,
                    request_id=ev.request_id or "",
                    response_id=ev.response_id or "",
                    baseline_request_id=ev.baseline_request_id or "",
                    baseline_response_id=ev.baseline_response_id or "",
                    data=ev.data,
                    reproducible=ev.reproducible
                )

        # 5. CONTROLLED PHASE TRANSITIONS
        if current_phase == "DISCOVERY" and (self.state.iteration >= 2 or "crawl" in decision.tool):
            self.state.phase = "ANALYSIS"
            self._emit_event("phase_changed", {"from": "DISCOVERY", "to": "ANALYSIS"})
        elif current_phase == "ANALYSIS" and self.state.iteration >= 4:
            self.state.phase = "INVESTIGATION"
            self._emit_event("phase_changed", {"from": "ANALYSIS", "to": "INVESTIGATION"})
        elif current_phase == "INVESTIGATION" and len(self.memory.findings) > 0 and self.state.iteration >= 8:
            self.state.phase = "VERIFICATION"
            self._emit_event("phase_changed", {"from": "INVESTIGATION", "to": "VERIFICATION"})
        elif current_phase == "VERIFICATION" and self.state.iteration >= 10:
            self.state.phase = "REPORTING"
            self._emit_event("phase_changed", {"from": "VERIFICATION", "to": "REPORTING"})
        elif current_phase == "REPORTING" or decision.action == "stop":
            self.state.phase = "COMPLETE"
            self.state.stop_reason = "ASSESSMENT_FINISHED"
            self._emit_event("assessment_completed", {"reason": self.state.stop_reason})
            return False

        return True

    async def run(self, max_steps: int = 15):
        """Runs the agent loop until completion or budget limits."""
        for _ in range(max_steps):
            active = await self.step()
            if not active:
                break
            await asyncio.sleep(0.05) # Yield control
