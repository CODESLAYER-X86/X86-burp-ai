from __future__ import annotations
import json
import time
from typing import Dict, Any, List, Optional
from .protocol import LeaderPlan
from .gemini_client import GeminiClient
from .credentials import GeminiProject


LEADER_SYSTEM_PROMPT = """You are the Team Leader and Investigation Planner for Agentic-Burp.
Your model identity is Gemini 3.5 Flash-Lite.

Your role:
- Decompose the high-level security/CTF assessment objective into prioritized investigation tasks.
- Guide the Gemma 4 31B Security Researcher on which attack surface areas to explore next.
- Recommend appropriate tool categories (Observation, Request manipulation, Session, Active testing, Evidence).
- Never issue raw network/shell execution commands. Produce structured strategic plans only.
"""


class TeamLeader:
    """
    Gemini 3.5 Flash-Lite — Team Leader / Investigation Planner (Section 8).
    High-throughput planning, task decomposition, and focus prioritization.
    """
    def __init__(self, project: Optional[GeminiProject] = None):
        self.project = project or GeminiProject(
            project_id="leader-flash-lite",
            model="gemini-2.5-flash", # Maps to Gemini Flash-Lite fast planning
            api_key="",
            input_tokens_per_minute=30000
        )
        self.client = GeminiClient(self.project)

    async def plan(
        self,
        objective: str,
        phase: str,
        compact_state: Dict[str, Any]
    ) -> LeaderPlan:
        # If offline or key not provided, execute deterministic strategic planner
        if not self.project.api_key or self.project.api_key.startswith("mock_"):
            return self._deterministic_plan(phase, compact_state)

        prompt = (
            f"Assessment Objective: {objective}\n"
            f"Current Assessment Phase: {phase}\n\n"
            f"Compact State Summary:\n{json.dumps(compact_state, indent=2)}\n\n"
            "Provide your strategic planning decision as valid JSON matching this schema:\n"
            "{\n"
            '  "priority": "high|medium|low",\n'
            '  "mission": "Specific investigation task",\n'
            '  "recommended_focus": "crawl|authorization|parameter_analysis|injection_test|verification",\n'
            '  "recommended_tools": ["crawl", "run_detector"],\n'
            '  "task_queue": ["Task 1", "Task 2"],\n'
            '  "knowledge_hints": ["Topic 1"],\n'
            '  "reasoning_summary": "Strategic rationale",\n'
            '  "confidence": 0.88\n'
            "}"
        )

        resp = await self.client.generate_content(LEADER_SYSTEM_PROMPT, prompt)
        if resp.get("status") == "success":
            try:
                raw = resp["text"].strip()
                if raw.startswith("```"):
                    lines = raw.splitlines()[1:]
                    if lines and lines[-1].startswith("```"):
                        lines = lines[:-1]
                    raw = "\n".join(lines).strip()
                data = json.loads(raw)
                return LeaderPlan.model_validate(data)
            except Exception:
                pass

        return self._deterministic_plan(phase, compact_state)

    def _deterministic_plan(self, phase: str, compact_state: Dict[str, Any]) -> LeaderPlan:
        recent_obs = compact_state.get("recent_observations", [])
        obs_text = " ".join(str(o) for o in recent_obs).lower()

        if phase == "DISCOVERY" or compact_state.get("discovered_endpoints_count", 0) == 0:
            return LeaderPlan(
                priority="high",
                mission="Perform initial attack surface discovery and sitemap mapping",
                recommended_focus="crawl",
                recommended_tools=["crawl", "get_http_history"],
                task_queue=["Crawl seed URL", "Enumerate forms and parameters"],
                knowledge_hints=["Attack surface mapping"],
                reasoning_summary="No endpoints mapped yet. Prioritize passive & crawler discovery.",
                confidence=0.95
            )

        if "syntax error" in obs_text or "error" in obs_text:
            return LeaderPlan(
                priority="high",
                mission="Investigate potential SQL injection syntax break",
                recommended_focus="injection_test",
                recommended_tools=["run_detector", "replay_request"],
                task_queue=["Verify SQL error reproducibility", "Test balanced quotes"],
                knowledge_hints=["SQL injection error signatures"],
                reasoning_summary="Database error pattern identified in recent response. Focus on query injection verification.",
                confidence=0.90
            )

        if "id" in obs_text or "order" in obs_text or "user" in obs_text:
            return LeaderPlan(
                priority="high",
                mission="Investigate object-level authorization boundary across user identities",
                recommended_focus="authorization",
                recommended_tools=["run_detector", "replay_request"],
                task_queue=["Test parameter under User B identity", "Compare response objects"],
                knowledge_hints=["IDOR BOLA REST API object testing"],
                reasoning_summary="Predictable object identifier observed. Recommend cross-session boundary audit.",
                confidence=0.88
            )

        return LeaderPlan(
            priority="medium",
            mission="Analyze discovered parameters and passive security posture",
            recommended_focus="parameter_analysis",
            recommended_tools=["run_detector", "fuzz_parameter"],
            task_queue=["Audit security headers", "Probe reflected parameters"],
            knowledge_hints=["Reflected XSS canary analysis"],
            reasoning_summary="Attack surface mapped. Focus on active parameter verification.",
            confidence=0.82
        )
