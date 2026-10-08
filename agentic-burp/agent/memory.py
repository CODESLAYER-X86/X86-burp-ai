from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from models.finding import Finding
from models.observation import Observation
from storage.database import Database


class AgentMemory:
    """
    3-Layer memory management with deterministic context ranking and compaction.
    Raw 40KB+ HTTP responses are strictly kept in SQLite, while compact observations
    and structured facts populate LLM context.
    """
    def __init__(self, assessment_id: str, db: Optional[Database] = None):
        self.assessment_id = assessment_id
        self.db = db

        # Short-term memory
        self.last_decision: Optional[Dict[str, Any]] = None
        self.last_observation: Optional[Observation] = None
        self.current_hypothesis: Optional[Dict[str, Any]] = None

        # Session memory
        self.observations: List[Observation] = []
        self.endpoints: List[str] = []
        self.findings: List[Finding] = []

    def record_observation(self, obs: Observation):
        self.last_observation = obs
        self.observations.append(obs)

    def record_finding(self, finding: Finding):
        # Update or append
        existing = [f for f in self.findings if f.id == finding.id]
        if existing:
            idx = self.findings.index(existing[0])
            self.findings[idx] = finding
        else:
            self.findings.append(finding)

    def build_llm_context(
        self,
        phase: str,
        current_objective: str,
        max_tokens_budget: int = 4000
    ) -> Dict[str, Any]:
        """
        Builds a compact, prioritized context window for Gemma 4 31B.
        Prioritizes:
        1. Current objective
        2. Current hypothesis
        3. Latest interesting observations
        4. Key findings
        5. Endpoint inventory summary
        """
        # Deduplicate & rank observations
        interesting_obs = [obs.compact_for_llm() for obs in self.observations if obs.interesting][-6:]
        regular_obs = [obs.compact_for_llm() for obs in self.observations if not obs.interesting][-2:]
        combined_obs = regular_obs + interesting_obs

        # Compact findings list
        compact_findings = []
        for f in self.findings:
            compact_findings.append({
                "id": f.id,
                "type": f.finding_type,
                "status": f.status,
                "endpoint": f.endpoint,
                "severity": f.severity,
            })

        context: Dict[str, Any] = {
            "phase": phase,
            "objective": current_objective,
            "discovered_endpoints_count": len(self.endpoints),
            "sample_endpoints": self.endpoints[:10],
            "recent_observations": combined_obs,
            "active_findings": compact_findings,
        }

        if self.current_hypothesis:
            context["current_hypothesis"] = self.current_hypothesis

        return context
