from __future__ import annotations
import uuid
from typing import Any, Dict, List, Optional
from models.base import Model
from models.finding import Finding
from models.observation import Observation
from models.task import Task


class AgentState(Model):
    run_id: str = ""
    target: str = ""
    phase: str = "DISCOVERY" # DISCOVERY | ANALYSIS | INVESTIGATION | VERIFICATION | REPORTING | COMPLETE
    iteration: int = 0
    discovered_endpoints: List[str] = []
    interesting_endpoints: List[str] = []
    observations: List[Observation] = []
    findings: List[Finding] = []
    pending_tasks: List[Task] = []
    completed_tasks: List[Task] = []
    stop_reason: Optional[str] = None
    paused: bool = False

    def __init__(self, **kwargs):
        if "run_id" not in kwargs or not kwargs["run_id"]:
            kwargs["run_id"] = f"run_{uuid.uuid4().hex[:8]}"
        if "discovered_endpoints" not in kwargs:
            kwargs["discovered_endpoints"] = []
        if "interesting_endpoints" not in kwargs:
            kwargs["interesting_endpoints"] = []
        if "observations" not in kwargs:
            kwargs["observations"] = []
        if "findings" not in kwargs:
            kwargs["findings"] = []
        if "pending_tasks" not in kwargs:
            kwargs["pending_tasks"] = []
        if "completed_tasks" not in kwargs:
            kwargs["completed_tasks"] = []
        super().__init__(**kwargs)
