from __future__ import annotations
from typing import Any, Dict, Optional
from models.base import Model


class AgentDecision(Model):
    action: str = "investigate"
    tool: str = "http_request"
    arguments: Dict[str, Any] = {}
    reasoning_summary: str = ""
    hypothesis_id: Optional[str] = None
    confidence: float = 0.8
