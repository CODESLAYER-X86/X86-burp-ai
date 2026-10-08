from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from .base import Model


class Observation(Model):
    id: str = ""
    category: str = "http_response"
    source: str = "http"
    request_id: Optional[str] = None
    endpoint: str = ""
    parameter: Optional[str] = None
    baseline: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    differences: Optional[Dict[str, Any]] = None
    signals: List[str] = []
    severity_hint: str = "info"
    raw_reference: Optional[str] = None
    interesting: bool = False
    summary: str = ""
    created_at: float = 0.0

    def __init__(self, **kwargs):
        if "id" not in kwargs or not kwargs["id"]:
            kwargs["id"] = f"obs_{uuid.uuid4().hex[:10]}"
        if "created_at" not in kwargs or not kwargs["created_at"]:
            kwargs["created_at"] = datetime.now(timezone.utc).timestamp()
        if "signals" not in kwargs:
            kwargs["signals"] = []
        super().__init__(**kwargs)

    def compact_for_llm(self) -> Dict[str, Any]:
        """Provides high-density token-efficient representation for Gemini reasoning."""
        data: Dict[str, Any] = {
            "id": self.id,
            "category": self.category,
            "endpoint": self.endpoint,
            "interesting": self.interesting,
        }
        if self.parameter:
            data["param"] = self.parameter
        if self.signals:
            data["signals"] = self.signals
        if self.differences:
            data["diffs"] = self.differences
        if self.severity_hint and self.severity_hint != "info":
            data["hint"] = self.severity_hint
        if self.summary:
            data["summary"] = self.summary
        return data
