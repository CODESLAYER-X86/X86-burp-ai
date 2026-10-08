from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from .base import Model


class Evidence(Model):
    id: str = ""
    evidence_type: str = "differential_response"
    request_id: Optional[str] = None
    response_id: Optional[str] = None
    baseline_request_id: Optional[str] = None
    baseline_response_id: Optional[str] = None
    description: str = ""
    data: Dict[str, Any] = {}
    reproducible: bool = True
    created_at: float = 0.0

    def __init__(self, **kwargs):
        if "id" not in kwargs or not kwargs["id"]:
            kwargs["id"] = f"evi_{uuid.uuid4().hex[:10]}"
        if "created_at" not in kwargs or not kwargs["created_at"]:
            kwargs["created_at"] = datetime.now(timezone.utc).timestamp()
        if "data" not in kwargs:
            kwargs["data"] = {}
        super().__init__(**kwargs)
