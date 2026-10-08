from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from .base import Model


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


class FindingStatus(str, Enum):
    SUSPECTED = "SUSPECTED"
    INVESTIGATING = "INVESTIGATING"
    VERIFIED = "VERIFIED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class Finding(Model):
    id: str = ""
    finding_type: str = ""
    title: str = ""
    severity: str = FindingSeverity.MEDIUM.value
    confidence: str = FindingConfidence.MEDIUM.value
    status: str = FindingStatus.SUSPECTED.value
    endpoint: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None
    description: str = ""
    evidence_ids: List[str] = []
    impact: str = ""
    remediation: str = ""
    detector: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0

    def __init__(self, **kwargs):
        if "id" not in kwargs or not kwargs["id"]:
            kwargs["id"] = f"fnd_{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc).timestamp()
        if "created_at" not in kwargs or not kwargs["created_at"]:
            kwargs["created_at"] = now
        if "updated_at" not in kwargs or not kwargs["updated_at"]:
            kwargs["updated_at"] = now
        if "evidence_ids" not in kwargs:
            kwargs["evidence_ids"] = []
        super().__init__(**kwargs)
