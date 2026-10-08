from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from .base import Model


class TaskType(str, Enum):
    DISCOVER = "DISCOVER"
    ANALYZE = "ANALYZE"
    INVESTIGATE = "INVESTIGATE"
    VERIFY = "VERIFY"
    REPORT = "REPORT"


class TaskStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Task(Model):
    id: str = ""
    task_type: str = TaskType.DISCOVER.value
    description: str = ""
    target: str = ""
    constraints: Dict[str, Any] = {}
    priority: int = 1
    status: str = TaskStatus.PENDING.value
    created_at: float = 0.0

    def __init__(self, **kwargs):
        if "id" not in kwargs or not kwargs["id"]:
            kwargs["id"] = f"tsk_{uuid.uuid4().hex[:10]}"
        if "created_at" not in kwargs or not kwargs["created_at"]:
            kwargs["created_at"] = datetime.now(timezone.utc).timestamp()
        if "constraints" not in kwargs:
            kwargs["constraints"] = {}
        super().__init__(**kwargs)
