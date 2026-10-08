from __future__ import annotations
import time
from typing import Dict, List, Optional, Any
from models.base import Model
from models.request import HTTPRequest
from models.response import HTTPResponse


class RequestDiff(Model):
    parameter: Optional[str] = None
    header: Optional[str] = None
    old_value: str = ""
    new_value: str = ""
    reason: str = ""


class InterceptedTransaction(Model):
    id: str
    timestamp: float
    client_ip: str = "127.0.0.1"
    original_request: HTTPRequest
    modified_request: Optional[HTTPRequest] = None
    modifications: List[RequestDiff] = []
    response: Optional[HTTPResponse] = None
    status: str = "PENDING" # PENDING | FORWARDED | DROPPED
    intercepted_by: str = "human" # human | ai | pass_through
    ai_observation_id: Optional[str] = None

    def __init__(self, **kwargs):
        if "timestamp" not in kwargs or not kwargs["timestamp"]:
            kwargs["timestamp"] = time.time()
        if "modifications" not in kwargs:
            kwargs["modifications"] = []
        super().__init__(**kwargs)

    def has_modifications(self) -> bool:
        return len(self.modifications) > 0 or (self.modified_request is not None and self.modified_request.url != self.original_request.url)
