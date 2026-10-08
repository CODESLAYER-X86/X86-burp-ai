from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union, Any
from .base import Model


class HTTPRequest(Model):
    request_id: str = ""
    session_id: str = "default"
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = {}
    query_params: List[Tuple[str, str]] = []
    cookies: Dict[str, str] = {}
    body: Optional[Union[str, bytes]] = None
    timestamp: float = 0.0

    def __init__(self, **kwargs):
        if "request_id" not in kwargs or not kwargs["request_id"]:
            kwargs["request_id"] = f"req_{uuid.uuid4().hex[:12]}"
        if "timestamp" not in kwargs or not kwargs["timestamp"]:
            kwargs["timestamp"] = datetime.now(timezone.utc).timestamp()
        if "method" in kwargs:
            kwargs["method"] = kwargs["method"].upper()
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        if "cookies" not in kwargs:
            kwargs["cookies"] = {}
        if "query_params" not in kwargs:
            kwargs["query_params"] = []
        super().__init__(**kwargs)

    @property
    def query_dict(self) -> Dict[str, str]:
        res = {}
        for k, v in self.query_params:
            res[k] = v
        return res
