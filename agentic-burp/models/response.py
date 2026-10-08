from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional
from .base import Model


class HTTPResponse(Model):
    request_id: str = ""
    status_code: int = 200
    headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    body: bytes = b""
    body_text: str = ""
    body_size: int = 0
    content_type: str = ""
    sha256: str = ""
    elapsed_ms: float = 0.0
    url: str = ""
    redirected: bool = False
    redirect_chain: List[str] = []
    timestamp: float = 0.0
    truncated: bool = False

    def __init__(self, **kwargs):
        if "timestamp" not in kwargs or not kwargs["timestamp"]:
            kwargs["timestamp"] = datetime.now(timezone.utc).timestamp()
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        if "cookies" not in kwargs:
            kwargs["cookies"] = {}
        if "redirect_chain" not in kwargs:
            kwargs["redirect_chain"] = []

        raw_body = kwargs.get("body", b"")
        if isinstance(raw_body, str):
            kwargs["body_text"] = raw_body
            kwargs["body"] = raw_body.encode("utf-8", errors="replace")
        elif isinstance(raw_body, bytes):
            kwargs["body"] = raw_body
            kwargs["body_text"] = raw_body.decode("utf-8", errors="replace")
        else:
            kwargs["body"] = b""
            kwargs["body_text"] = ""

        kwargs["body_size"] = len(kwargs["body"])
        kwargs["sha256"] = hashlib.sha256(kwargs["body"]).hexdigest()

        # Extract content type
        for k, v in kwargs["headers"].items():
            if k.lower() == "content-type":
                kwargs["content_type"] = v.split(";")[0].strip().lower()
                break

        super().__init__(**kwargs)
