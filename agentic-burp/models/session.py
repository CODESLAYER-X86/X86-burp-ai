from __future__ import annotations
from enum import Enum
from typing import Dict, Optional
from .base import Model


class AuthState(str, Enum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    AUTHENTICATED = "AUTHENTICATED"
    EXPIRED = "EXPIRED"
    LOGGED_OUT = "LOGGED_OUT"
    UNKNOWN = "UNKNOWN"


class AssessmentSession(Model):
    id: str = "default"
    name: str = "Anonymous"
    principal: str = "anonymous"
    auth_state: str = AuthState.UNAUTHENTICATED.value
    cookies: Dict[str, str] = {}
    headers: Dict[str, str] = {}

    def __init__(self, **kwargs):
        if "cookies" not in kwargs:
            kwargs["cookies"] = {}
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        super().__init__(**kwargs)

    def sanitized_headers(self) -> Dict[str, str]:
        """Redacts sensitive credentials for logging and LLM context."""
        out = {}
        for k, v in self.headers.items():
            k_low = k.lower()
            if any(s in k_low for s in ["auth", "token", "key", "secret", "cookie"]):
                out[k] = "[REDACTED]"
            else:
                out[k] = v
        return out
