from __future__ import annotations
import time
from typing import Dict, List, Optional
from models.base import Model


class DynamicToken(Model):
    name: str
    location: str # header | cookie | form_field | json_field | query
    value: str
    previous_value: Optional[str] = None
    header_name: Optional[str] = None # e.g. X-CSRF-Token or Authorization
    cookie_name: Optional[str] = None
    source_endpoint: Optional[str] = None
    source_request_id: Optional[str] = None
    injected_endpoints: List[str] = []
    status: str = "ACTIVE" # ACTIVE | EXPIRED | ROTATING
    created_at: float = 0.0
    updated_at: float = 0.0

    def __init__(self, **kwargs):
        if "created_at" not in kwargs or not kwargs["created_at"]:
            kwargs["created_at"] = time.time()
        if "updated_at" not in kwargs or not kwargs["updated_at"]:
            kwargs["updated_at"] = time.time()
        if "injected_endpoints" not in kwargs:
            kwargs["injected_endpoints"] = []
        super().__init__(**kwargs)

    def update_value(self, new_val: str, request_id: Optional[str] = None):
        if self.value != new_val:
            self.previous_value = self.value
            self.value = new_val
            self.updated_at = time.time()
            if request_id:
                self.source_request_id = request_id

    def to_summary(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "current_value": self.value[:16] + "..." if len(self.value) > 16 else self.value,
            "previous_value": (self.previous_value[:16] + "...") if self.previous_value and len(self.previous_value) > 16 else self.previous_value,
            "status": self.status,
            "source": self.source_endpoint,
            "updated_at": self.updated_at
        }


class TokenStore:
    """Central store tracking dynamic tokens across the assessment lifecycle."""
    def __init__(self):
        self._tokens: Dict[str, DynamicToken] = {}

    def set_token(self, token: DynamicToken):
        existing = self._tokens.get(token.name)
        if existing:
            existing.update_value(token.value, token.source_request_id)
        else:
            self._tokens[token.name] = token

    def get_token(self, name: str) -> Optional[DynamicToken]:
        return self._tokens.get(name)

    def list_tokens(self) -> List[DynamicToken]:
        return list(self._tokens.values())

    def clear(self):
        self._tokens.clear()
