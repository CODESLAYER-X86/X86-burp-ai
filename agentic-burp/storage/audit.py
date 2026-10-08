from __future__ import annotations
import json
import time
from typing import Any, Dict, List
from .database import Database


class AuditRepository:
    def __init__(self, db: Database):
        self.db = db

    def record_event(self, assessment_id: str, event_type: str, data: Dict[str, Any]):
        # Redact any accidental sensitive headers or keys before writing
        sanitized = self._sanitize(data)
        query = "INSERT INTO audit_events (assessment_id, event_type, timestamp, data_json) VALUES (?, ?, ?, ?)"
        self.db.execute_write(query, (assessment_id, event_type, time.time(), json.dumps(sanitized)))

    def list_events(self, assessment_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self.db.query_all(
            "SELECT * FROM audit_events WHERE assessment_id = ? ORDER BY id DESC LIMIT ?",
            (assessment_id, limit)
        )
        for r in rows:
            if "data_json" in r:
                r["data"] = json.loads(r["data_json"])
        return rows

    def _sanitize(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            res = {}
            for k, v in obj.items():
                if any(s in str(k).lower() for s in ["key", "token", "secret", "auth", "password"]):
                    res[k] = "[REDACTED]"
                else:
                    res[k] = self._sanitize(v)
            return res
        elif isinstance(obj, list):
            return [self._sanitize(i) for i in obj]
        return obj
