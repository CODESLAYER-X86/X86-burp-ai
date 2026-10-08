from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from .database import Database
from models.request import HTTPRequest
from models.response import HTTPResponse


class TrafficRepository:
    def __init__(self, db: Database):
        self.db = db

    def save_transaction(self, assessment_id: str, request: HTTPRequest, response: Optional[HTTPResponse]):
        req_headers_json = json.dumps(request.headers)
        req_params_json = json.dumps(request.query_params)
        req_cookies_json = json.dumps(request.cookies)
        req_body = request.body if isinstance(request.body, str) else (request.body.decode("utf-8", errors="replace") if isinstance(request.body, bytes) else "")

        status_code = response.status_code if response else 0
        resp_headers_json = json.dumps(response.headers) if response else "{}"
        resp_body = response.body_text if response else ""
        body_size = response.body_size if response else 0
        content_type = response.content_type if response else ""
        sha256 = response.sha256 if response else ""
        elapsed_ms = response.elapsed_ms if response else 0.0
        truncated = 1 if (response and response.truncated) else 0

        query = """
        INSERT OR REPLACE INTO http_traffic (
            request_id, assessment_id, session_id, method, url,
            headers_json, query_params_json, cookies_json, request_body,
            status_code, response_headers_json, response_body,
            body_size, content_type, sha256, elapsed_ms, truncated, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        self.db.execute_write(query, (
            request.request_id, assessment_id, request.session_id, request.method, request.url,
            req_headers_json, req_params_json, req_cookies_json, req_body,
            status_code, resp_headers_json, resp_body,
            body_size, content_type, sha256, elapsed_ms, truncated, request.timestamp
        ))

    def get_transaction(self, request_id: str) -> Optional[Dict[str, Any]]:
        return self.db.query_one("SELECT * FROM http_traffic WHERE request_id = ?", (request_id,))

    def list_transactions(self, assessment_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        return self.db.query_all(
            "SELECT request_id, session_id, method, url, status_code, body_size, content_type, elapsed_ms, timestamp FROM http_traffic WHERE assessment_id = ? ORDER BY timestamp DESC LIMIT ?",
            (assessment_id, limit)
        )
