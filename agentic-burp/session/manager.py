from __future__ import annotations
from typing import Dict, List, Optional, Tuple, Any
from models.session import AssessmentSession
from models.request import HTTPRequest
from models.response import HTTPResponse
from .token_store import TokenStore, DynamicToken
from .extractor import TokenExtractor
from .injector import TokenInjector
from .recovery import SessionRecoveryManager


class SessionManager:
    """
    Coordinates multi-identity assessment sessions, dynamic token stores,
    automatic extraction, dependency injection, and recovery.
    """
    def __init__(self):
        self.token_store = TokenStore()
        self.recovery_manager = SessionRecoveryManager(self.token_store)
        self.sessions: Dict[str, AssessmentSession] = {
            "session_a": AssessmentSession(
                id="session_a",
                name="User A (Alice / Tenant Owner)",
                principal="alice",
                headers={"X-User-Identity": "alice", "Authorization": "Bearer token_alice_initial"}
            ),
            "session_b": AssessmentSession(
                id="session_b",
                name="User B (Bob / Cross-Tenant)",
                principal="bob",
                headers={"X-User-Identity": "bob", "Authorization": "Bearer token_bob_initial"}
            ),
            "unauth": AssessmentSession(
                id="unauth",
                name="Unauthenticated (Anonymous)",
                principal="anonymous",
                headers={}
            )
        }
        self.active_session_id = "session_a"

    def get_active_session(self) -> AssessmentSession:
        return self.sessions.get(self.active_session_id) or self.sessions["session_a"]

    def set_active_session(self, session_id: str):
        if session_id in self.sessions:
            self.active_session_id = session_id

    def list_sessions(self) -> List[AssessmentSession]:
        return list(self.sessions.values())

    def prepare_outbound_request(self, request: HTTPRequest, session_id: Optional[str] = None) -> HTTPRequest:
        sess = self.sessions.get(session_id or self.active_session_id) or self.get_active_session()
        # Merge session headers
        merged = dict(request.headers)
        merged.update(sess.headers)
        request.headers = merged

        merged_cookies = dict(request.cookies)
        merged_cookies.update(sess.cookies)
        request.cookies = merged_cookies

        # Deterministic token injection
        return TokenInjector.inject(request, self.token_store)

    def process_incoming_response(self, response: HTTPResponse, source_endpoint: str):
        TokenExtractor.extract_from_response(response, source_endpoint, self.token_store)
