from __future__ import annotations
import time
from typing import Dict, Optional, Callable, Any, Tuple
from models.request import HTTPRequest
from models.response import HTTPResponse
from models.session import AssessmentSession
from .token_store import TokenStore


class SessionRecoveryManager:
    """
    Automated session recovery engine (Section 7).
    Detects HTTP 401/403 session expiration, triggers recovery macros,
    updates the token store, and retries the request safely within budget.
    """
    def __init__(self, token_store: TokenStore):
        self.token_store = token_store
        self.recovery_macros: Dict[str, Callable[[], Dict[str, str]]] = {}
        self.recovery_history: list = []

    def register_recovery_macro(self, session_id: str, macro: Callable[[], Dict[str, str]]):
        self.recovery_macros[session_id] = macro

    def is_session_expired(self, response: HTTPResponse) -> bool:
        if response.status_code in [401, 419]:
            return True
        if response.status_code == 403:
            b_low = response.body_text.lower()
            if any(s in b_low for s in ["session expired", "token expired", "unauthenticated", "login required"]):
                return True
        return False

    async def attempt_recovery(
        self,
        session: AssessmentSession,
        failed_request: HTTPRequest,
        http_client: Any
    ) -> Tuple[bool, Optional[HTTPResponse], str]:
        """Executes recovery macro and retries original request with fresh credentials."""
        session_id = session.id
        macro = self.recovery_macros.get(session_id)

        before_state = dict(session.headers)

        if not macro:
            # Default recovery: renew mock test identity credentials
            new_token = f"token_refreshed_{session_id}_{int(time.time())}"
            session.headers["Authorization"] = f"Bearer {new_token}"
            session.headers["X-User-Identity"] = session.principal
        else:
            new_creds = macro()
            session.headers.update(new_creds)

        after_state = dict(session.headers)
        record = {
            "timestamp": time.time(),
            "session_id": session_id,
            "session_before": "[REDACTED_TOKENS]",
            "session_after": "[REDACTED_TOKENS]",
            "recovery_reason": "HTTP 401 / Session Invalidation Detected",
            "recovery_action": "Executed credential renewal macro",
        }
        self.recovery_history.append(record)

        # Rebuild and retry original request
        rebuilt_headers = dict(failed_request.headers)
        rebuilt_headers.update(session.headers)
        retry_req = HTTPRequest(
            method=failed_request.method,
            url=failed_request.url,
            headers=rebuilt_headers,
            cookies=dict(session.cookies),
            body=failed_request.body,
            session_id=session_id
        )

        resp, err = await http_client.execute(retry_req, session=session)
        if resp and resp.status_code not in [401, 419]:
            record["retry_result"] = f"SUCCESS (HTTP {resp.status_code})"
            return True, resp, "Session successfully recovered and request retried."

        record["retry_result"] = f"FAILED (HTTP {resp.status_code if resp else 'ERROR'})"
        return False, resp, f"Recovery attempt failed: {err or 'Unauthorized status persisted'}"
