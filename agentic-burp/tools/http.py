from __future__ import annotations
import asyncio
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from models.request import HTTPRequest
from models.response import HTTPResponse
from models.session import AssessmentSession
from scope.validator import ScopeValidator


class RateLimiter:
    """Sliding-window token rate limiter for outbound HTTP requests."""
    def __init__(self, max_per_minute: int = 60):
        self.max_per_minute = max_per_minute
        self.timestamps: List[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self._lock:
            now = time.time()
            # Discard timestamps older than 60 seconds
            self.timestamps = [t for t in self.timestamps if now - t < 60.0]
            if len(self.timestamps) >= self.max_per_minute:
                return False
            self.timestamps.append(now)
            return True


class HTTPClient:
    """
    Central Asynchronous HTTP Execution Engine for Agentic-Burp.
    Strictly enforces Scope, Rate Limits, Session Jars, Bounded Payloads, and Timing.
    """
    def __init__(
        self,
        scope_validator: ScopeValidator,
        max_requests_per_minute: int = 60,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 5242880, # 5MB limit
        follow_redirects: bool = True,
        max_redirects: int = 5
    ):
        self.scope_validator = scope_validator
        self.rate_limiter = RateLimiter(max_requests_per_minute)
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.cookie_jar: Dict[str, str] = {}

    async def execute(
        self,
        request: HTTPRequest,
        session: Optional[AssessmentSession] = None
    ) -> Tuple[Optional[HTTPResponse], Optional[str]]:
        """
        Executes HTTP request through the security gate.
        Returns (HTTPResponse, error_code).
        """
        # 1. SCOPE VALIDATION (MANDATORY GATEWAY)
        scope_check = self.scope_validator.validate_request(request.method, request.url)
        if not scope_check:
            return None, f"SCOPE_DENIED: {scope_check.reason}"

        # 2. RATE LIMIT ENFORCEMENT
        can_proceed = await self.rate_limiter.acquire()
        if not can_proceed:
            return None, "RATE_LIMITED: Outbound request rate limit reached"

        # 3. PREPARE REQUEST HEADERS AND COOKIES
        headers = dict(request.headers)
        if "User-Agent" not in headers:
            headers["User-Agent"] = "Agentic-Burp/1.0 (Authorized Security Assessment)"

        # Merge session headers & cookies
        effective_cookies = dict(self.cookie_jar)
        if session:
            for k, v in session.headers.items():
                headers[k] = v
            for k, v in session.cookies.items():
                effective_cookies[k] = v
        for k, v in request.cookies.items():
            effective_cookies[k] = v

        if effective_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in effective_cookies.items())

        # Prepare body
        body_bytes = None
        if request.body:
            if isinstance(request.body, str):
                body_bytes = request.body.encode("utf-8")
            else:
                body_bytes = request.body

        start_time = time.time()
        try:
            # Execute in thread executor to keep async loop non-blocking
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                None,
                self._sync_fetch,
                request.method,
                request.url,
                headers,
                body_bytes
            )
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            resp.elapsed_ms = elapsed_ms
            resp.request_id = request.request_id

            # Update session/cookie jar from response Set-Cookie
            for k, v in resp.cookies.items():
                self.cookie_jar[k] = v
                if session:
                    session.cookies[k] = v

            return resp, None

        except urllib.error.HTTPError as e:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            resp_headers = dict(e.headers.items())
            raw_body = e.read(self.max_response_bytes)
            error_resp = HTTPResponse(
                request_id=request.request_id,
                status_code=e.code,
                headers=resp_headers,
                body=raw_body,
                elapsed_ms=elapsed_ms,
                url=request.url
            )
            return error_resp, None

        except urllib.error.URLError as e:
            reason = str(e.reason).lower()
            if "timed out" in reason:
                return None, "TIMEOUT"
            if "name or service not known" in reason or "nodename nor servname" in reason:
                return None, "DNS_ERROR"
            if "connection refused" in reason:
                return None, "CONNECTION_REFUSED"
            return None, f"CONNECTION_ERROR: {e.reason}"

        except TimeoutError:
            return None, "TIMEOUT"
        except Exception as e:
            return None, f"INTERNAL_ERROR: {str(e)}"

    def _sync_fetch(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body_bytes: Optional[bytes]
    ) -> HTTPResponse:
        req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=self.timeout_seconds) as response:
            status_code = response.getcode()
            resp_headers = dict(response.headers.items())
            raw_body = response.read(self.max_response_bytes)
            truncated = len(raw_body) >= self.max_response_bytes

            # Extract cookies
            cookies = {}
            for k, v in response.headers.items():
                if k.lower() == "set-cookie":
                    cookie_parts = v.split(";")[0].strip()
                    if "=" in cookie_parts:
                        ck, cv = cookie_parts.split("=", 1)
                        cookies[ck.strip()] = cv.strip()

            return HTTPResponse(
                status_code=status_code,
                headers=resp_headers,
                cookies=cookies,
                body=raw_body,
                url=response.geturl(),
                truncated=truncated
            )
