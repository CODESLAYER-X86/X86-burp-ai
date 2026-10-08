from __future__ import annotations
from typing import Any, List
from models.evidence import Evidence
from models.finding import Finding, FindingSeverity, FindingConfidence, FindingStatus
from models.request import HTTPRequest
from .base import DetectorResult, SecurityContext, SecurityDetector


class CSRFDetector(SecurityDetector):
    @property
    def name(self) -> str:
        return "csrf"

    def can_analyze(self, context: SecurityContext) -> bool:
        # Applicable for state-changing endpoints (POST, PUT, PATCH, DELETE)
        return context.endpoint.method in ["POST", "PUT", "PATCH", "DELETE"]

    async def analyze(self, context: SecurityContext, http_client: Any) -> DetectorResult:
        evidence_list: List[Evidence] = []
        candidate_findings: List[Finding] = []

        headers = context.baseline_request.headers
        cookies = context.baseline_request.cookies

        # Check if auth is cookie-based
        has_session_cookie = len(cookies) > 0 or "Cookie" in headers
        has_csrf_token = any("csrf" in k.lower() or "xsrf" in k.lower() for k in headers.keys())

        # Check body for CSRF token if string
        if isinstance(context.baseline_request.body, str):
            if "csrf" in context.baseline_request.body.lower():
                has_csrf_token = True

        # Probe without any custom CSRF header or token
        stripped_headers = {k: v for k, v in headers.items() if not any(s in k.lower() for s in ["csrf", "xsrf", "token"])}
        probe_req = HTTPRequest(
            method=context.baseline_request.method,
            url=context.baseline_request.url,
            headers=stripped_headers,
            cookies=cookies,
            body=context.baseline_request.body,
            session_id=context.baseline_request.session_id
        )

        resp, err = await http_client.execute(probe_req)
        if not resp:
            return DetectorResult(self.name, "INCONCLUSIVE", summary="CSRF probe failed")

        # If request is accepted with 200/204/302 without CSRF validation and has cookie auth
        if not has_csrf_token and resp.status_code in [200, 204, 302] and has_session_cookie:
            evidence = Evidence(
                evidence_type="missing_csrf_protection",
                request_id=probe_req.request_id,
                response_id=resp.request_id,
                baseline_request_id=context.baseline_request.request_id,
                baseline_response_id=context.baseline_response.request_id,
                description=f"State-changing {context.endpoint.method} request accepted without CSRF token under cookie-based session.",
                data={
                    "status_code": resp.status_code,
                    "method": context.endpoint.method,
                    "cookies_present": list(cookies.keys())
                }
            )
            evidence_list.append(evidence)

            finding = Finding(
                finding_type="CROSS_SITE_REQUEST_FORGERY",
                title=f"Missing CSRF Protection on {context.endpoint.method} {context.endpoint.path}",
                severity=FindingSeverity.MEDIUM.value,
                confidence=FindingConfidence.HIGH.value,
                status=FindingStatus.VERIFIED.value,
                endpoint=context.endpoint.path,
                method=context.endpoint.method,
                description=f"The endpoint accepts state-changing {context.endpoint.method} requests without validating an anti-CSRF token or verifying Origin headers.",
                evidence_ids=[evidence.id],
                impact="An attacker could induce an authenticated victim's browser to execute unauthorized state-changing actions.",
                remediation="Implement anti-CSRF tokens (synchronizer token pattern), enforce SameSite=Lax/Strict cookie attributes, and validate Origin headers.",
                detector=self.name
            )
            candidate_findings.append(finding)

            return DetectorResult(
                detector_name=self.name,
                status="SUPPORTED",
                evidence_list=evidence_list,
                candidate_findings=candidate_findings,
                summary=f"CSRF vulnerability identified on {context.endpoint.method} {context.endpoint.path}."
            )

        return DetectorResult(self.name, "REFUTED", summary=f"CSRF protection observed on {context.endpoint.path}.")
