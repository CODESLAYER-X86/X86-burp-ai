from __future__ import annotations
from typing import Any, List
from models.evidence import Evidence
from models.finding import Finding, FindingSeverity, FindingConfidence, FindingStatus
from models.request import HTTPRequest
from .base import DetectorResult, SecurityContext, SecurityDetector


class AuthDetector(SecurityDetector):
    @property
    def name(self) -> str:
        return "auth"

    def can_analyze(self, context: SecurityContext) -> bool:
        # Applicable for private API paths or authenticated endpoints
        path_low = context.endpoint.path.lower()
        return any(s in path_low for s in ["/api/", "/account", "/admin", "/profile", "/order", "/dashboard"])

    async def analyze(self, context: SecurityContext, http_client: Any) -> DetectorResult:
        evidence_list: List[Evidence] = []
        candidate_findings: List[Finding] = []

        # Send completely unauthenticated request with empty headers and cookies
        unauth_req = HTTPRequest(
            method=context.baseline_request.method,
            url=context.baseline_request.url,
            headers={}, # Stripped auth
            cookies={},
            session_id="unauthenticated"
        )

        resp, err = await http_client.execute(unauth_req)
        if not resp:
            return DetectorResult(self.name, "INCONCLUSIVE", summary="Unauthenticated probe failed")

        # Baseline was 200, but unauthenticated is also 200 with data
        if resp.status_code == 200 and resp.body_size > 150:
            evidence = Evidence(
                evidence_type="missing_authentication",
                request_id=unauth_req.request_id,
                response_id=resp.request_id,
                baseline_request_id=context.baseline_request.request_id,
                baseline_response_id=context.baseline_response.request_id,
                description=f"Protected path {context.endpoint.path} is accessible without authentication (HTTP 200).",
                data={
                    "status_code": resp.status_code,
                    "body_size": resp.body_size
                }
            )
            evidence_list.append(evidence)

            finding = Finding(
                finding_type="BROKEN_AUTHENTICATION",
                title=f"Unauthenticated Access to Protected Endpoint {context.endpoint.path}",
                severity=FindingSeverity.HIGH.value,
                confidence=FindingConfidence.HIGH.value,
                status=FindingStatus.VERIFIED.value,
                endpoint=context.endpoint.path,
                method=context.endpoint.method,
                description=f"The endpoint {context.endpoint.path} returned HTTP 200 and data when accessed without any authentication credentials.",
                evidence_ids=[evidence.id],
                impact="Unauthenticated external users can access sensitive application endpoints without signing in.",
                remediation="Ensure middleware enforces authentication tokens or session validation before processing requests to this endpoint.",
                detector=self.name
            )
            candidate_findings.append(finding)

            return DetectorResult(
                detector_name=self.name,
                status="SUPPORTED",
                evidence_list=evidence_list,
                candidate_findings=candidate_findings,
                summary=f"Missing authentication verified on {context.endpoint.path}."
            )

        return DetectorResult(self.name, "REFUTED", summary=f"Authentication properly enforced on {context.endpoint.path}.")
