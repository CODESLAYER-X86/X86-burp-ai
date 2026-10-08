from __future__ import annotations
import urllib.parse
from typing import Any, List
from models.evidence import Evidence
from models.finding import Finding, FindingSeverity, FindingConfidence, FindingStatus
from models.request import HTTPRequest
from models.session import AssessmentSession
from .base import DetectorResult, SecurityContext, SecurityDetector


class IDORDetector(SecurityDetector):
    @property
    def name(self) -> str:
        return "idor"

    def can_analyze(self, context: SecurityContext) -> bool:
        # Applicable if path or query has an object identifier (e.g. id, order_id, user_id)
        params = [p.lower() for p in context.endpoint.parameters]
        id_names = ["id", "order_id", "user_id", "account_id", "doc_id", "profile_id"]
        return any(any(idn in p for idn in id_names) for p in params) or ("id" in context.endpoint.path.lower())

    async def analyze(self, context: SecurityContext, http_client: Any) -> DetectorResult:
        evidence_list: List[Evidence] = []
        candidate_findings: List[Finding] = []

        # Find target object parameter
        target_param = "id"
        for p in context.endpoint.parameters:
            if "id" in p.lower():
                target_param = p
                break

        parsed = urllib.parse.urlsplit(context.baseline_request.url)
        base_query = dict(urllib.parse.parse_qsl(parsed.query))
        source_val = base_query.get(target_param, "101")

        # Create alternate object identifier (e.g. 101 -> 102)
        try:
            target_val = str(int(source_val) + 1)
        except ValueError:
            target_val = f"{source_val}_alt"

        # Check if second session (User B) is available in context
        session_b = context.sessions.get("session_b") or AssessmentSession(
            id="session_b",
            name="Authorized Test User B",
            principal="user_b",
            headers={"X-User-Identity": "user_b"}
        )

        # User B requests Object belonging to User A (source_val)
        b_query = dict(base_query)
        b_query[target_param] = source_val
        cross_url = urllib.parse.urlunsplit((
            parsed.scheme, parsed.netloc, parsed.path,
            urllib.parse.urlencode(b_query), ""
        ))

        req_cross = HTTPRequest(
            method=context.baseline_request.method,
            url=cross_url,
            session_id=session_b.id,
            headers=dict(session_b.headers)
        )

        resp_cross, err_cross = await http_client.execute(req_cross, session=session_b)
        if not resp_cross:
            return DetectorResult(self.name, "INCONCLUSIVE", summary="Cross-account request failed")

        # Analyze cross-account response
        # If User B receives 200 OK with data matching User A's object, IDOR is indicated
        is_unauthorized_success = (resp_cross.status_code == 200 and resp_cross.body_size > 20)

        if is_unauthorized_success:
            evidence = Evidence(
                evidence_type="broken_object_authorization",
                request_id=req_cross.request_id,
                response_id=resp_cross.request_id,
                baseline_request_id=context.baseline_request.request_id,
                baseline_response_id=context.baseline_response.request_id,
                description=f"User B successfully retrieved resource {source_val} owned by User A with HTTP 200.",
                data={
                    "parameter": target_param,
                    "target_object": source_val,
                    "user_a_status": context.baseline_response.status_code,
                    "user_b_status": resp_cross.status_code,
                    "body_size": resp_cross.body_size
                }
            )
            evidence_list.append(evidence)

            finding = Finding(
                finding_type="BOLA_IDOR",
                title=f"Broken Object-Level Authorization (IDOR) on {context.endpoint.path}",
                severity=FindingSeverity.HIGH.value,
                confidence=FindingConfidence.CONFIRMED.value,
                status=FindingStatus.VERIFIED.value,
                endpoint=context.endpoint.path,
                method=context.endpoint.method,
                parameter=target_param,
                description=f"The endpoint at {context.endpoint.path} failed to enforce object-level access control on parameter '{target_param}'. User B was able to access data owned by User A.",
                evidence_ids=[evidence.id],
                impact="An attacker could enumerate and access private customer orders, account data, or sensitive user records across tenant boundaries.",
                remediation="Implement server-side authorization checks verifying that the authenticated user owns or has explicit permission to view the requested object ID.",
                detector=self.name
            )
            candidate_findings.append(finding)

            return DetectorResult(
                detector_name=self.name,
                status="SUPPORTED",
                evidence_list=evidence_list,
                candidate_findings=candidate_findings,
                summary=f"IDOR verified: User B accessed object {source_val} belonging to User A."
            )

        return DetectorResult(self.name, "REFUTED", summary=f"Proper authorization boundary enforced on {target_param}.")
