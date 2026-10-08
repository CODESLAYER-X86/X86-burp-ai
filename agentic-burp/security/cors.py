from __future__ import annotations
from typing import Any, List
from models.evidence import Evidence
from models.finding import Finding, FindingSeverity, FindingConfidence, FindingStatus
from models.request import HTTPRequest
from .base import DetectorResult, SecurityContext, SecurityDetector


class CORSDetector(SecurityDetector):
    @property
    def name(self) -> str:
        return "cors"

    def can_analyze(self, context: SecurityContext) -> bool:
        # Applicable for API endpoints
        return "/api/" in context.endpoint.path.lower() or "cors" in context.endpoint.path.lower()

    async def analyze(self, context: SecurityContext, http_client: Any) -> DetectorResult:
        evidence_list: List[Evidence] = []
        candidate_findings: List[Finding] = []

        untrusted_origin = "https://untrusted-third-party.example"
        probe_headers = dict(context.baseline_request.headers)
        probe_headers["Origin"] = untrusted_origin

        probe_req = HTTPRequest(
            method=context.baseline_request.method,
            url=context.baseline_request.url,
            headers=probe_headers,
            session_id=context.baseline_request.session_id
        )

        resp, err = await http_client.execute(probe_req)
        if not resp:
            return DetectorResult(self.name, "INCONCLUSIVE", summary="CORS probe failed")

        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        acao = resp_headers.get("access-control-allow-origin", "")
        acac = resp_headers.get("access-control-allow-credentials", "").lower() == "true"

        # Check for reflective origin + credentials allowed
        if acao == untrusted_origin and acac:
            evidence = Evidence(
                evidence_type="insecure_cors_misconfiguration",
                request_id=probe_req.request_id,
                response_id=resp.request_id,
                baseline_request_id=context.baseline_request.request_id,
                baseline_response_id=context.baseline_response.request_id,
                description=f"Server reflects arbitrary Origin '{untrusted_origin}' with Access-Control-Allow-Credentials: true.",
                data={
                    "origin_sent": untrusted_origin,
                    "acao_returned": acao,
                    "credentials_allowed": acac
                }
            )
            evidence_list.append(evidence)

            finding = Finding(
                finding_type="CORS_MISCONFIGURATION",
                title=f"Insecure CORS Misconfiguration on {context.endpoint.path}",
                severity=FindingSeverity.MEDIUM.value,
                confidence=FindingConfidence.CONFIRMED.value,
                status=FindingStatus.VERIFIED.value,
                endpoint=context.endpoint.path,
                method=context.endpoint.method,
                description=f"The endpoint reflects arbitrary Origin headers in Access-Control-Allow-Origin while permitting credentials, allowing cross-origin data exfiltration.",
                evidence_ids=[evidence.id],
                impact="An external malicious website visited by an authenticated user can read sensitive responses via cross-origin JavaScript requests.",
                remediation="Avoid dynamically reflecting arbitrary Origin headers with credentials. Maintain an explicit whitelist of trusted origins.",
                detector=self.name
            )
            candidate_findings.append(finding)

            return DetectorResult(
                detector_name=self.name,
                status="SUPPORTED",
                evidence_list=evidence_list,
                candidate_findings=candidate_findings,
                summary=f"Insecure CORS misconfiguration identified on {context.endpoint.path}."
            )

        return DetectorResult(self.name, "REFUTED", summary=f"CORS policy on {context.endpoint.path} is secure.")
