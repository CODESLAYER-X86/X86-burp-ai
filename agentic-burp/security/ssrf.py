from __future__ import annotations
import urllib.parse
import uuid
from typing import Any, List
from models.evidence import Evidence
from models.finding import Finding, FindingSeverity, FindingConfidence, FindingStatus
from models.request import HTTPRequest
from .base import DetectorResult, SecurityContext, SecurityDetector


class SSRFDetector(SecurityDetector):
    @property
    def name(self) -> str:
        return "ssrf"

    def can_analyze(self, context: SecurityContext) -> bool:
        # Applicable if parameter name suggests URL or host destination
        url_param_names = ["url", "dest", "target", "redirect", "uri", "fetch", "webhook", "callback"]
        params = [p.lower() for p in context.endpoint.parameters]
        return any(any(un in p for un in url_param_names) for p in params)

    async def analyze(self, context: SecurityContext, http_client: Any) -> DetectorResult:
        evidence_list: List[Evidence] = []
        candidate_findings: List[Finding] = []

        target_param = "url"
        for p in context.endpoint.parameters:
            if any(un in p.lower() for un in ["url", "dest", "target", "uri", "fetch"]):
                target_param = p
                break

        # Safe callback correlation test using loopback or controlled callback target
        correlation_token = f"ssrf_token_{uuid.uuid4().hex[:8]}"
        callback_test_url = f"http://127.0.0.1:8080/callback?token={correlation_token}"

        parsed = urllib.parse.urlsplit(context.baseline_request.url)
        base_query = dict(urllib.parse.parse_qsl(parsed.query))
        probe_query = dict(base_query)
        probe_query[target_param] = callback_test_url

        probe_url = urllib.parse.urlunsplit((
            parsed.scheme, parsed.netloc, parsed.path,
            urllib.parse.urlencode(probe_query), ""
        ))

        req_probe = HTTPRequest(
            method=context.baseline_request.method,
            url=probe_url,
            headers=dict(context.baseline_request.headers),
            session_id=context.baseline_request.session_id
        )

        resp, err = await http_client.execute(req_probe)
        if not resp:
            return DetectorResult(self.name, "INCONCLUSIVE", summary="SSRF probe failed to execute")

        # Check if response reflects fetched callback data or correlation token
        if correlation_token in resp.body_text:
            evidence = Evidence(
                evidence_type="server_side_fetch_confirmed",
                request_id=req_probe.request_id,
                response_id=resp.request_id,
                baseline_request_id=context.baseline_request.request_id,
                baseline_response_id=context.baseline_response.request_id,
                description=f"Server fetched the supplied URL parameter and returned the response containing token '{correlation_token}'.",
                data={
                    "parameter": target_param,
                    "callback_url": callback_test_url,
                    "correlation_token": correlation_token
                }
            )
            evidence_list.append(evidence)

            finding = Finding(
                finding_type="SERVER_SIDE_REQUEST_FORGERY",
                title=f"Server-Side Request Forgery (SSRF) in parameter '{target_param}'",
                severity=FindingSeverity.HIGH.value,
                confidence=FindingConfidence.CONFIRMED.value,
                status=FindingStatus.VERIFIED.value,
                endpoint=context.endpoint.path,
                method=context.endpoint.method,
                parameter=target_param,
                description=f"The application backend fetches arbitrary URLs provided in the '{target_param}' parameter and returns the target content.",
                evidence_ids=[evidence.id],
                impact="An attacker could leverage SSRF to scan internal network infrastructure, access cloud instance metadata services, or forge internal requests.",
                remediation="Validate URL inputs against a strict allowlist. Disable HTTP redirects, block internal/loopback IP ranges, and isolate outbound fetchers.",
                detector=self.name
            )
            candidate_findings.append(finding)

            return DetectorResult(
                detector_name=self.name,
                status="SUPPORTED",
                evidence_list=evidence_list,
                candidate_findings=candidate_findings,
                summary=f"SSRF verified in parameter '{target_param}'."
            )

        return DetectorResult(self.name, "REFUTED", summary=f"No SSRF behavior identified in '{target_param}'.")
