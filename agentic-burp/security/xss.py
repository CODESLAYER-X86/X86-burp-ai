from __future__ import annotations
import html
import urllib.parse
from typing import Any, List
from models.evidence import Evidence
from models.finding import Finding, FindingSeverity, FindingConfidence, FindingStatus
from models.request import HTTPRequest
from .base import DetectorResult, SecurityContext, SecurityDetector


class XSSDetector(SecurityDetector):
    @property
    def name(self) -> str:
        return "xss"

    def can_analyze(self, context: SecurityContext) -> bool:
        # Applicable for endpoints with parameters returning HTML or text
        return len(context.endpoint.parameters) > 0

    async def analyze(self, context: SecurityContext, http_client: Any) -> DetectorResult:
        evidence_list: List[Evidence] = []
        candidate_findings: List[Finding] = []

        target_param = context.endpoint.parameters[0]
        canary = "xss_probe_7381<test>\"'"
        safe_canary_marker = "xss_probe_7381<test>"

        parsed = urllib.parse.urlsplit(context.baseline_request.url)
        base_query = dict(urllib.parse.parse_qsl(parsed.query))
        probe_query = dict(base_query)
        probe_query[target_param] = canary

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
            return DetectorResult(self.name, "INCONCLUSIVE", summary="Network probe failed")

        body_text = resp.body_text
        reflected_raw = safe_canary_marker in body_text
        reflected_encoded = html.escape(safe_canary_marker) in body_text

        if reflected_raw and not reflected_encoded:
            # Unescaped reflection! Check context
            context_type = "html_body"
            if f'"{safe_canary_marker}' in body_text or f"'{safe_canary_marker}" in body_text:
                context_type = "html_attribute"
            elif f"<script" in body_text and safe_canary_marker in body_text:
                context_type = "javascript_block"

            evidence = Evidence(
                evidence_type="unencoded_reflection",
                request_id=req_probe.request_id,
                response_id=resp.request_id,
                baseline_request_id=context.baseline_request.request_id,
                baseline_response_id=context.baseline_response.request_id,
                description=f"Canary probe reflected verbatim without HTML entity encoding in context '{context_type}'.",
                data={
                    "parameter": target_param,
                    "canary": canary,
                    "context": context_type
                }
            )
            evidence_list.append(evidence)

            finding = Finding(
                finding_type="CROSS_SITE_SCRIPTING",
                title=f"Reflected XSS in parameter '{target_param}'",
                severity=FindingSeverity.HIGH.value if context_type != "html_attribute" else FindingSeverity.MEDIUM.value,
                confidence=FindingConfidence.CONFIRMED.value,
                status=FindingStatus.VERIFIED.value,
                endpoint=context.endpoint.path,
                method=context.endpoint.method,
                parameter=target_param,
                description=f"User-supplied input in parameter '{target_param}' is reflected without sanitization or HTML encoding in {context_type}.",
                evidence_ids=[evidence.id],
                impact="An attacker could execute arbitrary scripts in the victim's browser, steal session tokens, or perform actions on their behalf.",
                remediation="Contextually HTML-encode user input before rendering it in web pages. Implement a strong Content-Security-Policy (CSP).",
                detector=self.name
            )
            candidate_findings.append(finding)

            return DetectorResult(
                detector_name=self.name,
                status="SUPPORTED",
                evidence_list=evidence_list,
                candidate_findings=candidate_findings,
                summary=f"Reflected XSS confirmed in parameter '{target_param}' ({context_type})."
            )

        return DetectorResult(self.name, "REFUTED", summary=f"Parameter '{target_param}' is not vulnerable to reflected XSS.")
