from __future__ import annotations
import urllib.parse
from typing import Any, List
from models.evidence import Evidence
from models.finding import Finding, FindingSeverity, FindingConfidence, FindingStatus
from models.request import HTTPRequest
from tools.analyzer import compare_responses
from .base import DetectorResult, SecurityContext, SecurityDetector


SQL_ERROR_PATTERNS = [
    "syntax error", "sqlstate", "sqlite3.operationalerror",
    "pg_query", "mysql_fetch", "ora-01756", "unclosed quotation mark",
    "quoted string not properly terminated", "check the manual that corresponds to your mysql"
]


class SQLiDetector(SecurityDetector):
    @property
    def name(self) -> str:
        return "sqli"

    def can_analyze(self, context: SecurityContext) -> bool:
        # Applicable only if the endpoint has query parameters or form fields
        return len(context.endpoint.parameters) > 0 or bool(context.baseline_request.query_params)

    async def analyze(self, context: SecurityContext, http_client: Any) -> DetectorResult:
        evidence_list: List[Evidence] = []
        candidate_findings: List[Finding] = []

        target_param = context.endpoint.parameters[0] if context.endpoint.parameters else "id"
        parsed = urllib.parse.urlsplit(context.baseline_request.url)
        base_query = dict(urllib.parse.parse_qsl(parsed.query))

        # Test 1: Single quote syntax break
        quote_query = dict(base_query)
        quote_query[target_param] = f"{base_query.get(target_param, '1')}'"
        quote_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(quote_query), ""))

        req_quote = HTTPRequest(
            method=context.baseline_request.method,
            url=quote_url,
            headers=dict(context.baseline_request.headers),
            session_id=context.baseline_request.session_id
        )

        resp_quote, err_quote = await http_client.execute(req_quote)
        if not resp_quote:
            return DetectorResult(self.name, "INCONCLUSIVE", summary="Network error during SQLi probe")

        quote_diff = compare_responses(context.baseline_response, resp_quote)

        # Check for DB error signature
        error_found = False
        detected_sig = ""
        for sig in SQL_ERROR_PATTERNS:
            if sig in resp_quote.body_text.lower() and sig not in context.baseline_response.body_text.lower():
                error_found = True
                detected_sig = sig
                break

        # Test 2: Balanced quote repair (e.g. `''` or balance verification)
        balance_query = dict(base_query)
        balance_query[target_param] = f"{base_query.get(target_param, '1')}''"
        balance_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(balance_query), ""))
        req_balance = HTTPRequest(
            method=context.baseline_request.method,
            url=balance_url,
            headers=dict(context.baseline_request.headers),
            session_id=context.baseline_request.session_id
        )
        resp_balance, _ = await http_client.execute(req_balance)

        if error_found:
            evidence = Evidence(
                evidence_type="sql_syntax_error",
                request_id=req_quote.request_id,
                response_id=resp_quote.request_id,
                baseline_request_id=context.baseline_request.request_id,
                baseline_response_id=context.baseline_response.request_id,
                description=f"Database error signature '{detected_sig}' triggered by quote injection on parameter '{target_param}'.",
                data={
                    "parameter": target_param,
                    "signature": detected_sig,
                    "diff": quote_diff
                }
            )
            evidence_list.append(evidence)

            status = FindingStatus.VERIFIED.value if (resp_balance and resp_balance.status_code == context.baseline_response.status_code) else FindingStatus.INVESTIGATING.value

            finding = Finding(
                finding_type="SQL_INJECTION",
                title=f"SQL Injection in parameter '{target_param}'",
                severity=FindingSeverity.HIGH.value,
                confidence=FindingConfidence.HIGH.value if status == FindingStatus.VERIFIED.value else FindingConfidence.MEDIUM.value,
                status=status,
                endpoint=context.endpoint.path,
                method=context.endpoint.method,
                parameter=target_param,
                description=f"Parameter '{target_param}' triggers database syntax errors when injected with single quotes, indicating improper query parameterization.",
                evidence_ids=[evidence.id],
                impact="An attacker could execute arbitrary database queries, access sensitive data, or bypass authentication.",
                remediation="Use parameterized queries / prepared statements (e.g., ORM, parameterized SQL). Never concatenate untrusted input into query strings.",
                detector=self.name
            )
            candidate_findings.append(finding)

            return DetectorResult(
                detector_name=self.name,
                status="SUPPORTED",
                evidence_list=evidence_list,
                candidate_findings=candidate_findings,
                summary=f"SQL Injection candidate identified on parameter '{target_param}' with signature '{detected_sig}'."
            )

        return DetectorResult(self.name, "REFUTED", summary=f"No SQL injection vulnerability detected on '{target_param}'.")
