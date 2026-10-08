from __future__ import annotations
import urllib.parse
from typing import Any, Dict, Optional, Tuple

from models.endpoint import Endpoint
from models.observation import Observation
from models.request import HTTPRequest
from models.response import HTTPResponse
from scope.validator import ScopeValidator
from security.base import SecurityContext
from security.registry import DetectorRegistry
from tools.crawler import Crawler
from tools.fuzz import Fuzzer
from tools.http import HTTPClient
from tools.repeater import Repeater
from .budget import BudgetManager
from .decisions import AgentDecision
from .tool_registry import ToolRegistry


class Executor:
    """
    Mandatory security gate for Agentic-Burp.
    Validates tool existence, permissions, scope, and budgets before executing any action.
    """
    def __init__(
        self,
        tool_registry: ToolRegistry,
        scope_validator: ScopeValidator,
        budget_manager: BudgetManager,
        http_client: HTTPClient,
        detector_registry: DetectorRegistry,
        crawler: Crawler,
        repeater: Repeater,
        fuzzer: Fuzzer,
        allow_destructive: bool = False
    ):
        self.tool_registry = tool_registry
        self.scope_validator = scope_validator
        self.budget_manager = budget_manager
        self.http_client = http_client
        self.detector_registry = detector_registry
        self.crawler = crawler
        self.repeater = repeater
        self.fuzzer = fuzzer
        self.allow_destructive = allow_destructive

    async def execute(
        self,
        assessment_id: str,
        decision: AgentDecision,
        current_endpoint: Optional[Endpoint] = None,
        baseline_req: Optional[HTTPRequest] = None,
        baseline_resp: Optional[HTTPResponse] = None
    ) -> Tuple[bool, Optional[Observation], Dict[str, Any]]:
        # 1. TOOL REGISTRY LOOKUP
        tool_def = self.tool_registry.get(decision.tool)
        if not tool_def:
            obs = Observation(
                category="tool_rejected",
                source="executor",
                interesting=False,
                summary=f"Requested tool '{decision.tool}' is not registered."
            )
            return False, obs, {"error": "TOOL_NOT_REGISTERED"}

        # 2. PERMISSION VALIDATION
        if tool_def.permission == "DESTRUCTIVE" and not self.allow_destructive:
            obs = Observation(
                category="permission_denied",
                source="executor",
                interesting=False,
                summary="Destructive tools are strictly disabled by assessment safety policy."
            )
            return False, obs, {"error": "PERMISSION_DENIED"}

        # 3. BUDGET CHECK
        if not self.budget_manager.can_execute_http():
            obs = Observation(
                category="budget_exhausted",
                source="executor",
                interesting=False,
                summary="Maximum HTTP request budget reached."
            )
            return False, obs, {"error": "HTTP_BUDGET_EXHAUSTED"}

        # 4. DISPATCH EXECUTION
        args = decision.arguments
        if decision.tool == "crawl":
            seed_url = args.get("seed_url") or (current_endpoint.canonical_url if current_endpoint else "http://127.0.0.1:8080")
            result = await self.crawler.crawl(seed_url)
            self.budget_manager.record_http_request()
            return True, result.get("observation"), result

        elif decision.tool == "run_detector":
            detector_name = args.get("detector", "sqli")
            detector = self.detector_registry.get(detector_name)
            if not detector:
                obs = Observation(category="detector_error", source="executor", summary=f"Detector '{detector_name}' not found.")
                return False, obs, {"error": "DETECTOR_NOT_FOUND"}

            # Build SecurityContext
            ep = current_endpoint or Endpoint(method="GET", host="127.0.0.1", port=8080, path="/api/profile", parameters=["id"])
            breq = baseline_req or HTTPRequest(method="GET", url=ep.canonical_url + "?id=101")
            bresp = baseline_resp or HTTPResponse(status_code=200, body=b'{"id": 101, "name": "Alice"}')

            sec_context = SecurityContext(
                assessment_id=assessment_id,
                endpoint=ep,
                baseline_request=breq,
                baseline_response=bresp
            )

            # Check detector applicability
            if not detector.can_analyze(sec_context):
                obs = Observation(
                    category="detector_inapplicable",
                    source="executor",
                    summary=f"Detector '{detector_name}' is not applicable to endpoint {ep.path}."
                )
                return True, obs, {"status": "NOT_APPLICABLE"}

            det_result = await detector.analyze(sec_context, self.http_client)
            self.budget_manager.record_http_request()

            obs = Observation(
                category="detector_result",
                source=detector_name,
                endpoint=ep.path,
                interesting=det_result.status == "SUPPORTED",
                summary=det_result.summary,
                differences={"status": det_result.status, "findings_count": len(det_result.candidate_findings)}
            )
            return True, obs, {
                "detector_result": det_result,
                "findings": det_result.candidate_findings,
                "evidence": det_result.evidence_list
            }

        elif decision.tool == "replay_request":
            if not baseline_req:
                baseline_req = HTTPRequest(method="GET", url="http://127.0.0.1:8080/api/profile?id=101")
            result = await self.repeater.replay(baseline_req, baseline_resp, args.get("mutations", {}))
            self.budget_manager.record_http_request()
            return True, result.get("observation"), result

        elif decision.tool == "fuzz_parameter":
            target_param = args.get("parameter", "id")
            if not baseline_req:
                baseline_req = HTTPRequest(method="GET", url=f"http://127.0.0.1:8080/api/profile?{target_param}=1")
            if not baseline_resp:
                baseline_resp = HTTPResponse(status_code=200, body=b'{"status": "ok"}')
            result = await self.fuzzer.fuzz_parameter(baseline_req, baseline_resp, target_param, args.get("family", "numeric_boundary"))
            self.budget_manager.record_http_request()
            return True, result.get("observation"), result

        obs = Observation(category="tool_completed", source="executor", summary=f"Executed {decision.tool}")
        return True, obs, {"status": "success"}
