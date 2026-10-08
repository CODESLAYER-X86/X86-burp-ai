from __future__ import annotations
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from models.observation import Observation
from models.request import HTTPRequest
from models.response import HTTPResponse
from storage.traffic import TrafficRepository
from .analyzer import compare_responses
from .http import HTTPClient


class Repeater:
    """
    Deterministic Repeater tool for replaying requests with structured mutations.
    Compares replay result with original baseline response.
    """
    def __init__(self, http_client: HTTPClient, traffic_repo: Optional[TrafficRepository] = None):
        self.http_client = http_client
        self.traffic_repo = traffic_repo

    async def replay(
        self,
        base_request: HTTPRequest,
        baseline_response: Optional[HTTPResponse] = None,
        mutations: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes mutated request and computes differences against baseline.
        """
        mutations = mutations or {}

        # 1. Clone request and apply structured mutations
        method = mutations.get("method", base_request.method).upper()
        url = base_request.url
        headers = dict(base_request.headers)
        cookies = dict(base_request.cookies)
        body = base_request.body

        # Query param mutations
        if "query" in mutations:
            parsed = urllib.parse.urlsplit(url)
            query_dict = dict(urllib.parse.parse_qsl(parsed.query))
            for k, v in mutations["query"].items():
                if v is None:
                    query_dict.pop(k, None)
                else:
                    query_dict[k] = str(v)
            new_query = urllib.parse.urlencode(query_dict)
            url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, ""))

        # Path mutation
        if "path" in mutations:
            parsed = urllib.parse.urlsplit(url)
            url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, mutations["path"], parsed.query, ""))

        # Header mutations
        if "headers" in mutations:
            for k, v in mutations["headers"].items():
                if v is None:
                    headers.pop(k, None)
                else:
                    headers[k] = str(v)

        # Cookie mutations
        if "cookies" in mutations:
            for k, v in mutations["cookies"].items():
                if v is None:
                    cookies.pop(k, None)
                else:
                    cookies[k] = str(v)

        # Body mutation
        if "body" in mutations:
            body = mutations["body"]

        mutated_req = HTTPRequest(
            method=method,
            url=url,
            headers=headers,
            cookies=cookies,
            body=body,
            session_id=base_request.session_id
        )

        # 2. Execute via HTTPClient
        new_resp, err = await self.http_client.execute(mutated_req)
        if err or not new_resp:
            return {
                "success": False,
                "error": err or "Failed to receive response",
                "request": mutated_req,
                "response": None,
                "comparison": None
            }

        # 3. Compare with baseline if provided
        comparison = None
        interesting = False
        if baseline_response:
            comparison = compare_responses(baseline_response, new_resp)
            interesting = comparison["interesting"]

        obs = Observation(
            category="repeater_replay",
            source="repeater",
            request_id=mutated_req.request_id,
            endpoint=f"{mutated_req.method} {urllib.parse.urlsplit(mutated_req.url).path}",
            interesting=interesting,
            summary=f"Replay status: {new_resp.status_code} ({new_resp.body_size} bytes)" + (
                f", similarity: {comparison['similarity']}" if comparison else ""
            ),
            differences=comparison,
            result={
                "status_code": new_resp.status_code,
                "body_size": new_resp.body_size,
                "elapsed_ms": new_resp.elapsed_ms,
            }
        )

        return {
            "success": True,
            "request": mutated_req,
            "response": new_resp,
            "comparison": comparison,
            "observation": obs,
        }
