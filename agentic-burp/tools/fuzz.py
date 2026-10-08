from __future__ import annotations
import asyncio
import collections
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from models.observation import Observation
from models.request import HTTPRequest
from models.response import HTTPResponse
from .analyzer import compare_responses
from .http import HTTPClient


FUZZ_MUTATIONS = {
    "numeric_boundary": ["0", "-1", "1", "2147483647", "999999", "NaN", "0.0"],
    "null_and_empty": ["", "%00", "null", "undefined", "None"],
    "string_bounds": ["A" * 50, "A" * 500, "admin", "root", "true", "false"],
    "special_chars": ["'", "\"", "`", ";", "--", "/*", "../", "..\\", "%2e%2e%2f"],
    "boolean_variants": ["1", "0", "true", "false", "yes", "no"]
}


class Fuzzer:
    """
    Controlled fuzzing engine.
    Executes bounded test mutations, clusters responses,
    and returns aggregated deviations to prevent token waste.
    """
    def __init__(
        self,
        http_client: HTTPClient,
        max_cases: int = 30,
        concurrency: int = 3
    ):
        self.http_client = http_client
        self.max_cases = max_cases
        self.semaphore = asyncio.Semaphore(concurrency)

    async def fuzz_parameter(
        self,
        base_request: HTTPRequest,
        baseline_response: HTTPResponse,
        target_param: str,
        mutation_family: str = "numeric_boundary"
    ) -> Dict[str, Any]:
        candidates = FUZZ_MUTATIONS.get(mutation_family, FUZZ_MUTATIONS["numeric_boundary"])[:self.max_cases]

        results = []
        clusters = collections.defaultdict(list)
        interesting_deviations = []

        parsed = urllib.parse.urlsplit(base_request.url)
        base_query = dict(urllib.parse.parse_qsl(parsed.query))

        for payload in candidates:
            async with self.semaphore:
                # Mutate parameter
                m_query = dict(base_query)
                m_query[target_param] = payload
                m_url = urllib.parse.urlunsplit((
                    parsed.scheme, parsed.netloc, parsed.path,
                    urllib.parse.urlencode(m_query), ""
                ))

                req = HTTPRequest(
                    method=base_request.method,
                    url=m_url,
                    headers=dict(base_request.headers),
                    cookies=dict(base_request.cookies),
                    session_id=base_request.session_id
                )

                resp, err = await self.http_client.execute(req)
                if not resp:
                    continue

                diff = compare_responses(baseline_response, resp)
                cluster_key = f"{resp.status_code}_{round(resp.body_size, -2)}"
                clusters[cluster_key].append(payload)

                if diff["interesting"]:
                    interesting_deviations.append({
                        "payload": payload,
                        "status": resp.status_code,
                        "size": resp.body_size,
                        "similarity": diff["similarity"],
                        "reasons": diff["reasons"]
                    })

                results.append((payload, resp, diff))

        summary_text = (
            f"Fuzz test on '{target_param}' ({mutation_family}): {len(results)} cases tested. "
            f"Found {len(interesting_deviations)} notable deviations across {len(clusters)} response clusters."
        )

        obs = Observation(
            category="fuzz_summary",
            source="fuzzer",
            endpoint=f"{base_request.method} {parsed.path}",
            parameter=target_param,
            interesting=len(interesting_deviations) > 0,
            summary=summary_text,
            signals=[f"{len(interesting_deviations)}_deviations"],
            differences={
                "deviations": interesting_deviations[:5],
                "clusters": {k: len(v) for k, v in clusters.items()}
            }
        )

        return {
            "summary": summary_text,
            "parameter": target_param,
            "total_cases": len(results),
            "deviations": interesting_deviations,
            "clusters": {k: len(v) for k, v in clusters.items()},
            "observation": obs,
        }
