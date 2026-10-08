from __future__ import annotations
import asyncio
import collections
import urllib.parse
from typing import Any, Dict, List, Set, Tuple

from models.endpoint import Endpoint, ParameterInfo
from models.observation import Observation
from models.request import HTTPRequest
from scope.resolver import extract_host_port, normalize_url
from .http import HTTPClient
from .parser import parse_html


class Crawler:
    """
    Controlled, queue-based crawler enforcing scope, depth limits, and deduplication.
    Generates compact summary observations for LLM reasoning.
    """
    def __init__(
        self,
        http_client: HTTPClient,
        max_depth: int = 3,
        max_pages: int = 50,
        max_requests: int = 100,
        same_origin_only: bool = True
    ):
        self.http_client = http_client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.max_requests = max_requests
        self.same_origin_only = same_origin_only

        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Dict[str, Endpoint] = {}
        self.discovered_forms: List[Dict[str, Any]] = []

    async def crawl(self, seed_url: str) -> Dict[str, Any]:
        """Runs the queue-based crawl from a starting seed URL."""
        queue: collections.deque[Tuple[str, int]] = collections.deque()
        canonical_seed = normalize_url(seed_url)
        queue.append((canonical_seed, 0))
        self.visited_urls.add(canonical_seed)

        seed_scheme, seed_host, seed_port = extract_host_port(seed_url)
        total_requests = 0

        while queue and len(self.visited_urls) <= self.max_pages and total_requests < self.max_requests:
            current_url, depth = queue.popleft()
            if depth > self.max_depth:
                continue

            req = HTTPRequest(method="GET", url=current_url)
            total_requests += 1

            resp, err = await self.http_client.execute(req)
            if not resp or resp.status_code >= 400:
                continue

            # Record discovered endpoint
            parsed = urllib.parse.urlsplit(current_url)
            params = []
            if parsed.query:
                params = [k for k, _ in urllib.parse.parse_qsl(parsed.query)]

            endpoint_key = f"GET {parsed.path}"
            if endpoint_key not in self.discovered_endpoints:
                self.discovered_endpoints[endpoint_key] = Endpoint(
                    method="GET",
                    scheme=parsed.scheme,
                    host=parsed.hostname or seed_host,
                    port=parsed.port or (443 if parsed.scheme == "https" else 80),
                    path=parsed.path,
                    parameters=params,
                    source="crawler"
                )

            # Parse content if HTML
            if "html" in resp.content_type or not resp.content_type:
                parsed_content = parse_html(resp.body_text, current_url)

                # Record forms
                for form in parsed_content["forms"]:
                    self.discovered_forms.append(form)
                    form_path = urllib.parse.urlsplit(form["action"]).path
                    form_params = [f["name"] for f in form["fields"]]
                    form_key = f"{form['method']} {form_path}"
                    if form_key not in self.discovered_endpoints:
                        self.discovered_endpoints[form_key] = Endpoint(
                            method=form["method"],
                            scheme=seed_scheme,
                            host=seed_host,
                            port=seed_port,
                            path=form_path,
                            parameters=form_params,
                            source="form"
                        )

                # Queue next links within scope & depth
                for link in parsed_content["links"] + parsed_content["api_endpoints"]:
                    c_link = normalize_url(link)
                    if c_link in self.visited_urls:
                        continue

                    link_scheme, link_host, link_port = extract_host_port(c_link)
                    if self.same_origin_only and (link_host != seed_host or link_port != seed_port):
                        continue

                    # Pre-validate scope before queueing
                    if not self.http_client.scope_validator.validate_url(c_link):
                        continue

                    self.visited_urls.add(c_link)
                    queue.append((c_link, depth + 1))

        # Build compact crawl summary observation
        parameterized = [ep for ep in self.discovered_endpoints.values() if ep.parameters]
        summary_text = (
            f"Crawl completed: {len(self.visited_urls)} pages inspected, "
            f"{len(self.discovered_endpoints)} unique endpoints ({len(parameterized)} parameterized), "
            f"{len(self.discovered_forms)} HTML forms identified."
        )

        observation = Observation(
            category="crawl_summary",
            source="crawler",
            endpoint=seed_url,
            interesting=len(parameterized) > 0 or len(self.discovered_forms) > 0,
            summary=summary_text,
            signals=[f"{len(self.discovered_endpoints)}_endpoints", f"{len(parameterized)}_params"],
            result={
                "pages_crawled": len(self.visited_urls),
                "total_endpoints": len(self.discovered_endpoints),
                "parameterized_count": len(parameterized),
                "forms_count": len(self.discovered_forms),
            }
        )

        return {
            "summary": summary_text,
            "endpoints": list(self.discovered_endpoints.values()),
            "forms": self.discovered_forms,
            "observation": observation,
            "pages_visited": len(self.visited_urls),
        }
