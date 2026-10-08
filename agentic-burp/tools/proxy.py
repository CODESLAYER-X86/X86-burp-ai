from __future__ import annotations
import asyncio
from typing import Any, Callable, Dict, Optional
from models.request import HTTPRequest
from models.response import HTTPResponse
from scope.validator import ScopeValidator
from storage.traffic import TrafficRepository
from .scanner import run_passive_scan


class InterceptionProxy:
    """
    Traffic Interception Proxy Pipeline.
    Intercepts authorized browser/client traffic, validates scope, stores traffic,
    and runs passive security analysis.
    """
    def __init__(
        self,
        scope_validator: ScopeValidator,
        traffic_repo: TrafficRepository,
        on_observation: Optional[Callable[[Any], None]] = None
    ):
        self.scope_validator = scope_validator
        self.traffic_repo = traffic_repo
        self.on_observation = on_observation
        self.intercept_enabled = False

    def process_captured_transaction(
        self,
        assessment_id: str,
        request: HTTPRequest,
        response: Optional[HTTPResponse]
    ) -> bool:
        """Processes captured transaction through scope gate and storage."""
        # Check scope
        scope_result = self.scope_validator.validate_request(request.method, request.url)
        if not scope_result:
            return False # Drop out-of-scope traffic

        # Save to storage
        self.traffic_repo.save_transaction(assessment_id, request, response)

        # Passive security scan
        if response and self.on_observation:
            passive_obs = run_passive_scan(response)
            for obs in passive_obs:
                self.on_observation(obs)

        return True
