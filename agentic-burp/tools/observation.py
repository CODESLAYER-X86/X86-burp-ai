from __future__ import annotations
from typing import Any, Dict, List, Optional
from models.observation import Observation
from models.request import HTTPRequest
from models.response import HTTPResponse


class ObservationBuilder:
    """
    Constructs compressed, structured observations from network operations
    to protect the Gemini token budget while maintaining high evidentiary signal.
    """
    @staticmethod
    def from_http_transaction(
        request: HTTPRequest,
        response: Optional[HTTPResponse],
        comparison: Optional[Dict[str, Any]] = None,
        signals: Optional[List[str]] = None
    ) -> Observation:
        signals = signals or []
        interesting = False

        if response:
            if response.status_code in [500, 401, 403]:
                interesting = True
                signals.append(f"status_{response.status_code}")

            if comparison and comparison.get("interesting"):
                interesting = True
                signals.extend(comparison.get("reasons", []))

        summary = f"{request.method} {request.url}"
        if response:
            summary += f" -> {response.status_code} ({response.body_size} bytes, {response.elapsed_ms}ms)"
        else:
            summary += " -> Network Failed"

        return Observation(
            category="http_transaction",
            source="http",
            request_id=request.request_id,
            endpoint=request.url,
            signals=signals,
            interesting=interesting,
            summary=summary,
            differences=comparison,
            result={
                "status_code": response.status_code if response else 0,
                "body_size": response.body_size if response else 0,
                "elapsed_ms": response.elapsed_ms if response else 0.0,
            } if response else {}
        )
