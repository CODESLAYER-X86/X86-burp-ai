from __future__ import annotations
import time
from typing import Dict, Optional


class BudgetManager:
    """
    Global assessment-wide budget and quota enforcement.
    Ensures runs do not enter infinite loops or exceed safe operational envelopes.
    """
    def __init__(
        self,
        max_llm_calls: int = 50,
        max_http_requests: int = 500,
        max_iterations: int = 50,
        max_verification_requests: int = 20
    ):
        self.max_llm_calls = max_llm_calls
        self.max_http_requests = max_http_requests
        self.max_iterations = max_iterations
        self.max_verification_requests = max_verification_requests

        self.current_llm_calls = 0
        self.current_http_requests = 0
        self.current_iterations = 0
        self.current_verification_requests = 0
        self.estimated_input_tokens = 0
        self.estimated_output_tokens = 0

    def can_call_llm(self) -> bool:
        return self.current_llm_calls < self.max_llm_calls

    def record_llm_call(self, input_tokens: int, output_tokens: int):
        self.current_llm_calls += 1
        self.estimated_input_tokens += input_tokens
        self.estimated_output_tokens += output_tokens

    def can_execute_http(self) -> bool:
        return self.current_http_requests < self.max_http_requests

    def record_http_request(self):
        self.current_http_requests += 1

    def increment_iteration(self) -> bool:
        self.current_iterations += 1
        return self.current_iterations <= self.max_iterations

    def get_operational_mode(self) -> str:
        """
        Calculates adaptive operational posture:
        NORMAL -> REDUCED_LLM -> DETERMINISTIC_HEAVY -> LLM_PAUSED
        """
        remaining_llm = self.max_llm_calls - self.current_llm_calls
        if remaining_llm <= 0:
            return "LLM_PAUSED"
        elif remaining_llm <= 5:
            return "DETERMINISTIC_HEAVY"
        elif remaining_llm <= 15:
            return "REDUCED_LLM"
        return "NORMAL"

    def summary(self) -> Dict[str, int]:
        return {
            "llm_calls": self.current_llm_calls,
            "max_llm_calls": self.max_llm_calls,
            "http_requests": self.current_http_requests,
            "max_http_requests": self.max_http_requests,
            "iterations": self.current_iterations,
            "max_iterations": self.max_iterations,
            "estimated_input_tokens": self.estimated_input_tokens,
            "estimated_output_tokens": self.estimated_output_tokens,
        }
