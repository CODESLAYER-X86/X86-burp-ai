from __future__ import annotations
import time
from typing import Any, Dict, List, Optional
from .credentials import GeminiProject
from .gemini_client import GeminiClient
from .quota import QuotaManager


class GeminiAPIRouter:
    """
    Quota-aware Multi-Project API Rotation Router (Section 2.X).
    Routes requests according to available capacity, executes bounded failover,
    and updates sliding-window token accounting.
    """
    def __init__(self, quota_manager: QuotaManager, max_attempts: int = 3):
        self.quota_manager = quota_manager
        self.max_attempts = max_attempts

    async def generate(
        self,
        system_instruction: str,
        prompt: str,
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        estimated_input_tokens = len(prompt) // 4
        attempts = 0

        while attempts < self.max_attempts:
            now = time.time()
            project = self.quota_manager.select_best_project(estimated_input_tokens, now)
            if not project:
                return {
                    "status": "error",
                    "error_type": "ALL_PROJECTS_EXHAUSTED",
                    "error": "All available Gemini projects are currently in cooldown or daily quota exhausted."
                }

            client = GeminiClient(project)
            resp = await client.generate_content(system_instruction, prompt, tools)

            if resp.get("status") == "success":
                # Record successful usage
                in_tok = resp.get("input_tokens", estimated_input_tokens)
                out_tok = resp.get("output_tokens", 100)
                self.quota_manager.record_usage(project.project_id, in_tok, out_tok, now)
                resp["project_id"] = project.project_id
                return resp

            # Handle error
            err_type = resp.get("error_type", "UNKNOWN")
            self.quota_manager.record_error(project.project_id, err_type, now)

            # Classify error: 429 triggers failover to next eligible project
            if err_type == "429_RESOURCE_EXHAUSTED":
                attempts += 1
                continue
            elif err_type == "401_UNAUTHORIZED":
                attempts += 1
                continue
            else:
                # Application/request error: do not rotate, return immediately
                return resp

        return {
            "status": "error",
            "error_type": "MAX_FAILOVER_EXCEEDED",
            "error": f"Failed after {self.max_attempts} project rotation attempts."
        }
