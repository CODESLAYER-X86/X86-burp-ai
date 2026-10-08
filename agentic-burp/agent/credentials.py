from __future__ import annotations
import os
from typing import Dict, List, Optional
from models.base import Model


class GeminiProject(Model):
    project_id: str
    api_key: str
    model: str = "gemma-4-31b"
    enabled: bool = True
    daily_request_limit: int = 14000
    input_tokens_per_minute: int = 16000
    requests_today: int = 0
    consecutive_errors: int = 0
    cooldown_until: float = 0.0

    def is_available(self, current_time: float) -> bool:
        if not self.enabled:
            return False
        if self.cooldown_until > current_time:
            return False
        if self.requests_today >= self.daily_request_limit:
            return False
        return True


def load_gemini_projects_from_env() -> List[GeminiProject]:
    """
    Loads arbitrary number of Gemini projects from environment variables.
    Never persists keys in plain text logs or database.
    """
    projects: List[GeminiProject] = []
    default_model = os.environ.get("GEMINI_MODEL", "gemma-4-31b")

    # Primary key fallback
    primary_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if primary_key:
        projects.append(GeminiProject(
            project_id="primary-project",
            api_key=primary_key,
            model=default_model,
        ))

    # Multi-project indices (GEMINI_PROJECT_1_*, GEMINI_PROJECT_2_*, ...)
    idx = 1
    while True:
        pid = os.environ.get(f"GEMINI_PROJECT_{idx}_ID")
        pkey = os.environ.get(f"GEMINI_PROJECT_{idx}_API_KEY")
        pmodel = os.environ.get(f"GEMINI_PROJECT_{idx}_MODEL", default_model)

        if not pid and not pkey:
            if idx > 3: # Allow up to 3 checked misses
                break
            idx += 1
            continue

        if pkey:
            projects.append(GeminiProject(
                project_id=pid or f"project-{idx}",
                api_key=pkey,
                model=pmodel,
            ))
        idx += 1

    return projects
