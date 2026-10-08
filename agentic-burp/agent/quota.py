from __future__ import annotations
import time
from typing import Dict, List, Optional, Tuple
from .credentials import GeminiProject


class QuotaManager:
    """
    Sliding-window token usage and daily request tracker for multi-project rotation.
    Enforces rolling 1-minute token windows and cooldown failovers.
    """
    def __init__(self, projects: List[GeminiProject], rolling_window_seconds: float = 60.0):
        self.projects = {p.project_id: p for p in projects}
        self.rolling_window_seconds = rolling_window_seconds
        # Mapping: project_id -> list of (timestamp, input_tokens)
        self.token_history: Dict[str, List[Tuple[float, int]]] = {
            p.project_id: [] for p in projects
        }

    def register_project(self, project: GeminiProject):
        self.projects[project.project_id] = project
        if project.project_id not in self.token_history:
            self.token_history[project.project_id] = []

    def get_rolling_token_usage(self, project_id: str, current_time: float) -> int:
        history = self.token_history.get(project_id, [])
        cutoff = current_time - self.rolling_window_seconds
        # Purge older entries
        active = [entry for entry in history if entry[0] >= cutoff]
        self.token_history[project_id] = active
        return sum(tokens for _, tokens in active)

    def select_best_project(self, estimated_input_tokens: int, current_time: float) -> Optional[GeminiProject]:
        """
        Quota-driven selection: selects the project with greatest usable capacity
        that can safely accommodate estimated input tokens.
        """
        eligible: List[Tuple[float, GeminiProject]] = []

        for p in self.projects.values():
            if not p.is_available(current_time):
                continue

            current_tpm = self.get_rolling_token_usage(p.project_id, current_time)
            remaining_tpm = p.input_tokens_per_minute - current_tpm

            # Safety headroom check (reserve 15% margin)
            if remaining_tpm < (estimated_input_tokens * 1.15):
                continue

            # Calculate capacity score = remaining_tpm - (consecutive_errors * 2000)
            score = remaining_tpm - (p.consecutive_errors * 2000)
            eligible.append((score, p))

        if not eligible:
            return None

        # Sort descending by capacity score
        eligible.sort(key=lambda x: x[0], reverse=True)
        return eligible[0][1]

    def record_usage(self, project_id: str, input_tokens: int, output_tokens: int, current_time: float):
        if project_id in self.projects:
            self.projects[project_id].requests_today += 1
            self.projects[project_id].consecutive_errors = 0
            if project_id not in self.token_history:
                self.token_history[project_id] = []
            self.token_history[project_id].append((current_time, input_tokens))

    def record_error(self, project_id: str, error_type: str, current_time: float):
        p = self.projects.get(project_id)
        if not p:
            return

        p.consecutive_errors += 1

        if error_type == "429_RESOURCE_EXHAUSTED":
            # Exponential backoff cooldown: 10s -> 30s -> 90s (max 300s)
            delay = min(10.0 * (3 ** (p.consecutive_errors - 1)), 300.0)
            p.cooldown_until = current_time + delay
        elif error_type == "401_UNAUTHORIZED":
            # Invalid credential: permanently disable this project
            p.enabled = False
