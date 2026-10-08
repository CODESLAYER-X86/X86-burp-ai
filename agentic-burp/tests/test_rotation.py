import unittest
import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agent.credentials import GeminiProject
from agent.quota import QuotaManager
from agent.api_router import GeminiAPIRouter


class TestMultiProjectRotation(unittest.TestCase):
    def setUp(self):
        self.p1 = GeminiProject(
            project_id="proj-alpha",
            api_key="mock_key_1",
            model="gemma-4-31b",
            input_tokens_per_minute=10000
        )
        self.p2 = GeminiProject(
            project_id="proj-beta",
            api_key="mock_key_2",
            model="gemma-4-31b",
            input_tokens_per_minute=16000
        )
        self.mgr = QuotaManager([self.p1, self.p2], rolling_window_seconds=60.0)
        self.router = GeminiAPIRouter(self.mgr)

    def test_quota_selection_picks_higher_headroom(self):
        now = time.time()
        # beta has 16000 TPM vs alpha 10000 TPM -> beta selected
        chosen = self.mgr.select_best_project(estimated_input_tokens=1000, current_time=now)
        self.assertIsNotNone(chosen)
        self.assertEqual(chosen.project_id, "proj-beta")

    def test_sliding_window_token_accounting(self):
        now = time.time()
        self.mgr.record_usage("proj-beta", input_tokens=15000, output_tokens=100, current_time=now)
        # beta now only has 1000 tokens left -> alpha has 10000 left
        chosen = self.mgr.select_best_project(estimated_input_tokens=2000, current_time=now)
        self.assertEqual(chosen.project_id, "proj-alpha")

    def test_429_backoff_cooldown(self):
        now = time.time()
        self.mgr.record_error("proj-beta", "429_RESOURCE_EXHAUSTED", now)
        self.assertTrue(self.p2.cooldown_until > now)
        self.assertFalse(self.p2.is_available(now))
        # Project alpha should now be chosen instead
        chosen = self.mgr.select_best_project(estimated_input_tokens=1000, current_time=now)
        self.assertEqual(chosen.project_id, "proj-alpha")

    def test_401_disables_project(self):
        now = time.time()
        self.mgr.record_error("proj-alpha", "401_UNAUTHORIZED", now)
        self.assertFalse(self.p1.enabled)
        self.assertFalse(self.p1.is_available(now))


if __name__ == "__main__":
    unittest.main()
