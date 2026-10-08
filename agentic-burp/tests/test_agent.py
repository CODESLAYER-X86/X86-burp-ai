import asyncio
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agent.agent import Agent
from agent.api_router import GeminiAPIRouter
from agent.budget import BudgetManager
from agent.credentials import GeminiProject
from agent.executor import Executor
from agent.planner import Planner
from agent.quota import QuotaManager
from agent.tool_registry import ToolDefinition, ToolRegistry
from models.scope import ScopePolicy
from scope.validator import ScopeValidator
from security import get_default_detector_registry
from storage.database import Database
from tools.crawler import Crawler
from tools.fuzz import Fuzzer
from tools.http import HTTPClient
from tools.repeater import Repeater


class TestAgentLoop(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.policy = ScopePolicy(targets=["http://127.0.0.1:8080"])
        self.scope_validator = ScopeValidator(self.policy)
        self.budget = BudgetManager(max_llm_calls=10, max_http_requests=50, max_iterations=6)
        self.http_client = HTTPClient(self.scope_validator)
        self.crawler = Crawler(self.http_client)
        self.repeater = Repeater(self.http_client)
        self.fuzzer = Fuzzer(self.http_client)
        self.detector_reg = get_default_detector_registry()

        self.tool_reg = ToolRegistry()
        self.tool_reg.register(ToolDefinition(
            name="crawl", description="Crawl target", permission="ACTIVE", input_schema={}
        ))
        self.tool_reg.register(ToolDefinition(
            name="run_detector", description="Run security detector", permission="ACTIVE", input_schema={}
        ))

        p = GeminiProject(project_id="test-proj", api_key="", model="gemma-4-31b")
        qmgr = QuotaManager([p])
        router = GeminiAPIRouter(qmgr)
        self.planner = Planner(router)

        self.executor = Executor(
            tool_registry=self.tool_reg,
            scope_validator=self.scope_validator,
            budget_manager=self.budget,
            http_client=self.http_client,
            detector_registry=self.detector_reg,
            crawler=self.crawler,
            repeater=self.repeater,
            fuzzer=self.fuzzer
        )

        self.agent = Agent(
            assessment_id="test_run_01",
            target_url="http://127.0.0.1:8080",
            planner=self.planner,
            executor=self.executor,
            tool_registry=self.tool_reg,
            budget_manager=self.budget,
            db=self.db
        )

    def test_agent_runs_and_transitions_phases(self):
        asyncio.run(self.agent.run(max_steps=5))
        # Verify iteration count incremented
        self.assertGreater(self.agent.state.iteration, 0)
        # Verify events recorded in audit log
        events = self.agent.audit_repo.list_events("test_run_01")
        self.assertGreater(len(events), 0)

    def test_budget_exhaustion_stops_agent(self):
        self.budget.current_iterations = 6 # Max iterations
        can_step = asyncio.run(self.agent.step())
        self.assertFalse(can_step)
        self.assertEqual(self.agent.state.phase, "COMPLETE")
        self.assertEqual(self.agent.state.stop_reason, "MAX_ITERATIONS_REACHED")


if __name__ == "__main__":
    unittest.main()
