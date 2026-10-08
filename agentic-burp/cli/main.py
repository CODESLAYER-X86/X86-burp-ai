from __future__ import annotations
import argparse
import asyncio
import os
import sys
from typing import List

from agent.agent import Agent
from agent.api_router import GeminiAPIRouter
from agent.budget import BudgetManager
from agent.credentials import GeminiProject, load_gemini_projects_from_env
from agent.executor import Executor
from agent.planner import Planner
from agent.quota import QuotaManager
from agent.tool_registry import ToolDefinition, ToolRegistry
from models.scope import ScopePolicy
from reports.generator import ReportGenerator
from scope.validator import ScopeValidator
from security import get_default_detector_registry
from storage.database import Database
from tools.crawler import Crawler
from tools.fuzz import Fuzzer
from tools.http import HTTPClient
from tools.repeater import Repeater


def build_system(db_path: str = "agentic_burp.sqlite3", target_url: str = "http://127.0.0.1:8080"):
    db = Database(db_path)
    policy = ScopePolicy(
        targets=[target_url],
        allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        allowed_ports=[80, 443, 8080, 8443, 3000],
        allow_internal_loopback=True,
    )
    scope_validator = ScopeValidator(policy)
    budget = BudgetManager(max_llm_calls=50, max_http_requests=200, max_iterations=20)
    http_client = HTTPClient(scope_validator)
    crawler = Crawler(http_client)
    repeater = Repeater(http_client)
    fuzzer = Fuzzer(http_client)
    detector_reg = get_default_detector_registry()

    # Tool registry
    tool_reg = ToolRegistry()
    tool_reg.register(ToolDefinition(
        name="crawl", description="Discover endpoints and forms within authorized target scope.",
        permission="ACTIVE", input_schema={"seed_url": "string"}
    ))
    tool_reg.register(ToolDefinition(
        name="run_detector", description="Execute targeted security detector (sqli, xss, idor, auth, ssrf, csrf, cors).",
        permission="ACTIVE", input_schema={"detector": "string", "target": "string"}
    ))
    tool_reg.register(ToolDefinition(
        name="replay_request", description="Replay HTTP request with structured mutations.",
        permission="ACTIVE", input_schema={"mutations": "object"}
    ))
    tool_reg.register(ToolDefinition(
        name="fuzz_parameter", description="Controlled fuzzing of a target parameter.",
        permission="ACTIVE", input_schema={"parameter": "string", "family": "string"}
    ))

    # Quota & Multi-Project API Rotation
    projects = load_gemini_projects_from_env()
    if not projects:
        projects.append(GeminiProject(project_id="default-project", api_key="", model="gemma-4-31b"))

    quota_mgr = QuotaManager(projects)
    api_router = GeminiAPIRouter(quota_mgr)
    planner = Planner(api_router)

    executor = Executor(
        tool_registry=tool_reg,
        scope_validator=scope_validator,
        budget_manager=budget,
        http_client=http_client,
        detector_registry=detector_reg,
        crawler=crawler,
        repeater=repeater,
        fuzzer=fuzzer
    )

    return db, agent_factory(target_url, planner, executor, tool_reg, budget, db)


def agent_factory(target_url, planner, executor, tool_reg, budget, db):
    def _create(assessment_id: str):
        return Agent(
            assessment_id=assessment_id,
            target_url=target_url,
            planner=planner,
            executor=executor,
            tool_registry=tool_reg,
            budget_manager=budget,
            db=db
        )
    return _create


def cmd_doctor():
    """Runs health check of Agentic-Burp environment."""
    print("=" * 50)
    print("Agentic-Burp Diagnostic Check (doctor)")
    print("=" * 50)
    print(f"[OK] Python version: {sys.version.split()[0]}")

    # Check SQLite
    try:
        db = Database(":memory:")
        print("[OK] SQLite WAL engine operational")
    except Exception as e:
        print(f"[FAIL] SQLite error: {e}")

    # Check Scope Validator
    try:
        pol = ScopePolicy(targets=["http://127.0.0.1:8080"])
        val = ScopeValidator(pol)
        assert val.validate_url("http://127.0.0.1:8080/test")
        assert not val.validate_url("http://169.254.169.254/metadata") # SSRF protect
        print("[OK] Scope and SSRF boundary validation active")
    except Exception as e:
        print(f"[FAIL] Scope validation error: {e}")

    # Check Model configuration
    model = os.environ.get("GEMINI_MODEL", "gemma-4-31b")
    print(f"[OK] Target Reasoning Model: {model}")

    # Check Projects
    projects = load_gemini_projects_from_env()
    print(f"[OK] Configured Gemini Projects: {len(projects)}")
    print("[OK] Agentic-Burp is ready for authorized assessments.")
    print("=" * 50)


def cmd_scan(target_url: str):
    """Executes full autonomous assessment against authorized target."""
    print(f"\n[*] Starting Agentic-Burp Assessment against {target_url}...")
    db, factory = build_system(target_url=target_url)
    assessment_id = "cli_assessment_01"

    # Register in DB
    now_ts = time.time()
    db.execute_write(
        "INSERT OR REPLACE INTO assessments (id, name, target_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (assessment_id, "CLI Assessment", target_url, now_ts, now_ts)
    )

    agent = factory(assessment_id)
    asyncio.run(agent.run(max_steps=12))

    # Print summary
    generator = ReportGenerator(db)
    print("\n" + generator.generate_markdown(assessment_id))


def main():
    parser = argparse.ArgumentParser(description="Agentic-Burp AI-Assisted Web Security Assessment Platform")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("doctor", help="Check system prerequisites and connectivity")
    scan_p = subparsers.add_parser("scan", help="Run automated assessment")
    scan_p.add_argument("--target", default="http://127.0.0.1:8080", help="Target URL within scope")

    args = parser.parse_args()
    if args.command == "doctor":
        cmd_doctor()
    elif args.command == "scan":
        cmd_scan(args.target)
    else:
        cmd_doctor()


if __name__ == "__main__":
    main()
