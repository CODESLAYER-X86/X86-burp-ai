from __future__ import annotations
from typing import List, Dict, Any, Optional
from models.base import Model


class LeaderPlan(Model):
    priority: str = "high" # high | medium | low
    mission: str = "Discover application attack surface"
    recommended_focus: str = "crawl" # crawl | authorization | parameter_analysis | injection_test | verification
    recommended_tools: List[str] = ["crawl", "get_http_history"]
    task_queue: List[str] = []
    knowledge_hints: List[str] = []
    reasoning_summary: str = ""
    confidence: float = 0.85


class GemmaActionDecision(Model):
    action: str = "investigate" # investigate | replay | fuzz | verify | report | stop
    tool: str = "http_request"
    arguments: Dict[str, Any] = {}
    hypothesis: Optional[str] = None
    reasoning_summary: str = ""
    confidence: float = 0.82
    requested_knowledge_topic: Optional[str] = None


class DualAgentExchange(Model):
    timestamp: float
    iteration: int
    leader_plan: LeaderPlan
    gemma_decision: GemmaActionDecision
    observation_summary: str = ""
    evidence_collected: List[str] = []
