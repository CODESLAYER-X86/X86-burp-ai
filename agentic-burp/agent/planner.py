from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from .api_router import GeminiAPIRouter
from .decisions import AgentDecision
from .prompts import SYSTEM_PROMPT, PHASE_PROMPTS


class Planner:
    """
    Communicates with Gemma 4 31B via GeminiAPIRouter.
    Converts compact context into strongly typed AgentDecision models.
    """
    def __init__(self, api_router: GeminiAPIRouter):
        self.api_router = api_router

    async def decide(
        self,
        phase: str,
        context: Dict[str, Any],
        available_tools: List[Dict[str, Any]]
    ) -> AgentDecision:
        phase_instructions = PHASE_PROMPTS.get(phase, PHASE_PROMPTS["INVESTIGATION"])
        prompt = (
            f"{phase_instructions}\n\n"
            f"Current Context:\n{json.dumps(context, indent=2)}\n\n"
            f"Available Registered Tools:\n{json.dumps(available_tools, indent=2)}\n\n"
            f"Provide your decision as valid JSON matching this schema:\n"
            f'{{"action": "crawl|investigate|verify|stop", "tool": "tool_name", "arguments": {{}}, "reasoning_summary": "...", "confidence": 0.85}}\n'
        )

        resp = await self.api_router.generate(
            system_instruction=SYSTEM_PROMPT,
            prompt=prompt,
            tools=available_tools
        )

        if resp.get("status") != "success":
            # Graceful recovery: return safe default decision
            return AgentDecision(
                action="investigate",
                tool="run_detector",
                arguments={"detector": "sqli"},
                reasoning_summary="Fallback reasoning due to transient router condition.",
                confidence=0.5
            )

        try:
            raw_text = resp["text"].strip()
            if raw_text.startswith("```"):
                lines = raw_text.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                raw_text = "\n".join(lines).strip()

            parsed = json.loads(raw_text)
            return AgentDecision.model_validate(parsed)
        except Exception:
            # Malformed recovery
            return AgentDecision(
                action="investigate",
                tool="run_detector",
                arguments={"detector": "idor"},
                reasoning_summary="Recovered from malformed LLM response; selecting candidate investigation.",
                confidence=0.6
            )
