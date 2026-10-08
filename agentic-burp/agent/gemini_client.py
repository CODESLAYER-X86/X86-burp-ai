from __future__ import annotations
import json
import os
import time
from typing import Any, Dict, List, Optional
from .credentials import GeminiProject


class GeminiClient:
    """
    Communicates with Gemini API / Google GenAI SDK.
    Configured for gemma-4-31b reasoning engine.
    Includes built-in offline test provider for zero-quota environments.
    """
    def __init__(self, project: GeminiProject):
        self.project = project
        self.model = project.model or "gemma-4-31b"

    async def generate_content(
        self,
        system_instruction: str,
        prompt: str,
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Sends generation request to Gemini API."""
        start_time = time.time()

        # If running offline or API key is not configured, use deterministic reasoning fallback
        if not self.project.api_key or self.project.api_key.startswith("mock_"):
            return self._mock_reasoning_response(prompt, tools)

        try:
            # Check if google.genai is available
            import urllib.request
            # Use direct Google GenAI API endpoint if SDK not installed
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.project.api_key}"
            payload = {
                "systemInstruction": {"parts": [{"text": system_instruction}]},
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": 800,
                    "responseMimeType": "application/json"
                }
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                elapsed = round((time.time() - start_time) * 1000, 2)
                return {
                    "status": "success",
                    "text": text,
                    "latency_ms": elapsed,
                    "input_tokens": len(prompt) // 4,
                    "output_tokens": len(text) // 4
                }
        except Exception as e:
            err_str = str(e)
            if "429" in err_str:
                return {"status": "error", "error_type": "429_RESOURCE_EXHAUSTED", "error": err_str}
            if "401" in err_str or "403" in err_str:
                return {"status": "error", "error_type": "401_UNAUTHORIZED", "error": err_str}
            if "400" in err_str:
                return {"status": "error", "error_type": "400_INVALID_REQUEST", "error": err_str}
            return {"status": "error", "error_type": "5xx_TRANSIENT", "error": err_str}

    def _mock_reasoning_response(self, prompt: str, tools: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Deterministic reasoning simulation for unit tests and local labs."""
        p_low = prompt.lower()
        if "discovery" in p_low:
            decision = {
                "action": "crawl",
                "tool": "crawl",
                "arguments": {"max_depth": 2, "max_pages": 30},
                "reasoning_summary": "Initiating discovery crawl to map authorized target attack surface.",
                "confidence": 0.95
            }
        elif "investigation" in p_low or "candidate" in p_low:
            decision = {
                "action": "investigate",
                "tool": "run_detector",
                "arguments": {"detector": "idor", "target": "GET /api/profile?id=101"},
                "reasoning_summary": "Testing authorization boundary across test identities on profile object ID.",
                "confidence": 0.88
            }
        elif "verification" in p_low:
            decision = {
                "action": "verify",
                "tool": "verify_finding",
                "arguments": {"finding_type": "BOLA_IDOR"},
                "reasoning_summary": "Verifying multi-account evidence reproducibility before confirming finding.",
                "confidence": 0.92
            }
        else:
            decision = {
                "action": "investigate",
                "tool": "run_detector",
                "arguments": {"detector": "sqli", "target": "GET /api/products?cat=items"},
                "reasoning_summary": "Auditing parameterized product endpoint for database query syntax errors.",
                "confidence": 0.85
            }

        text = json.dumps(decision)
        return {
            "status": "success",
            "text": text,
            "latency_ms": 25.0,
            "input_tokens": len(prompt) // 4,
            "output_tokens": len(text) // 4
        }
