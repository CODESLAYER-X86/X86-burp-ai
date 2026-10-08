from __future__ import annotations
from typing import List, Optional
from models.base import Model


class KnowledgeMetadata(Model):
    id: str
    title: str
    category: str # IDOR | SQLI | XSS | CSRF | CORS | SSRF | AUTH | CTF_FLAG
    context: str # REST_API | WEB_FORM | SESSION | HEADER | GRAPHQL
    difficulty: str = "medium" # low | medium | high
    source_type: str = "TECHNIQUE_REFERENCE" # TECHNIQUE_REFERENCE | CTF_WRITEUP | CHECKLIST
    techniques: List[str] = []

    def __init__(self, **kwargs):
        if "techniques" not in kwargs:
            kwargs["techniques"] = []
        super().__init__(**kwargs)


class KnowledgeChunk(Model):
    id: str
    title: str
    category: str
    context: str
    content: str
    techniques: List[str] = []
    advisory_notes: str = ""
    relevance_score: float = 0.0

    def compact_for_llm(self, max_chars: int = 400) -> str:
        """Returns concise advisory snippet for Gemma 4 31B."""
        truncated = self.content[:max_chars].strip()
        if len(self.content) > max_chars:
            truncated += "..."
        return f"[{self.category}] {self.title}: {truncated}"
