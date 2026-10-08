from __future__ import annotations
from typing import List, Dict, Any, Optional
from models.observation import Observation
from .metadata import KnowledgeChunk
from .index import KnowledgeIndex


class KnowledgeRetriever:
    """
    Situation-aware knowledge retriever (Sections 12-16).
    Translates structured observations into focused technical queries and returns
    a bounded number of advisory snippets (default 2-4) to prevent token waste.
    """
    def __init__(self, index: Optional[KnowledgeIndex] = None, max_snippets: int = 3):
        self.index = index or KnowledgeIndex()
        self.max_snippets = max_snippets

    def build_query_from_observation(self, observation: Observation) -> str:
        """Constructs focused search terms from structured observation signals."""
        terms = []
        if observation.category:
            terms.append(observation.category.replace("_", " "))
        if observation.endpoint:
            terms.append(observation.endpoint.replace("/", " "))
        if observation.parameter:
            terms.append(f"parameter {observation.parameter}")
        if observation.signals:
            terms.extend([s.replace("_", " ") for s in observation.signals])
        if observation.summary:
            terms.append(observation.summary)

        # Detect specific vulnerability contexts
        obs_text = f"{observation.endpoint} {observation.summary} {' '.join(observation.signals)}".lower()
        if "id" in obs_text or "order" in obs_text or "user" in obs_text or "tenant" in obs_text:
            terms.append("IDOR BOLA authorization boundary object identifier")
        if "syntax" in obs_text or "sqlite" in obs_text or "sql" in obs_text:
            terms.append("SQL injection syntax error quote probe")
        if "script" in obs_text or "xss" in obs_text or "reflect" in obs_text:
            terms.append("XSS canary reflection HTML entity encoding")
        if "origin" in obs_text or "cors" in obs_text:
            terms.append("CORS Access-Control-Allow-Origin credentials reflection")
        if "csrf" in obs_text or "token" in obs_text:
            terms.append("CSRF state changing token SameSite")
        if "flag" in obs_text or "ctf" in obs_text:
            terms.append("CTF flag retrieval pattern validation")

        return " ".join(terms)

    def retrieve_relevant_snippets(self, observation: Observation) -> List[str]:
        """Retrieves and formats compact advisory snippets for Gemma 4 31B."""
        query = self.build_query_from_observation(observation)
        matched_chunks = self.index.search(query, top_k=self.max_snippets)
        return [c.compact_for_llm(max_chars=400) for c in matched_chunks]

    def query(self, raw_query: str, top_k: int = 3) -> List[KnowledgeChunk]:
        return self.index.search(raw_query, top_k=top_k)
