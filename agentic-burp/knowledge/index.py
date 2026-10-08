from __future__ import annotations
import re
import math
from typing import List, Dict, Tuple
from .metadata import KnowledgeChunk
from .seed_data import SEED_KNOWLEDGE_DOCUMENTS
from .chunker import KnowledgeChunker


class KnowledgeIndex:
    """
    Searchable, token-efficient knowledge index using BM25-style keyword relevance scoring.
    Does not require external vector databases or network calls.
    """
    def __init__(self):
        self.chunks: List[KnowledgeChunk] = []
        self._doc_frequencies: Dict[str, int] = {}
        self._initialize_seed_corpus()

    def _initialize_seed_corpus(self):
        for doc in SEED_KNOWLEDGE_DOCUMENTS:
            parsed_chunks = KnowledgeChunker.chunk_document(doc)
            for c in parsed_chunks:
                self.add_chunk(c)

    def _tokenize(self, text: str) -> List[str]:
        return [w.lower() for w in re.findall(r'[a-zA-Z0-9_\-]+', text) if len(w) > 2]

    def add_chunk(self, chunk: KnowledgeChunk):
        self.chunks.append(chunk)
        tokens = set(self._tokenize(chunk.title + " " + chunk.content + " " + " ".join(chunk.techniques)))
        for t in tokens:
            self._doc_frequencies[t] = self._doc_frequencies.get(t, 0) + 1

    def search(self, query: str, top_k: int = 3) -> List[KnowledgeChunk]:
        q_tokens = self._tokenize(query)
        if not q_tokens:
            return self.chunks[:top_k]

        scored: List[Tuple[float, KnowledgeChunk]] = []
        total_docs = len(self.chunks) or 1

        for chunk in self.chunks:
            chunk_text = (chunk.title + " " + chunk.category + " " + chunk.content + " " + " ".join(chunk.techniques)).lower()
            score = 0.0

            for qt in q_tokens:
                # Frequency in document
                count = chunk_text.count(qt)
                if count > 0:
                    df = self._doc_frequencies.get(qt, 1)
                    idf = math.log((total_docs + 1) / (df + 0.5)) + 1.0
                    # Boost category and technique matches
                    boost = 2.0 if qt in chunk.category.lower() or any(qt in t.lower() for t in chunk.techniques) else 1.0
                    score += count * idf * boost

            if score > 0.0:
                chunk.relevance_score = round(score, 3)
                scored.append((score, chunk))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in scored[:top_k]]
