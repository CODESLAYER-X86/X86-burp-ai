from __future__ import annotations
from typing import List, Dict, Any
from .metadata import KnowledgeChunk


class KnowledgeChunker:
    """Ingests raw security documents and formats them into searchable knowledge chunks."""
    @staticmethod
    def chunk_document(doc: Dict[str, Any], max_chunk_chars: int = 600) -> List[KnowledgeChunk]:
        content = doc.get("content", "")
        chunks: List[KnowledgeChunk] = []

        if len(content) <= max_chunk_chars:
            chunks.append(KnowledgeChunk(
                id=doc["id"],
                title=doc["title"],
                category=doc["category"],
                context=doc["context"],
                content=content,
                techniques=doc.get("techniques", []),
                advisory_notes=doc.get("advisory_notes", "")
            ))
            return chunks

        # Split into smaller paragraphs/chunks
        paragraphs = content.split(". ")
        current_text = ""
        part = 1
        for p in paragraphs:
            if len(current_text) + len(p) > max_chunk_chars and current_text:
                chunks.append(KnowledgeChunk(
                    id=f"{doc['id']}_p{part}",
                    title=f"{doc['title']} (Part {part})",
                    category=doc["category"],
                    context=doc["context"],
                    content=current_text.strip(),
                    techniques=doc.get("techniques", []),
                    advisory_notes=doc.get("advisory_notes", "")
                ))
                part += 1
                current_text = p + ". "
            else:
                current_text += p + ". "

        if current_text:
            chunks.append(KnowledgeChunk(
                id=f"{doc['id']}_p{part}",
                title=f"{doc['title']} (Part {part})",
                category=doc["category"],
                context=doc["context"],
                content=current_text.strip(),
                techniques=doc.get("techniques", []),
                advisory_notes=doc.get("advisory_notes", "")
            ))

        return chunks
