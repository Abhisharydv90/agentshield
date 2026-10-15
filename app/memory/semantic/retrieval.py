"""Memory retrieval with integrity-first filtering."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from app.memory.semantic.index import DeterministicEmbeddingProvider, cosine_similarity
from app.memory.security.poisoning import scan_memory
from app.memory.security.validation import verify_content_hash


@dataclass(frozen=True)
class RetrievalCandidate:
    memory_id: uuid.UUID
    content: str
    content_hash: str
    embedding: list[float] | None
    metadata: dict[str, Any]


class MemoryRetriever:
    """Score candidates only after integrity and poisoning checks."""

    def __init__(self, provider: DeterministicEmbeddingProvider | None = None) -> None:
        self.provider = provider or DeterministicEmbeddingProvider()

    def score(
        self,
        *,
        query: str,
        candidates: list[RetrievalCandidate],
    ) -> list[tuple[RetrievalCandidate, float, float]]:
        query_vector = self.provider.embed(query)
        scored: list[tuple[RetrievalCandidate, float, float]] = []

        for candidate in candidates:
            if not verify_content_hash(candidate.content, candidate.content_hash):
                continue

            poisoning = scan_memory(candidate.content)
            if poisoning.suspicious:
                continue

            vector = candidate.embedding or self.provider.embed(candidate.content)
            semantic = cosine_similarity(query_vector, vector)

            lexical = (
                0.15
                if query.strip().lower() in candidate.content.lower()
                else 0.0
            )

            score = min(1.0, max(0.0, semantic) * 0.85 + lexical)
            scored.append((candidate, score, poisoning.score))

        scored.sort(key=lambda item: (-item[1], str(item[0].memory_id)))
        return scored
