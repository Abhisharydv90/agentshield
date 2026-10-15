"""Provider-neutral semantic indexing for Memory Fabric.

The implementation uses a deterministic local embedding so Phase 6 is fully
functional without locking the platform to one embedding vendor.  Phase 13 can
replace the index provider with pgvector/Qdrant/etc. behind the same interface.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from app.security.identity.crypto import sha256_hex

_TOKEN_RE = re.compile(r"[A-Za-z0-9_:-]+")


@dataclass(frozen=True)
class SemanticMatch:
    item_id: str
    score: float


class EmbeddingProvider:
    dimension: int = 128

    def embed(self, text: str) -> list[float]:
        raise NotImplementedError


class DeterministicEmbeddingProvider(EmbeddingProvider):
    """Stable non-ML embedding used as the Phase 6 baseline."""

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimension
        tokens = _TOKEN_RE.findall(text.lower())

        if not tokens:
            return vector

        for token in tokens:
            digest = sha256_hex(token)
            first = int(digest[:8], 16)
            second = int(digest[8:16], 16)
            index = first % self.dimension
            sign = 1.0 if second % 2 == 0 else -1.0
            magnitude = 1.0 + (int(digest[16:20], 16) / 65535.0)
            vector[index] += sign * magnitude

        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0.0:
            return vector
        return [value / norm for value in vector]


def cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right):
        raise ValueError("embedding dimensions do not match")
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm)


class SemanticIndex:
    """In-memory vector index used by tests and small deployments."""

    def __init__(self, provider: EmbeddingProvider | None = None) -> None:
        self.provider = provider or DeterministicEmbeddingProvider()
        self._vectors: dict[str, list[float]] = {}

    def upsert(self, item_id: str, text: str) -> None:
        self._vectors[item_id] = self.provider.embed(text)

    def remove(self, item_id: str) -> None:
        self._vectors.pop(item_id, None)

    def search(
        self,
        query: str,
        *,
        limit: int = 10,
        allowed_ids: Iterable[str] | None = None,
    ) -> list[SemanticMatch]:
        allowed = set(allowed_ids) if allowed_ids is not None else set(self._vectors)
        query_vector = self.provider.embed(query)
        matches = [
            SemanticMatch(
                item_id=item_id,
                score=cosine_similarity(query_vector, vector),
            )
            for item_id, vector in self._vectors.items()
            if item_id in allowed
        ]
        matches.sort(key=lambda item: (-item.score, item.item_id))
        return matches[:limit]
