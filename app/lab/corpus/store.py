"""Append-only deterministic regression corpus.

This Phase 9 backend is process-local. Persistence can be moved to the
AURAGENT data/control-plane layers later without changing the corpus record
schema or hashes.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

CORPUS_SCHEMA = "auragent.lab.corpus.entry.v1"


@dataclass(frozen=True)
class CorpusEntry:
    entry_id: str
    payload: Any
    payload_hash: str
    source: str
    labels: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, *, redact_payload: bool = False) -> dict[str, Any]:
        return {
            "schema": CORPUS_SCHEMA,
            "entry_id": self.entry_id,
            "payload": "<redacted>" if redact_payload else self.payload,
            "payload_hash": self.payload_hash,
            "source": self.source,
            "labels": list(self.labels),
            "metadata": dict(self.metadata),
        }


class CorpusStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, CorpusEntry] = {}
        self._by_hash: dict[str, str] = {}

    @staticmethod
    def _hash(payload: Any) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def add(
        self,
        *,
        payload: Any,
        source: str,
        labels: Iterable[str] = (),
        metadata: dict[str, Any] | None = None,
    ) -> CorpusEntry:
        payload_hash = self._hash(payload)
        with self._lock:
            existing_id = self._by_hash.get(payload_hash)
            if existing_id is not None:
                return self._entries[existing_id]
            entry = CorpusEntry(
                entry_id=str(uuid.uuid4()),
                payload=payload,
                payload_hash=payload_hash,
                source=source,
                labels=tuple(sorted(set(labels))),
                metadata=dict(metadata or {}),
            )
            self._entries[entry.entry_id] = entry
            self._by_hash[payload_hash] = entry.entry_id
            return entry

    def get(self, entry_id: str) -> CorpusEntry | None:
        with self._lock:
            return self._entries.get(entry_id)

    def list(self, *, limit: int = 100) -> list[CorpusEntry]:
        if limit < 1 or limit > 1_000:
            raise ValueError("corpus_limit_out_of_range")
        with self._lock:
            return list(self._entries.values())[-limit:]

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def export(self, *, limit: int = 1_000) -> list[dict[str, Any]]:
        return [item.to_dict(redact_payload=False) for item in self.list(limit=limit)]
