"""Version-chain utilities for the AURAGENT Memory Fabric.

Memory versions are immutable records linked by a previous-version hash.
This module is independent from persistence so the same canonical hashing
rules can be reused by storage, verification, replay, and later Evidence
Fabric integrations.

Security properties:
- A version hash commits to the memory id, version number, content hash,
  previous version hash, embedding, writer, source, and metadata.
- Version numbers advance exactly by one.
- The first version has no previous-version hash.
- Later versions reference the exact hash of the immediately prior version.
- Verification never grants authority and never mutates SecurityContext.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from app.security.identity.crypto import sha256_hex


class VersioningError(ValueError):
    """Base error for Memory Fabric version-chain violations."""


class VersionSequenceError(VersioningError):
    """Raised when version numbers or parent links are invalid."""


class VersionIntegrityError(VersioningError):
    """Raised when a computed version hash does not match the stored hash."""


@dataclass(frozen=True)
class VersionCommit:
    """Canonical, storage-neutral description of one memory version."""

    memory_id: str
    version_number: int
    content_hash: str
    previous_version_hash: str | None
    embedding: tuple[float, ...]
    writer_agent_id: str
    source_id: str | None
    metadata: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.memory_id.strip():
            raise VersioningError("memory_id is required")
        if self.version_number <= 0:
            raise VersionSequenceError("version_number must be positive")
        if len(self.content_hash) != 64:
            raise VersioningError("content_hash must be a SHA-256 hex digest")
        if not self.writer_agent_id.strip():
            raise VersioningError("writer_agent_id is required")


def canonical_version_payload(commit: VersionCommit) -> dict[str, Any]:
    """Build the exact canonical payload committed by the version hash."""

    return {
        "schema": "auragent.memory-version.v1",
        "memory_id": commit.memory_id,
        "version_number": commit.version_number,
        "content_hash": commit.content_hash,
        "previous_version_hash": commit.previous_version_hash,
        "embedding": list(commit.embedding),
        "writer_agent_id": commit.writer_agent_id,
        "source_id": commit.source_id,
        "metadata": dict(commit.metadata),
    }


def compute_version_hash(commit: VersionCommit) -> str:
    """Return the canonical SHA-256 hash for a memory version."""

    return sha256_hex(canonical_version_payload(commit))


def assert_append_transition(
    *,
    previous_version_number: int | None,
    previous_version_hash: str | None,
    next_version_number: int,
    next_previous_version_hash: str | None,
) -> None:
    """Validate an immutable version-chain append transition."""

    if previous_version_number is None:
        if next_version_number != 1:
            raise VersionSequenceError("first memory version must be version 1")
        if next_previous_version_hash is not None:
            raise VersionSequenceError("first memory version cannot have a parent hash")
        return

    if previous_version_number <= 0:
        raise VersionSequenceError("previous_version_number must be positive")

    expected_number = previous_version_number + 1
    if next_version_number != expected_number:
        raise VersionSequenceError(
            f"version_sequence_gap:expected={expected_number}:actual={next_version_number}"
        )

    if not previous_version_hash:
        raise VersionSequenceError("previous version hash is required for an existing chain")

    if next_previous_version_hash != previous_version_hash:
        raise VersionSequenceError("version_parent_hash_mismatch")


def verify_version_commit(
    commit: VersionCommit,
    stored_version_hash: str,
) -> bool:
    """Verify one stored version against its canonical hash."""

    computed = compute_version_hash(commit)
    if computed.lower() != stored_version_hash.lower():
        raise VersionIntegrityError("memory_version_hash_mismatch")
    return True


def serialize_version_commit(commit: VersionCommit) -> str:
    """Stable JSON form useful for evidence, replay, or debugging."""

    return json.dumps(
        canonical_version_payload(commit),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def commit_from_components(
    *,
    memory_id: str,
    version_number: int,
    content_hash: str,
    previous_version_hash: str | None,
    embedding: list[float] | tuple[float, ...],
    writer_agent_id: str,
    source_id: str | None,
    metadata: Mapping[str, Any] | None = None,
) -> VersionCommit:
    """Construct a VersionCommit using the same fields as MemoryStore."""

    return VersionCommit(
        memory_id=str(memory_id),
        version_number=int(version_number),
        content_hash=str(content_hash),
        previous_version_hash=previous_version_hash,
        embedding=tuple(float(value) for value in embedding),
        writer_agent_id=str(writer_agent_id),
        source_id=str(source_id) if source_id else None,
        metadata=dict(metadata or {}),
    )
