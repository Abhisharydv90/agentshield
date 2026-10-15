"""AURAGENT Phase 6 — Memory Fabric."""

from app.memory.models import (
    MemoryCreate,
    MemoryKind,
    MemoryRecordView,
    MemorySearchQuery,
    MemorySearchResult,
    MemoryUpdate,
)
from app.memory.store import MemoryStore, MemorySecurityError, VersionConflictError

__all__ = [
    "MemoryCreate",
    "MemoryKind",
    "MemoryRecordView",
    "MemorySearchQuery",
    "MemorySearchResult",
    "MemoryUpdate",
    "MemoryStore",
    "MemorySecurityError",
    "VersionConflictError",
    "VersionCommit",
    "VersionIntegrityError",
    "VersionSequenceError",
    "VersioningError",
    "assert_append_transition",
    "canonical_version_payload",
    "commit_from_components",
    "compute_version_hash",
    "serialize_version_commit",
    "verify_version_commit",
]

from app.memory.versioning import (
    VersionCommit,
    VersionIntegrityError,
    VersionSequenceError,
    VersioningError,
    assert_append_transition,
    canonical_version_payload,
    commit_from_components,
    compute_version_hash,
    serialize_version_commit,
    verify_version_commit,
)
