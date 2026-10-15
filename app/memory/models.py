"""Domain contracts for the AURAGENT Memory Fabric.

Memory is data, not authority.  Retrieved content can influence model
reasoning, but it never mutates SecurityContext, capabilities, policy,
delegation, or approval state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping


class MemoryKind(StrEnum):
    USER = "user"
    AGENT = "agent"
    TOOL = "tool"
    EXTERNAL = "external"
    SUMMARY = "summary"
    SYSTEM = "system"


class MemoryStatus(StrEnum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    DELETED = "deleted"


class TrustClass(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    UNTRUSTED = "untrusted"


class InfluenceClass(StrEnum):
    USER = "user"
    AGENT = "agent"
    TOOL = "tool"
    EXTERNAL = "external"
    SYSTEM = "system"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class MemoryCreate:
    namespace: str
    key: str
    content: str
    kind: MemoryKind = MemoryKind.AGENT
    source: Mapping[str, Any] | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    retention_days: int | None = None
    on_poisoning: str = "reject"

    def __post_init__(self) -> None:
        if not self.namespace.strip():
            raise ValueError("namespace is required")
        if not self.key.strip():
            raise ValueError("key is required")
        if not isinstance(self.content, str):
            raise ValueError("content must be a string")
        if self.on_poisoning not in {"reject", "quarantine"}:
            raise ValueError("on_poisoning must be reject or quarantine")
        if self.retention_days is not None and self.retention_days <= 0:
            raise ValueError("retention_days must be positive")


@dataclass(frozen=True)
class MemoryUpdate:
    content: str
    expected_version: int
    source: Mapping[str, Any] | None = None
    metadata: Mapping[str, Any] | None = None
    retention_days: int | None = None
    on_poisoning: str = "reject"

    def __post_init__(self) -> None:
        if not isinstance(self.content, str):
            raise ValueError("content must be a string")
        if self.expected_version <= 0:
            raise ValueError("expected_version must be positive")
        if self.on_poisoning not in {"reject", "quarantine"}:
            raise ValueError("on_poisoning must be reject or quarantine")
        if self.retention_days is not None and self.retention_days <= 0:
            raise ValueError("retention_days must be positive")


@dataclass(frozen=True)
class MemorySearchQuery:
    query: str
    namespace: str | None = None
    kind: MemoryKind | None = None
    limit: int = 10
    min_score: float = 0.0

    def __post_init__(self) -> None:
        if not self.query.strip():
            raise ValueError("query is required")
        if not 1 <= self.limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if not 0.0 <= self.min_score <= 1.0:
            raise ValueError("min_score must be between 0 and 1")


@dataclass(frozen=True)
class MemoryRecordView:
    memory_id: str
    tenant_id: str
    agent_id: str
    namespace: str
    key: str
    kind: str
    content: str
    content_hash: str
    version: int
    status: str
    trust_class: str
    influence_class: str
    source_id: str | None
    retention_until: str | None
    metadata: Mapping[str, Any]


@dataclass(frozen=True)
class MemorySearchResult:
    memory: MemoryRecordView
    score: float
    integrity_verified: bool
    poisoning_score: float
    provenance: Mapping[str, Any]
