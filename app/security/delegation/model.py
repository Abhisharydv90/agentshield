"""Authority state and delegation contracts.

The authority tuple deliberately covers capabilities, operations, resources,
data scope, network scope, time, budget, delegation depth and risk ceiling.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable


@dataclass(frozen=True)
class ResourceScope:
    """Explicit resource scope. Wildcards are rejected by default."""

    values: frozenset[str]

    @classmethod
    def from_values(cls, values: Iterable[str]) -> "ResourceScope":
        normalized = frozenset(str(v).strip() for v in values if str(v).strip())
        if any("*" in value for value in normalized):
            raise ValueError("wildcard resource scope is not supported")
        return cls(normalized)

    def is_subset_of(self, other: "ResourceScope") -> bool:
        return self.values.issubset(other.values)


@dataclass(frozen=True)
class AuthorityState:
    """Machine-comparable authority boundary."""

    capabilities: frozenset[str] = field(default_factory=frozenset)
    operations: frozenset[str] = field(default_factory=frozenset)
    resources: ResourceScope = field(default_factory=lambda: ResourceScope(frozenset()))
    data_scopes: ResourceScope = field(default_factory=lambda: ResourceScope(frozenset()))
    network_scopes: ResourceScope = field(default_factory=lambda: ResourceScope(frozenset()))
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    budget_cents: int | None = None
    delegation_depth: int = 0
    risk_ceiling: float = 100.0

    def __post_init__(self) -> None:
        if self.budget_cents is not None and self.budget_cents < 0:
            raise ValueError("budget_cents cannot be negative")
        if self.delegation_depth < 0:
            raise ValueError("delegation_depth cannot be negative")
        if not 0.0 <= float(self.risk_ceiling) <= 100.0:
            raise ValueError("risk_ceiling must be between 0 and 100")
        if self.valid_from and self.valid_until and self.valid_until < self.valid_from:
            raise ValueError("valid_until cannot precede valid_from")

    @classmethod
    def from_values(
        cls,
        *,
        capabilities: Iterable[str] = (),
        operations: Iterable[str] = (),
        resources: Iterable[str] = (),
        data_scopes: Iterable[str] = (),
        network_scopes: Iterable[str] = (),
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
        budget_cents: int | None = None,
        delegation_depth: int = 0,
        risk_ceiling: float = 100.0,
    ) -> "AuthorityState":
        return cls(
            capabilities=frozenset(str(v).strip() for v in capabilities if str(v).strip()),
            operations=frozenset(str(v).strip() for v in operations if str(v).strip()),
            resources=ResourceScope.from_values(resources),
            data_scopes=ResourceScope.from_values(data_scopes),
            network_scopes=ResourceScope.from_values(network_scopes),
            valid_from=valid_from,
            valid_until=valid_until,
            budget_cents=budget_cents,
            delegation_depth=delegation_depth,
            risk_ceiling=float(risk_ceiling),
        )

    def to_dict(self) -> dict:
        def iso(v: datetime | None) -> str | None:
            return v.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if v else None
        return {
            "capabilities": sorted(self.capabilities),
            "operations": sorted(self.operations),
            "resources": sorted(self.resources.values),
            "data_scopes": sorted(self.data_scopes.values),
            "network_scopes": sorted(self.network_scopes.values),
            "valid_from": iso(self.valid_from),
            "valid_until": iso(self.valid_until),
            "budget_cents": self.budget_cents,
            "delegation_depth": self.delegation_depth,
            "risk_ceiling": self.risk_ceiling,
        }


@dataclass(frozen=True)
class DelegationViolation:
    field: str
    reason: str


@dataclass(frozen=True)
class DelegationGrant:
    grant_id: uuid.UUID
    tenant_id: uuid.UUID
    parent_agent_id: uuid.UUID
    child_agent_id: uuid.UUID
    authority: AuthorityState
    parent_authority_hash: str
    issued_at: datetime
    expires_at: datetime
    nonce: str
    escalation_authorized: bool = False
    escalation_reason: str | None = None
    metadata: dict | None = None

    def __post_init__(self) -> None:
        if self.expires_at < self.issued_at:
            raise ValueError("grant expiration cannot precede issuance")
        if self.authority.valid_until and self.authority.valid_until > self.expires_at:
            raise ValueError("authority cannot outlive the delegation grant")
