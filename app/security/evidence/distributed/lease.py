"""Fenced lease contract for distributed Evidence Fabric writers.

The in-memory coordinator is intentionally a development/reference backend.
A production deployment must place the same fencing semantics behind a shared
store such as PostgreSQL or Redis before multiple independent workers rely on
the lease for correctness.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from typing import Protocol


class LeaseConflictError(RuntimeError):
    """Raised when another owner currently holds a lease."""


class LeaseExpiredError(RuntimeError):
    """Raised when a caller attempts to use an expired lease."""


@dataclass(frozen=True)
class EvidenceLease:
    lease_id: str
    resource: str
    owner_id: str
    fencing_token: int
    expires_at: float

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self.expires_at


class EvidenceLeaseCoordinator(Protocol):
    async def acquire(
        self,
        *,
        resource: str,
        owner_id: str,
        ttl_seconds: float = 15.0,
    ) -> EvidenceLease: ...

    async def renew(
        self,
        lease: EvidenceLease,
        *,
        ttl_seconds: float = 15.0,
    ) -> EvidenceLease: ...

    async def release(self, lease: EvidenceLease) -> None: ...


@dataclass
class _LeaseState:
    lease_id: str
    owner_id: str
    fencing_token: int
    expires_at: float


class InMemoryEvidenceLeaseCoordinator:
    """Reference lease coordinator with fencing tokens."""

    def __init__(self) -> None:
        self._states: dict[str, _LeaseState] = {}
        self._counters: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def acquire(
        self,
        *,
        resource: str,
        owner_id: str,
        ttl_seconds: float = 15.0,
    ) -> EvidenceLease:
        _validate(resource, owner_id, ttl_seconds)

        async with self._lock:
            existing = self._states.get(resource)
            now = time.monotonic()

            if existing and existing.expires_at > now:
                raise LeaseConflictError("lease_already_held")

            token = self._counters.get(resource, 0) + 1
            self._counters[resource] = token

            lease = EvidenceLease(
                lease_id=str(uuid.uuid4()),
                resource=resource,
                owner_id=owner_id,
                fencing_token=token,
                expires_at=now + ttl_seconds,
            )
            self._states[resource] = _LeaseState(
                lease_id=lease.lease_id,
                owner_id=owner_id,
                fencing_token=token,
                expires_at=lease.expires_at,
            )
            return lease

    async def renew(
        self,
        lease: EvidenceLease,
        *,
        ttl_seconds: float = 15.0,
    ) -> EvidenceLease:
        _validate(lease.resource, lease.owner_id, ttl_seconds)

        async with self._lock:
            state = self._states.get(lease.resource)
            now = time.monotonic()
            if state is None:
                raise LeaseExpiredError("lease_not_found")
            if state.lease_id != lease.lease_id:
                raise LeaseExpiredError("lease_fencing_mismatch")
            if state.owner_id != lease.owner_id:
                raise LeaseExpiredError("lease_owner_mismatch")
            if state.expires_at <= now:
                self._states.pop(lease.resource, None)
                raise LeaseExpiredError("lease_expired")
            if state.fencing_token != lease.fencing_token:
                raise LeaseExpiredError("lease_fencing_token_mismatch")

            renewed = EvidenceLease(
                lease_id=lease.lease_id,
                resource=lease.resource,
                owner_id=lease.owner_id,
                fencing_token=lease.fencing_token,
                expires_at=now + ttl_seconds,
            )
            state.expires_at = renewed.expires_at
            return renewed

    async def release(self, lease: EvidenceLease) -> None:
        async with self._lock:
            state = self._states.get(lease.resource)
            if state is None:
                return
            if state.lease_id != lease.lease_id:
                raise LeaseExpiredError("lease_fencing_mismatch")
            if state.fencing_token != lease.fencing_token:
                raise LeaseExpiredError("lease_fencing_token_mismatch")
            self._states.pop(lease.resource, None)


def _validate(resource: str, owner_id: str, ttl_seconds: float) -> None:
    if not resource.strip():
        raise ValueError("lease_resource_required")
    if not owner_id.strip():
        raise ValueError("lease_owner_required")
    if not 1.0 <= ttl_seconds <= 300.0:
        raise ValueError("lease_ttl_out_of_bounds")
