"""Fenced worker lease coordinator for scale reference deployments."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


class LeaseError(RuntimeError):
    pass


class LeaseConflict(LeaseError):
    pass


class LeaseExpired(LeaseError):
    pass


@dataclass(frozen=True)
class Lease:
    key: str
    worker_id: str
    token: int
    expires_at: datetime
    region: str
    epoch: int


class InMemoryLeaseCoordinator:
    """Reference coordinator.

    Production multi-worker correctness requires a shared linearizable store
    (for example Redis/PostgreSQL). The fencing-token contract remains the same.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._leases: dict[str, Lease] = {}
        self._tokens: dict[str, int] = {}

    async def acquire(
        self,
        *,
        key: str,
        worker_id: str,
        region: str,
        ttl_seconds: int,
    ) -> Lease:
        if not key.strip() or not worker_id.strip() or not region.strip():
            raise ValueError("lease key, worker_id and region are required")
        if ttl_seconds < 1 or ttl_seconds > 300:
            raise ValueError("ttl_seconds must be between 1 and 300")

        now = datetime.now(timezone.utc)

        async with self._lock:
            current = self._leases.get(key)
            if current is not None and current.expires_at > now:
                raise LeaseConflict("lease is held by another worker")

            token = self._tokens.get(key, 0) + 1
            self._tokens[key] = token
            lease = Lease(
                key=key,
                worker_id=worker_id,
                token=token,
                expires_at=now + timedelta(seconds=ttl_seconds),
                region=region,
                epoch=token,
            )
            self._leases[key] = lease
            return lease

    async def renew(
        self,
        *,
        key: str,
        worker_id: str,
        token: int,
        ttl_seconds: int,
    ) -> Lease:
        now = datetime.now(timezone.utc)
        if ttl_seconds < 1 or ttl_seconds > 300:
            raise ValueError("ttl_seconds must be between 1 and 300")

        async with self._lock:
            current = self._leases.get(key)
            if current is None or current.token != token:
                raise LeaseConflict("fencing token is not current")
            if current.worker_id != worker_id:
                raise LeaseConflict("worker does not own lease")
            if current.expires_at <= now:
                raise LeaseExpired("lease expired")

            lease = Lease(
                key=current.key,
                worker_id=current.worker_id,
                token=current.token,
                expires_at=now + timedelta(seconds=ttl_seconds),
                region=current.region,
                epoch=current.epoch,
            )
            self._leases[key] = lease
            return lease

    async def release(
        self,
        *,
        key: str,
        worker_id: str,
        token: int,
    ) -> None:
        async with self._lock:
            current = self._leases.get(key)
            if current is None:
                return
            if current.worker_id != worker_id or current.token != token:
                raise LeaseConflict("lease owner or fencing token mismatch")
            self._leases.pop(key, None)

    async def assert_fenced(
        self,
        *,
        key: str,
        worker_id: str,
        token: int,
    ) -> None:
        now = datetime.now(timezone.utc)
        async with self._lock:
            current = self._leases.get(key)
            if current is None:
                raise LeaseConflict("lease not found")
            if current.worker_id != worker_id or current.token != token:
                raise LeaseConflict("stale fencing token")
            if current.expires_at <= now:
                raise LeaseExpired("lease expired")
