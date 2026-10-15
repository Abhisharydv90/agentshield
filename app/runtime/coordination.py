"""
AURAGENT multi-agent coordination.

Coordination does not grant authority.

The Trust/Security Kernel remains the sole authority boundary.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class CoordinationLease:
    lease_id: uuid.UUID
    tenant_id: uuid.UUID
    agent_id: uuid.UUID
    resource: str
    acquired_at: datetime
    expires_at: datetime


class AgentCoordinator:
    """
    Tenant-scoped coordination primitive.

    Useful for:
    - shared workflow ownership,
    - leader selection,
    - resource serialization,
    - duplicate suppression.

    It does not modify agent capabilities.
    """

    def __init__(
        self,
        *,
        default_lease_seconds: int = 30,
    ) -> None:
        if not 1 <= default_lease_seconds <= 3600:
            raise ValueError(
                "invalid_lease_duration"
            )

        self.default_lease_seconds = (
            default_lease_seconds
        )

        self._leases: dict[
            tuple[uuid.UUID, str],
            CoordinationLease,
        ] = {}

        self._lock = asyncio.Lock()

    async def acquire(
        self,
        *,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        resource: str,
        lease_seconds: int | None = None,
    ) -> CoordinationLease | None:
        resource = resource.strip()

        if not resource:
            raise ValueError(
                "coordination_resource_required"
            )

        seconds = (
            lease_seconds
            if lease_seconds is not None
            else self.default_lease_seconds
        )

        if not 1 <= seconds <= 3600:
            raise ValueError(
                "invalid_lease_duration"
            )

        now = utc_now()
        key = (
            tenant_id,
            resource,
        )

        async with self._lock:
            existing = self._leases.get(
                key
            )

            if (
                existing is not None
                and existing.expires_at > now
            ):
                return None

            lease = CoordinationLease(
                lease_id=uuid.uuid4(),
                tenant_id=tenant_id,
                agent_id=agent_id,
                resource=resource,
                acquired_at=now,
                expires_at=(
                    now
                    + __import__(
                        "datetime"
                    ).timedelta(
                        seconds=seconds
                    )
                ),
            )

            self._leases[key] = lease

            return lease

    async def release(
        self,
        *,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        lease_id: uuid.UUID,
        resource: str,
    ) -> bool:
        key = (
            tenant_id,
            resource,
        )

        async with self._lock:
            lease = self._leases.get(
                key
            )

            if lease is None:
                return False

            if (
                lease.lease_id != lease_id
                or lease.agent_id != agent_id
                or lease.tenant_id != tenant_id
            ):
                return False

            del self._leases[key]
            return True

    async def cleanup_expired(self) -> int:
        now = utc_now()

        async with self._lock:
            expired = [
                key
                for key, lease
                in self._leases.items()
                if lease.expires_at <= now
            ]

            for key in expired:
                del self._leases[key]

            return len(expired)