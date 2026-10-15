"""Phase 13 Scale Fabric facade."""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID

from .contracts import (
    EventEnvelope,
    HealthSnapshot,
    RegionDescriptor,
    ScaleLimits,
    ShardDescriptor,
    WorkItem,
)
from .health import evaluate_health
from .regions import select_region, validate_region_set
from .scheduler import FencedWorkScheduler
from .sharding import shard_for_tenant


class ScaleService:
    """Stateless-facing scale facade.

    This class deliberately composes bounded, replaceable adapters. It does not
    bypass the Trust Kernel and does not mint authority for workers.
    """

    def __init__(
        self,
        *,
        limits: ScaleLimits | None = None,
        scheduler: FencedWorkScheduler | None = None,
    ) -> None:
        self.limits = limits or ScaleLimits()
        self.scheduler = scheduler or FencedWorkScheduler()

    def shard_tenant(self, tenant_id: UUID) -> ShardDescriptor:
        return shard_for_tenant(
            tenant_id=tenant_id,
            total_shards=self.limits.max_partitions,
        )

    @staticmethod
    def digest_payload(payload: Any) -> str:
        raw = repr(payload).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def choose_region(
        regions: list[RegionDescriptor],
        preferred: str | None = None,
    ) -> RegionDescriptor:
        validate_region_set(regions)
        return select_region(regions=regions, preferred=preferred)

    @staticmethod
    def health(
        *,
        region: str,
        worker_id: str,
        active_leases: int,
        queue_depth: int,
        event_lag: int,
    ) -> HealthSnapshot:
        return evaluate_health(
            region=region,
            worker_id=worker_id,
            active_leases=active_leases,
            queue_depth=queue_depth,
            event_lag=event_lag,
        )

    async def enqueue(self, work: WorkItem) -> None:
        await self.scheduler.enqueue(work)
