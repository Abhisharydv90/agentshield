"""Distributed work claiming without authority escalation."""

from __future__ import annotations

import asyncio
from collections import deque

from .contracts import WorkItem
from .leases import InMemoryLeaseCoordinator, Lease, LeaseConflict


class DistributedQueue:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._queues: dict[str, deque[WorkItem]] = {}

    async def enqueue(self, work: WorkItem) -> None:
        async with self._lock:
            self._queues.setdefault(work.partition_key, deque()).append(work)

    async def depth(self, partition_key: str) -> int:
        async with self._lock:
            return len(self._queues.get(partition_key, ()))

    async def claim(
        self,
        *,
        partition_key: str,
        worker_id: str,
    ) -> WorkItem | None:
        async with self._lock:
            queue = self._queues.get(partition_key)
            if not queue:
                return None
            return queue.popleft()


class FencedWorkScheduler:
    """Reference scheduler.

    The Trust Kernel remains the authority boundary. Scheduling assigns work;
    it never creates capabilities or authority.
    """

    def __init__(
        self,
        *,
        queue: DistributedQueue | None = None,
        leases: InMemoryLeaseCoordinator | None = None,
    ) -> None:
        self.queue = queue or DistributedQueue()
        self.leases = leases or InMemoryLeaseCoordinator()

    async def enqueue(self, work: WorkItem) -> None:
        await self.queue.enqueue(work)

    async def acquire_partition(
        self,
        *,
        partition_key: str,
        worker_id: str,
        region: str,
        ttl_seconds: int = 30,
    ) -> Lease:
        return await self.leases.acquire(
            key=f"partition:{partition_key}",
            worker_id=worker_id,
            region=region,
            ttl_seconds=ttl_seconds,
        )

    async def claim(
        self,
        *,
        partition_key: str,
        worker_id: str,
        lease_token: int,
    ) -> WorkItem | None:
        await self.leases.assert_fenced(
            key=f"partition:{partition_key}",
            worker_id=worker_id,
            token=lease_token,
        )
        return await self.queue.claim(
            partition_key=partition_key,
            worker_id=worker_id,
        )
