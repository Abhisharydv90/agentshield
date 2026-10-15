"""Phase 13 Scale Fabric deterministic boundary tests."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from app.scale.contracts import EventEnvelope, RegionDescriptor, WorkItem
from app.scale.events import EventBusError, InMemoryEventBus
from app.scale.health import evaluate_health
from app.scale.idempotency import IdempotencyConflict, InMemoryIdempotencyStore
from app.scale.leases import InMemoryLeaseCoordinator, LeaseConflict
from app.scale.regions import RegionRoutingError, select_region, validate_region_set
from app.scale.scheduler import FencedWorkScheduler
from app.scale.service import ScaleService
from app.scale.sharding import partition_for_key, shard_for_tenant
from app.scale.workflows import InMemoryWorkflowStore, WorkflowConflict, state_digest


TENANT = UUID("11111111-1111-1111-1111-111111111111")


def work(partition_key: str = "p0") -> WorkItem:
    return WorkItem(
        work_id=uuid4(),
        tenant_id=TENANT,
        partition_key=partition_key,
        operation="test",
        payload_digest="a" * 64,
        created_at=datetime.now(timezone.utc),
        trace_id="trace-1",
        dedupe_key="dedupe-1",
    )


def event(seq: int) -> EventEnvelope:
    return EventEnvelope(
        event_id=uuid4(),
        tenant_id=TENANT,
        topic="test",
        partition_key="p0",
        sequence=seq,
        occurred_at=datetime.now(timezone.utc),
        trace_id="trace-1",
        payload_digest="b" * 64,
    )


def test_tenant_sharding_is_deterministic():
    one = shard_for_tenant(tenant_id=TENANT, total_shards=128)
    two = shard_for_tenant(tenant_id=TENANT, total_shards=128)
    assert one == two
    assert 0 <= one.shard_id < 128


def test_partition_hash_is_stable():
    assert partition_for_key(partition_key="abc", partition_count=32) == \
        partition_for_key(partition_key="abc", partition_count=32)


def test_lease_fencing_rejects_second_owner():
    async def scenario():
        leases = InMemoryLeaseCoordinator()
        first = await leases.acquire(
            key="p0",
            worker_id="w1",
            region="r1",
            ttl_seconds=30,
        )
        with pytest.raises(LeaseConflict):
            await leases.acquire(
                key="p0",
                worker_id="w2",
                region="r1",
                ttl_seconds=30,
            )
        return first

    first = asyncio.run(scenario())
    assert first.token == 1


def test_scheduler_requires_current_fence():
    async def scenario():
        scheduler = FencedWorkScheduler()
        await scheduler.enqueue(work())
        lease = await scheduler.acquire_partition(
            partition_key="p0",
            worker_id="w1",
            region="r1",
        )
        item = await scheduler.claim(
            partition_key="p0",
            worker_id="w1",
            lease_token=lease.token,
        )
        return item

    result = asyncio.run(scenario())
    assert result is not None


def test_event_bus_requires_contiguous_sequence():
    async def scenario():
        bus = InMemoryEventBus()
        await bus.publish([event(0)])
        with pytest.raises(EventBusError):
            await bus.publish([event(2)])

    asyncio.run(scenario())


def test_idempotency_rejects_different_request_digest():
    async def scenario():
        store = InMemoryIdempotencyStore()
        claimed, _ = await store.claim(
            namespace="test",
            key="same",
            request_digest="a" * 64,
        )
        assert claimed is True
        with pytest.raises(IdempotencyConflict):
            await store.claim(
                namespace="test",
                key="same",
                request_digest="b" * 64,
            )

    asyncio.run(scenario())


def test_workflow_checkpoint_uses_optimistic_version():
    async def scenario():
        store = InMemoryWorkflowStore()
        first = await store.save(
            workflow_id="wf1",
            expected_version=0,
            state="running",
            state_data={"step": 1},
        )
        with pytest.raises(WorkflowConflict):
            await store.save(
                workflow_id="wf1",
                expected_version=0,
                state="running",
                state_data={"step": 2},
            )
        return first

    result = asyncio.run(scenario())
    assert result.version == 1
    assert result.state_digest == state_digest({"step": 1})


def test_region_set_requires_one_control_plane():
    regions = [
        RegionDescriptor(region="r1", control_plane_region=True),
        RegionDescriptor(region="r2"),
    ]
    validate_region_set(regions)
    assert select_region(regions, preferred="r2").region == "r2"


def test_region_set_rejects_two_control_planes():
    regions = [
        RegionDescriptor(region="r1", control_plane_region=True),
        RegionDescriptor(region="r2", control_plane_region=True),
    ]
    with pytest.raises(RegionRoutingError):
        validate_region_set(regions)


@pytest.mark.parametrize(
    "queue_depth,event_lag,expected",
    [
        (0, 0, "healthy"),
        (1001, 0, "degraded"),
        (2001, 0, "unavailable"),
    ],
)
def test_health_degradation_is_deterministic(queue_depth, event_lag, expected):
    snapshot = evaluate_health(
        region="r1",
        worker_id="w1",
        active_leases=0,
        queue_depth=queue_depth,
        event_lag=event_lag,
    )
    assert snapshot.status.value == expected


def test_scale_payload_digest_is_sha256():
    digest = ScaleService.digest_payload({"hello": "world"})
    assert len(digest) == 64
    assert digest == ScaleService.digest_payload({"hello": "world"})
