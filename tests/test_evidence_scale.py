"""Phase 8 distributed Evidence Fabric build-level tests.

These tests are intentionally local and deterministic. They do not require
PostgreSQL, Redis, Docker, or a configured external anchor provider.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from app.security.evidence.anchoring.external import (
    ExternalAnchorError,
    build_anchor_document,
)
from app.security.evidence.distributed.invariants import (
    DistributedEvidenceInvariantError,
    EvidenceBatch,
    EvidenceFragment,
    assert_batch_append,
    compute_batch_root,
    verify_batch,
)
from app.security.evidence.distributed.lease import (
    InMemoryEvidenceLeaseCoordinator,
    LeaseConflictError,
)


def _fragment(tenant_id: uuid.UUID, sequence: int) -> EvidenceFragment:
    return EvidenceFragment(
        tenant_id=tenant_id,
        evidence_id=uuid.uuid4(),
        artifact_hash=f"{sequence:064x}",
        sequence=sequence,
    )


def test_distributed_batch_root_is_deterministic() -> None:
    tenant_id = uuid.uuid4()
    fragments = (
        _fragment(tenant_id, 2),
        _fragment(tenant_id, 1),
    )

    first = compute_batch_root(
        tenant_id=tenant_id,
        writer_id="worker-a",
        sequence=0,
        previous_root=None,
        fragments=fragments,
    )
    second = compute_batch_root(
        tenant_id=tenant_id,
        writer_id="worker-a",
        sequence=0,
        previous_root=None,
        fragments=tuple(reversed(fragments)),
    )
    assert first == second


def test_cross_tenant_fragment_is_rejected() -> None:
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    fragments = (_fragment(tenant_b, 0),)
    root = compute_batch_root(
        tenant_id=tenant_a,
        writer_id="worker-a",
        sequence=0,
        previous_root=None,
        fragments=fragments,
    )

    with pytest.raises(DistributedEvidenceInvariantError):
        EvidenceBatch(
            tenant_id=tenant_a,
            writer_id="worker-a",
            sequence=0,
            previous_root=None,
            fragments=fragments,
            batch_root=root,
        )


def test_batch_append_requires_contiguous_sequence() -> None:
    tenant_id = uuid.uuid4()
    fragment = _fragment(tenant_id, 0)
    root = compute_batch_root(
        tenant_id=tenant_id,
        writer_id="worker-a",
        sequence=2,
        previous_root="0" * 64,
        fragments=(fragment,),
    )
    batch = EvidenceBatch(
        tenant_id=tenant_id,
        writer_id="worker-a",
        sequence=2,
        previous_root="0" * 64,
        fragments=(fragment,),
        batch_root=root,
    )
    with pytest.raises(DistributedEvidenceInvariantError):
        assert_batch_append(
            previous_sequence=0,
            previous_root="0" * 64,
            batch=batch,
        )


def test_batch_verification_accepts_valid_root() -> None:
    tenant_id = uuid.uuid4()
    fragment = _fragment(tenant_id, 0)
    root = compute_batch_root(
        tenant_id=tenant_id,
        writer_id="worker-a",
        sequence=0,
        previous_root=None,
        fragments=(fragment,),
    )
    batch = EvidenceBatch(
        tenant_id=tenant_id,
        writer_id="worker-a",
        sequence=0,
        previous_root=None,
        fragments=(fragment,),
        batch_root=root,
    )
    assert verify_batch(batch) is True


@pytest.mark.asyncio
async def test_in_memory_lease_fencing() -> None:
    coordinator = InMemoryEvidenceLeaseCoordinator()

    first = await coordinator.acquire(
        resource="tenant-evidence",
        owner_id="worker-a",
        ttl_seconds=5,
    )

    with pytest.raises(LeaseConflictError):
        await coordinator.acquire(
            resource="tenant-evidence",
            owner_id="worker-b",
            ttl_seconds=5,
        )

    renewed = await coordinator.renew(first, ttl_seconds=5)
    assert renewed.fencing_token == first.fencing_token

    await coordinator.release(renewed)

    second = await coordinator.acquire(
        resource="tenant-evidence",
        owner_id="worker-b",
        ttl_seconds=5,
    )
    assert second.fencing_token > first.fencing_token


def test_anchor_document_contains_only_commitment() -> None:
    tenant_id = uuid.uuid4()
    package_hash = "a" * 64
    document = build_anchor_document(
        tenant_id=tenant_id,
        package_hash=package_hash,
    )
    payload = document.to_dict()
    assert payload["package_hash"] == package_hash
    assert "raw_evidence" not in payload


def test_anchor_document_rejects_bad_hash() -> None:
    with pytest.raises(ExternalAnchorError):
        build_anchor_document(
            tenant_id=uuid.uuid4(),
            package_hash="not-a-hash",
        )
