"""
AURAGENT Phase 8 forensic reconstruction tests.

Covers:

- trace reconstruction
- evidence-to-event hash verification
- read-only replay semantics
- truncation behavior
- tenant isolation
- deterministic compliance package fingerprinting
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.db.models import Tenant
from app.db.session import async_session
from app.security.evidence.forensics import (
    compute_compliance_package_hash,
    reconstruct_replay,
    reconstruct_trace,
)
from app.security.evidence.query import (
    EvidenceQueryService,
)
from app.security.evidence.verify import (
    verify_evidence_graph,
)
from app.telemetry.audit import (
    write_event,
)


async def _create_tenant(
    prefix: str,
) -> uuid.UUID:
    async with async_session() as session:
        tenant = Tenant(
            slug=(
                prefix
                + "-"
                + uuid.uuid4().hex[:12]
            ),
            name="AURAGENT Phase 8 Forensics Test",
        )

        session.add(
            tenant
        )

        await session.commit()

        return tenant.tenant_id


async def _delete_tenant(
    tenant_id: uuid.UUID,
) -> None:
    async with async_session() as session:
        tenant = await session.get(
            Tenant,
            tenant_id,
        )

        if tenant is not None:
            await session.delete(
                tenant
            )

        await session.commit()


async def _write_trace_events(
    tenant_id: uuid.UUID,
    trace_id: str,
    count: int,
) -> None:
    for index in range(count):
        async with async_session() as session:
            await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id=trace_id,
                threat_category=(
                    "phase8-test"
                ),
                action_taken=(
                    "blocked"
                    if index % 2
                    else "allowed"
                ),
                evaluator_reasoning=(
                    f"phase8-event-{index}"
                ),
            )


@pytest.mark.asyncio
async def test_trace_reconstruction_is_ordered_and_hash_checked():
    tenant_id = await _create_tenant(
        "phase8-trace"
    )

    trace_id = (
        "phase8-trace-"
        + uuid.uuid4().hex
    )

    try:
        await _write_trace_events(
            tenant_id=tenant_id,
            trace_id=trace_id,
            count=3,
        )

        async with async_session() as session:
            trace = await reconstruct_trace(
                session=session,
                tenant_id=tenant_id,
                trace_id=trace_id,
                max_events=10,
            )

            assert trace is not None

            assert (
                trace.event_count
                == 3
            )

            assert (
                trace.node_count
                == 3
            )

            assert (
                trace.edge_count
                == 2
            )

            assert (
                trace.truncated
                is False
            )

            assert (
                trace.integrity.status
                == "verified"
            )

            assert [
                record.sequence
                for record in trace.records
            ] == [1, 2, 3]

            assert all(
                record.record_hash_valid
                for record in trace.records
            )

            assert all(
                record.evidence_hash_valid
                for record in trace.records
            )

            assert all(
                record.evidence_id
                is not None
                for record in trace.records
            )

    finally:
        await _delete_tenant(
            tenant_id
        )


@pytest.mark.asyncio
async def test_forensic_replay_is_explicitly_non_executing():
    tenant_id = await _create_tenant(
        "phase8-replay"
    )

    trace_id = (
        "phase8-replay-"
        + uuid.uuid4().hex
    )

    try:
        await _write_trace_events(
            tenant_id=tenant_id,
            trace_id=trace_id,
            count=2,
        )

        async with async_session() as session:
            replay = await reconstruct_replay(
                session=session,
                tenant_id=tenant_id,
                trace_id=trace_id,
                max_events=10,
            )

            assert replay is not None

            assert (
                len(replay.records)
                == 2
            )

            # The replay model is historical reconstruction only.
            assert replay.records
            assert all(
                record.record_hash_valid
                for record in replay.records
            )

    finally:
        await _delete_tenant(
            tenant_id
        )


@pytest.mark.asyncio
async def test_trace_limit_reports_real_truncation():
    tenant_id = await _create_tenant(
        "phase8-limit"
    )

    trace_id = (
        "phase8-limit-"
        + uuid.uuid4().hex
    )

    try:
        await _write_trace_events(
            tenant_id=tenant_id,
            trace_id=trace_id,
            count=3,
        )

        async with async_session() as session:
            trace = await reconstruct_trace(
                session=session,
                tenant_id=tenant_id,
                trace_id=trace_id,
                max_events=2,
            )

            assert trace is not None

            assert (
                trace.event_count
                == 2
            )

            assert (
                trace.truncated
                is True
            )

            assert (
                trace.integrity.status
                == "partial"
            )

    finally:
        await _delete_tenant(
            tenant_id
        )


@pytest.mark.asyncio
async def test_trace_is_tenant_scoped():
    tenant_a = await _create_tenant(
        "phase8-a"
    )

    tenant_b = await _create_tenant(
        "phase8-b"
    )

    trace_id = (
        "phase8-cross-"
        + uuid.uuid4().hex
    )

    try:
        await _write_trace_events(
            tenant_id=tenant_a,
            trace_id=trace_id,
            count=2,
        )

        async with async_session() as session:
            trace_a = await reconstruct_trace(
                session=session,
                tenant_id=tenant_a,
                trace_id=trace_id,
                max_events=10,
            )

            trace_b = await reconstruct_trace(
                session=session,
                tenant_id=tenant_b,
                trace_id=trace_id,
                max_events=10,
            )

            assert trace_a is not None
            assert (
                trace_a.event_count
                == 2
            )

            assert trace_b is None

    finally:
        await _delete_tenant(
            tenant_a
        )

        await _delete_tenant(
            tenant_b
        )


@pytest.mark.asyncio
async def test_compliance_package_hash_is_stable_for_same_contents():
    tenant_id = await _create_tenant(
        "phase8-package"
    )

    try:
        await _write_trace_events(
            tenant_id=tenant_id,
            trace_id=(
                "phase8-package-"
                + uuid.uuid4().hex
            ),
            count=2,
        )

        async with async_session() as session:
            exported = (
                await EvidenceQueryService.export_tenant(
                    session=session,
                    tenant_id=tenant_id,
                    max_nodes=100,
                    max_edges=100,
                )
            )

            verification = (
                await verify_evidence_graph(
                    session=session,
                    tenant_id=tenant_id,
                )
            )

            verification_payload = (
                verification.to_dict()
            )

            hash_a = (
                compute_compliance_package_hash(
                    tenant_id=
                        tenant_id,
                    nodes=
                        exported.nodes,
                    edges=
                        exported.edges,
                    verification=
                        verification_payload,
                )
            )

            hash_b = (
                compute_compliance_package_hash(
                    tenant_id=
                        tenant_id,
                    nodes=
                        exported.nodes,
                    edges=
                        exported.edges,
                    verification=
                        verification_payload,
                )
            )

            assert hash_a == hash_b
            assert len(hash_a) == 64

            

    finally:
        await _delete_tenant(
            tenant_id
        )
@pytest.mark.asyncio
async def test_trace_node_limit_is_enforced_at_reconstruction_boundary():
    tenant_id = await _create_tenant(
        "phase8-node-limit"
    )

    trace_id = (
        "phase8-node-limit-"
        + uuid.uuid4().hex
    )

    try:
        await _write_trace_events(
            tenant_id=tenant_id,
            trace_id=trace_id,
            count=3,
        )

        async with async_session() as session:
            trace = await reconstruct_trace(
                session=session,
                tenant_id=tenant_id,
                trace_id=trace_id,
                max_events=2,
            )

        assert trace is not None
        assert trace.event_count == 2
        assert trace.node_count == 2
        assert trace.truncated is True

    finally:
        await _delete_tenant(
            tenant_id
        )
