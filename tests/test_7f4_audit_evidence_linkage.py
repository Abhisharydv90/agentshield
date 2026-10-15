"""
7F-4 audit/evidence causal-linkage tests.

These tests prove that successive runtime audit events become a directed
Evidence Graph chain, while historical evidence gaps and tenant boundaries
are handled safely.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.db.models import (
    EvidenceEdge,
    EvidenceNode,
    SecurityEvent,
    Tenant,
)
from app.db.session import async_session
from app.security.evidence.runtime import (
    RUNTIME_EVIDENCE_EDGE_RELATION,
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
            name="7F-4 Evidence Linkage Test",
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


@pytest.mark.asyncio
async def test_audit_events_form_one_causal_evidence_chain():

    tenant_id = await _create_tenant(
        "7f4-chain"
    )

    try:

        async with async_session() as session:

            first = await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f4-first",
                threat_category="benign",
                action_taken="allowed",
                evaluator_reasoning="first event",
            )

        async with async_session() as session:

            second = await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f4-second",
                threat_category="destructive",
                action_taken="blocked",
                evaluator_reasoning="second event",
            )

        async with async_session() as session:

            third = await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f4-third",
                threat_category="privilege_escalation",
                action_taken="blocked",
                evaluator_reasoning="third event",
            )

        async with async_session() as session:

            node_result = await session.execute(
                select(
                    EvidenceNode
                )
                .where(
                    EvidenceNode.tenant_id
                    == tenant_id
                )
            )

            nodes = (
                node_result
                .scalars()
                .all()
            )

            edge_result = await session.execute(
                select(
                    EvidenceEdge
                )
                .where(
                    EvidenceEdge.tenant_id
                    == tenant_id
                )
            )

            edges = (
                edge_result
                .scalars()
                .all()
            )

        assert len(nodes) == 3
        assert len(edges) == 2

        node_by_event = {
            node.security_event_id:
                node
            for node in nodes
        }

        assert first.event_id in (
            node_by_event
        )

        assert second.event_id in (
            node_by_event
        )

        assert third.event_id in (
            node_by_event
        )

        first_node = (
            node_by_event[
                first.event_id
            ]
        )

        second_node = (
            node_by_event[
                second.event_id
            ]
        )

        third_node = (
            node_by_event[
                third.event_id
            ]
        )

        edges_by_target = {
            edge.to_evidence_id:
                edge
            for edge in edges
        }

        assert (
            edges_by_target[
                second_node.evidence_id
            ].from_evidence_id
            == first_node.evidence_id
        )

        assert (
            edges_by_target[
                second_node.evidence_id
            ].to_evidence_id
            == second_node.evidence_id
        )

        assert (
            edges_by_target[
                second_node.evidence_id
            ].relation
            == RUNTIME_EVIDENCE_EDGE_RELATION
        )

        assert (
            edges_by_target[
                third_node.evidence_id
            ].from_evidence_id
            == second_node.evidence_id
        )

        assert (
            edges_by_target[
                third_node.evidence_id
            ].to_evidence_id
            == third_node.evidence_id
        )

        for edge in edges:

            assert edge.tenant_id == tenant_id

    finally:

        await _delete_tenant(
            tenant_id
        )


@pytest.mark.asyncio
async def test_missing_historical_evidence_is_a_safe_lineage_boundary():

    tenant_id = await _create_tenant(
        "7f4-boundary"
    )

    try:

        async with async_session() as session:

            first = await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f4-historical",
                threat_category="test",
                action_taken="blocked",
                evaluator_reasoning="historical event",
            )

        # Simulate a legacy audit row that has no EvidenceNode.
        # The next runtime event must not fabricate a predecessor edge.
        async with async_session() as session:

            node_result = await session.execute(
                select(
                    EvidenceNode
                )
                .where(
                    EvidenceNode.tenant_id
                    == tenant_id
                )
                .where(
                    EvidenceNode.security_event_id
                    == first.event_id
                )
            )

            first_node = (
                node_result
                .scalar_one()
            )

            await session.delete(
                first_node
            )

            await session.commit()

        async with async_session() as session:

            second = await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f4-after-boundary",
                threat_category="benign",
                action_taken="allowed",
                evaluator_reasoning="after boundary",
            )

        async with async_session() as session:

            nodes_result = await session.execute(
                select(
                    EvidenceNode
                )
                .where(
                    EvidenceNode.tenant_id
                    == tenant_id
                )
            )

            nodes = (
                nodes_result
                .scalars()
                .all()
            )

            edges_result = await session.execute(
                select(
                    EvidenceEdge
                )
                .where(
                    EvidenceEdge.tenant_id
                    == tenant_id
                )
            )

            edges = (
                edges_result
                .scalars()
                .all()
            )

            audit_result = await session.execute(
                select(
                    SecurityEvent
                )
                .where(
                    SecurityEvent.tenant_id
                    == tenant_id
                )
            )

            audit_events = (
                audit_result
                .scalars()
                .all()
            )

        assert len(audit_events) == 2
        assert len(nodes) == 1
        assert len(edges) == 0

        assert nodes[0].security_event_id == (
            second.event_id
        )

    finally:

        await _delete_tenant(
            tenant_id
        )


@pytest.mark.asyncio
async def test_evidence_edges_cannot_cross_tenant_boundaries():

    tenant_a = await _create_tenant(
        "7f4-tenant-a"
    )

    tenant_b = await _create_tenant(
        "7f4-tenant-b"
    )

    try:

        async with async_session() as session:

            await write_event(
                session=session,
                tenant_id=tenant_a,
                request_id="tenant-a-first",
                threat_category="test",
                action_taken="blocked",
                evaluator_reasoning="a1",
            )

        async with async_session() as session:

            await write_event(
                session=session,
                tenant_id=tenant_a,
                request_id="tenant-a-second",
                threat_category="test",
                action_taken="blocked",
                evaluator_reasoning="a2",
            )

        async with async_session() as session:

            await write_event(
                session=session,
                tenant_id=tenant_b,
                request_id="tenant-b-first",
                threat_category="test",
                action_taken="blocked",
                evaluator_reasoning="b1",
            )

        async with async_session() as session:

            await write_event(
                session=session,
                tenant_id=tenant_b,
                request_id="tenant-b-second",
                threat_category="test",
                action_taken="blocked",
                evaluator_reasoning="b2",
            )

        async with async_session() as session:

            result = await session.execute(
                select(
                    EvidenceEdge
                )
                .order_by(
                    EvidenceEdge.created_at.asc()
                )
            )

            edges = (
                result
                .scalars()
                .all()
            )

        tenant_a_edges = [
            edge
            for edge in edges
            if edge.tenant_id == tenant_a
        ]

        tenant_b_edges = [
            edge
            for edge in edges
            if edge.tenant_id == tenant_b
        ]

        assert len(tenant_a_edges) == 1
        assert len(tenant_b_edges) == 1

        assert (
            tenant_a_edges[0].tenant_id
            == tenant_a
        )

        assert (
            tenant_b_edges[0].tenant_id
            == tenant_b
        )

        assert (
            tenant_a_edges[0].from_evidence_id
            != tenant_b_edges[0].from_evidence_id
        )

        assert (
            tenant_a_edges[0].to_evidence_id
            != tenant_b_edges[0].to_evidence_id
        )

    finally:

        await _delete_tenant(
            tenant_a
        )

        await _delete_tenant(
            tenant_b
        )