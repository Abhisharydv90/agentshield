"""
7F-5 Evidence investigation/query tests.

Covers:

- tenant-scoped listing
- keyset pagination
- single-node retrieval
- bounded graph traversal
- tenant isolation
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.db.models import (
    EvidenceNode,
    Tenant,
)
from app.db.session import async_session
from app.security.evidence.query import (
    EvidenceFilters,
    EvidenceQueryService,
)
from app.telemetry.audit import write_event


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
            name="7F-5 Evidence Query Test",
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
async def test_keyset_pagination_returns_all_nodes_without_overlap():

    tenant_id = await _create_tenant(
        "7f5-pagination"
    )

    try:

        for index in range(3):

            async with async_session() as session:

                await write_event(
                    session=session,
                    tenant_id=tenant_id,
                    request_id=f"7f5-{index}",
                    threat_category="test",
                    action_taken="blocked",
                    evaluator_reasoning=f"event-{index}",
                )

        async with async_session() as session:

            first_page = (
                await EvidenceQueryService.list_nodes(
                    session=session,
                    tenant_id=tenant_id,
                    filters=EvidenceFilters(
                        page_size=2,
                    ),
                )
            )

            assert len(
                first_page.nodes
            ) == 2

            assert (
                first_page.has_more
                is True
            )

            assert first_page.next_cursor is not None

            second_page = (
                await EvidenceQueryService.list_nodes(
                    session=session,
                    tenant_id=tenant_id,
                    filters=EvidenceFilters(
                        page_size=2,
                        cursor=first_page.next_cursor,
                    ),
                )
            )

            assert len(
                second_page.nodes
            ) == 1

            assert (
                second_page.has_more
                is False
            )

            first_ids = {
                node.evidence_id
                for node in first_page.nodes
            }

            second_ids = {
                node.evidence_id
                for node in second_page.nodes
            }

            assert first_ids.isdisjoint(
                second_ids
            )

    finally:

        await _delete_tenant(
            tenant_id
        )


@pytest.mark.asyncio
async def test_graph_traversal_reconstructs_local_causality():

    tenant_id = await _create_tenant(
        "7f5-graph"
    )

    try:

        async with async_session() as session:

            first = await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f5-first",
                threat_category="test",
                action_taken="allowed",
                evaluator_reasoning="first",
            )

        async with async_session() as session:

            second = await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f5-second",
                threat_category="test",
                action_taken="blocked",
                evaluator_reasoning="second",
            )

        async with async_session() as session:

            await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f5-third",
                threat_category="test",
                action_taken="blocked",
                evaluator_reasoning="third",
            )

        async with async_session() as session:

            node = (
                await session.execute(
                    select(
                        EvidenceNode
                    )
                    .where(
                        EvidenceNode.tenant_id
                        == tenant_id
                    )
                    .where(
                        EvidenceNode.security_event_id
                        == second.event_id
                    )
                )
            ).scalar_one()

            graph = (
                await EvidenceQueryService.get_graph(
                    session=session,
                    tenant_id=tenant_id,
                    evidence_id=node.evidence_id,
                    depth=1,
                    max_nodes=3,
                )
            )

            assert graph is not None
            assert (
                graph.root.evidence_id
                == node.evidence_id
            )

            assert len(
                graph.nodes
            ) == 3

            assert len(
                graph.edges
            ) == 2

            assert graph.truncated is False

    finally:

        await _delete_tenant(
            tenant_id
        )


@pytest.mark.asyncio
async def test_queries_cannot_cross_tenant_boundaries():

    tenant_a = await _create_tenant(
        "7f5-a"
    )

    tenant_b = await _create_tenant(
        "7f5-b"
    )

    try:

        async with async_session() as session:

            event_a = await write_event(
                session=session,
                tenant_id=tenant_a,
                request_id="tenant-a",
                threat_category="test",
                action_taken="blocked",
                evaluator_reasoning="a",
            )

        async with async_session() as session:

            await write_event(
                session=session,
                tenant_id=tenant_b,
                request_id="tenant-b",
                threat_category="test",
                action_taken="blocked",
                evaluator_reasoning="b",
            )

        async with async_session() as session:

            node_a = (
                await session.execute(
                    select(
                        EvidenceNode
                    )
                    .where(
                        EvidenceNode.tenant_id
                        == tenant_a
                    )
                    .where(
                        EvidenceNode.security_event_id
                        == event_a.event_id
                    )
                )
            ).scalar_one()

            result_a = (
                await EvidenceQueryService.get_node(
                    session=session,
                    tenant_id=tenant_a,
                    evidence_id=node_a.evidence_id,
                )
            )

            result_b = (
                await EvidenceQueryService.get_node(
                    session=session,
                    tenant_id=tenant_b,
                    evidence_id=node_a.evidence_id,
                )
            )

            assert result_a is not None
            assert result_b is None

    finally:

        await _delete_tenant(
            tenant_a
        )

        await _delete_tenant(
            tenant_b
        )