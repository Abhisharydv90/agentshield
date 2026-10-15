"""
7F-6 Evidence Graph integrity and adversarial verification tests.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.db.models import (
    EvidenceEdge,
    EvidenceNode,
    Tenant,
)
from app.db.session import async_session
from app.security.authorization import can
from app.security.evidence.verify import (
    verify_evidence_graph,
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
            name="7F-6 Integrity Test",
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
async def test_valid_runtime_evidence_graph_verifies():

    tenant_id = await _create_tenant(
        "7f6-valid"
    )

    try:

        async with async_session() as session:

            await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f6-1",
                threat_category="test",
                action_taken="allowed",
                evaluator_reasoning="one",
            )

        async with async_session() as session:

            await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f6-2",
                threat_category="test",
                action_taken="blocked",
                evaluator_reasoning="two",
            )

        async with async_session() as session:

            result = await verify_evidence_graph(
                session=session,
                tenant_id=tenant_id,
            )

            assert result.valid is True
            assert result.chain_valid is True
            assert result.nodes_checked == 2
            assert result.edges_checked == 1
            assert result.truncated is False
            assert result.issues == []

    finally:

        await _delete_tenant(
            tenant_id
        )


@pytest.mark.asyncio
async def test_tampered_artifact_hash_is_detected():

    tenant_id = await _create_tenant(
        "7f6-artifact"
    )

    try:

        async with async_session() as session:

            await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f6-artifact",
                threat_category="test",
                action_taken="blocked",
                evaluator_reasoning="original",
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
                )
            ).scalar_one()

            node.artifact_hash = (
                "0" * 64
            )

            await session.commit()

        async with async_session() as session:

            result = await verify_evidence_graph(
                session=session,
                tenant_id=tenant_id,
            )

            assert result.valid is False

            assert any(
                issue.code
                == "artifact_hash_mismatch"
                for issue in result.issues
            )

    finally:

        await _delete_tenant(
            tenant_id
        )


@pytest.mark.asyncio
async def test_tampered_edge_relation_is_detected():

    tenant_id = await _create_tenant(
        "7f6-edge"
    )

    try:

        async with async_session() as session:

            await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f6-edge-1",
                threat_category="test",
                action_taken="allowed",
                evaluator_reasoning="one",
            )

        async with async_session() as session:

            await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f6-edge-2",
                threat_category="test",
                action_taken="blocked",
                evaluator_reasoning="two",
            )

        async with async_session() as session:

            edge = (
                await session.execute(
                    select(
                        EvidenceEdge
                    )
                    .where(
                        EvidenceEdge.tenant_id
                        == tenant_id
                    )
                )
            ).scalar_one()

            edge.relation = (
                "forged_relation"
            )

            await session.commit()

        async with async_session() as session:

            result = await verify_evidence_graph(
                session=session,
                tenant_id=tenant_id,
            )

            assert result.valid is False

            assert any(
                issue.code
                == "edge_relation_invalid"
                for issue in result.issues
            )

    finally:

        await _delete_tenant(
            tenant_id
        )


def test_evidence_control_plane_permissions():

    assert can(
        "member",
        "tenant.evidence.read",
    ) is True

    assert can(
        "admin",
        "tenant.evidence.verify",
    ) is True

    assert can(
        "owner",
        "tenant.evidence.export",
    ) is True

    assert can(
        "member",
        "tenant.evidence.verify",
    ) is False

    assert can(
        "member",
        "tenant.evidence.export",
    ) is False