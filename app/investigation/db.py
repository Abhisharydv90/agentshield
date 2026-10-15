"""Database adapter for derived Phase 10 investigation views."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import cast, or_, select, Text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import EvidenceEdge, EvidenceNode, SecurityEvent


async def load_trace_nodes(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    trace_id: str,
    limit: int,
) -> list[EvidenceNode]:
    result = await session.execute(
        select(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.trace_id == trace_id,
        )
        .order_by(EvidenceNode.created_at.asc(), EvidenceNode.evidence_id.asc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def load_trace_edges(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    trace_id: str,
    limit: int,
) -> list[EvidenceEdge]:
    result = await session.execute(
        select(EvidenceEdge)
        .where(
            EvidenceEdge.tenant_id == tenant_id,
            EvidenceEdge.trace_id == trace_id,
        )
        .order_by(EvidenceEdge.created_at.asc(), EvidenceEdge.edge_id.asc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def load_node(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    evidence_id: UUID,
) -> EvidenceNode | None:
    result = await session.execute(
        select(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.evidence_id == evidence_id,
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def load_local_edges(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    evidence_ids: Sequence[UUID],
    limit: int,
) -> list[EvidenceEdge]:
    if not evidence_ids:
        return []
    result = await session.execute(
        select(EvidenceEdge)
        .where(
            EvidenceEdge.tenant_id == tenant_id,
            or_(
                EvidenceEdge.from_evidence_id.in_(evidence_ids),
                EvidenceEdge.to_evidence_id.in_(evidence_ids),
            ),
        )
        .order_by(EvidenceEdge.created_at.asc(), EvidenceEdge.edge_id.asc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def load_events(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    event_ids: Sequence[UUID],
    limit: int,
) -> list[SecurityEvent]:
    if not event_ids:
        return []
    result = await session.execute(
        select(SecurityEvent)
        .where(
            SecurityEvent.tenant_id == tenant_id,
            SecurityEvent.event_id.in_(event_ids),
        )
        .order_by(SecurityEvent.timestamp.asc(), SecurityEvent.event_id.asc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def search_traceable_nodes(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    query: str,
    limit: int,
    trace_id: str | None = None,
    node_type: str | None = None,
    source: str | None = None,
) -> list[EvidenceNode]:
    statement = select(EvidenceNode).where(EvidenceNode.tenant_id == tenant_id)
    if trace_id is not None:
        statement = statement.where(EvidenceNode.trace_id == trace_id)
    if node_type is not None:
        statement = statement.where(EvidenceNode.node_type == node_type)
    if source is not None:
        statement = statement.where(EvidenceNode.source == source)

    pattern = f"%{query.strip()}%"
    statement = statement.where(
        or_(
            EvidenceNode.trace_id.ilike(pattern),
            EvidenceNode.node_type.ilike(pattern),
            EvidenceNode.source.ilike(pattern),
            EvidenceNode.artifact_hash.ilike(pattern),
            cast(EvidenceNode.metadata_redacted, Text).ilike(pattern),
        )
    )
    statement = statement.order_by(
        EvidenceNode.created_at.desc(),
        EvidenceNode.evidence_id.desc(),
    ).limit(limit)

    result = await session.execute(statement)
    return list(result.scalars().all())


def to_uuid(value: Any) -> UUID:
    if isinstance(value, UUID):
        return value
    return UUID(str(value))


def node_view(node: EvidenceNode):
    from .contracts import EvidenceNodeView

    return EvidenceNodeView(
        evidence_id=node.evidence_id,
        trace_id=node.trace_id,
        node_type=node.node_type,
        schema_version=node.schema_version,
        artifact_hash=node.artifact_hash,
        source=node.source,
        metadata_redacted=dict(node.metadata_redacted or {}),
        security_event_id=node.security_event_id,
        created_at=node.created_at,
    )


def edge_view(edge: EvidenceEdge):
    from .contracts import EvidenceEdgeView

    return EvidenceEdgeView(
        edge_id=edge.edge_id,
        trace_id=edge.trace_id,
        from_evidence_id=edge.from_evidence_id,
        to_evidence_id=edge.to_evidence_id,
        relation=edge.relation,
        created_at=edge.created_at,
    )
