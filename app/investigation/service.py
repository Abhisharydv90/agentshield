"""Phase 10 Investigation Platform orchestration service."""

from __future__ import annotations

import hashlib
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from .causality import build_cause_candidates, choose_trace_target
from .contracts import (
    CauseCandidate,
    ExplainabilityView,
    GraphView,
    IncidentView,
    InvestigationLimits,
    ReplayStep,
    SearchHit,
    TimelineItem,
)
from .db import (
    edge_view,
    load_events,
    load_local_edges,
    load_node,
    load_trace_edges,
    load_trace_nodes,
    node_view,
    search_traceable_nodes,
)
from .explain import build_explainability
from .graph import bounded_bfs
from .replay import build_forensic_replay
from .search import local_search
from .timeline import build_timeline, event_ids


def build_incident_id(*, tenant_id: UUID, trace_id: str) -> str:
    digest = hashlib.sha256(
        f"{tenant_id}:{trace_id}".encode("utf-8")
    ).hexdigest()
    return f"inc_{digest[:24]}"


def _status(nodes) -> str:
    if not nodes:
        return "not_found"
    suspicious = {
        "blocked",
        "denied",
        "quarantined",
        "security",
        "approval_required",
        "injection",
        "violation",
    }
    if any(
        node.node_type.casefold() in suspicious
        for node in nodes
    ):
        return "investigate"
    return "observed"


class InvestigationService:
    """Read-only derived investigation views over Evidence Fabric data."""

    @staticmethod
    async def incident(
        session: AsyncSession,
        *,
        tenant_id: UUID,
        trace_id: str,
        limits: InvestigationLimits,
    ) -> IncidentView:
        raw_nodes = await load_trace_nodes(
            session,
            tenant_id=tenant_id,
            trace_id=trace_id,
            limit=limits.max_nodes + 1,
        )
        bounded = len(raw_nodes) > limits.max_nodes
        raw_nodes = raw_nodes[:limits.max_nodes]

        raw_edges = await load_trace_edges(
            session,
            tenant_id=tenant_id,
            trace_id=trace_id,
            limit=limits.max_edges + 1,
        )
        bounded = bounded or len(raw_edges) > limits.max_edges
        raw_edges = raw_edges[:limits.max_edges]

        nodes = [node_view(node) for node in raw_nodes]
        edges = [edge_view(edge) for edge in raw_edges]

        ids = event_ids(nodes)
        events = await load_events(
            session,
            tenant_id=tenant_id,
            event_ids=list(ids),
            limit=limits.max_timeline,
        )

        timeline = build_timeline(
            nodes=nodes,
            events=events,
            limit=limits.max_timeline,
        )

        target = choose_trace_target(nodes, edges)
        causes = (
            build_cause_candidates(
                target_evidence_id=target,
                nodes=nodes,
                edges=edges,
                max_candidates=20,
                max_depth=limits.max_depth,
            )
            if target is not None
            else []
        )

        graph = None
        explainability = None
        if target is not None:
            local = bounded_bfs(
                root_evidence_id=target,
                nodes=nodes,
                edges=edges,
                max_depth=limits.max_depth,
                max_nodes=limits.max_nodes,
                max_edges=limits.max_edges,
            )
            if local is not None:
                graph = GraphView(
                    root_evidence_id=target,
                    nodes=local.nodes,
                    edges=local.edges,
                    depth=local.depth,
                    truncated=local.truncated or bounded,
                )
                subject = next(
                    node for node in nodes
                    if node.evidence_id == target
                )
                explainability = build_explainability(
                    subject=subject,
                    nodes=local.nodes,
                    edges=local.edges,
                )

        replay = build_forensic_replay(
            timeline=timeline,
            nodes=nodes,
            edges=edges,
            max_steps=limits.max_timeline,
        )

        first_seen = min((node.created_at for node in nodes), default=None)
        last_seen = max((node.created_at for node in nodes), default=None)

        return IncidentView(
            incident_id=build_incident_id(
                tenant_id=tenant_id,
                trace_id=trace_id,
            ),
            tenant_id=tenant_id,
            trace_id=trace_id,
            status=_status(nodes),
            first_seen=first_seen,
            last_seen=last_seen,
            node_count=len(nodes),
            edge_count=len(edges),
            event_count=len(events),
            root_evidence_id=target,
            timeline=timeline,
            causes=causes,
            graph=graph,
            explainability=explainability,
            forensic_replay=replay,
            bounded=bounded,
            replay_is_executable=False,
        )

    @staticmethod
    async def graph(
        session: AsyncSession,
        *,
        tenant_id: UUID,
        evidence_id: UUID,
        limits: InvestigationLimits,
    ) -> GraphView | None:
        root = await load_node(
            session,
            tenant_id=tenant_id,
            evidence_id=evidence_id,
        )
        if root is None:
            return None

        seed = node_view(root)
        trace_nodes = await load_trace_nodes(
            session,
            tenant_id=tenant_id,
            trace_id=root.trace_id,
            limit=limits.max_nodes * 2,
        )
        nodes = [node_view(node) for node in trace_nodes]
        if seed.evidence_id not in {item.evidence_id for item in nodes}:
            nodes.append(seed)

        edges = [
            edge_view(edge)
            for edge in await load_local_edges(
                session,
                tenant_id=tenant_id,
                evidence_ids=[item.evidence_id for item in nodes],
                limit=limits.max_edges + 1,
            )
        ]

        local = bounded_bfs(
            root_evidence_id=evidence_id,
            nodes=nodes,
            edges=edges,
            max_depth=limits.max_depth,
            max_nodes=limits.max_nodes,
            max_edges=limits.max_edges,
        )
        if local is None:
            return None

        return GraphView(
            root_evidence_id=evidence_id,
            nodes=local.nodes,
            edges=local.edges,
            depth=local.depth,
            truncated=local.truncated,
        )

    @staticmethod
    async def timeline(
        session: AsyncSession,
        *,
        tenant_id: UUID,
        trace_id: str,
        limits: InvestigationLimits,
    ) -> list[TimelineItem]:
        raw_nodes = await load_trace_nodes(
            session,
            tenant_id=tenant_id,
            trace_id=trace_id,
            limit=limits.max_timeline,
        )
        nodes = [node_view(node) for node in raw_nodes]
        ids = list(event_ids(nodes))
        events = await load_events(
            session,
            tenant_id=tenant_id,
            event_ids=ids,
            limit=limits.max_timeline,
        )
        return build_timeline(
            nodes=nodes,
            events=events,
            limit=limits.max_timeline,
        )

    @staticmethod
    async def causes(
        session: AsyncSession,
        *,
        tenant_id: UUID,
        trace_id: str,
        limits: InvestigationLimits,
    ) -> list[CauseCandidate]:
        raw_nodes = await load_trace_nodes(
            session,
            tenant_id=tenant_id,
            trace_id=trace_id,
            limit=limits.max_nodes,
        )
        raw_edges = await load_trace_edges(
            session,
            tenant_id=tenant_id,
            trace_id=trace_id,
            limit=limits.max_edges,
        )
        nodes = [node_view(node) for node in raw_nodes]
        edges = [edge_view(edge) for edge in raw_edges]
        target = choose_trace_target(nodes, edges)
        if target is None:
            return []
        return build_cause_candidates(
            target_evidence_id=target,
            nodes=nodes,
            edges=edges,
            max_candidates=20,
            max_depth=limits.max_depth,
        )

    @staticmethod
    async def replay(
        session: AsyncSession,
        *,
        tenant_id: UUID,
        trace_id: str,
        limits: InvestigationLimits,
    ) -> list[ReplayStep]:
        raw_nodes = await load_trace_nodes(
            session,
            tenant_id=tenant_id,
            trace_id=trace_id,
            limit=limits.max_timeline,
        )
        nodes = [node_view(node) for node in raw_nodes]
        events = await load_events(
            session,
            tenant_id=tenant_id,
            event_ids=list(event_ids(nodes)),
            limit=limits.max_timeline,
        )
        timeline = build_timeline(
            nodes=nodes,
            events=events,
            limit=limits.max_timeline,
        )
        edges = [
            edge_view(edge)
            for edge in await load_trace_edges(
                session,
                tenant_id=tenant_id,
                trace_id=trace_id,
                limit=limits.max_edges,
            )
        ]
        return build_forensic_replay(
            timeline=timeline,
            nodes=nodes,
            edges=edges,
            max_steps=limits.max_timeline,
        )

    @staticmethod
    async def explain(
        session: AsyncSession,
        *,
        tenant_id: UUID,
        evidence_id: UUID,
        limits: InvestigationLimits,
    ) -> ExplainabilityView | None:
        subject = await load_node(
            session,
            tenant_id=tenant_id,
            evidence_id=evidence_id,
        )
        if subject is None:
            return None

        trace_nodes = await load_trace_nodes(
            session,
            tenant_id=tenant_id,
            trace_id=subject.trace_id,
            limit=limits.max_nodes * 2,
        )
        nodes = [node_view(node) for node in trace_nodes]
        edges = [
            edge_view(edge)
            for edge in await load_local_edges(
                session,
                tenant_id=tenant_id,
                evidence_ids=[item.evidence_id for item in nodes],
                limit=limits.max_edges,
            )
        ]
        local = bounded_bfs(
            root_evidence_id=evidence_id,
            nodes=nodes,
            edges=edges,
            max_depth=limits.max_depth,
            max_nodes=limits.max_nodes,
            max_edges=limits.max_edges,
        )
        if local is None:
            return None
        return build_explainability(
            subject=node_view(subject),
            nodes=local.nodes,
            edges=local.edges,
        )

    @staticmethod
    async def search(
        session: AsyncSession,
        *,
        tenant_id: UUID,
        query: str,
        limits: InvestigationLimits,
        trace_id: str | None = None,
        node_type: str | None = None,
        source: str | None = None,
    ) -> list[SearchHit]:
        if not query.strip():
            return []
        raw_nodes = await search_traceable_nodes(
            session,
            tenant_id=tenant_id,
            query=query,
            limit=limits.max_search,
            trace_id=trace_id,
            node_type=node_type,
            source=source,
        )
        nodes = [node_view(node) for node in raw_nodes]
        return local_search(
            nodes=nodes,
            query=query,
            limit=limits.max_search,
            trace_id=trace_id,
            node_type=node_type,
            source=source,
        )
