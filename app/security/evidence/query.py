"""
Evidence Graph query service.

Security and scale properties:

- every query requires an explicit tenant_id
- cursor pagination uses created_at + evidence_id
- no OFFSET pagination
- graph traversal is bounded by depth/node/edge limits
- graph expansion is tenant-scoped
- evidence responses expose only redacted metadata

7J scaling boundary:
    keyset pagination + bounded graph traversal + bounded export.
"""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import EvidenceEdge, EvidenceNode
from app.security.evidence.limits import (
    DEFAULT_GRAPH_DEPTH,
    DEFAULT_GRAPH_NODES,
    DEFAULT_PAGE_SIZE,
    MAX_CURSOR_LENGTH,
    MAX_EXPORT_EDGES,
    MAX_EXPORT_NODES,
    MAX_GRAPH_EDGES,
    MAX_GRAPH_NODES,
    MAX_GRAPH_DEPTH,
    MAX_PAGE_SIZE,
)


# ============================================================
# Cursor
# ============================================================


@dataclass(frozen=True)
class EvidenceCursor:
    created_at: datetime
    evidence_id: uuid.UUID


def encode_cursor(
    *,
    created_at: datetime,
    evidence_id: uuid.UUID,
) -> str:
    """
    Encode a keyset pagination position.

    The cursor is opaque query state. It contains no authorization
    material and does not grant access to another tenant.
    """

    if created_at.tzinfo is None:
        created_at = created_at.replace(
            tzinfo=timezone.utc
        )
    else:
        created_at = created_at.astimezone(
            timezone.utc
        )

    payload = {
        "created_at": created_at.isoformat(),
        "evidence_id": str(evidence_id),
    }

    raw = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    return (
        base64.urlsafe_b64encode(raw)
        .decode("ascii")
        .rstrip("=")
    )


def decode_cursor(
    value: str,
) -> EvidenceCursor:
    """
    Decode and validate a cursor.

    Invalid cursors fail closed.
    """

    if not value:
        raise ValueError(
            "evidence_cursor_empty"
        )

    if len(value) > MAX_CURSOR_LENGTH:
        raise ValueError(
            "evidence_cursor_too_long"
        )

    padding = "=" * (
        (-len(value)) % 4
    )

    try:
        raw = base64.urlsafe_b64decode(
            (
                value + padding
            ).encode("ascii")
        )

        payload = json.loads(
            raw.decode("utf-8")
        )

        created_at = datetime.fromisoformat(
            str(
                payload[
                    "created_at"
                ]
            )
        )

        if created_at.tzinfo is None:
            created_at = created_at.replace(
                tzinfo=timezone.utc
            )
        else:
            created_at = created_at.astimezone(
                timezone.utc
            )

        evidence_id = uuid.UUID(
            str(
                payload[
                    "evidence_id"
                ]
            )
        )

        return EvidenceCursor(
            created_at=created_at,
            evidence_id=evidence_id,
        )

    except (
        ValueError,
        KeyError,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:

        raise ValueError(
            "evidence_cursor_invalid"
        ) from exc


# ============================================================
# Filters
# ============================================================


@dataclass(frozen=True)
class EvidenceFilters:
    trace_id: str | None = None
    node_type: str | None = None
    source: str | None = None
    artifact_hash: str | None = None
    security_event_id: uuid.UUID | None = None
    created_after: datetime | None = None
    created_before: datetime | None = None
    page_size: int = DEFAULT_PAGE_SIZE
    cursor: str | None = None


@dataclass(frozen=True)
class EvidencePage:
    nodes: list[EvidenceNode]
    next_cursor: str | None
    has_more: bool


@dataclass(frozen=True)
class EvidenceGraph:
    root: EvidenceNode
    nodes: list[EvidenceNode]
    edges: list[EvidenceEdge]
    truncated: bool


@dataclass(frozen=True)
class EvidenceExport:
    nodes: list[EvidenceNode]
    edges: list[EvidenceEdge]
    truncated: bool


# ============================================================
# Datetime normalization
# ============================================================


def _normalize_datetime(
    value: datetime | None,
) -> datetime | None:

    if value is None:
        return None

    if value.tzinfo is None:

        return value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(
        timezone.utc
    )


# ============================================================
# Filter application
# ============================================================


def _apply_filters(
    stmt,
    *,
    tenant_id: uuid.UUID,
    filters: EvidenceFilters,
):
    """
    Apply all evidence filters.

    Tenant isolation is always applied first.
    """

    stmt = stmt.where(
        EvidenceNode.tenant_id
        == tenant_id
    )

    if filters.trace_id is not None:

        stmt = stmt.where(
            EvidenceNode.trace_id
            == filters.trace_id
        )

    if filters.node_type is not None:

        stmt = stmt.where(
            EvidenceNode.node_type
            == filters.node_type
        )

    if filters.source is not None:

        stmt = stmt.where(
            EvidenceNode.source
            == filters.source
        )

    if filters.artifact_hash is not None:

        stmt = stmt.where(
            EvidenceNode.artifact_hash
            == filters.artifact_hash
        )

    if filters.security_event_id is not None:

        stmt = stmt.where(
            EvidenceNode.security_event_id
            == filters.security_event_id
        )

    created_after = _normalize_datetime(
        filters.created_after
    )

    created_before = _normalize_datetime(
        filters.created_before
    )

    if created_after is not None:

        stmt = stmt.where(
            EvidenceNode.created_at
            >= created_after
        )

    if created_before is not None:

        stmt = stmt.where(
            EvidenceNode.created_at
            <= created_before
        )

    return stmt


# ============================================================
# Query service
# ============================================================


class EvidenceQueryService:
    """
    Read-only Evidence Graph access.

    Every method requires an explicit tenant_id.

    This service intentionally does not expose raw SecurityEvent
    evaluator reasoning. The API layer serializes EvidenceNode
    metadata only.
    """

    # ========================================================
    # List nodes
    # ========================================================

    @staticmethod
    async def list_nodes(
        *,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        filters: EvidenceFilters,
    ) -> EvidencePage:

        page_size = min(
            max(
                int(
                    filters.page_size
                ),
                1,
            ),
            MAX_PAGE_SIZE,
        )

        stmt = select(
            EvidenceNode
        )

        stmt = _apply_filters(
            stmt,
            tenant_id=tenant_id,
            filters=filters,
        )

        # ----------------------------------------------------
        # Keyset pagination
        # ----------------------------------------------------

        if filters.cursor:

            cursor = decode_cursor(
                filters.cursor
            )

            stmt = stmt.where(
                or_(
                    EvidenceNode.created_at
                    < cursor.created_at,

                    (
                        EvidenceNode.created_at
                        == cursor.created_at
                    )
                    & (
                        EvidenceNode.evidence_id
                        < cursor.evidence_id
                    ),
                )
            )

        stmt = (
            stmt
            .order_by(
                EvidenceNode.created_at.desc(),
                EvidenceNode.evidence_id.desc(),
            )
            .limit(
                page_size + 1
            )
        )

        rows = (
            await session.execute(
                stmt
            )
        ).scalars().all()

        has_more = (
            len(rows)
            > page_size
        )

        nodes = rows[
            :page_size
        ]

        next_cursor = None

        if has_more and nodes:

            last = nodes[-1]

            next_cursor = encode_cursor(
                created_at=
                    last.created_at,
                evidence_id=
                    last.evidence_id,
            )

        return EvidencePage(
            nodes=nodes,
            next_cursor=next_cursor,
            has_more=has_more,
        )

    # ========================================================
    # Get single node
    # ========================================================

    @staticmethod
    async def get_node(
        *,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        evidence_id: uuid.UUID,
    ) -> EvidenceNode | None:

        stmt = (
            select(
                EvidenceNode
            )
            .where(
                EvidenceNode.tenant_id
                == tenant_id
            )
            .where(
                EvidenceNode.evidence_id
                == evidence_id
            )
            .limit(1)
        )

        return (
            await session.execute(
                stmt
            )
        ).scalar_one_or_none()

    # ========================================================
    # Bounded graph traversal
    # ========================================================

    @staticmethod
    async def get_graph(
        *,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        evidence_id: uuid.UUID,
        depth: int = DEFAULT_GRAPH_DEPTH,
        max_nodes: int = DEFAULT_GRAPH_NODES,
    ) -> EvidenceGraph | None:
        """
        Traverse the local Evidence Graph around one root node.

        Important truncation rule:

        `truncated=True` means something was actually omitted because
        the node/edge bounds were exceeded.

        Merely reaching max_nodes exactly does NOT imply truncation.
        """

        depth = min(
            max(
                int(depth),
                0,
            ),
            MAX_GRAPH_DEPTH,
        )

        max_nodes = min(
            max(
                int(max_nodes),
                1,
            ),
            MAX_GRAPH_NODES,
        )

        # ----------------------------------------------------
        # Resolve root
        # ----------------------------------------------------

        root = await EvidenceQueryService.get_node(
            session=session,
            tenant_id=tenant_id,
            evidence_id=evidence_id,
        )

        if root is None:
            return None

        # ----------------------------------------------------
        # Traversal state
        # ----------------------------------------------------

        visited: set[
            uuid.UUID
        ] = {
            root.evidence_id
        }

        frontier: set[
            uuid.UUID
        ] = {
            root.evidence_id
        }

        collected_edges: dict[
            uuid.UUID,
            EvidenceEdge,
        ] = {}

        truncated = False

        # ----------------------------------------------------
        # BFS traversal
        # ----------------------------------------------------

        for _level in range(
            depth
        ):

            if not frontier:
                break

            frontier_list = list(
                frontier
            )

            # ------------------------------------------------
            # Fetch incident edges.
            #
            # The query is tenant scoped and bounded.
            # ------------------------------------------------

            stmt = (
                select(
                    EvidenceEdge
                )
                .where(
                    EvidenceEdge.tenant_id
                    == tenant_id
                )
                .where(
                    or_(
                        EvidenceEdge.from_evidence_id.in_(
                            frontier_list
                        ),
                        EvidenceEdge.to_evidence_id.in_(
                            frontier_list
                        ),
                    )
                )
                .order_by(
                    EvidenceEdge.created_at.asc(),
                    EvidenceEdge.edge_id.asc(),
                )
                .limit(
                    MAX_GRAPH_EDGES + 1
                )
            )

            edges = (
                await session.execute(
                    stmt
                )
            ).scalars().all()

            # ------------------------------------------------
            # Detect edge-level bounding.
            #
            # We deliberately request one extra row so we can
            # distinguish "exactly at limit" from "more existed".
            # ------------------------------------------------

            if (
                len(edges)
                > MAX_GRAPH_EDGES
            ):

                truncated = True

                edges = edges[
                    :MAX_GRAPH_EDGES
                ]

            next_frontier: set[
                uuid.UUID
            ] = set()

            # ------------------------------------------------
            # Collect edges and candidate nodes.
            # ------------------------------------------------

            for edge in edges:

                if (
                    edge.edge_id
                    not in collected_edges
                ):

                    collected_edges[
                        edge.edge_id
                    ] = edge

                candidates = (
                    edge.from_evidence_id,
                    edge.to_evidence_id,
                )

                for candidate in candidates:

                    if candidate in visited:
                        continue

                    if candidate in next_frontier:
                        continue

                    # ----------------------------------------
                    # Node budget.
                    #
                    # If a candidate cannot fit, it is actually
                    # omitted, therefore truncation is real.
                    # ----------------------------------------

                    projected_size = (
                        len(visited)
                        + len(next_frontier)
                        + 1
                    )

                    if (
                        projected_size
                        > max_nodes
                    ):

                        truncated = True

                        continue

                    next_frontier.add(
                        candidate
                    )

            # ------------------------------------------------
            # Advance frontier.
            # ------------------------------------------------

            visited.update(
                next_frontier
            )

            frontier = (
                next_frontier
            )

            # ------------------------------------------------
            # IMPORTANT:
            #
            # Do NOT mark truncation merely because:
            #
            #     len(visited) == max_nodes
            #
            # Exactly filling the bound is a successful,
            # complete result for the requested traversal.
            # ------------------------------------------------

            if not frontier:
                break

        # ====================================================
        # Resolve nodes
        # ====================================================

        node_ids = list(
            visited
        )

        node_result = await session.execute(
            select(
                EvidenceNode
            )
            .where(
                EvidenceNode.tenant_id
                == tenant_id
            )
            .where(
                EvidenceNode.evidence_id.in_(
                    node_ids
                )
            )
            .order_by(
                EvidenceNode.created_at.asc(),
                EvidenceNode.evidence_id.asc(),
            )
        )

        nodes = (
            node_result
            .scalars()
            .all()
        )

        # ====================================================
        # Final edge ordering
        # ====================================================

        edge_list = sorted(
            collected_edges.values(),
            key=lambda edge: (
                edge.created_at,
                edge.edge_id,
            ),
        )

        # Defensive final bound.
        #
        # Normally the +1 query handling above already guarantees
        # this limit, but keep the invariant explicit.
        if (
            len(edge_list)
            > MAX_GRAPH_EDGES
        ):

            edge_list = edge_list[
                :MAX_GRAPH_EDGES
            ]

            truncated = True

        # ====================================================
        # Return
        # ====================================================

        return EvidenceGraph(
            root=root,
            nodes=nodes,
            edges=edge_list,
            truncated=truncated,
        )

    # ========================================================
    # Tenant export
    # ========================================================

    @staticmethod
    async def export_tenant(
        *,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        max_nodes: int = MAX_EXPORT_NODES,
        max_edges: int = MAX_EXPORT_EDGES,
    ) -> EvidenceExport:

        max_nodes = min(
            max(
                int(max_nodes),
                1,
            ),
            MAX_EXPORT_NODES,
        )

        max_edges = min(
            max(
                int(max_edges),
                1,
            ),
            MAX_EXPORT_EDGES,
        )

        # ----------------------------------------------------
        # Nodes
        # ----------------------------------------------------

        node_rows = (
            await session.execute(
                select(
                    EvidenceNode
                )
                .where(
                    EvidenceNode.tenant_id
                    == tenant_id
                )
                .order_by(
                    EvidenceNode.created_at.asc(),
                    EvidenceNode.evidence_id.asc(),
                )
                .limit(
                    max_nodes + 1
                )
            )
        ).scalars().all()

        truncated = (
            len(node_rows)
            > max_nodes
        )

        nodes = node_rows[
            :max_nodes
        ]

        node_ids = {
            node.evidence_id
            for node in nodes
        }

        # ----------------------------------------------------
        # Edges
        # ----------------------------------------------------

        edge_rows = (
            await session.execute(
                select(
                    EvidenceEdge
                )
                .where(
                    EvidenceEdge.tenant_id
                    == tenant_id
                )
                .order_by(
                    EvidenceEdge.created_at.asc(),
                    EvidenceEdge.edge_id.asc(),
                )
                .limit(
                    max_edges + 1
                )
            )
        ).scalars().all()

        if (
            len(edge_rows)
            > max_edges
        ):

            truncated = True

        edges = [
            edge
            for edge in edge_rows[
                :max_edges
            ]
            if (
                edge.from_evidence_id
                in node_ids
                and edge.to_evidence_id
                in node_ids
            )
        ]

        return EvidenceExport(
            nodes=nodes,
            edges=edges,
            truncated=truncated,
        )