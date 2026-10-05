"""
Evidence Graph API.

Endpoints:

GET /api/evidence/nodes
GET /api/evidence/nodes/{evidence_id}
GET /api/evidence/graph/{evidence_id}
GET /api/evidence/verify
GET /api/evidence/summary
GET /api/evidence/export

Security:

- browser session required
- tenant comes only from AuthMiddleware
- RBAC enforced
- all DB queries are tenant-scoped
- evaluator reasoning is never exposed
- bounded pagination/traversal/export
- responses are never cached
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
    Request,
    Response,
)
from sqlalchemy import func, select

from app.db.models import (
    EvidenceEdge,
    EvidenceNode,
)
from app.db.session import async_session
from app.security.authorization import (
    require_permission,
)
from app.security.evidence.contracts import (
    EvidenceEdgeResponse,
    EvidenceExportResponse,
    EvidenceGraphResponse,
    EvidenceNodeResponse,
    EvidencePageResponse,
    EvidenceSummaryResponse,
    EvidenceVerificationResponse,
)
from app.security.evidence.limits import (
    DEFAULT_GRAPH_DEPTH,
    DEFAULT_GRAPH_NODES,
    DEFAULT_PAGE_SIZE,
    MAX_CURSOR_LENGTH,
    MAX_GRAPH_DEPTH,
    MAX_GRAPH_NODES,
    MAX_TRACE_ID_LENGTH,
    MAX_NODE_TYPE_LENGTH,
    MAX_SOURCE_LENGTH,
    MAX_EXPORT_NODES,
)
from app.security.evidence.query import (
    EvidenceFilters,
    EvidenceQueryService,
)
from app.security.evidence.verify import (
    verify_evidence_graph,
)


router = APIRouter(
    prefix="/evidence",
    tags=["evidence"],
)


# ============================================================
# Auth / RBAC
# ============================================================


def _require_evidence_access(
    request: Request,
    permission: str,
):
    tenant = getattr(
        request.state,
        "tenant",
        None,
    )

    user = getattr(
        request.state,
        "user",
        None,
    )

    if tenant is None:
        raise HTTPException(
            status_code=401,
            detail="no_tenant",
        )

    # Evidence investigation is a human control-plane operation.
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="human_session_required",
        )

    require_permission(
        user.role,
        permission,
    )

    return tenant


def _no_store(
    response: Response,
) -> None:
    response.headers[
        "Cache-Control"
    ] = "no-store, max-age=0"

    response.headers[
        "Pragma"
    ] = "no-cache"


# ============================================================
# Serialization
# ============================================================


def _node_response(
    node: EvidenceNode,
) -> dict[str, Any]:

    return {
        "evidence_id":
            node.evidence_id,

        "tenant_id":
            node.tenant_id,

        "trace_id":
            node.trace_id,

        "node_type":
            node.node_type,

        "schema_version":
            node.schema_version,

        "artifact_hash":
            node.artifact_hash,

        "source":
            node.source,

        "metadata_redacted":
            dict(
                node.metadata_redacted
                or {}
            ),

        "security_event_id":
            node.security_event_id,

        "created_at":
            node.created_at.isoformat(),
    }


def _edge_response(
    edge: EvidenceEdge,
) -> dict[str, Any]:

    return {
        "edge_id":
            edge.edge_id,

        "tenant_id":
            edge.tenant_id,

        "trace_id":
            edge.trace_id,

        "from_evidence_id":
            edge.from_evidence_id,

        "to_evidence_id":
            edge.to_evidence_id,

        "relation":
            edge.relation,

        "created_at":
            edge.created_at.isoformat(),
    }


# ============================================================
# Nodes
# ============================================================


@router.get(
    "/nodes",
    response_model=EvidencePageResponse,
)
async def list_evidence_nodes(
    request: Request,
    response: Response,
    trace_id: str | None = Query(
        default=None,
        max_length=MAX_TRACE_ID_LENGTH,
    ),
    node_type: str | None = Query(
        default=None,
        max_length=MAX_NODE_TYPE_LENGTH,
    ),
    source: str | None = Query(
        default=None,
        max_length=MAX_SOURCE_LENGTH,
    ),
    artifact_hash: str | None = Query(
        default=None,
        min_length=64,
        max_length=64,
    ),
    security_event_id: str | None = Query(
        default=None,
        max_length=36,
    ),
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    page_size: int = Query(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=200,
    ),
    cursor: str | None = Query(
        default=None,
        max_length=MAX_CURSOR_LENGTH,
    ),
):

    tenant = _require_evidence_access(
        request,
        "tenant.evidence.read",
    )

    parsed_event_id = None

    if security_event_id:
        try:
            parsed_event_id = uuid.UUID(
                security_event_id
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail="invalid_security_event_id",
            ) from exc

    filters = EvidenceFilters(
        trace_id=trace_id,
        node_type=node_type,
        source=source,
        artifact_hash=artifact_hash,
        security_event_id=parsed_event_id,
        created_after=created_after,
        created_before=created_before,
        page_size=page_size,
        cursor=cursor,
    )

    async with async_session() as session:

        page = (
            await EvidenceQueryService.list_nodes(
                session=session,
                tenant_id=tenant.tenant_id,
                filters=filters,
            )
        )

    _no_store(response)

    return {
        "nodes": [
            _node_response(
                node
            )
            for node in page.nodes
        ],
        "next_cursor":
            page.next_cursor,
        "has_more":
            page.has_more,
    }


# ============================================================
# Single node
# ============================================================


@router.get(
    "/nodes/{evidence_id}",
    response_model=EvidenceNodeResponse,
)
async def get_evidence_node(
    evidence_id: str,
    request: Request,
    response: Response,
):

    tenant = _require_evidence_access(
        request,
        "tenant.evidence.read",
    )

    try:
        parsed_id = uuid.UUID(
            evidence_id
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="invalid_evidence_id",
        ) from exc

    async with async_session() as session:

        node = (
            await EvidenceQueryService.get_node(
                session=session,
                tenant_id=tenant.tenant_id,
                evidence_id=parsed_id,
            )
        )

    if node is None:
        raise HTTPException(
            status_code=404,
            detail="evidence_not_found",
        )

    _no_store(response)

    return _node_response(
        node
    )


# ============================================================
# Graph traversal
# ============================================================


@router.get(
    "/graph/{evidence_id}",
    response_model=EvidenceGraphResponse,
)
async def get_evidence_graph(
    evidence_id: str,
    request: Request,
    response: Response,
    depth: int = Query(
        default=DEFAULT_GRAPH_DEPTH,
        ge=0,
        le=MAX_GRAPH_DEPTH,
    ),
    limit: int = Query(
        default=DEFAULT_GRAPH_NODES,
        ge=1,
        le=MAX_GRAPH_NODES,
    ),
):

    tenant = _require_evidence_access(
        request,
        "tenant.evidence.read",
    )

    try:
        parsed_id = uuid.UUID(
            evidence_id
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="invalid_evidence_id",
        ) from exc

    async with async_session() as session:

        graph = (
            await EvidenceQueryService.get_graph(
                session=session,
                tenant_id=tenant.tenant_id,
                evidence_id=parsed_id,
                depth=depth,
                max_nodes=limit,
            )
        )

    if graph is None:
        raise HTTPException(
            status_code=404,
            detail="evidence_not_found",
        )

    _no_store(response)

    return {
        "root_evidence_id":
            graph.root.evidence_id,

        "nodes": [
            _node_response(
                node
            )
            for node in graph.nodes
        ],

        "edges": [
            _edge_response(
                edge
            )
            for edge in graph.edges
        ],

        "truncated":
            graph.truncated,
    }


# ============================================================
# Verification
# ============================================================


@router.get(
    "/verify",
    response_model=EvidenceVerificationResponse,
)
async def verify_evidence(
    request: Request,
    response: Response,
):

    tenant = _require_evidence_access(
        request,
        "tenant.evidence.verify",
    )

    async with async_session() as session:

        result = await verify_evidence_graph(
            session=session,
            tenant_id=tenant.tenant_id,
        )

    _no_store(response)

    output = result.to_dict()

    output["verified_at"] = (
        datetime.now(
            timezone.utc
        ).isoformat()
    )

    return output


# ============================================================
# Summary
# ============================================================


@router.get(
    "/summary",
    response_model=EvidenceSummaryResponse,
)
async def evidence_summary(
    request: Request,
    response: Response,
):

    tenant = _require_evidence_access(
        request,
        "tenant.evidence.read",
    )

    async with async_session() as session:

        node_count = await session.scalar(
            select(
                func.count()
            )
            .select_from(
                EvidenceNode
            )
            .where(
                EvidenceNode.tenant_id
                == tenant.tenant_id
            )
        )

        edge_count = await session.scalar(
            select(
                func.count()
            )
            .select_from(
                EvidenceEdge
            )
            .where(
                EvidenceEdge.tenant_id
                == tenant.tenant_id
            )
        )

    _no_store(response)

    return {
        "tenant":
            tenant.slug,

        "node_count":
            int(
                node_count or 0
            ),

        "edge_count":
            int(
                edge_count or 0
            ),
    }


# ============================================================
# Compliance export
# ============================================================


@router.get(
    "/export",
    response_model=EvidenceExportResponse,
)
async def export_evidence(
    request: Request,
    response: Response,
    max_nodes: int = Query(
        default=1000,
        ge=1,
        le=MAX_EXPORT_NODES,
    ),
):

    tenant = _require_evidence_access(
        request,
        "tenant.evidence.export",
    )

    async with async_session() as session:

        exported = (
            await EvidenceQueryService.export_tenant(
                session=session,
                tenant_id=tenant.tenant_id,
                max_nodes=max_nodes,
            )
        )

        verification = (
            await verify_evidence_graph(
                session=session,
                tenant_id=tenant.tenant_id,
            )
        )

    _no_store(response)

    verification_payload = (
        verification.to_dict()
    )

    verification_payload[
        "verified_at"
    ] = (
        datetime.now(
            timezone.utc
        ).isoformat()
    )

    return {
        "schema_version":
            "7.0",

        "exported_at":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "tenant":
            tenant.slug,

        "truncated":
            exported.truncated,

        "verification":
            verification_payload,

        "nodes": [
            _node_response(
                node
            )
            for node in exported.nodes
        ],

        "edges": [
            _edge_response(
                edge
            )
            for edge in exported.edges
        ],

        "privacy": {
            "evaluator_reasoning":
                "excluded",
            "raw_secrets":
                "excluded",
            "payload_bodies":
                "excluded",
        },
    }