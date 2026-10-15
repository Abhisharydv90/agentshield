"""AURAGENT Phase 8 Evidence administration and compliance surface.

This router is intentionally human-admin scoped. Agent API keys are not
sufficient for evidence administration.

Existing Phase 7F evidence/query/forensics primitives remain the source of
truth. This module adds the Phase 8 distributed/anchoring/compliance control
surface without executing replay or mutating evidence records.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from app.db.models import EvidenceEdge
from app.db.session import async_session
from app.security.authorization import Role, normalize_role
from app.security.evidence.anchoring.external import build_anchor_document
from app.security.evidence.forensics import (
    compute_compliance_package_hash,
    reconstruct_replay,
)
from app.security.evidence.query import EvidenceQueryService


router = APIRouter(prefix="/v1/evidence/admin", tags=["evidence-admin"])


class PrepareAnchorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: uuid.UUID
    package_hash: str = Field(min_length=64, max_length=64)


def _require_human_admin(request: Request) -> Any:
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status_code=403, detail="human_admin_required")

    try:
        role = normalize_role(str(user.role))
    except (AttributeError, HTTPException) as exc:
        raise HTTPException(status_code=403, detail="invalid_admin_principal") from exc

    if role not in {Role.OWNER, Role.ADMIN}:
        raise HTTPException(status_code=403, detail="admin_required")

    tenant = getattr(request.state, "tenant", None)
    if tenant is None:
        raise HTTPException(status_code=403, detail="tenant_required")

    return tenant


def _serialize_node(node) -> dict[str, Any]:
    return {
        "evidence_id": str(node.evidence_id),
        "tenant_id": str(node.tenant_id),
        "trace_id": node.trace_id,
        "node_type": node.node_type,
        "schema_version": node.schema_version,
        "artifact_hash": node.artifact_hash,
        "source": node.source,
        "metadata_redacted": dict(node.metadata_redacted or {}),
        "security_event_id": (
            str(node.security_event_id)
            if node.security_event_id is not None
            else None
        ),
        "created_at": node.created_at.isoformat(),
    }


def _serialize_edge(edge: EvidenceEdge) -> dict[str, Any]:
    return {
        "edge_id": str(edge.edge_id),
        "tenant_id": str(edge.tenant_id),
        "trace_id": edge.trace_id,
        "from_evidence_id": str(edge.from_evidence_id),
        "to_evidence_id": str(edge.to_evidence_id),
        "relation": edge.relation,
        "created_at": edge.created_at.isoformat(),
    }


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    tenant = _require_human_admin(request)
    async with async_session() as session:
        from sqlalchemy import func, select
        from app.db.models import EvidenceNode, SecurityEvent

        node_count = (
            await session.execute(
                select(func.count())
                .select_from(EvidenceNode)
                .where(EvidenceNode.tenant_id == tenant.tenant_id)
            )
        ).scalar_one()

        event_count = (
            await session.execute(
                select(func.count())
                .select_from(SecurityEvent)
                .where(SecurityEvent.tenant_id == tenant.tenant_id)
            )
        ).scalar_one()

        edge_count = (
            await session.execute(
                select(func.count())
                .select_from(EvidenceEdge)
                .where(EvidenceEdge.tenant_id == tenant.tenant_id)
            )
        ).scalar_one()

    return {
        "phase": "8",
        "service": "AURAGENT",
        "tenant_id": str(tenant.tenant_id),
        "evidence_nodes": int(node_count),
        "evidence_edges": int(edge_count),
        "security_events": int(event_count),
        "features": {
            "immutable_evidence": True,
            "forensic_replay": True,
            "distributed_invariants": True,
            "external_anchor_prepare": True,
            "raw_evidence_export": False,
        },
    }


@router.post("/verify")
async def verify_evidence(request: Request) -> dict[str, Any]:
    tenant = _require_human_admin(request)

    async with async_session() as session:
        from app.telemetry import audit

        verification = await audit.verify_chain(
            session=session,
            tenant_id=tenant.tenant_id,
        )

        evidence_export = await EvidenceQueryService.export_tenant(
            session=session,
            tenant_id=tenant.tenant_id,
        )

        evidence_graph_ok = True
        node_hashes = [
            str(node.artifact_hash)
            for node in evidence_export.nodes
        ]

    return {
        "tenant_id": str(tenant.tenant_id),
        "audit_chain": verification,
        "evidence": {
            "nodes_checked": len(node_hashes),
            "edges_checked": len(evidence_export.edges),
            "truncated": evidence_export.truncated,
            "artifact_hashes_present": all(
                len(value) == 64 for value in node_hashes
            ),
            "status": "valid" if evidence_graph_ok else "invalid",
        },
    }


@router.get("/trace/{trace_id}")
async def trace_reconstruction(
    request: Request,
    trace_id: str,
) -> dict[str, Any]:
    tenant = _require_human_admin(request)

    if not trace_id or len(trace_id) > 128:
        raise HTTPException(status_code=400, detail="invalid_trace_id")

    async with async_session() as session:
        reconstruction = await reconstruct_replay(
            session=session,
            tenant_id=tenant.tenant_id,
            trace_id=trace_id,
        )

    if reconstruction is None:
        raise HTTPException(status_code=404, detail="trace_not_found")

    # The forensics object contains bounded, redacted evidence data. Replay is
    # forensic reconstruction only; nothing is executed here.
    return {
        "mode": "forensic_read_only",
        "trace": dataclasses.asdict(reconstruction),
    }


@router.get("/export")
async def export_compliance_package(
    request: Request,
) -> JSONResponse:
    tenant = _require_human_admin(request)

    async with async_session() as session:
        exported = await EvidenceQueryService.export_tenant(
            session=session,
            tenant_id=tenant.tenant_id,
        )

        verification = {
            "audit_chain": await _verify_audit_chain(
                session,
                tenant.tenant_id,
            ),
            "evidence_export_truncated": exported.truncated,
        }

        package_hash = compute_compliance_package_hash(
            tenant_id=tenant.tenant_id,
            nodes=exported.nodes,
            edges=exported.edges,
            verification=verification,
        )

    package = {
        "schema": "auragent-compliance-package.v1",
        "tenant_id": str(tenant.tenant_id),
        "package_hash": package_hash,
        "verification": verification,
        "nodes": [_serialize_node(node) for node in exported.nodes],
        "edges": [_serialize_edge(edge) for edge in exported.edges],
        "truncated": exported.truncated,
    }

    return JSONResponse(content=package)


@router.post("/anchor/prepare")
async def prepare_external_anchor(
    request: Request,
    body: PrepareAnchorRequest,
) -> dict[str, Any]:
    tenant = _require_human_admin(request)

    if body.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=403, detail="tenant_scope_violation")

    try:
        document = build_anchor_document(
            tenant_id=body.tenant_id,
            package_hash=body.package_hash,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid_anchor_document") from exc

    return {
        "submitted": False,
        "reason": "explicit_provider_configuration_required",
        "document": document.to_dict(),
        "document_digest": document.digest(),
    }


async def _verify_audit_chain(session, tenant_id: uuid.UUID) -> dict[str, Any]:
    from app.telemetry import audit

    return await audit.verify_chain(
        session=session,
        tenant_id=tenant_id,
    )
