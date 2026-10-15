"""AURAGENT Phase 10 — Investigation Platform API."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db

from app.investigation.contracts import (
    CauseCandidate,
    ExplainabilityView,
    GraphView,
    IncidentView,
    InvestigationLimits,
    ReplayStep,
    SearchHit,
    TimelineItem,
)
from app.investigation.service import InvestigationService

router = APIRouter(
    prefix="/v1/investigation",
    tags=["investigation"],
)


def _tenant_id(request: Request) -> UUID:
    tenant = getattr(request.state, "tenant", None)
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )

    candidate = getattr(tenant, "tenant_id", tenant)
    try:
        return UUID(str(candidate))
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid tenant context",
        ) from exc


def _require_investigator(request: Request) -> None:
    user = getattr(request.state, "user", None)
    role = getattr(user, "role", None)
    normalized = getattr(role, "value", role)
    normalized = str(normalized or "").casefold()
    if normalized not in {"owner", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="investigation access requires owner/admin",
        )


def _limits(
    max_nodes: int = Query(default=250, ge=1, le=1000),
    max_edges: int = Query(default=500, ge=1, le=2000),
    max_depth: int = Query(default=6, ge=0, le=12),
    max_timeline: int = Query(default=500, ge=1, le=1000),
    max_search: int = Query(default=100, ge=1, le=250),
) -> InvestigationLimits:
    return InvestigationLimits(
        max_nodes=max_nodes,
        max_edges=max_edges,
        max_depth=max_depth,
        max_timeline=max_timeline,
        max_search=max_search,
    )


@router.get("/incident/{trace_id}", response_model=IncidentView)
async def get_incident(
    trace_id: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    limits: InvestigationLimits = Depends(_limits),
) -> IncidentView:
    _require_investigator(request)
    return await InvestigationService.incident(
        session,
        tenant_id=_tenant_id(request),
        trace_id=trace_id,
        limits=limits,
    )


@router.get("/graph/{evidence_id}", response_model=GraphView)
async def get_graph(
    evidence_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_db),
    limits: InvestigationLimits = Depends(_limits),
) -> GraphView:
    _require_investigator(request)
    result = await InvestigationService.graph(
        session,
        tenant_id=_tenant_id(request),
        evidence_id=evidence_id,
        limits=limits,
    )
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="evidence not found",
        )
    return result


@router.get("/timeline/{trace_id}", response_model=list[TimelineItem])
async def get_timeline(
    trace_id: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    limits: InvestigationLimits = Depends(_limits),
) -> list[TimelineItem]:
    _require_investigator(request)
    return await InvestigationService.timeline(
        session,
        tenant_id=_tenant_id(request),
        trace_id=trace_id,
        limits=limits,
    )


@router.get("/causes/{trace_id}", response_model=list[CauseCandidate])
async def get_causes(
    trace_id: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    limits: InvestigationLimits = Depends(_limits),
) -> list[CauseCandidate]:
    _require_investigator(request)
    return await InvestigationService.causes(
        session,
        tenant_id=_tenant_id(request),
        trace_id=trace_id,
        limits=limits,
    )


@router.get("/replay/{trace_id}", response_model=list[ReplayStep])
async def get_replay(
    trace_id: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    limits: InvestigationLimits = Depends(_limits),
) -> list[ReplayStep]:
    _require_investigator(request)
    # This endpoint reconstructs history only. It never executes actions.
    return await InvestigationService.replay(
        session,
        tenant_id=_tenant_id(request),
        trace_id=trace_id,
        limits=limits,
    )


@router.get("/explain/{evidence_id}", response_model=ExplainabilityView)
async def explain(
    evidence_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_db),
    limits: InvestigationLimits = Depends(_limits),
) -> ExplainabilityView:
    _require_investigator(request)
    result = await InvestigationService.explain(
        session,
        tenant_id=_tenant_id(request),
        evidence_id=evidence_id,
        limits=limits,
    )
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="evidence not found",
        )
    return result


@router.get("/search", response_model=list[SearchHit])
async def search(
    request: Request,
    q: str = Query(min_length=1, max_length=256),
    trace_id: str | None = Query(default=None, max_length=128),
    node_type: str | None = Query(default=None, max_length=64),
    source: str | None = Query(default=None, max_length=64),
    session: AsyncSession = Depends(get_db),
    limits: InvestigationLimits = Depends(_limits),
) -> list[SearchHit]:
    _require_investigator(request)
    return await InvestigationService.search(
        session,
        tenant_id=_tenant_id(request),
        query=q,
        limits=limits,
        trace_id=trace_id,
        node_type=node_type,
        source=source,
    )
