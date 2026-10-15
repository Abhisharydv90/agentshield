"""AURAGENT Phase 13 — Scale API."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app.scale.contracts import (
    HealthSnapshot,
    RegionDescriptor,
    ShardDescriptor,
)
from app.scale.service import ScaleService


router = APIRouter(prefix="/v1/scale", tags=["scale"])

_service = ScaleService()


class RegionsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    regions: list[RegionDescriptor] = Field(min_length=1)


class HealthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    region: str
    worker_id: str
    active_leases: int = Field(ge=0)
    queue_depth: int = Field(ge=0)
    event_lag: int = Field(ge=0)


def _require_tenant(request: Request) -> None:
    if getattr(request.state, "tenant", None) is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )


def _require_admin(request: Request) -> None:
    _require_tenant(request)
    user = getattr(request.state, "user", None)
    role = getattr(user, "role", None)
    normalized = str(getattr(role, "value", role) or "").casefold()
    if normalized not in {"owner", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="scale administration requires owner/admin",
        )


@router.get("/shard/{tenant_id}", response_model=ShardDescriptor)
async def tenant_shard(
    tenant_id: UUID,
    request: Request,
) -> ShardDescriptor:
    _require_tenant(request)

    current_tenant = getattr(request.state.tenant, "tenant_id", request.state.tenant)
    try:
        current_uuid = UUID(str(current_tenant))
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid tenant context",
        ) from exc

    if current_uuid != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cross-tenant shard inspection is forbidden",
        )

    return _service.shard_tenant(tenant_id)


@router.post("/region/select", response_model=RegionDescriptor)
async def select_region(
    body: RegionsRequest,
    request: Request,
    preferred: str | None = Query(default=None, max_length=64),
) -> RegionDescriptor:
    _require_admin(request)
    try:
        return _service.choose_region(
            body.regions,
            preferred=preferred,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc


@router.post("/health", response_model=HealthSnapshot)
async def health(
    body: HealthRequest,
    request: Request,
) -> HealthSnapshot:
    _require_tenant(request)
    return _service.health(
        region=body.region,
        worker_id=body.worker_id,
        active_leases=body.active_leases,
        queue_depth=body.queue_depth,
        event_lag=body.event_lag,
    )
