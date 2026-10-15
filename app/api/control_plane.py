"""AURAGENT Phase 11 — Control Plane API."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.control_plane.contracts import (
    ABACContext, APIKeyView, ConfigPatchRequest, ConfigView,
    OrganizationView, ProjectCreateRequest, ProjectView, UsageSummary,
)
from app.control_plane.service import ControlPlaneService

router = APIRouter(prefix="/v1/control-plane", tags=["control-plane"])


def _tenant_id(request: Request) -> UUID:
    tenant = getattr(request.state, "tenant", None)
    if tenant is None:
        raise HTTPException(status_code=401, detail="tenant context required")
    raw = getattr(tenant, "tenant_id", tenant)
    try:
        return UUID(str(raw))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="invalid tenant context") from exc


def _role(request: Request):
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="authenticated user required")
    role = getattr(user, "role", None)
    if role is None:
        raise HTTPException(status_code=403, detail="user role required")
    return role


def _context(request: Request, resource_type: str, resource_id: str, action: str) -> ABACContext:
    user = getattr(request.state, "user", None)
    principal = getattr(user, "user_id", getattr(user, "id", "unknown"))
    role = getattr(user, "role", None)
    role_value = getattr(role, "value", role)
    return ABACContext(
        organization_id=_tenant_id(request),
        principal_id=str(principal),
        principal_type="user",
        role=str(role_value),
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        attributes={"scope_source": "server"},
    )


@router.get("/organization", response_model=OrganizationView)
async def organization(request: Request, session: AsyncSession = Depends(get_db)):
    result = await ControlPlaneService.organization(
        session, role=_role(request),
        context=_context(request, "organization", "current", "read"),
    )
    if result is None:
        raise HTTPException(status_code=404, detail="organization not found")
    return result


@router.get("/projects", response_model=list[ProjectView])
async def projects(request: Request, session: AsyncSession = Depends(get_db)):
    return await ControlPlaneService.list_projects(
        session, role=_role(request),
        context=_context(request, "project", "collection", "read"),
    )


@router.post("/projects", response_model=ProjectView, status_code=201)
async def create_project(
    body: ProjectCreateRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
):
    try:
        return await ControlPlaneService.create_project(
            session, role=_role(request),
            context=_context(request, "project", body.name, "manage"),
            name=body.name, description=body.description,
        )
    except (ValueError, RuntimeError, LookupError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.delete("/projects/{name}", status_code=204)
async def delete_project(
    name: str, request: Request, session: AsyncSession = Depends(get_db)
):
    try:
        await ControlPlaneService.delete_project(
            session, role=_role(request),
            context=_context(request, "project", name, "manage"),
            project_name=name,
        )
    except (ValueError, RuntimeError, LookupError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/configuration", response_model=ConfigView)
async def configuration(request: Request, session: AsyncSession = Depends(get_db)):
    return await ControlPlaneService.configuration(
        session, role=_role(request),
        context=_context(request, "configuration", "current", "read"),
    )


@router.patch("/configuration", response_model=ConfigView)
async def patch_configuration(
    body: ConfigPatchRequest, request: Request,
    session: AsyncSession = Depends(get_db)
):
    try:
        return await ControlPlaneService.configuration(
            session, role=_role(request),
            context=_context(request, "configuration", "current", "configure"),
            patch=body.values,
        )
    except (ValueError, RuntimeError, LookupError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/api-keys", response_model=list[APIKeyView])
async def api_keys(request: Request, session: AsyncSession = Depends(get_db)):
    return await ControlPlaneService.api_keys(
        session, role=_role(request),
        context=_context(request, "api_key", "inventory", "read"),
    )


@router.get("/usage", response_model=UsageSummary)
async def usage(
    request: Request,
    since: datetime | None = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=5000),
    session: AsyncSession = Depends(get_db),
):
    return await ControlPlaneService.usage(
        session, role=_role(request),
        context=_context(request, "billing", "usage", "read"),
        since=since, limit=limit,
    )
