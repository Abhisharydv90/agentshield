"""AURAGENT Phase 1 deployment control-plane API."""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, model_validator

from app.db.session import async_session
from app.development import service
from app.security.authorization import require_permission


router = APIRouter(prefix="/v1/deployments", tags=["deployments"])


def _context(request: Request, permission: str):
    tenant = getattr(request.state, "tenant", None)
    user = getattr(request.state, "user", None)
    if tenant is None:
        raise HTTPException(status_code=401, detail="no_tenant")
    if user is None or getattr(request.state, "auth_type", None) != "session":
        raise HTTPException(status_code=403, detail="human_session_required")
    if getattr(user, "status", "active") != "active":
        raise HTTPException(status_code=403, detail="user_inactive")
    require_permission(user.role, permission)
    return tenant.tenant_id, user.user_id


def _uuid(value: str, error: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=error) from exc


class DeploymentCreateRequest(BaseModel):
    agent_id: str
    version_id: str
    environment: str = Field(min_length=1, max_length=32)
    region: str = Field(default="local", min_length=1, max_length=64)
    desired_replicas: int = Field(default=1, ge=1, le=100)
    config: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_config(self):
        encoded = json.dumps(self.config, separators=(",", ":"), ensure_ascii=False)
        if len(encoded.encode("utf-8")) > 128 * 1024:
            raise ValueError("deployment_config_too_large")
        return self


@router.get("")
async def list_deployments(request: Request, agent_id: str | None = None):
    tenant_id, _ = _context(request, "tenant.agents.read")
    async with async_session() as session:
        parsed_agent = _uuid(agent_id, "invalid_agent_id") if agent_id else None
        return await service.list_deployments(session, tenant_id, parsed_agent)


@router.post("", status_code=201)
async def create_deployment(body: DeploymentCreateRequest, request: Request):
    tenant_id, user_id = _context(request, "tenant.agents.write")
    async with async_session() as session:
        try:
            return await service.create_deployment(
                session,
                tenant_id=tenant_id,
                user_id=user_id,
                agent_id=_uuid(body.agent_id, "invalid_agent_id"),
                version_id=_uuid(body.version_id, "invalid_version_id"),
                environment=body.environment,
                region=body.region,
                desired_replicas=body.desired_replicas,
                config=body.config,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{deployment_id}/stop")
async def stop_deployment(deployment_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.write")
    async with async_session() as session:
        try:
            return await service.stop_deployment(
                session,
                tenant_id=tenant_id,
                deployment_id=_uuid(deployment_id, "invalid_deployment_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/{deployment_id}")
async def get_deployment(deployment_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.read")
    async with async_session() as session:
        deployment_id_uuid = _uuid(deployment_id, "invalid_deployment_id")
        rows = await service.list_deployments(session, tenant_id)
        for row in rows:
            if row["deployment_id"] == str(deployment_id_uuid):
                return row
        raise HTTPException(status_code=404, detail="deployment_not_found")
