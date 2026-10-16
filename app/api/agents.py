"""AURAGENT Phase 1 — Agent Development & Management API."""

from __future__ import annotations

import json
import uuid
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.development import service
from app.security.authorization import require_permission
from app.security.capabilities import Capability, normalize_capabilities


router = APIRouter(prefix="/v1/agents", tags=["agents"])


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


class AgentCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    capabilities: list[str] = Field(
        default_factory=lambda: [Capability.AGENT_INVOKE.value],
        min_length=1,
        max_length=32,
    )
    manifest: dict[str, Any] = Field(default_factory=dict)
    api_key_id: str | None = None
    version: str = Field(default="1.0.0", max_length=32)

    @model_validator(mode="after")
    def validate_input(self):
        encoded = json.dumps(self.manifest, separators=(",", ":"), ensure_ascii=False)
        if len(encoded.encode("utf-8")) > 256 * 1024:
            raise ValueError("agent_manifest_too_large")
        normalized = normalize_capabilities(self.capabilities)
        if Capability.AGENT_INVOKE.value not in normalized:
            raise ValueError("agent_invoke_capability_required")
        self.capabilities = normalized
        return self


class AgentPatchRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    api_key_id: str | None = None


class LifecycleRequest(BaseModel):
    status: Literal["active", "suspended", "revoked"]


class VersionCreateRequest(BaseModel):
    version: str = Field(min_length=1, max_length=32)
    description: str = Field(default="", max_length=500)
    capabilities: list[str] = Field(min_length=1, max_length=32)
    manifest: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_input(self):
        normalize_capabilities(self.capabilities)
        encoded = json.dumps(self.manifest, separators=(",", ":"), ensure_ascii=False)
        if len(encoded.encode("utf-8")) > 256 * 1024:
            raise ValueError("agent_manifest_too_large")
        return self


class MemberRequest(BaseModel):
    user_id: str
    role: Literal["viewer", "operator", "manager"] = "viewer"


class TemplateCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    version: str = Field(default="1.0.0", max_length=32)
    capabilities: list[str] = Field(
        default_factory=lambda: [Capability.AGENT_INVOKE.value],
        min_length=1,
        max_length=32,
    )
    manifest: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_input(self):
        self.capabilities = normalize_capabilities(self.capabilities)
        encoded = json.dumps(self.manifest, separators=(",", ":"), ensure_ascii=False)
        if len(encoded.encode("utf-8")) > 256 * 1024:
            raise ValueError("template_manifest_too_large")
        if Capability.AGENT_INVOKE.value not in self.capabilities:
            raise ValueError("agent_invoke_capability_required")
        return self


class TemplateAgentRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    api_key_id: str | None = None


@router.get("")
async def list_agents(request: Request):
    tenant_id, _ = _context(request, "tenant.agents.read")
    from app.db.session import async_session
    async with async_session() as session:
        return await service.list_agents(session, tenant_id)


@router.post("", status_code=201)
async def create_agent(body: AgentCreateRequest, request: Request):
    tenant_id, user_id = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.create_agent(
                session,
                tenant_id=tenant_id,
                user_id=user_id,
                name=body.name,
                description=body.description,
                capabilities=body.capabilities,
                manifest=body.manifest,
                api_key_id=body.api_key_id,
                initial_version=body.version,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc



@router.get("/{agent_id}")
async def get_agent(agent_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.read")
    from app.db.session import async_session
    async with async_session() as session:
        row = await service.get_agent(session, tenant_id, _uuid(agent_id, "invalid_agent_id"))
        if row is None:
            raise HTTPException(status_code=404, detail="agent_not_found")
        return service.agent_view(row)


@router.patch("/{agent_id}")
async def patch_agent(agent_id: str, body: AgentPatchRequest, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.update_agent(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                name=body.name,
                description=body.description,
                api_key_id=body.api_key_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(agent_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.delete")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            await service.delete_agent(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{agent_id}/lifecycle")
async def lifecycle(agent_id: str, body: LifecycleRequest, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.transition_agent(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                status=body.status,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except HTTPException:
            raise
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{agent_id}/versions")
async def versions(agent_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.read")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.list_versions(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{agent_id}/versions", status_code=201)
async def create_version(agent_id: str, body: VersionCreateRequest, request: Request):
    tenant_id, user_id = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.create_version(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                user_id=user_id,
                version=body.version,
                description=body.description,
                capabilities=body.capabilities,
                manifest=body.manifest,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{agent_id}/versions/{version_id}/publish")
async def publish_version(agent_id: str, version_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.publish_version(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                version_id=_uuid(version_id, "invalid_version_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{agent_id}/versions/{version_id}/revoke")
async def revoke_version(agent_id: str, version_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.revoke_version(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                version_id=_uuid(version_id, "invalid_version_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/{agent_id}/members")
async def members(agent_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.read")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.list_members(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{agent_id}/members", status_code=201)
async def add_member(agent_id: str, body: MemberRequest, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.add_member(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                user_id=_uuid(body.user_id, "invalid_user_id"),
                role=body.role,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/{agent_id}/members/{user_id}", status_code=204)
async def remove_member(agent_id: str, user_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            await service.remove_member(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                user_id=_uuid(user_id, "invalid_user_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc




@router.get("/{agent_id}")
async def get_agent(agent_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.read")
    from app.db.session import async_session
    async with async_session() as session:
        row = await service.get_agent(session, tenant_id, _uuid(agent_id, "invalid_agent_id"))
        if row is None:
            raise HTTPException(status_code=404, detail="agent_not_found")
        return service.agent_view(row)


@router.patch("/{agent_id}")
async def patch_agent(agent_id: str, body: AgentPatchRequest, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.update_agent(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                name=body.name,
                description=body.description,
                api_key_id=body.api_key_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(agent_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.delete")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            await service.delete_agent(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{agent_id}/lifecycle")
async def lifecycle(agent_id: str, body: LifecycleRequest, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.transition_agent(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                status=body.status,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except HTTPException:
            raise
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{agent_id}/versions")
async def versions(agent_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.read")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.list_versions(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{agent_id}/versions", status_code=201)
async def create_version(agent_id: str, body: VersionCreateRequest, request: Request):
    tenant_id, user_id = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.create_version(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                user_id=user_id,
                version=body.version,
                description=body.description,
                capabilities=body.capabilities,
                manifest=body.manifest,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{agent_id}/versions/{version_id}/publish")
async def publish_version(agent_id: str, version_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.publish_version(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                version_id=_uuid(version_id, "invalid_version_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{agent_id}/versions/{version_id}/revoke")
async def revoke_version(agent_id: str, version_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.revoke_version(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                version_id=_uuid(version_id, "invalid_version_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/{agent_id}/members")
async def members(agent_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.read")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.list_members(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{agent_id}/members", status_code=201)
async def add_member(agent_id: str, body: MemberRequest, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.add_member(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                user_id=_uuid(body.user_id, "invalid_user_id"),
                role=body.role,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/{agent_id}/members/{user_id}", status_code=204)
async def remove_member(agent_id: str, user_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            await service.remove_member(
                session,
                tenant_id=tenant_id,
                agent_id=_uuid(agent_id, "invalid_agent_id"),
                user_id=_uuid(user_id, "invalid_user_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/templates")
async def templates(request: Request):
    tenant_id, _ = _context(request, "tenant.agents.read")
    from app.db.session import async_session
    async with async_session() as session:
        return await service.list_templates(session, tenant_id)


@router.post("/templates", status_code=201)
async def create_template(body: TemplateCreateRequest, request: Request):
    tenant_id, user_id = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.create_template(
                session,
                tenant_id=tenant_id,
                user_id=user_id,
                name=body.name,
                description=body.description,
                version=body.version,
                capabilities=body.capabilities,
                manifest=body.manifest,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/templates/{template_id}", status_code=204)
async def delete_template(template_id: str, request: Request):
    tenant_id, _ = _context(request, "tenant.agents.delete")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            await service.delete_template(
                session,
                tenant_id=tenant_id,
                template_id=_uuid(template_id, "invalid_template_id"),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/from-template/{template_id}", status_code=201)
async def from_template(template_id: str, body: TemplateAgentRequest, request: Request):
    tenant_id, user_id = _context(request, "tenant.agents.write")
    from app.db.session import async_session
    async with async_session() as session:
        try:
            return await service.create_agent_from_template(
                session,
                tenant_id=tenant_id,
                user_id=user_id,
                template_id=_uuid(template_id, "invalid_template_id"),
                name=body.name,
                api_key_id=body.api_key_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
