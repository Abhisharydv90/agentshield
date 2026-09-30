"""
Tenant-facing endpoints.

Reads the authenticated tenant from request.state.tenant (set by AuthMiddleware)
and exposes:
  - Gateway settings (get / patch)
  - API key management (list / create / revoke)
  - Tenant metadata (name, slug, plan, created_at)
  - Agent registry (CRUD)
  - Policy registry (CRUD)
  - Webhook integrations (CRUD)
"""

from __future__ import annotations

import secrets as _secrets
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.db.session import async_session
from app.db.models import (
    Tenant,
    TenantSettings,
    APIKey,
    User,
    SecurityEvent,
    Agent,
    Policy,
    Webhook,
)
from app.security.api_keys import generate_key, hash_key, key_prefix


router = APIRouter(prefix="/api/tenant", tags=["tenant"])


# ============================================================
# Helpers
# ============================================================

def _require_tenant(request: Request) -> Tenant:
    tenant = getattr(request.state, "tenant", None)
    if tenant is None:
        raise HTTPException(status_code=401, detail="no_tenant")
    return tenant


async def _ensure_settings(session, tenant_id) -> TenantSettings:
    """Fetch the tenant's settings, creating the row if it doesn't exist."""
    settings = await session.get(TenantSettings, tenant_id)
    if settings is None:
        settings = TenantSettings(tenant_id=tenant_id)
        session.add(settings)
        await session.commit()
        await session.refresh(settings)
    return settings


# ============================================================
# Schemas
# ============================================================

class SettingsPatch(BaseModel):
    inbound_scanner_enabled: bool | None = None
    pii_redaction_enabled: bool | None = None
    judge_enabled: bool | None = None
    alert_sounds: bool | None = None
    email_alerts: bool | None = None


class APIKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


# ============================================================
# GET /api/tenant/me  — tenant metadata
# ============================================================

@router.get("/me")
async def get_tenant_me(request: Request) -> dict[str, Any]:
    tenant = _require_tenant(request)
    async with async_session() as session:
        users = (
            await session.execute(
                select(User).where(User.tenant_id == tenant.tenant_id)
            )
        ).scalars().all()

        events_count = len(
            (
                await session.execute(
                    select(SecurityEvent).where(
                        SecurityEvent.tenant_id == tenant.tenant_id
                    )
                )
            ).scalars().all()
        )

    return {
        "tenant_id": str(tenant.tenant_id),
        "name": tenant.name,
        "slug": tenant.slug,
        "status": tenant.status,
        "created_at": tenant.created_at.isoformat(),
        "users_count": len(users),
        "events_count": events_count,
        "plan": "pro",
    }


# ============================================================
# GET /api/tenant/settings
# ============================================================

@router.get("/settings")
async def get_settings(request: Request) -> dict[str, Any]:
    tenant = _require_tenant(request)
    async with async_session() as session:
        settings = await _ensure_settings(session, tenant.tenant_id)
        return {
            "inbound_scanner_enabled": settings.inbound_scanner_enabled,
            "pii_redaction_enabled": settings.pii_redaction_enabled,
            "judge_enabled": settings.judge_enabled,
            "alert_sounds": settings.alert_sounds,
            "email_alerts": settings.email_alerts,
            "updated_at": settings.updated_at.isoformat(),
        }


# ============================================================
# PATCH /api/tenant/settings
# ============================================================

@router.patch("/settings")
async def patch_settings(
    req: SettingsPatch, request: Request
) -> dict[str, Any]:
    tenant = _require_tenant(request)
    async with async_session() as session:
        settings = await _ensure_settings(session, tenant.tenant_id)

        for field, value in req.model_dump(exclude_none=True).items():
            setattr(settings, field, value)

        settings.updated_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(settings)

        return {
            "inbound_scanner_enabled": settings.inbound_scanner_enabled,
            "pii_redaction_enabled": settings.pii_redaction_enabled,
            "judge_enabled": settings.judge_enabled,
            "alert_sounds": settings.alert_sounds,
            "email_alerts": settings.email_alerts,
            "updated_at": settings.updated_at.isoformat(),
        }


# ============================================================
# GET /api/tenant/api-keys
# ============================================================

@router.get("/api-keys")
async def list_api_keys(request: Request) -> list[dict[str, Any]]:
    tenant = _require_tenant(request)
    async with async_session() as session:
        rows = (
            await session.execute(
                select(APIKey)
                .where(APIKey.tenant_id == tenant.tenant_id)
                .order_by(APIKey.created_at.desc())
            )
        ).scalars().all()

    return [
        {
            "key_id": str(k.key_id),
            "name": k.name,
            "key_prefix": k.key_prefix + "_" + "•" * 12,
            "created_at": k.created_at.isoformat(),
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            "revoked": k.revoked,
        }
        for k in rows
    ]


# ============================================================
# POST /api/tenant/api-keys
# ============================================================

@router.post("/api-keys")
async def create_api_key(
    req: APIKeyCreate, request: Request
) -> dict[str, Any]:
    tenant = _require_tenant(request)
    raw_key = generate_key(live=True)

    async with async_session() as session:
        api_key = APIKey(
            tenant_id=tenant.tenant_id,
            name=req.name.strip(),
            key_prefix=key_prefix(raw_key),
            key_hash=hash_key(raw_key),
        )
        session.add(api_key)
        await session.commit()
        await session.refresh(api_key)

        return {
            "key_id": str(api_key.key_id),
            "name": api_key.name,
            "key_prefix": api_key.key_prefix + "_" + "•" * 12,
            "created_at": api_key.created_at.isoformat(),
            "last_used_at": None,
            "revoked": False,
            "raw_key": raw_key,
        }


# ============================================================
# DELETE /api/tenant/api-keys/{key_id}
# ============================================================

@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: str, request: Request) -> dict[str, Any]:
    tenant = _require_tenant(request)

    try:
        kid = _uuid.UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid_key_id")

    async with async_session() as session:
        key = await session.get(APIKey, kid)
        if key is None or key.tenant_id != tenant.tenant_id:
            raise HTTPException(status_code=404, detail="key_not_found")

        key.revoked = True
        await session.commit()

    return {"ok": True, "key_id": key_id}


# ============================================================
# Agents CRUD
# ============================================================

class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    scopes: list[str] = Field(default_factory=list)


class AgentPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    scopes: list[str] | None = None
    status: str | None = None


def _agent_to_dict(a: Agent) -> dict[str, Any]:
    return {
        "agent_id": str(a.agent_id),
        "name": a.name,
        "description": a.description,
        "scopes": a.scopes,
        "status": a.status,
        "created_at": a.created_at.isoformat(),
        "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
    }


@router.get("/agents")
async def list_agents(request: Request) -> list[dict[str, Any]]:
    tenant = _require_tenant(request)
    async with async_session() as session:
        rows = (
            await session.execute(
                select(Agent)
                .where(Agent.tenant_id == tenant.tenant_id)
                .order_by(Agent.created_at.desc())
            )
        ).scalars().all()
    return [_agent_to_dict(a) for a in rows]


@router.post("/agents")
async def create_agent(
    req: AgentCreate, request: Request
) -> dict[str, Any]:
    tenant = _require_tenant(request)
    async with async_session() as session:
        agent = Agent(
            tenant_id=tenant.tenant_id,
            name=req.name.strip(),
            description=req.description.strip(),
            scopes=req.scopes,
        )
        session.add(agent)
        await session.commit()
        await session.refresh(agent)
        return _agent_to_dict(agent)


@router.patch("/agents/{agent_id}")
async def update_agent(
    agent_id: str, req: AgentPatch, request: Request
) -> dict[str, Any]:
    tenant = _require_tenant(request)
    try:
        aid = _uuid.UUID(agent_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid_agent_id")

    async with async_session() as session:
        agent = await session.get(Agent, aid)
        if agent is None or agent.tenant_id != tenant.tenant_id:
            raise HTTPException(status_code=404, detail="agent_not_found")

        for field, value in req.model_dump(exclude_none=True).items():
            setattr(agent, field, value)

        await session.commit()
        await session.refresh(agent)
        return _agent_to_dict(agent)


@router.delete("/agents/{agent_id}")
async def delete_agent(agent_id: str, request: Request) -> dict[str, Any]:
    tenant = _require_tenant(request)
    try:
        aid = _uuid.UUID(agent_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid_agent_id")

    async with async_session() as session:
        agent = await session.get(Agent, aid)
        if agent is None or agent.tenant_id != tenant.tenant_id:
            raise HTTPException(status_code=404, detail="agent_not_found")

        await session.delete(agent)
        await session.commit()

    return {"ok": True, "agent_id": agent_id}


# ============================================================
# Policies CRUD
# ============================================================

class PolicyRule(BaseModel):
    tool_pattern: str = Field(min_length=1, max_length=120)
    op: str | None = None
    target_allowlist: list[str] = Field(default_factory=list)
    target_denylist: list[str] = Field(default_factory=list)
    decision: str = "deny"  # allow | deny | step_up


class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    version: str = Field(default="1.0.0", max_length=20)
    active: bool = False
    rules: list[PolicyRule] = Field(default_factory=list)


class PolicyPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    version: str | None = Field(default=None, max_length=20)
    active: bool | None = None
    rules: list[PolicyRule] | None = None


def _policy_to_dict(p: Policy) -> dict[str, Any]:
    return {
        "policy_id": str(p.policy_id),
        "name": p.name,
        "description": p.description,
        "version": p.version,
        "active": p.active,
        "rules": p.rules,
        "rules_count": len(p.rules or []),
        "created_at": p.created_at.isoformat(),
        "updated_at": p.updated_at.isoformat(),
    }


@router.get("/policies")
async def list_policies(request: Request) -> list[dict[str, Any]]:
    tenant = _require_tenant(request)
    async with async_session() as session:
        rows = (
            await session.execute(
                select(Policy)
                .where(Policy.tenant_id == tenant.tenant_id)
                .order_by(Policy.created_at.desc())
            )
        ).scalars().all()
    return [_policy_to_dict(p) for p in rows]


@router.post("/policies")
async def create_policy(
    req: PolicyCreate, request: Request
) -> dict[str, Any]:
    tenant = _require_tenant(request)
    async with async_session() as session:
        policy = Policy(
            tenant_id=tenant.tenant_id,
            name=req.name.strip(),
            description=req.description.strip(),
            version=req.version,
            active=req.active,
            rules=[r.model_dump() for r in req.rules],
        )
        session.add(policy)
        await session.commit()
        await session.refresh(policy)
        return _policy_to_dict(policy)


@router.patch("/policies/{policy_id}")
async def update_policy(
    policy_id: str, req: PolicyPatch, request: Request
) -> dict[str, Any]:
    tenant = _require_tenant(request)
    try:
        pid = _uuid.UUID(policy_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid_policy_id")

    async with async_session() as session:
        policy = await session.get(Policy, pid)
        if policy is None or policy.tenant_id != tenant.tenant_id:
            raise HTTPException(status_code=404, detail="policy_not_found")

        data = req.model_dump(exclude_none=True)
        if "rules" in data:
            data["rules"] = [r for r in data["rules"]]

        for field, value in data.items():
            setattr(policy, field, value)

        await session.commit()
        await session.refresh(policy)
        return _policy_to_dict(policy)


@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: str, request: Request) -> dict[str, Any]:
    tenant = _require_tenant(request)
    try:
        pid = _uuid.UUID(policy_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid_policy_id")

    async with async_session() as session:
        policy = await session.get(Policy, pid)
        if policy is None or policy.tenant_id != tenant.tenant_id:
            raise HTTPException(status_code=404, detail="policy_not_found")
        await session.delete(policy)
        await session.commit()
    return {"ok": True, "policy_id": policy_id}


# ============================================================
# Webhooks CRUD
# ============================================================

class WebhookCreate(BaseModel):
    url: str = Field(min_length=1, max_length=500)
    description: str = Field(default="", max_length=200)
    events: list[str] = Field(default_factory=lambda: ["blocked"])
    active: bool = True


class WebhookPatch(BaseModel):
    url: str | None = Field(default=None, min_length=1, max_length=500)
    description: str | None = Field(default=None, max_length=200)
    events: list[str] | None = None
    active: bool | None = None


def _webhook_to_dict(w: Webhook, reveal_secret: bool = False) -> dict[str, Any]:
    return {
        "webhook_id": str(w.webhook_id),
        "url": w.url,
        "description": w.description,
        "events": w.events,
        "active": w.active,
        "created_at": w.created_at.isoformat(),
        "updated_at": w.updated_at.isoformat(),
        "secret": w.secret if reveal_secret else None,
    }


@router.get("/webhooks")
async def list_webhooks(request: Request) -> list[dict[str, Any]]:
    tenant = _require_tenant(request)
    async with async_session() as session:
        rows = (
            await session.execute(
                select(Webhook)
                .where(Webhook.tenant_id == tenant.tenant_id)
                .order_by(Webhook.created_at.desc())
            )
        ).scalars().all()
    return [_webhook_to_dict(w) for w in rows]


@router.post("/webhooks")
async def create_webhook(
    req: WebhookCreate, request: Request
) -> dict[str, Any]:
    tenant = _require_tenant(request)
    async with async_session() as session:
        webhook = Webhook(
            tenant_id=tenant.tenant_id,
            url=req.url.strip(),
            description=req.description.strip(),
            events=req.events,
            active=req.active,
            secret=_secrets.token_hex(32),
        )
        session.add(webhook)
        await session.commit()
        await session.refresh(webhook)
        return _webhook_to_dict(webhook, reveal_secret=True)


@router.patch("/webhooks/{webhook_id}")
async def update_webhook(
    webhook_id: str, req: WebhookPatch, request: Request
) -> dict[str, Any]:
    tenant = _require_tenant(request)
    try:
        wid = _uuid.UUID(webhook_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid_webhook_id")

    async with async_session() as session:
        webhook = await session.get(Webhook, wid)
        if webhook is None or webhook.tenant_id != tenant.tenant_id:
            raise HTTPException(status_code=404, detail="webhook_not_found")

        for field, value in req.model_dump(exclude_none=True).items():
            setattr(webhook, field, value)

        await session.commit()
        await session.refresh(webhook)
        return _webhook_to_dict(webhook)


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, request: Request) -> dict[str, Any]:
    tenant = _require_tenant(request)
    try:
        wid = _uuid.UUID(webhook_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid_webhook_id")

    async with async_session() as session:
        webhook = await session.get(Webhook, wid)
        if webhook is None or webhook.tenant_id != tenant.tenant_id:
            raise HTTPException(status_code=404, detail="webhook_not_found")
        await session.delete(webhook)
        await session.commit()
    return {"ok": True, "webhook_id": webhook_id}