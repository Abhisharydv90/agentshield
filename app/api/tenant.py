"""
Tenant-facing management endpoints.

Human access:
    Browser session -> User -> RBAC -> tenant management.

API-key access:
    API keys are intentionally NOT accepted as human-management
    authorization for these endpoints.

Tenant isolation is enforced on every database operation by
tenant_id.

Management permissions are defined in:
    app.security.authorization
"""

from __future__ import annotations

import secrets as _secrets
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.db.models import (
    APIKey,
    Agent,
    Policy,
    SecurityEvent,
    Tenant,
    TenantSettings,
    User,
    Webhook,
)
from app.db.session import async_session
from app.security.api_keys import (
    generate_key,
    hash_key,
    key_prefix,
)
from app.security.authorization import (
    require_permission,
)


router = APIRouter(
    prefix="/api/tenant",
    tags=["tenant"],
)


# ============================================================
# Authentication / authorization helpers
# ============================================================


def _require_tenant(
    request: Request,
) -> Tenant:
    """
    Retrieve the tenant attached by AuthMiddleware.
    """

    tenant = getattr(
        request.state,
        "tenant",
        None,
    )

    if tenant is None:
        raise HTTPException(
            status_code=401,
            detail="no_tenant",
        )

    return tenant


def _require_user(
    request: Request,
) -> User:
    """
    Tenant administration requires a human browser session.

    API-key authenticated requests are intentionally rejected.
    """

    user = getattr(
        request.state,
        "user",
        None,
    )

    auth_type = getattr(
        request.state,
        "auth_type",
        None,
    )

    if auth_type != "session":
        raise HTTPException(
            status_code=403,
            detail="human_session_required",
        )

    if user is None:
        raise HTTPException(
            status_code=403,
            detail="human_session_required",
        )

    if user.status != "active":
        raise HTTPException(
            status_code=403,
            detail="user_inactive",
        )

    return user


def _authorize(
    request: Request,
    permission: str,
) -> tuple[Tenant, User]:
    """
    Resolve the authenticated tenant/user and enforce one
    management permission.
    """

    tenant = _require_tenant(
        request
    )

    user = _require_user(
        request
    )

    require_permission(
        user.role,
        permission,
    )

    return (
        tenant,
        user,
    )


# ============================================================
# Settings helper
# ============================================================


async def _ensure_settings(
    session,
    tenant_id,
) -> TenantSettings:
    """
    Fetch tenant settings.

    Creates the default settings row when one does not exist.
    """

    row = await session.get(
        TenantSettings,
        tenant_id,
    )

    if row is None:

        row = TenantSettings(
            tenant_id=tenant_id
        )

        session.add(row)

        await session.commit()

        await session.refresh(
            row
        )

    return row


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
    name: str = Field(
        min_length=1,
        max_length=120,
    )


# ============================================================
# Tenant metadata
# ============================================================


@router.get("/me")
async def get_tenant_me(
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.read",
    )

    async with async_session() as session:

        users = (
            await session.execute(
                select(User).where(
                    User.tenant_id
                    == tenant.tenant_id
                )
            )
        ).scalars().all()

        events_count = len(
            (
                await session.execute(
                    select(SecurityEvent).where(
                        SecurityEvent.tenant_id
                        == tenant.tenant_id
                    )
                )
            ).scalars().all()
        )

    return {
        "tenant_id":
            str(tenant.tenant_id),
        "name":
            tenant.name,
        "slug":
            tenant.slug,
        "status":
            tenant.status,
        "created_at":
            tenant.created_at.isoformat(),
        "users_count":
            len(users),
        "events_count":
            events_count,
        "plan":
            "pro",
    }


# ============================================================
# Settings
# ============================================================


@router.get("/settings")
async def get_settings(
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.settings.read",
    )

    async with async_session() as session:

        settings = await _ensure_settings(
            session,
            tenant.tenant_id,
        )

        return {
            "inbound_scanner_enabled":
                settings.inbound_scanner_enabled,
            "pii_redaction_enabled":
                settings.pii_redaction_enabled,
            "judge_enabled":
                settings.judge_enabled,
            "alert_sounds":
                settings.alert_sounds,
            "email_alerts":
                settings.email_alerts,
            "updated_at":
                settings.updated_at.isoformat(),
        }


@router.patch("/settings")
async def patch_settings(
    req: SettingsPatch,
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.settings.write",
    )

    async with async_session() as session:

        row = await _ensure_settings(
            session,
            tenant.tenant_id,
        )

        for (
            field,
            value,
        ) in req.model_dump(
            exclude_none=True
        ).items():

            setattr(
                row,
                field,
                value,
            )

        row.updated_at = (
            datetime.now(
                timezone.utc
            )
        )

        await session.commit()

        await session.refresh(
            row
        )

        return {
            "inbound_scanner_enabled":
                row.inbound_scanner_enabled,
            "pii_redaction_enabled":
                row.pii_redaction_enabled,
            "judge_enabled":
                row.judge_enabled,
            "alert_sounds":
                row.alert_sounds,
            "email_alerts":
                row.email_alerts,
            "updated_at":
                row.updated_at.isoformat(),
        }


# ============================================================
# API keys
# ============================================================


@router.get("/api-keys")
async def list_api_keys(
    request: Request,
) -> list[dict[str, Any]]:

    tenant, _ = _authorize(
        request,
        "tenant.api_keys.read",
    )

    async with async_session() as session:

        rows = (
            await session.execute(
                select(APIKey)
                .where(
                    APIKey.tenant_id
                    == tenant.tenant_id
                )
                .order_by(
                    APIKey.created_at.desc()
                )
            )
        ).scalars().all()

    return [
        {
            "key_id":
                str(key.key_id),
            "name":
                key.name,
            "key_prefix":
                key.key_prefix
                + "_"
                + "•" * 12,
            "created_at":
                key.created_at.isoformat(),
            "last_used_at":
                (
                    key.last_used_at.isoformat()
                    if key.last_used_at
                    else None
                ),
            "revoked":
                key.revoked,
        }
        for key in rows
    ]


@router.post("/api-keys")
async def create_api_key(
    req: APIKeyCreate,
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.api_keys.write",
    )

    raw_key = generate_key(
        live=True
    )

    async with async_session() as session:

        api_key = APIKey(
            tenant_id=tenant.tenant_id,
            name=req.name.strip(),
            key_prefix=key_prefix(
                raw_key
            ),
            key_hash=hash_key(
                raw_key
            ),
        )

        session.add(
            api_key
        )

        await session.commit()

        await session.refresh(
            api_key
        )

        return {
            "key_id":
                str(api_key.key_id),
            "name":
                api_key.name,
            "key_prefix":
                api_key.key_prefix
                + "_"
                + "•" * 12,
            "created_at":
                api_key.created_at.isoformat(),
            "last_used_at":
                None,
            "revoked":
                False,
            "raw_key":
                raw_key,
        }


@router.delete(
    "/api-keys/{key_id}"
)
async def revoke_api_key(
    key_id: str,
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.api_keys.write",
    )

    try:

        kid = _uuid.UUID(
            key_id
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail="invalid_key_id",
        ) from exc

    async with async_session() as session:

        key = await session.get(
            APIKey,
            kid,
        )

        if (
            key is None
            or key.tenant_id
            != tenant.tenant_id
        ):
            raise HTTPException(
                status_code=404,
                detail="key_not_found",
            )

        key.revoked = True

        await session.commit()

    return {
        "ok": True,
        "key_id": key_id,
    }


# ============================================================
# Agent schemas
# ============================================================


class AgentCreate(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=120,
    )

    description: str = Field(
        default="",
        max_length=500,
    )

    scopes: list[str] = Field(
        default_factory=list
    )


class AgentPatch(BaseModel):
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=120,
    )

    description: str | None = Field(
        default=None,
        max_length=500,
    )

    scopes: list[str] | None = None

    status: str | None = None


def _agent_to_dict(
    agent: Agent,
) -> dict[str, Any]:

    return {
        "agent_id":
            str(agent.agent_id),
        "name":
            agent.name,
        "description":
            agent.description,
        "scopes":
            agent.scopes,
        "status":
            agent.status,
        "created_at":
            agent.created_at.isoformat(),
        "last_seen_at":
            (
                agent.last_seen_at.isoformat()
                if agent.last_seen_at
                else None
            ),
    }


# ============================================================
# Agents
# ============================================================


@router.get("/agents")
async def list_agents(
    request: Request,
) -> list[dict[str, Any]]:

    tenant, _ = _authorize(
        request,
        "tenant.agents.read",
    )

    async with async_session() as session:

        rows = (
            await session.execute(
                select(Agent)
                .where(
                    Agent.tenant_id
                    == tenant.tenant_id
                )
                .order_by(
                    Agent.created_at.desc()
                )
            )
        ).scalars().all()

    return [
        _agent_to_dict(agent)
        for agent in rows
    ]


@router.post("/agents")
async def create_agent(
    req: AgentCreate,
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.agents.write",
    )

    async with async_session() as session:

        agent = Agent(
            tenant_id=tenant.tenant_id,
            name=req.name.strip(),
            description=req.description.strip(),
            scopes=req.scopes,
        )

        session.add(
            agent
        )

        await session.commit()

        await session.refresh(
            agent
        )

        return _agent_to_dict(
            agent
        )


@router.patch(
    "/agents/{agent_id}"
)
async def update_agent(
    agent_id: str,
    req: AgentPatch,
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.agents.write",
    )

    try:

        aid = _uuid.UUID(
            agent_id
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail="invalid_agent_id",
        ) from exc

    async with async_session() as session:

        agent = await session.get(
            Agent,
            aid,
        )

        if (
            agent is None
            or agent.tenant_id
            != tenant.tenant_id
        ):
            raise HTTPException(
                status_code=404,
                detail="agent_not_found",
            )

        for (
            field,
            value,
        ) in req.model_dump(
            exclude_none=True
        ).items():

            setattr(
                agent,
                field,
                value,
            )

        await session.commit()

        await session.refresh(
            agent
        )

        return _agent_to_dict(
            agent
        )


@router.delete(
    "/agents/{agent_id}"
)
async def delete_agent(
    agent_id: str,
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.agents.delete",
    )

    try:

        aid = _uuid.UUID(
            agent_id
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail="invalid_agent_id",
        ) from exc

    async with async_session() as session:

        agent = await session.get(
            Agent,
            aid,
        )

        if (
            agent is None
            or agent.tenant_id
            != tenant.tenant_id
        ):
            raise HTTPException(
                status_code=404,
                detail="agent_not_found",
            )

        await session.delete(
            agent
        )

        await session.commit()

    return {
        "ok": True,
        "agent_id": agent_id,
    }


# ============================================================
# Policy schemas
# ============================================================


class PolicyRule(BaseModel):
    tool_pattern: str = Field(
        min_length=1,
        max_length=120,
    )

    op: str | None = None

    target_allowlist: list[str] = Field(
        default_factory=list
    )

    target_denylist: list[str] = Field(
        default_factory=list
    )

    decision: str = "deny"


class PolicyCreate(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=120,
    )

    description: str = Field(
        default="",
        max_length=500,
    )

    version: str = Field(
        default="1.0.0",
        max_length=20,
    )

    active: bool = False

    rules: list[PolicyRule] = Field(
        default_factory=list
    )


class PolicyPatch(BaseModel):
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=120,
    )

    description: str | None = Field(
        default=None,
        max_length=500,
    )

    version: str | None = Field(
        default=None,
        max_length=20,
    )

    active: bool | None = None

    rules: list[PolicyRule] | None = None


def _policy_to_dict(
    policy: Policy,
) -> dict[str, Any]:

    return {
        "policy_id":
            str(policy.policy_id),
        "name":
            policy.name,
        "description":
            policy.description,
        "version":
            policy.version,
        "active":
            policy.active,
        "rules":
            policy.rules,
        "rules_count":
            len(policy.rules or []),
        "created_at":
            policy.created_at.isoformat(),
        "updated_at":
            policy.updated_at.isoformat(),
    }


# ============================================================
# Policies
# ============================================================


@router.get("/policies")
async def list_policies(
    request: Request,
) -> list[dict[str, Any]]:

    tenant, _ = _authorize(
        request,
        "tenant.policies.read",
    )

    async with async_session() as session:

        rows = (
            await session.execute(
                select(Policy)
                .where(
                    Policy.tenant_id
                    == tenant.tenant_id
                )
                .order_by(
                    Policy.created_at.desc()
                )
            )
        ).scalars().all()

    return [
        _policy_to_dict(policy)
        for policy in rows
    ]


@router.post("/policies")
async def create_policy(
    req: PolicyCreate,
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.policies.write",
    )

    async with async_session() as session:

        policy = Policy(
            tenant_id=tenant.tenant_id,
            name=req.name.strip(),
            description=req.description.strip(),
            version=req.version,
            active=req.active,
            rules=[
                rule.model_dump()
                for rule in req.rules
            ],
        )

        session.add(
            policy
        )

        await session.commit()

        await session.refresh(
            policy
        )

        return _policy_to_dict(
            policy
        )


@router.patch(
    "/policies/{policy_id}"
)
async def update_policy(
    policy_id: str,
    req: PolicyPatch,
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.policies.write",
    )

    try:

        pid = _uuid.UUID(
            policy_id
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail="invalid_policy_id",
        ) from exc

    async with async_session() as session:

        policy = await session.get(
            Policy,
            pid,
        )

        if (
            policy is None
            or policy.tenant_id
            != tenant.tenant_id
        ):
            raise HTTPException(
                status_code=404,
                detail="policy_not_found",
            )

        data = req.model_dump(
            exclude_none=True
        )

        if "rules" in data:

            data["rules"] = [
                rule
                for rule in data["rules"]
            ]

        for (
            field,
            value,
        ) in data.items():

            setattr(
                policy,
                field,
                value,
            )

        await session.commit()

        await session.refresh(
            policy
        )

        return _policy_to_dict(
            policy
        )


@router.delete(
    "/policies/{policy_id}"
)
async def delete_policy(
    policy_id: str,
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.policies.delete",
    )

    try:

        pid = _uuid.UUID(
            policy_id
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail="invalid_policy_id",
        ) from exc

    async with async_session() as session:

        policy = await session.get(
            Policy,
            pid,
        )

        if (
            policy is None
            or policy.tenant_id
            != tenant.tenant_id
        ):
            raise HTTPException(
                status_code=404,
                detail="policy_not_found",
            )

        await session.delete(
            policy
        )

        await session.commit()

    return {
        "ok": True,
        "policy_id": policy_id,
    }


# ============================================================
# Webhook schemas
# ============================================================


class WebhookCreate(BaseModel):
    url: str = Field(
        min_length=1,
        max_length=500,
    )

    description: str = Field(
        default="",
        max_length=200,
    )

    events: list[str] = Field(
        default_factory=lambda: ["blocked"]
    )

    active: bool = True


class WebhookPatch(BaseModel):
    url: str | None = Field(
        default=None,
        min_length=1,
        max_length=500,
    )

    description: str | None = Field(
        default=None,
        max_length=200,
    )

    events: list[str] | None = None

    active: bool | None = None


def _webhook_to_dict(
    webhook: Webhook,
    reveal_secret: bool = False,
) -> dict[str, Any]:

    return {
        "webhook_id":
            str(webhook.webhook_id),
        "url":
            webhook.url,
        "description":
            webhook.description,
        "events":
            webhook.events,
        "active":
            webhook.active,
        "created_at":
            webhook.created_at.isoformat(),
        "updated_at":
            webhook.updated_at.isoformat(),
        "secret":
            (
                webhook.secret
                if reveal_secret
                else None
            ),
    }


# ============================================================
# Webhooks
# ============================================================


@router.get("/webhooks")
async def list_webhooks(
    request: Request,
) -> list[dict[str, Any]]:

    tenant, _ = _authorize(
        request,
        "tenant.webhooks.read",
    )

    async with async_session() as session:

        rows = (
            await session.execute(
                select(Webhook)
                .where(
                    Webhook.tenant_id
                    == tenant.tenant_id
                )
                .order_by(
                    Webhook.created_at.desc()
                )
            )
        ).scalars().all()

    return [
        _webhook_to_dict(
            webhook
        )
        for webhook in rows
    ]


@router.post("/webhooks")
async def create_webhook(
    req: WebhookCreate,
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.webhooks.write",
    )

    async with async_session() as session:

        webhook = Webhook(
            tenant_id=tenant.tenant_id,
            url=req.url.strip(),
            description=req.description.strip(),
            events=req.events,
            active=req.active,
            secret=_secrets.token_hex(
                32
            ),
        )

        session.add(
            webhook
        )

        await session.commit()

        await session.refresh(
            webhook
        )

        return _webhook_to_dict(
            webhook,
            reveal_secret=True,
        )


@router.patch(
    "/webhooks/{webhook_id}"
)
async def update_webhook(
    webhook_id: str,
    req: WebhookPatch,
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.webhooks.write",
    )

    try:

        wid = _uuid.UUID(
            webhook_id
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail="invalid_webhook_id",
        ) from exc

    async with async_session() as session:

        webhook = await session.get(
            Webhook,
            wid,
        )

        if (
            webhook is None
            or webhook.tenant_id
            != tenant.tenant_id
        ):
            raise HTTPException(
                status_code=404,
                detail="webhook_not_found",
            )

        for (
            field,
            value,
        ) in req.model_dump(
            exclude_none=True
        ).items():

            setattr(
                webhook,
                field,
                value,
            )

        await session.commit()

        await session.refresh(
            webhook
        )

        return _webhook_to_dict(
            webhook
        )


@router.delete(
    "/webhooks/{webhook_id}"
)
async def delete_webhook(
    webhook_id: str,
    request: Request,
) -> dict[str, Any]:

    tenant, _ = _authorize(
        request,
        "tenant.webhooks.delete",
    )

    try:

        wid = _uuid.UUID(
            webhook_id
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail="invalid_webhook_id",
        ) from exc

    async with async_session() as session:

        webhook = await session.get(
            Webhook,
            wid,
        )

        if (
            webhook is None
            or webhook.tenant_id
            != tenant.tenant_id
        ):
            raise HTTPException(
                status_code=404,
                detail="webhook_not_found",
            )

        await session.delete(
            webhook
        )

        await session.commit()

    return {
        "ok": True,
        "webhook_id":
            webhook_id,
    }