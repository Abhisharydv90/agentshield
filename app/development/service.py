"""Phase 1 agent development service layer.

All operations are tenant-scoped and management-only. This layer owns
persistent agent definitions, immutable versions, templates, memberships and
deployment declarations. It never executes a workload or mints authority.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Agent, APIKey, User
from app.development.lifecycle import validate_transition
from app.development.models import AgentDeployment, AgentMember, AgentTemplate, AgentVersion
from app.development.templates import (
    content_hash,
    normalize_manifest,
    normalize_template_capabilities,
    normalize_version,
)


MAX_CONFIG_BYTES = 128 * 1024
MAX_VERSION_MANIFEST_BYTES = 256 * 1024


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _json_size(value: Any) -> int:
    return len(
        json.dumps(
            value,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )


def _tenant_agent_stmt(tenant_id: uuid.UUID, agent_id: uuid.UUID):
    return select(Agent).where(
        Agent.tenant_id == tenant_id,
        Agent.agent_id == agent_id,
    )


async def get_agent(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
) -> Agent | None:
    return (
        await session.execute(
            _tenant_agent_stmt(tenant_id, agent_id)
        )
    ).scalar_one_or_none()


async def _validate_api_key(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    api_key_id: str | None,
    *,
    exclude_agent_id: uuid.UUID | None = None,
) -> uuid.UUID | None:
    if api_key_id is None:
        return None
    try:
        kid = uuid.UUID(api_key_id)
    except ValueError as exc:
        raise ValueError("invalid_api_key_id") from exc
    key = await session.get(APIKey, kid)
    if key is None or key.tenant_id != tenant_id:
        raise ValueError("api_key_not_found")
    if key.revoked:
        raise ValueError("api_key_revoked")

    binding = (
        await session.execute(
            select(Agent).where(Agent.api_key_id == kid)
        )
    ).scalar_one_or_none()
    if binding is not None and binding.agent_id != exclude_agent_id:
        raise ValueError("api_key_already_bound")

    return kid


def agent_view(agent: Agent) -> dict[str, Any]:
    return {
        "agent_id": str(agent.agent_id),
        "tenant_id": str(agent.tenant_id),
        "name": agent.name,
        "description": agent.description,
        "capabilities": sorted(set(agent.scopes or [])),
        "status": agent.status,
        "api_key_id": str(agent.api_key_id) if agent.api_key_id else None,
        "created_at": agent.created_at.isoformat(),
        "last_seen_at": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
    }


def version_view(version: AgentVersion) -> dict[str, Any]:
    return {
        "version_id": str(version.version_id),
        "agent_id": str(version.agent_id),
        "tenant_id": str(version.tenant_id),
        "version": version.version,
        "status": version.status,
        "description": version.description,
        "capabilities": sorted(set(version.capabilities or [])),
        "manifest": version.manifest,
        "content_hash": version.content_hash,
        "created_by_user_id": (
            str(version.created_by_user_id)
            if version.created_by_user_id
            else None
        ),
        "created_at": version.created_at.isoformat(),
        "published_at": version.published_at.isoformat() if version.published_at else None,
    }


def template_view(template: AgentTemplate) -> dict[str, Any]:
    return {
        "template_id": str(template.template_id),
        "tenant_id": str(template.tenant_id),
        "name": template.name,
        "description": template.description,
        "version": template.version,
        "capabilities": sorted(set(template.capabilities or [])),
        "manifest": template.manifest,
        "active": template.active,
        "created_by_user_id": (
            str(template.created_by_user_id)
            if template.created_by_user_id
            else None
        ),
        "created_at": template.created_at.isoformat(),
    }


def deployment_view(deployment: AgentDeployment) -> dict[str, Any]:
    return {
        "deployment_id": str(deployment.deployment_id),
        "agent_id": str(deployment.agent_id),
        "tenant_id": str(deployment.tenant_id),
        "version_id": str(deployment.version_id),
        "environment": deployment.environment,
        "region": deployment.region,
        "desired_replicas": deployment.desired_replicas,
        "status": deployment.status,
        "config": deployment.config,
        "created_by_user_id": (
            str(deployment.created_by_user_id)
            if deployment.created_by_user_id
            else None
        ),
        "created_at": deployment.created_at.isoformat(),
        "updated_at": deployment.updated_at.isoformat(),
    }


def member_view(member: AgentMember, user: User | None = None) -> dict[str, Any]:
    return {
        "membership_id": str(member.membership_id),
        "agent_id": str(member.agent_id),
        "user_id": str(member.user_id),
        "email": user.email if user else None,
        "name": user.name if user else None,
        "role": member.role,
        "created_at": member.created_at.isoformat(),
    }


async def list_agents(session: AsyncSession, tenant_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(Agent)
            .where(Agent.tenant_id == tenant_id)
            .order_by(Agent.created_at.desc())
        )
    ).scalars().all()
    return [agent_view(row) for row in rows]


async def create_agent(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    name: str,
    description: str,
    capabilities: list[str],
    manifest: dict[str, Any] | None = None,
    api_key_id: str | None = None,
    initial_version: str = "1.0.0",
) -> dict[str, Any]:
    name = name.strip()
    description = description.strip()
    if not name:
        raise ValueError("agent_name_required")
    if _json_size(manifest or {}) > MAX_VERSION_MANIFEST_BYTES:
        raise ValueError("agent_manifest_too_large")

    capabilities = normalize_template_capabilities(capabilities)
    manifest = normalize_manifest(manifest or {})
    version = normalize_version(initial_version)
    bound_key = await _validate_api_key(session, tenant_id, api_key_id)

    agent = Agent(
        tenant_id=tenant_id,
        name=name,
        description=description,
        scopes=capabilities,
        status="active",
        api_key_id=bound_key,
    )
    session.add(agent)
    await session.flush()

    merged_manifest = {
        "agent": {"name": name, "description": description},
        **manifest,
    }
    version_record = AgentVersion(
        tenant_id=tenant_id,
        agent_id=agent.agent_id,
        version=version,
        status="published",
        description=description,
        capabilities=capabilities,
        manifest=merged_manifest,
        content_hash=content_hash(
            name=name,
            description=description,
            version=version,
            capabilities=capabilities,
            manifest=merged_manifest,
        ),
        created_by_user_id=user_id,
        published_at=_utcnow(),
    )
    session.add(version_record)

    session.add(
        AgentMember(
            tenant_id=tenant_id,
            agent_id=agent.agent_id,
            user_id=user_id,
            role="manager",
        )
    )
    await session.commit()
    await session.refresh(agent)
    return agent_view(agent)


async def update_agent(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    name: str | None = None,
    description: str | None = None,
    api_key_id: str | None = None,
) -> dict[str, Any]:
    agent = await get_agent(session, tenant_id, agent_id)
    if agent is None:
        raise LookupError("agent_not_found")

    if name is not None:
        value = name.strip()
        if not value:
            raise ValueError("agent_name_required")
        agent.name = value
    if description is not None:
        agent.description = description.strip()
    if api_key_id is not None:
        agent.api_key_id = await _validate_api_key(
            session,
            tenant_id,
            api_key_id,
            exclude_agent_id=agent.agent_id,
        )

    await session.commit()
    await session.refresh(agent)
    return agent_view(agent)


async def delete_agent(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
) -> None:
    agent = await get_agent(session, tenant_id, agent_id)
    if agent is None:
        raise LookupError("agent_not_found")
    if agent.status != "revoked":
        raise ValueError("agent_must_be_revoked_before_delete")
    await session.delete(agent)
    await session.commit()


async def transition_agent(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    status: str,
) -> dict[str, Any]:
    agent = await get_agent(session, tenant_id, agent_id)
    if agent is None:
        raise LookupError("agent_not_found")
    validate_transition(agent.status, status)
    agent.status = status
    if status in {"suspended", "revoked"}:
        await session.execute(
            update(AgentDeployment)
            .where(
                AgentDeployment.tenant_id == tenant_id,
                AgentDeployment.agent_id == agent_id,
                AgentDeployment.status == "active",
            )
            .values(status="stopped")
        )
    await session.commit()
    await session.refresh(agent)
    return agent_view(agent)


async def list_versions(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
) -> list[dict[str, Any]]:
    agent = await get_agent(session, tenant_id, agent_id)
    if agent is None:
        raise LookupError("agent_not_found")
    rows = (
        await session.execute(
            select(AgentVersion)
            .where(
                AgentVersion.tenant_id == tenant_id,
                AgentVersion.agent_id == agent_id,
            )
            .order_by(AgentVersion.created_at.desc())
        )
    ).scalars().all()
    return [version_view(row) for row in rows]


async def create_version(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    user_id: uuid.UUID,
    version: str,
    description: str,
    capabilities: list[str],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    agent = await get_agent(session, tenant_id, agent_id)
    if agent is None:
        raise LookupError("agent_not_found")
    if agent.status == "revoked":
        raise ValueError("agent_revoked")

    normalized_version = normalize_version(version)
    capabilities = normalize_template_capabilities(capabilities)
    manifest = normalize_manifest(manifest)
    if _json_size(manifest) > MAX_VERSION_MANIFEST_BYTES:
        raise ValueError("agent_manifest_too_large")

    exists = (
        await session.execute(
            select(AgentVersion).where(
                AgentVersion.tenant_id == tenant_id,
                AgentVersion.agent_id == agent_id,
                AgentVersion.version == normalized_version,
            )
        )
    ).scalar_one_or_none()
    if exists is not None:
        raise ValueError("agent_version_already_exists")

    row = AgentVersion(
        tenant_id=tenant_id,
        agent_id=agent_id,
        version=normalized_version,
        status="draft",
        description=description.strip(),
        capabilities=capabilities,
        manifest=manifest,
        content_hash=content_hash(
            name=agent.name,
            description=description.strip(),
            version=normalized_version,
            capabilities=capabilities,
            manifest=manifest,
        ),
        created_by_user_id=user_id,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return version_view(row)


async def publish_version(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    version_id: uuid.UUID,
) -> dict[str, Any]:
    agent = await get_agent(session, tenant_id, agent_id)
    if agent is None:
        raise LookupError("agent_not_found")
    row = await session.get(AgentVersion, version_id)
    if row is None or row.tenant_id != tenant_id or row.agent_id != agent_id:
        raise LookupError("agent_version_not_found")
    if row.status == "revoked":
        raise ValueError("agent_version_revoked")

    row.status = "published"
    row.published_at = _utcnow()
    agent.scopes = sorted(set(row.capabilities or []))

    await session.commit()
    await session.refresh(row)
    return version_view(row)


async def revoke_version(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    version_id: uuid.UUID,
) -> dict[str, Any]:
    agent = await get_agent(session, tenant_id, agent_id)
    if agent is None:
        raise LookupError("agent_not_found")
    row = await session.get(AgentVersion, version_id)
    if row is None or row.tenant_id != tenant_id or row.agent_id != agent_id:
        raise LookupError("agent_version_not_found")
    if row.status == "revoked":
        return version_view(row)

    published = (
        await session.execute(
            select(AgentVersion)
            .where(
                AgentVersion.tenant_id == tenant_id,
                AgentVersion.agent_id == agent_id,
                AgentVersion.status == "published",
                AgentVersion.version_id != version_id,
            )
            .order_by(AgentVersion.published_at.desc(), AgentVersion.created_at.desc())
        )
    ).scalars().all()

    was_published = row.status == "published"
    if was_published and not published:
        raise ValueError("cannot_revoke_only_published_version")

    row.status = "revoked"

    # If the revoked version is currently represented by the Agent capability
    # set, switch to the newest remaining published version so runtime does
    # not retain capabilities from a revoked definition.
    if (
        was_published
        and set(agent.scopes or []) == set(row.capabilities or [])
        and published
    ):
        agent.scopes = sorted(set(published[0].capabilities or []))

    await session.commit()
    await session.refresh(row)
    return version_view(row)


async def list_templates(session: AsyncSession, tenant_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(AgentTemplate)
            .where(
                AgentTemplate.tenant_id == tenant_id,
                AgentTemplate.active.is_(True),
            )
            .order_by(AgentTemplate.created_at.desc())
        )
    ).scalars().all()
    return [template_view(row) for row in rows]


async def create_template(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    name: str,
    description: str,
    version: str,
    capabilities: list[str],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    name = name.strip()
    if not name:
        raise ValueError("template_name_required")
    version = normalize_version(version)
    capabilities = normalize_template_capabilities(capabilities)
    manifest = normalize_manifest(manifest)
    if _json_size(manifest) > MAX_VERSION_MANIFEST_BYTES:
        raise ValueError("template_manifest_too_large")

    exists = (
        await session.execute(
            select(AgentTemplate).where(
                AgentTemplate.tenant_id == tenant_id,
                AgentTemplate.name == name,
                AgentTemplate.version == version,
            )
        )
    ).scalar_one_or_none()
    if exists is not None:
        raise ValueError("agent_template_already_exists")

    row = AgentTemplate(
        tenant_id=tenant_id,
        name=name,
        description=description.strip(),
        version=version,
        capabilities=capabilities,
        manifest=manifest,
        active=True,
        created_by_user_id=user_id,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return template_view(row)


async def delete_template(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    template_id: uuid.UUID,
) -> None:
    row = await session.get(AgentTemplate, template_id)
    if row is None or row.tenant_id != tenant_id:
        raise LookupError("agent_template_not_found")
    row.active = False
    await session.commit()


async def create_agent_from_template(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    template_id: uuid.UUID,
    name: str,
    api_key_id: str | None,
) -> dict[str, Any]:
    template = await session.get(AgentTemplate, template_id)
    if template is None or template.tenant_id != tenant_id or not template.active:
        raise LookupError("agent_template_not_found")

    return await create_agent(
        session,
        tenant_id=tenant_id,
        user_id=user_id,
        name=name,
        description=template.description,
        capabilities=list(template.capabilities or []),
        manifest=dict(template.manifest or {}),
        api_key_id=api_key_id,
        initial_version=template.version,
    )


async def list_deployments(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID | None = None,
) -> list[dict[str, Any]]:
    statement = select(AgentDeployment).where(
        AgentDeployment.tenant_id == tenant_id
    )
    if agent_id is not None:
        statement = statement.where(AgentDeployment.agent_id == agent_id)
    rows = (
        await session.execute(
            statement.order_by(AgentDeployment.created_at.desc())
        )
    ).scalars().all()
    return [deployment_view(row) for row in rows]


async def create_deployment(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    agent_id: uuid.UUID,
    version_id: uuid.UUID,
    environment: str,
    region: str,
    desired_replicas: int,
    config: dict[str, Any],
) -> dict[str, Any]:
    agent = await get_agent(session, tenant_id, agent_id)
    if agent is None:
        raise LookupError("agent_not_found")
    if agent.status != "active":
        raise ValueError("agent_not_active")

    version = await session.get(AgentVersion, version_id)
    if version is None or version.tenant_id != tenant_id or version.agent_id != agent_id:
        raise LookupError("agent_version_not_found")
    if version.status != "published":
        raise ValueError("deployment_requires_published_version")

    environment = environment.strip()
    region = region.strip()
    if not environment or len(environment) > 32:
        raise ValueError("invalid_deployment_environment")
    if not region or len(region) > 64:
        raise ValueError("invalid_deployment_region")
    if not 1 <= desired_replicas <= 100:
        raise ValueError("invalid_deployment_replicas")
    if _json_size(config) > MAX_CONFIG_BYTES:
        raise ValueError("deployment_config_too_large")

    row = AgentDeployment(
        tenant_id=tenant_id,
        agent_id=agent_id,
        version_id=version_id,
        environment=environment,
        region=region,
        desired_replicas=desired_replicas,
        status="active",
        config=config,
        created_by_user_id=user_id,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return deployment_view(row)


async def stop_deployment(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    deployment_id: uuid.UUID,
) -> dict[str, Any]:
    row = await session.get(AgentDeployment, deployment_id)
    if row is None or row.tenant_id != tenant_id:
        raise LookupError("deployment_not_found")
    if row.status == "retired":
        raise ValueError("deployment_retired")
    row.status = "stopped"
    await session.commit()
    await session.refresh(row)
    return deployment_view(row)


async def list_members(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
) -> list[dict[str, Any]]:
    agent = await get_agent(session, tenant_id, agent_id)
    if agent is None:
        raise LookupError("agent_not_found")
    rows = (
        await session.execute(
            select(AgentMember, User)
            .join(User, User.user_id == AgentMember.user_id)
            .where(
                AgentMember.tenant_id == tenant_id,
                AgentMember.agent_id == agent_id,
                User.tenant_id == tenant_id,
            )
            .order_by(AgentMember.created_at.asc())
        )
    ).all()
    return [member_view(member, user) for member, user in rows]


async def add_member(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    user_id: uuid.UUID,
    role: str,
) -> dict[str, Any]:
    agent = await get_agent(session, tenant_id, agent_id)
    if agent is None:
        raise LookupError("agent_not_found")
    if role not in {"viewer", "operator", "manager"}:
        raise ValueError("invalid_agent_member_role")

    user = await session.get(User, user_id)
    if user is None or user.tenant_id != tenant_id or user.status != "active":
        raise LookupError("user_not_found")

    existing = (
        await session.execute(
            select(AgentMember).where(
                AgentMember.tenant_id == tenant_id,
                AgentMember.agent_id == agent_id,
                AgentMember.user_id == user_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.role == "manager" and role != "manager":
            manager_count = (
                await session.execute(
                    select(AgentMember).where(
                        AgentMember.tenant_id == tenant_id,
                        AgentMember.agent_id == agent_id,
                        AgentMember.role == "manager",
                    )
                )
            ).scalars().all()
            if len(manager_count) <= 1:
                raise ValueError("cannot_remove_last_agent_manager")
        existing.role = role
        await session.commit()
        return member_view(existing, user)

    row = AgentMember(
        tenant_id=tenant_id,
        agent_id=agent_id,
        user_id=user_id,
        role=role,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return member_view(row, user)


async def remove_member(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    user_id: uuid.UUID,
) -> None:
    rows = (
        await session.execute(
            select(AgentMember).where(
                AgentMember.tenant_id == tenant_id,
                AgentMember.agent_id == agent_id,
                AgentMember.user_id == user_id,
            )
        )
    ).scalars().all()
    if not rows:
        raise LookupError("agent_member_not_found")

    if rows[0].role == "manager":
        manager_count = (
            await session.execute(
                select(AgentMember).where(
                    AgentMember.tenant_id == tenant_id,
                    AgentMember.agent_id == agent_id,
                    AgentMember.role == "manager",
                )
            )
        ).scalars().all()
        if len(manager_count) <= 1:
            raise ValueError("cannot_remove_last_agent_manager")

    for row in rows:
        await session.delete(row)
    await session.commit()
