"""Control Plane facade."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from .abac import ABACAuthorizer
from .config import validate_patch, version_for
from .contracts import (
    ABACContext, APIKeyView, ConfigView, OrganizationView, ProjectView,
    UsageSummary,
)
from .projects import create_record, project_id, normalize_name, reserved_key
from .repository import (
    load_api_keys, load_organization, load_projects, load_settings,
    load_usage_rows, save_project_records, save_settings,
)
from .rbac import ControlPlaneAction, require
from .usage import summarize_request_logs


class ControlPlaneService:
    """Administrative facade; it never creates or increases agent authority."""
    _abac = ABACAuthorizer()

    @classmethod
    def _auth(cls, role: object, context: ABACContext, action: ControlPlaneAction) -> None:
        require(role, action)
        cls._abac.authorize(
            principal_role=context.role,
            resource_type=context.resource_type,
            action=context.action,
            attributes={
                **context.attributes,
                "organization_id": str(context.organization_id),
                "scope_source": context.attributes.get("scope_source", "server"),
            },
        )

    @classmethod
    async def organization(cls, session: AsyncSession, *, role: object, context: ABACContext):
        cls._auth(role, context, ControlPlaneAction.READ)
        return await load_organization(session, context.organization_id)

    @classmethod
    async def list_projects(cls, session: AsyncSession, *, role: object, context: ABACContext):
        cls._auth(role, context.model_copy(update={"resource_type": "project", "action": "read"}),
                  ControlPlaneAction.READ)
        return await load_projects(session, context.organization_id)

    @classmethod
    async def create_project(
        cls, session: AsyncSession, *, role: object, context: ABACContext,
        name: str, description: str
    ):
        cls._auth(role, context.model_copy(update={"resource_type": "project", "action": "manage"}),
                  ControlPlaneAction.MANAGE_PROJECTS)
        values = await load_settings(session, context.organization_id)
        records = [r for r in values.get(reserved_key(), []) if isinstance(r, dict)]
        normalized = normalize_name(name)
        pid = project_id(context.organization_id, normalized)
        if any(str(r.get("project_id")) == pid for r in records):
            raise ValueError("project already exists")
        records.append(create_record(
            organization_id=context.organization_id,
            name=normalized,
            description=description,
        ))
        await save_project_records(session, context.organization_id, records)
        return next(r for r in await load_projects(session, context.organization_id)
                    if r.project_id == pid)

    @classmethod
    async def delete_project(
        cls, session: AsyncSession, *, role: object, context: ABACContext, project_name: str
    ) -> None:
        cls._auth(role, context.model_copy(update={"resource_type": "project", "action": "manage"}),
                  ControlPlaneAction.MANAGE_PROJECTS)
        values = await load_settings(session, context.organization_id)
        records = [r for r in values.get(reserved_key(), []) if isinstance(r, dict)]
        pid = project_id(context.organization_id, project_name)
        kept = [r for r in records if str(r.get("project_id")) != pid]
        if len(kept) == len(records):
            raise LookupError("project not found")
        await save_project_records(session, context.organization_id, kept)

    @classmethod
    async def configuration(
        cls, session: AsyncSession, *, role: object, context: ABACContext,
        patch: dict[str, Any] | None = None
    ) -> ConfigView:
        action = ControlPlaneAction.CONFIGURE if patch is not None else ControlPlaneAction.READ
        cls._auth(role, context.model_copy(update={"resource_type": "configuration", "action": action.value}), action)
        current = await load_settings(session, context.organization_id)
        next_values = validate_patch(current, patch) if patch is not None else current
        if patch is not None:
            await save_settings(session, context.organization_id, next_values)
        return ConfigView(
            organization_id=context.organization_id,
            version=version_for(next_values),
            values=next_values,
            mutable_keys=sorted(k for k in next_values if not k.startswith("_")),
        )

    @classmethod
    async def api_keys(cls, session: AsyncSession, *, role: object, context: ABACContext):
        cls._auth(role, context.model_copy(update={"resource_type": "api_key", "action": "read"}),
                  ControlPlaneAction.MANAGE_API_KEYS)
        return await load_api_keys(session, context.organization_id)

    @classmethod
    async def usage(
        cls, session: AsyncSession, *, role: object, context: ABACContext,
        since: datetime | None, limit: int
    ) -> UsageSummary:
        cls._auth(role, context.model_copy(update={"resource_type": "billing", "action": "read"}),
                  ControlPlaneAction.VIEW_USAGE)
        rows = await load_usage_rows(session, context.organization_id, since, min(max(limit, 1), 5000))
        return summarize_request_logs(
            organization_id=context.organization_id, rows=rows, since=since
        )
