"""Persistence adapters over existing AURAGENT core models."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import APIKey, RequestLog, Tenant, TenantSettings

from .api_management import api_key_view
from .contracts import APIKeyView, OrganizationView
from .projects import reserved_key, record_to_view


def _field(model_or_row: Any, *names: str) -> Any:
    for name in names:
        if hasattr(model_or_row, name):
            return getattr(model_or_row, name)
    return None


def _settings_dict(row: Any) -> dict[str, Any]:
    for name in ("settings", "config", "configuration", "values", "data", "metadata_json"):
        value = getattr(row, name, None)
        if isinstance(value, dict):
            return dict(value)
    return {}


def _json_column_name(row: Any) -> str | None:
    for name in ("settings", "config", "configuration", "values", "data", "metadata_json"):
        value = getattr(row, name, None)
        if value is not None and isinstance(value, dict):
            return name
    for name in ("settings", "config", "configuration", "values", "data", "metadata_json"):
        if hasattr(row, name):
            return name
    return None


async def load_organization(session: AsyncSession, organization_id: UUID) -> OrganizationView | None:
    result = await session.execute(
        select(Tenant).where(Tenant.tenant_id == organization_id).limit(1)
    )
    tenant = result.scalar_one_or_none()
    if tenant is None:
        return None

    settings_result = await session.execute(
        select(TenantSettings).where(TenantSettings.tenant_id == organization_id).limit(1)
    )
    settings_row = settings_result.scalar_one_or_none()
    return OrganizationView(
        organization_id=tenant.tenant_id,
        name=str(_field(tenant, "name", "tenant_name") or tenant.tenant_id),
        status=str(_field(tenant, "status", "state") or "active"),
        created_at=_field(tenant, "created_at"),
        settings_available=settings_row is not None,
    )


async def load_settings(session: AsyncSession, organization_id: UUID) -> dict[str, Any]:
    result = await session.execute(
        select(TenantSettings).where(TenantSettings.tenant_id == organization_id).limit(1)
    )
    row = result.scalar_one_or_none()
    return _settings_dict(row) if row else {}


async def save_settings(
    session: AsyncSession, organization_id: UUID, values: dict[str, Any]
) -> None:
    result = await session.execute(
        select(TenantSettings).where(TenantSettings.tenant_id == organization_id).limit(1)
    )
    row = result.scalar_one_or_none()
    if row is None:
        raise LookupError("tenant settings row does not exist")
    name = _json_column_name(row)
    if not name:
        raise RuntimeError("TenantSettings has no supported JSON configuration column")
    setattr(row, name, dict(values))


async def load_api_keys(
    session: AsyncSession, organization_id: UUID
) -> list[APIKeyView]:
    statement = select(APIKey).where(APIKey.tenant_id == organization_id)
    created_col = _field(APIKey, "created_at", "issued_at")
    if created_col is not None:
        statement = statement.order_by(created_col.desc())
    result = await session.execute(statement)
    return [api_key_view(row, organization_id) for row in result.scalars().all()]


async def load_usage_rows(
    session: AsyncSession,
    organization_id: UUID,
    since: datetime | None,
    limit: int,
) -> list[RequestLog]:
    statement = select(RequestLog).where(RequestLog.tenant_id == organization_id)
    timestamp_col = _field(RequestLog, "timestamp", "created_at")
    if since is not None and timestamp_col is not None:
        statement = statement.where(timestamp_col >= since)
    if timestamp_col is not None:
        statement = statement.order_by(timestamp_col.desc())
    result = await session.execute(statement.limit(limit))
    return list(result.scalars().all())


async def save_project_records(
    session: AsyncSession,
    organization_id: UUID,
    records: list[dict[str, Any]],
) -> None:
    values = await load_settings(session, organization_id)
    values[reserved_key()] = records
    await save_settings(session, organization_id, values)


async def load_projects(
    session: AsyncSession, organization_id: UUID
) -> list[Any]:
    values = await load_settings(session, organization_id)
    raw = values.get(reserved_key(), [])
    if not isinstance(raw, list):
        return []
    return [record_to_view(organization_id, r) for r in raw if isinstance(r, dict)]
