"""Persistent logical projects stored inside TenantSettings JSON configuration."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from .contracts import ProjectView

_KEY = "_auragent_projects"
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def normalize_name(name: str) -> str:
    value = name.strip()
    if not _NAME.fullmatch(value):
        raise ValueError(
            "project name must be 1-64 chars and use only letters, numbers, '.', '_' or '-'"
        )
    return value


def project_id(organization_id: UUID, name: str) -> str:
    normalized = normalize_name(name).casefold()
    digest = hashlib.sha256(
        f"{organization_id}:{normalized}".encode("utf-8")
    ).hexdigest()
    return f"prj_{digest[:24]}"


def record_to_view(organization_id: UUID, record: dict[str, Any]) -> ProjectView:
    return ProjectView(
        project_id=str(record["project_id"]),
        organization_id=organization_id,
        name=str(record["name"]),
        status=str(record.get("status", "active")),
        description=str(record.get("description", "")),
        created_at=(
            datetime.fromisoformat(record["created_at"])
            if record.get("created_at") else None
        ),
    )


def create_record(
    *,
    organization_id: UUID,
    name: str,
    description: str,
) -> dict[str, Any]:
    name = normalize_name(name)
    return {
        "project_id": project_id(organization_id, name),
        "organization_id": str(organization_id),
        "name": name,
        "description": description.strip()[:500],
        "status": "active",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def reserved_key() -> str:
    return _KEY
