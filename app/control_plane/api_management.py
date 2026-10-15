"""Safe API-key inventory adapter; secret material is never returned."""
from __future__ import annotations
from datetime import datetime
from typing import Any
from uuid import UUID
from .contracts import APIKeyView


def _get(obj: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return default


def api_key_view(row: Any, organization_id: UUID) -> APIKeyView:
    key_id = _get(row, "key_id", "api_key_id", "id", default="unknown")
    prefix = _get(row, "prefix", "key_prefix", default="")
    active = bool(_get(row, "active", "is_active", default=True))
    created = _get(row, "created_at", "issued_at")
    expires = _get(row, "expires_at", "expiry")
    last_used = _get(row, "last_used_at", "last_used")
    return APIKeyView(
        key_id=str(key_id),
        organization_id=organization_id,
        prefix=str(prefix),
        active=active,
        created_at=created if isinstance(created, datetime) else None,
        expires_at=expires if isinstance(expires, datetime) else None,
        last_used_at=last_used if isinstance(last_used, datetime) else None,
    )
