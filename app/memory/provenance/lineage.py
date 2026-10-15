"""Tamper-evident memory provenance lineage records."""

from __future__ import annotations

from typing import Any, Mapping

from app.security.identity.crypto import sha256_hex


def lineage_fingerprint(
    *,
    tenant_id: str,
    memory_id: str,
    version_id: str | None,
    operation: str,
    actor_agent_id: str,
    content_hash: str,
    previous_lineage_hash: str | None,
    metadata: Mapping[str, Any] | None = None,
) -> str:
    payload = {
        "schema": "auragent.memory-lineage.v1",
        "tenant_id": tenant_id,
        "memory_id": memory_id,
        "version_id": version_id,
        "operation": operation,
        "actor_agent_id": actor_agent_id,
        "content_hash": content_hash,
        "previous_lineage_hash": previous_lineage_hash,
        "metadata": dict(metadata or {}),
    }
    return sha256_hex(payload)


def lineage_payload(**kwargs: Any) -> dict[str, Any]:
    payload = dict(kwargs)
    payload["schema"] = "auragent.memory-lineage.v1"
    return payload
