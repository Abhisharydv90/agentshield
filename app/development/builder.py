"""Agent Builder primitives for AURAGENT Phase 1."""

from __future__ import annotations

from typing import Any

from app.development.manifests.manifest import AgentManifest
from app.development.templates import normalize_manifest


def build_manifest(
    *,
    runtime: str,
    entrypoint: str,
    model: str | None = None,
    tools: list[str] | None = None,
    environment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = AgentManifest(
        runtime=runtime,
        entrypoint=entrypoint,
        model=model,
        tools=list(tools or []),
        environment=dict(environment or {}),
    ).bounded_dict()
    return normalize_manifest(manifest)
