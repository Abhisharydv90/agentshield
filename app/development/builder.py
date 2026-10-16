"""Agent Builder primitives for AURAGENT Phase 1."""

from __future__ import annotations

from typing import Any

from app.development.templates import normalize_manifest


def build_manifest(
    *,
    runtime: str,
    entrypoint: str,
    model: str | None = None,
    tools: list[str] | None = None,
    environment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    runtime = runtime.strip()
    entrypoint = entrypoint.strip()
    if not runtime:
        raise ValueError("agent_runtime_required")
    if not entrypoint:
        raise ValueError("agent_entrypoint_required")
    manifest: dict[str, Any] = {
        "runtime": runtime,
        "entrypoint": entrypoint,
        "tools": list(tools or []),
        "environment": dict(environment or {}),
    }
    if model:
        manifest["model"] = model.strip()
    return normalize_manifest(manifest)
