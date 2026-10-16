"""Reusable agent template helpers."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from app.security.capabilities import normalize_capabilities


_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def normalize_version(value: str) -> str:
    value = str(value).strip()
    if not _VERSION_RE.fullmatch(value):
        raise ValueError("invalid_agent_version")
    return value


def normalize_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ValueError("agent_manifest_must_be_object")
    encoded = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode("utf-8")) > 256 * 1024:
        raise ValueError("agent_manifest_too_large")
    return manifest


def content_hash(*, name: str, description: str, version: str, capabilities: list[str], manifest: dict[str, Any]) -> str:
    payload = {
        "name": name,
        "description": description,
        "version": version,
        "capabilities": sorted(capabilities),
        "manifest": manifest,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def normalize_template_capabilities(values: list[str]) -> list[str]:
    return normalize_capabilities(values)
