"""Canonical tenant configuration helpers."""
from __future__ import annotations
import hashlib
import json
from typing import Any

IMMUTABLE_KEYS = {"tenant_id", "security_kernel", "authority_model"}


def canonicalize(values: dict[str, Any]) -> str:
    return json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def version_for(values: dict[str, Any]) -> str:
    return hashlib.sha256(canonicalize(values).encode("utf-8")).hexdigest()


def validate_patch(current: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    illegal = sorted(set(patch) & IMMUTABLE_KEYS)
    if illegal:
        raise ValueError(f"immutable keys cannot be changed: {illegal}")
    next_values = dict(current)
    for key, value in patch.items():
        if key.startswith("_"):
            raise ValueError("reserved configuration keys are not directly mutable")
        next_values[key] = value
    return next_values
