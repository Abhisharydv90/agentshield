"""
Canonical evidence serialization and hashing.

Evidence hashes are content-addressed identifiers for security artifacts.

Security properties:

- deterministic across equivalent Python representations
- stable ordering for dictionaries
- timezone-normalized datetimes
- UUIDs represented canonically
- compact JSON encoding
- SHA-256 output encoded as lowercase hexadecimal

The evidence hash is intentionally computed from the artifact content,
not from database IDs or insertion timestamps.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any


def _normalize(value: Any) -> Any:
    """
    Convert supported Python values into deterministic JSON-safe values.
    """

    if isinstance(value, dict):
        return {
            str(key): _normalize(value[key])
            for key in sorted(value, key=lambda item: str(item))
        }

    if isinstance(value, (list, tuple)):
        return [
            _normalize(item)
            for item in value
        ]

    if isinstance(value, uuid.UUID):
        return str(value)

    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        else:
            value = value.astimezone(timezone.utc)

        return value.isoformat()

    if isinstance(value, Decimal):
        return str(value)

    if value is None or isinstance(
        value,
        (str, int, float, bool),
    ):
        return value

    raise TypeError(
        f"unsupported_evidence_value:{type(value).__name__}"
    )


def canonicalize_evidence(
    payload: dict[str, Any],
) -> str:
    """
    Produce deterministic canonical JSON for an evidence artifact.
    """

    normalized = _normalize(payload)

    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def fingerprint_evidence(
    payload: dict[str, Any],
) -> str:
    """
    Compute the SHA-256 content fingerprint of an evidence artifact.
    """

    canonical = canonicalize_evidence(
        payload
    )

    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()