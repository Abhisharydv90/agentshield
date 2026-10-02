from datetime import datetime, timezone
import uuid

import pytest

from app.security.evidence.hashing import (
    canonicalize_evidence,
    fingerprint_evidence,
)


def test_evidence_hash_is_deterministic():
    first = {
        "node_type": "action",
        "tool_name": "db.query",
        "operation": "read",
    }

    second = {
        "operation": "read",
        "tool_name": "db.query",
        "node_type": "action",
    }

    assert canonicalize_evidence(first) == (
        canonicalize_evidence(second)
    )

    assert fingerprint_evidence(first) == (
        fingerprint_evidence(second)
    )


def test_evidence_hash_changes_when_content_changes():
    first = {
        "node_type": "action",
        "operation": "read",
    }

    second = {
        "node_type": "action",
        "operation": "write",
    }

    assert fingerprint_evidence(first) != (
        fingerprint_evidence(second)
    )


def test_uuid_and_datetime_are_canonicalized():
    evidence_id = uuid.UUID(
        "12345678-1234-5678-1234-567812345678"
    )

    timestamp = datetime(
        2026,
        10,
        2,
        12,
        0,
        tzinfo=timezone.utc,
    )

    payload = {
        "evidence_id": evidence_id,
        "timestamp": timestamp,
    }

    canonical = canonicalize_evidence(payload)

    assert str(evidence_id) in canonical
    assert timestamp.isoformat() in canonical


def test_unsupported_value_fails_closed():
    payload = {
        "bad_value": object(),
    }

    with pytest.raises(TypeError, match="unsupported_evidence_value"):
        canonicalize_evidence(payload)