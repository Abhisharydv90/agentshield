"""
PII security tests.

These tests verify placeholder behavior and the absence of the
old hard-coded secret.
"""

from __future__ import annotations

import hashlib
import hmac

from app.security.pii.redactor import (
    _make_placeholder,
)


def test_placeholder_is_not_raw_pii():

    raw_email = "alice@example.com"

    placeholder = _make_placeholder(
        kind="EMAIL_ADDRESS",
        value=raw_email,
        trace_id="trace-123",
        tenant="tenant-a",
    )

    assert raw_email not in placeholder

    assert placeholder.startswith(
        "<EMAIL_ADDRESS_"
    )

    assert placeholder.endswith(
        ">"
    )


def test_same_inputs_produce_same_placeholder():

    first = _make_placeholder(
        kind="EMAIL_ADDRESS",
        value="alice@example.com",
        trace_id="trace-123",
        tenant="tenant-a",
    )

    second = _make_placeholder(
        kind="EMAIL_ADDRESS",
        value="alice@example.com",
        trace_id="trace-123",
        tenant="tenant-a",
    )

    assert first == second


def test_different_tenants_produce_different_placeholders():

    tenant_a = _make_placeholder(
        kind="EMAIL_ADDRESS",
        value="alice@example.com",
        trace_id="trace-123",
        tenant="tenant-a",
    )

    tenant_b = _make_placeholder(
        kind="EMAIL_ADDRESS",
        value="alice@example.com",
        trace_id="trace-123",
        tenant="tenant-b",
    )

    assert tenant_a != tenant_b


def test_different_trace_ids_produce_different_placeholders():

    trace_a = _make_placeholder(
        kind="EMAIL_ADDRESS",
        value="alice@example.com",
        trace_id="trace-a",
        tenant="tenant-a",
    )

    trace_b = _make_placeholder(
        kind="EMAIL_ADDRESS",
        value="alice@example.com",
        trace_id="trace-b",
        tenant="tenant-a",
    )

    assert trace_a != trace_b


def test_placeholder_does_not_use_old_hardcoded_secret():

    old_secret = (
        b"agentshield-dev-secret-rotate-in-prod"
    )

    raw = (
        "v1|tenant-a|trace-123|"
        "EMAIL_ADDRESS|alice@example.com"
    )

    old_mac = hmac.new(
        old_secret,
        raw.encode(),
        hashlib.sha256,
    ).hexdigest()

    placeholder = _make_placeholder(
        kind="EMAIL_ADDRESS",
        value="alice@example.com",
        trace_id="trace-123",
        tenant="tenant-a",
    )

    assert old_mac[:16] not in placeholder