"""
Tool authorization tests.

These tests prove that:

- tool capabilities map to normalized operations
- missing capabilities fail closed
- external calls require network egress
- unknown operations are rejected
- non-SQL tool names are normalized correctly
- streaming tool-call fragments are not leaked by the gate
"""

from __future__ import annotations

from fastapi import HTTPException
import pytest

from app.policy.dsl import EXAMPLE_POLICY
from app.security.capabilities import (
    Capability,
    has_capability,
    missing_capabilities,
    required_capabilities_for_operation,
)
from app.security.judge.normalize import (
    normalize_tool_call,
)
from app.security.judge.stream_buffer import (
    StreamingToolCallGate,
)


# ============================================================
# Capability mapping
# ============================================================


def test_read_requires_tool_read():

    required = (
        required_capabilities_for_operation(
            "read"
        )
    )

    assert required == (
        Capability.TOOL_READ,
    )


def test_write_requires_tool_write():

    required = (
        required_capabilities_for_operation(
            "write"
        )
    )

    assert required == (
        Capability.TOOL_WRITE,
    )


def test_delete_requires_tool_delete():

    required = (
        required_capabilities_for_operation(
            "delete"
        )
    )

    assert required == (
        Capability.TOOL_DELETE,
    )


def test_execute_requires_tool_execute():

    required = (
        required_capabilities_for_operation(
            "execute"
        )
    )

    assert required == (
        Capability.TOOL_EXECUTE,
    )


def test_external_call_requires_execution_and_network():

    required = (
        required_capabilities_for_operation(
            "external_call"
        )
    )

    assert required == (
        Capability.TOOL_EXECUTE,
        Capability.NETWORK_EGRESS,
    )


# ============================================================
# Missing capabilities
# ============================================================


def test_missing_tool_capability():

    missing = missing_capabilities(
        ["agent:invoke"],
        [
            Capability.TOOL_READ
        ],
    )

    assert (
        "tool:read"
        in missing
    )


def test_capability_exists():

    assert has_capability(
        [
            "agent:invoke",
            "tool:read",
        ],
        Capability.TOOL_READ,
    )


# ============================================================
# Normalization
# ============================================================


def test_db_query_is_read():

    result = normalize_tool_call(
        {
            "name":
                "db.query",
            "args": {
                "query":
                    "SELECT * FROM billing_invoices",
                "table":
                    "billing_invoices",
            },
        }
    )

    assert result["op"] == "read"

    assert (
        result["target"]
        == "billing_invoices"
    )


def test_email_tool_is_external_call():

    result = normalize_tool_call(
        {
            "name":
                "email.send",
            "args": {
                "to":
                    "user@example.com",
                "subject":
                    "hello",
            },
        }
    )

    assert (
        result["op"]
        == "external_call"
    )


def test_http_tool_is_external_call():

    result = normalize_tool_call(
        {
            "name":
                "http.request",
            "args": {
                "host":
                    "example.com",
                "url":
                    "https://example.com",
            },
        }
    )

    assert (
        result["op"]
        == "external_call"
    )


def test_streaming_arguments_shape_is_supported():

    result = normalize_tool_call(
        {
            "name":
                "db.query",
            "arguments": {
                "query":
                    "SELECT * FROM billing_invoices",
                "table":
                    "billing_invoices",
            },
        }
    )

    assert result["op"] == "read"


def test_unknown_tool_operation_is_not_inferred_as_safe():

    result = normalize_tool_call(
        {
            "name":
                "mystery.operation",
            "args": {
                "value":
                    "hello",
            },
        }
    )

    assert (
        result["op"]
        == "unknown"
    )


# ============================================================
# Smuggling
# ============================================================


def test_compound_sql_is_detected():

    result = normalize_tool_call(
        {
            "name":
                "db.query",
            "args": {
                "query":
                    "SELECT * FROM users; DROP TABLE users",
                "table":
                    "users",
            },
        }
    )

    assert (
        result[
            "contains_compound_statement"
        ]
        is True
    )


# ============================================================
# Streaming gate
# ============================================================


def test_streaming_tool_fragments_are_not_forwarded():

    gate = StreamingToolCallGate()

    first_chunk = {
        "choices": [
            {
                "delta": {
                    "tool_calls": [
                        {
                            "index":
                                0,
                            "id":
                                "call_1",
                            "function": {
                                "name":
                                    "db.query",
                                "arguments":
                                    (
                                        '{"query":"SELECT '
                                    ),
                            },
                        }
                    ]
                },
                "finish_reason":
                    None,
            }
        ]
    }

    passthrough, completed = (
        gate.feed(
            first_chunk
        )
    )

    assert completed == []

    # The downstream stream must not contain the
    # attacker-controlled/incomplete tool call.
    assert not any(
        "tool_calls"
        in item
        for item in passthrough
    )


def test_streaming_tool_call_is_released_only_after_completion():

    gate = StreamingToolCallGate()

    chunks = [
        {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {
                                "index":
                                    0,
                                "id":
                                    "call_1",
                                "function": {
                                    "name":
                                        "db.query",
                                    "arguments":
                                        (
                                            '{"query":'
                                            '"SELECT * '
                                        ),
                                },
                            }
                        ]
                    },
                    "finish_reason":
                        None,
                }
            ]
        },
        {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {
                                "index":
                                    0,
                                "function": {
                                    "arguments":
                                        (
                                            'FROM billing_invoices",'
                                            '"table":'
                                            '"billing_invoices"}'
                                        ),
                                },
                            }
                        ]
                    },
                    "finish_reason":
                        "tool_calls",
                }
            ]
        },
    ]

    completed = []

    for chunk in chunks:

        passthrough, finished = (
            gate.feed(
                chunk
            )
        )

        assert not any(
            "tool_calls"
            in item
            for item in passthrough
        )

        completed.extend(
            finished
        )

    assert len(
        completed
    ) == 1

    assert (
        completed[0]["name"]
        == "db.query"
    )

    assert (
        completed[0]["arguments"]["table"]
        == "billing_invoices"
    )


# ============================================================
# Defensive policy baseline
# ============================================================


def test_example_policy_remains_deny_by_default():

    assert (
        EXAMPLE_POLICY.default
        == "deny"
    )