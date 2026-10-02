"""
Unit tests for AgentShield capability authorization.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.security.capabilities import (
    Capability,
    has_capability,
    normalize_capabilities,
    require_capability,
)


def test_valid_capabilities_are_normalized():

    result = normalize_capabilities(
        [
            "agent:invoke",
            "tool:read",
            "agent:invoke",
        ]
    )

    assert result == [
        "agent:invoke",
        "tool:read",
    ]


def test_unknown_capability_is_rejected():

    with pytest.raises(
        ValueError
    ):

        normalize_capabilities(
            [
                "agent:invoke",
                "root:everything",
            ]
        )


def test_agent_invoke_capability_is_detected():

    assert has_capability(
        ["agent:invoke"],
        Capability.AGENT_INVOKE,
    )


def test_missing_capability_returns_false():

    assert not has_capability(
        ["tool:read"],
        Capability.AGENT_INVOKE,
    )


def test_require_capability_allows_authorized_agent():

    require_capability(
        ["agent:invoke"],
        Capability.AGENT_INVOKE,
    )


def test_require_capability_rejects_missing_authority():

    with pytest.raises(
        HTTPException
    ) as exc_info:

        require_capability(
            ["tool:read"],
            Capability.AGENT_INVOKE,
        )

    assert (
        exc_info.value.status_code
        == 403
    )


def test_invalid_stored_capability_fails_closed():

    with pytest.raises(
        HTTPException
    ) as exc_info:

        require_capability(
            [
                "agent:invoke",
                "unknown:authority",
            ],
            Capability.AGENT_INVOKE,
        )

    assert (
        exc_info.value.status_code
        == 403
    )


def test_no_wildcard_capability():

    assert not has_capability(
        ["*"],
        Capability.AGENT_INVOKE,
    )