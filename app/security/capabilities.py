"""
AgentShield capability system.

Capabilities are explicit authorities assigned to an Agent.

This is separate from human RBAC.

Human:
    User -> Role -> Management Permission

Agent:
    API Key -> Agent -> Capability -> Runtime Action

Security principle:
    Unknown capabilities are rejected.
    Missing capabilities fail closed.
    No wildcard capability exists.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Iterable

from fastapi import HTTPException


class Capability(StrEnum):
    """
    Controlled AgentShield capability vocabulary.
    """

    AGENT_INVOKE = "agent:invoke"

    TOOL_READ = "tool:read"
    TOOL_WRITE = "tool:write"
    TOOL_DELETE = "tool:delete"
    TOOL_EXECUTE = "tool:execute"

    FILESYSTEM_READ = "filesystem:read"
    FILESYSTEM_WRITE = "filesystem:write"

    NETWORK_EGRESS = "network:egress"

    MEMORY_READ = "memory:read"
    MEMORY_WRITE = "memory:write"

    SECRET_USE = "secret:use"

    AGENT_DELEGATE = "agent:delegate"


CAPABILITY_VALUES = frozenset(
    capability.value
    for capability in Capability
)


def normalize_capabilities(
    values: Iterable[str],
) -> list[str]:
    """
    Validate and normalize a capability list.

    Unknown capability names raise ValueError so the function can
    be used directly inside Pydantic validators.
    """

    normalized: list[str] = []
    seen: set[str] = set()

    for raw in values:

        value = str(raw).strip()

        if not value:
            continue

        if value not in CAPABILITY_VALUES:
            raise ValueError(
                f"Unknown capability: {value}"
            )

        if value in seen:
            continue

        seen.add(value)
        normalized.append(value)

    return normalized


def has_capability(
    scopes: Iterable[str],
    capability: Capability | str,
) -> bool:
    """
    Return True only if the Agent explicitly possesses the
    requested capability.
    """

    requested = (
        capability.value
        if isinstance(
            capability,
            Capability,
        )
        else str(capability)
    )

    if requested not in CAPABILITY_VALUES:
        return False

    return requested in set(
        str(scope).strip()
        for scope in scopes
    )


def require_capability(
    scopes: Iterable[str],
    capability: Capability | str,
) -> None:
    """
    Enforce a capability.

    Invalid stored capability configuration and missing
    capabilities both fail closed.
    """

    scope_values = [
        str(scope).strip()
        for scope in scopes
    ]

    invalid = [
        scope
        for scope in scope_values
        if scope and scope not in CAPABILITY_VALUES
    ]

    if invalid:
        raise HTTPException(
            status_code=403,
            detail="invalid_capability_configuration",
        )

    if not has_capability(
        scope_values,
        capability,
    ):
        requested = (
            capability.value
            if isinstance(
                capability,
                Capability,
            )
            else str(capability)
        )

        raise HTTPException(
            status_code=403,
            detail={
                "error": "capability_required",
                "capability": requested,
            },
        )