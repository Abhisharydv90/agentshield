"""
AgentShield capability system.

Human and Agent authorization are separate security planes.

Human:
    User -> Role -> Management Permission

Agent:
    API Key -> Agent -> Capability -> Runtime Action

Capabilities are intentionally explicit.

Unknown capabilities fail closed.
Unknown runtime operations fail closed.
Wildcard authority is not supported.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Iterable, Sequence

from fastapi import HTTPException


# ============================================================
# Capability vocabulary
# ============================================================


class Capability(StrEnum):
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


# ============================================================
# Operation -> required capabilities
# ============================================================

OPERATION_CAPABILITIES: dict[
    str,
    tuple[Capability, ...],
] = {
    "read": (
        Capability.TOOL_READ,
    ),

    "write": (
        Capability.TOOL_WRITE,
    ),

    "delete": (
        Capability.TOOL_DELETE,
    ),

    "execute": (
        Capability.TOOL_EXECUTE,
    ),

    # External actions require both the ability to execute
    # the tool and permission to make network egress.
    "external_call": (
        Capability.TOOL_EXECUTE,
        Capability.NETWORK_EGRESS,
    ),
}


def required_capabilities_for_operation(
    operation: str,
) -> tuple[Capability, ...]:
    """
    Return the capabilities required for a normalized operation.

    Unknown operations intentionally return an empty tuple;
    callers must separately reject unknown operations.
    """

    return OPERATION_CAPABILITIES.get(
        operation,
        (),
    )


# ============================================================
# Capability normalization
# ============================================================


def normalize_capabilities(
    values: Iterable[str],
) -> list[str]:
    """
    Validate and deduplicate an Agent capability set.
    """

    normalized: list[str] = []
    seen: set[str] = set()

    for raw in values:

        value = str(
            raw
        ).strip()

        if not value:
            continue

        if value not in CAPABILITY_VALUES:

            raise ValueError(
                f"Unknown capability: {value}"
            )

        if value in seen:
            continue

        seen.add(
            value
        )

        normalized.append(
            value
        )

    return normalized


# ============================================================
# Capability lookup
# ============================================================


def missing_capabilities(
    scopes: Iterable[str],
    required: Sequence[
        Capability | str
    ],
) -> list[str]:
    """
    Return required capabilities that are missing.

    Invalid stored scopes also fail closed by being reported
    as missing/invalid authority.
    """

    normalized_scopes = {
        str(scope).strip()
        for scope in scopes
        if str(scope).strip()
    }

    invalid_scopes = [
        scope
        for scope in normalized_scopes
        if scope not in CAPABILITY_VALUES
    ]

    if invalid_scopes:

        return sorted(
            set(invalid_scopes)
        )

    missing: list[str] = []

    for item in required:

        value = (
            item.value
            if isinstance(
                item,
                Capability,
            )
            else str(item)
        )

        if value not in CAPABILITY_VALUES:

            missing.append(
                value
            )

        elif value not in normalized_scopes:

            missing.append(
                value
            )

    return missing


def has_capability(
    scopes: Iterable[str],
    capability: Capability | str,
) -> bool:
    """
    Check one explicit capability.
    """

    required = (
        capability.value
        if isinstance(
            capability,
            Capability,
        )
        else str(
            capability
        )
    )

    if required not in CAPABILITY_VALUES:
        return False

    return not missing_capabilities(
        scopes,
        [required],
    )


# ============================================================
# Enforcement
# ============================================================


def require_capability(
    scopes: Iterable[str],
    capability: Capability | str,
) -> None:
    """
    Raise HTTP 403 unless the requested capability exists.
    """

    required = (
        capability.value
        if isinstance(
            capability,
            Capability,
        )
        else str(
            capability
        )
    )

    missing = missing_capabilities(
        scopes,
        [required],
    )

    if missing:

        raise HTTPException(
            status_code=403,
            detail={
                "error":
                    "capability_required",
                "capability":
                    required,
            },
        )


def require_operation_capabilities(
    scopes: Iterable[str],
    operation: str,
) -> None:
    """
    Enforce the complete capability set required by
    a normalized runtime operation.
    """

    if operation not in OPERATION_CAPABILITIES:

        raise HTTPException(
            status_code=403,
            detail={
                "error":
                    "unknown_operation",
                "operation":
                    operation,
            },
        )

    required = required_capabilities_for_operation(
        operation
    )

    missing = missing_capabilities(
        scopes,
        required,
    )

    if missing:

        raise HTTPException(
            status_code=403,
            detail={
                "error":
                    "capabilities_required",
                "operation":
                    operation,
                "missing":
                    missing,
            },
        )