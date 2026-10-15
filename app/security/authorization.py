"""
AgentShield authorization primitives.

Human authorization is deliberately separate from agent capabilities.

Human roles:
    owner
    admin
    member

This module contains deterministic authorization rules only.
It does not access the database and does not make network calls.

Security principle:
    Unknown permissions fail closed.
"""

from __future__ import annotations

from enum import StrEnum

from fastapi import HTTPException


# ============================================================
# Roles
# ============================================================


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


# ============================================================
# Management permissions
# ============================================================


PERMISSIONS: dict[str, set[Role]] = {
    # --------------------------------------------------------
    # Tenant
    # --------------------------------------------------------

    "tenant.read": {
        Role.OWNER,
        Role.ADMIN,
        Role.MEMBER,
    },

    # --------------------------------------------------------
    # Tenant settings
    # --------------------------------------------------------

    "tenant.settings.read": {
        Role.OWNER,
        Role.ADMIN,
        Role.MEMBER,
    },

    "tenant.settings.write": {
        Role.OWNER,
        Role.ADMIN,
    },

    # --------------------------------------------------------
    # API keys
    # --------------------------------------------------------

    "tenant.api_keys.read": {
        Role.OWNER,
        Role.ADMIN,
    },

    "tenant.api_keys.write": {
        Role.OWNER,
        Role.ADMIN,
    },

    # --------------------------------------------------------
    # Agents
    # --------------------------------------------------------

    "tenant.agents.read": {
        Role.OWNER,
        Role.ADMIN,
        Role.MEMBER,
    },

    "tenant.agents.write": {
        Role.OWNER,
        Role.ADMIN,
    },

    "tenant.agents.delete": {
        Role.OWNER,
        Role.ADMIN,
    },

    # --------------------------------------------------------
    # Policies
    # --------------------------------------------------------

    "tenant.policies.read": {
        Role.OWNER,
        Role.ADMIN,
        Role.MEMBER,
    },

    "tenant.policies.write": {
        Role.OWNER,
        Role.ADMIN,
    },

    "tenant.policies.delete": {
        Role.OWNER,
        Role.ADMIN,
    },

    # --------------------------------------------------------
    # Webhooks
    # --------------------------------------------------------

    "tenant.webhooks.read": {
        Role.OWNER,
        Role.ADMIN,
        Role.MEMBER,
    },

    "tenant.webhooks.write": {
        Role.OWNER,
        Role.ADMIN,
    },

    "tenant.webhooks.delete": {
        Role.OWNER,
        Role.ADMIN,
    },

    # --------------------------------------------------------
    # Human approval control plane
    # --------------------------------------------------------

    "tenant.approvals.read": {
        Role.OWNER,
        Role.ADMIN,
    },

    "tenant.approvals.decide": {
        Role.OWNER,
        Role.ADMIN,
    },

    # --------------------------------------------------------
    # Evidence investigation control plane
    # --------------------------------------------------------
    #
    # Reading evidence is available to all tenant users.
    # Verification and compliance export are elevated operations.

    "tenant.evidence.read": {
        Role.OWNER,
        Role.ADMIN,
        Role.MEMBER,
    },

    "tenant.evidence.verify": {
        Role.OWNER,
        Role.ADMIN,
    },

    "tenant.evidence.export": {
        Role.OWNER,
        Role.ADMIN,
    },
}


# ============================================================
# Role normalization
# ============================================================


def normalize_role(
    role: str,
) -> Role:
    """
    Convert an arbitrary database role value into the controlled
    Role enum.

    Unknown roles fail closed.
    """

    try:
        return Role(role)
    except ValueError as exc:
        raise HTTPException(
            status_code=403,
            detail="invalid_role",
        ) from exc


# ============================================================
# Permission check
# ============================================================


def can(
    role: str,
    permission: str,
) -> bool:
    """
    Return True only when the supplied role has the requested
    permission.

    Unknown permissions intentionally return False.
    """

    normalized_role = normalize_role(
        role
    )

    allowed_roles = PERMISSIONS.get(
        permission
    )

    if allowed_roles is None:
        return False

    return normalized_role in allowed_roles


# ============================================================
# Enforcement
# ============================================================


def require_permission(
    role: str,
    permission: str,
) -> None:
    """
    Enforce one management permission.

    Raises HTTP 403 when the role is not authorized.
    """

    if not can(
        role,
        permission,
    ):
        raise HTTPException(
            status_code=403,
            detail="forbidden",
        )