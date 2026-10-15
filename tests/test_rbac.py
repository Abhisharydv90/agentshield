"""
RBAC unit tests for AgentShield.

These tests verify that management permissions are deterministic
and fail closed for unknown roles/permissions.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.security.authorization import (
    can,
    require_permission,
)


# ============================================================
# Owner
# ============================================================


def test_owner_can_manage_security_resources():

    assert can(
        "owner",
        "tenant.settings.write",
    )

    assert can(
        "owner",
        "tenant.api_keys.write",
    )

    assert can(
        "owner",
        "tenant.agents.write",
    )

    assert can(
        "owner",
        "tenant.policies.write",
    )

    assert can(
        "owner",
        "tenant.webhooks.write",
    )


# ============================================================
# Admin
# ============================================================


def test_admin_can_manage_security_resources():

    assert can(
        "admin",
        "tenant.settings.write",
    )

    assert can(
        "admin",
        "tenant.api_keys.write",
    )

    assert can(
        "admin",
        "tenant.agents.write",
    )

    assert can(
        "admin",
        "tenant.policies.write",
    )

    assert can(
        "admin",
        "tenant.webhooks.write",
    )


# ============================================================
# Member
# ============================================================


def test_member_can_read_resources():

    assert can(
        "member",
        "tenant.settings.read",
    )

    assert can(
        "member",
        "tenant.agents.read",
    )

    assert can(
        "member",
        "tenant.policies.read",
    )

    assert can(
        "member",
        "tenant.webhooks.read",
    )


def test_member_cannot_modify_resources():

    assert not can(
        "member",
        "tenant.settings.write",
    )

    assert not can(
        "member",
        "tenant.api_keys.write",
    )

    assert not can(
        "member",
        "tenant.agents.write",
    )

    assert not can(
        "member",
        "tenant.policies.write",
    )

    assert not can(
        "member",
        "tenant.webhooks.write",
    )


def test_member_cannot_delete_resources():

    assert not can(
        "member",
        "tenant.agents.delete",
    )

    assert not can(
        "member",
        "tenant.policies.delete",
    )

    assert not can(
        "member",
        "tenant.webhooks.delete",
    )


# ============================================================
# Unknown permissions
# ============================================================


def test_unknown_permission_fails_closed():

    assert not can(
        "owner",
        "unknown.permission",
    )

    assert not can(
        "admin",
        "unknown.permission",
    )


# ============================================================
# Unknown roles
# ============================================================


def test_unknown_role_is_rejected():

    with pytest.raises(
        HTTPException
    ) as exc_info:

        can(
            "superuser",
            "tenant.settings.read",
        )

    assert (
        exc_info.value.status_code
        == 403
    )


# ============================================================
# Enforcement helper
# ============================================================


def test_require_permission_allows_authorized_role():

    require_permission(
        "owner",
        "tenant.policies.write",
    )


def test_require_permission_rejects_member():

    with pytest.raises(
        HTTPException
    ) as exc_info:

        require_permission(
            "member",
            "tenant.policies.write",
        )

    assert (
        exc_info.value.status_code
        == 403
    )

    assert (
        exc_info.value.detail
        == "forbidden"
    )