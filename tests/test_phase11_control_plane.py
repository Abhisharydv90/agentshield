"""Deterministic Phase 11 control-plane tests."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest

from app.control_plane.abac import ABACAuthorizer, ABACDenied
from app.control_plane.config import validate_patch, version_for
from app.control_plane.projects import project_id, normalize_name
from app.control_plane.rbac import ControlPlaneAction, allowed
from app.control_plane.usage import summarize_request_logs


TENANT = UUID("11111111-1111-1111-1111-111111111111")


def test_owner_admin_member_rbac():
    assert allowed("owner", ControlPlaneAction.CONFIGURE)
    assert allowed("admin", ControlPlaneAction.MANAGE_PROJECTS)
    assert not allowed("member", ControlPlaneAction.MANAGE_API_KEYS)


def test_abac_requires_server_scope():
    with pytest.raises(ABACDenied):
        ABACAuthorizer().authorize(
            principal_role="admin",
            resource_type="project",
            action="read",
            attributes={"organization_id": str(TENANT)},
        )


def test_project_id_is_deterministic_and_tenant_bound():
    a = project_id(TENANT, "core")
    b = project_id(TENANT, "core")
    c = project_id(UUID("22222222-2222-2222-2222-222222222222"), "core")
    assert a == b
    assert a != c
    assert a.startswith("prj_")


@pytest.mark.parametrize("bad", ["", "space name", "*" * 65, "semi;colon"])
def test_bad_project_name_rejected(bad: str):
    with pytest.raises(ValueError):
        normalize_name(bad)


def test_configuration_security_keys_are_immutable():
    with pytest.raises(ValueError):
        validate_patch({"authority_model": "safe"}, {"authority_model": "weak"})


def test_configuration_version_is_canonical():
    assert version_for({"b": 2, "a": 1}) == version_for({"a": 1, "b": 2})
    assert len(version_for({"a": 1})) == 64


class Row:
    def __init__(self, decision: str):
        self.decision = decision


def test_usage_summary():
    result = summarize_request_logs(
        organization_id=TENANT,
        rows=[Row("approved"), Row("blocked"), Row("denied"), Row("approved")],
        since=datetime.now(timezone.utc),
    )
    assert result.request_count == 4
    assert result.approved_count == 2
    assert result.blocked_count == 1
    assert result.denied_count == 1
    assert result.estimated_usage_units == 4
