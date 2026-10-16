"""Evidence API authentication boundary regression coverage."""

from types import SimpleNamespace

from fastapi import HTTPException

from app.api.evidence import _require_evidence_access


def test_evidence_requires_human_session():
    request = SimpleNamespace(
        state=SimpleNamespace(
            tenant=SimpleNamespace(tenant_id="t1", status="active"),
            user=None,
            auth_type="api_key",
        )
    )

    try:
        _require_evidence_access(request, "tenant.evidence.read")
    except HTTPException as exc:
        assert exc.status_code == 403
        assert exc.detail == "human_session_required"
    else:
        raise AssertionError("agent/API-key evidence access must be denied")


def test_evidence_rejects_cross_tenant_human_session():
    request = SimpleNamespace(
        state=SimpleNamespace(
            tenant=SimpleNamespace(tenant_id="t1", status="active"),
            user=SimpleNamespace(
                tenant_id="t2",
                status="active",
                role="member",
            ),
            auth_type="session",
        )
    )

    try:
        _require_evidence_access(request, "tenant.evidence.read")
    except HTTPException as exc:
        assert exc.status_code == 403
        assert exc.detail == "tenant_mismatch"
    else:
        raise AssertionError("cross-tenant evidence access must be denied")
