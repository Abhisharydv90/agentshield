"""P1 regression tests for telemetry data minimization."""

from types import SimpleNamespace

from app.api.telemetry import _serialize_event


def test_telemetry_event_does_not_expose_evaluator_reasoning():
    event = SimpleNamespace(
        event_id="event-1",
        request_id="request-1",
        timestamp=SimpleNamespace(
            isoformat=lambda: "2026-10-15T00:00:00+00:00"
        ),
        threat_category="privilege_escalation",
        action_taken="blocked",
        evaluator_reasoning="sensitive model analysis",
        record_hash="a" * 64,
    )

    payload = _serialize_event(event)

    assert payload["threat_category"] == "privilege_escalation"
    assert payload["action_taken"] == "blocked"
    assert "evaluator_reasoning" not in payload
    assert "sensitive model analysis" not in str(payload)


def test_telemetry_access_requires_human_session():
    from types import SimpleNamespace
    from fastapi import HTTPException
    from app.api.telemetry import _require_human_telemetry_access

    request = SimpleNamespace(
        state=SimpleNamespace(
            tenant=SimpleNamespace(tenant_id="t1", status="active"),
            user=None,
            auth_type="api_key",
        )
    )

    try:
        _require_human_telemetry_access(request)
    except HTTPException as exc:
        assert exc.status_code == 403
        assert exc.detail == "human_session_required"
    else:
        raise AssertionError("agent/api-key telemetry access must be denied")


def test_telemetry_access_rejects_cross_tenant_session():
    from types import SimpleNamespace
    from fastapi import HTTPException
    from app.api.telemetry import _require_human_telemetry_access

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
        _require_human_telemetry_access(request)
    except HTTPException as exc:
        assert exc.status_code == 403
        assert exc.detail == "tenant_mismatch"
    else:
        raise AssertionError("cross-tenant telemetry access must be denied")
