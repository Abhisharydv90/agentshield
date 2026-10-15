"""P1 regression tests for telemetry data minimization."""

from types import SimpleNamespace

from app.api.telemetry import _serialize_event


def test_telemetry_event_does_not_expose_evaluator_reasoning():
    event = SimpleNamespace(
        event_id="event-1",
        request_id="request-1",
        timestamp=SimpleNamespace(isoformat=lambda: "2026-10-15T00:00:00+00:00"),
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


def test_telemetry_rejects_agent_authentication():
    from types import SimpleNamespace

    from fastapi import HTTPException
    from app.api.telemetry import _require_human_telemetry_access

    tenant = SimpleNamespace(
        tenant_id="tenant-1",
        status="active",
    )
    user = SimpleNamespace(
        user_id="user-1",
        tenant_id="tenant-1",
        status="active",
        role="member",
    )
    request = SimpleNamespace(
        state=SimpleNamespace(
            tenant=tenant,
            user=user,
            auth_type="api_key",
        )
    )

    try:
        _require_human_telemetry_access(request)
    except HTTPException as exc:
        assert exc.status_code == 403
        assert exc.detail == "human_session_required"
    else:
        raise AssertionError("agent authentication must not access telemetry")
