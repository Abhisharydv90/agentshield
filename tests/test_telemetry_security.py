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
