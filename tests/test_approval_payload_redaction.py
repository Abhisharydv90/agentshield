import uuid

from app.security.decision.engine import _redact_approval_payload


def test_approval_payload_redacts_nested_credentials_without_changing_safe_fields():
    payload = {
        "tool_name": "http.request",
        "arguments": {
            "url": "https://example.invalid",
            "Authorization": "Bearer super-secret",
            "nested": {"api_key": "abc123", "method": "GET"},
        },
        "agent_id": str(uuid.uuid4()),
    }
    redacted = _redact_approval_payload(payload)
    assert redacted["tool_name"] == payload["tool_name"]
    assert redacted["arguments"]["Authorization"] == "[REDACTED]"
    assert redacted["arguments"]["nested"]["api_key"] == "[REDACTED]"
    assert redacted["arguments"]["nested"]["method"] == "GET"
    assert "super-secret" not in str(redacted)
