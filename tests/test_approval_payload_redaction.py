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

def test_approval_payload_redacts_common_pii_keys():
    payload = {
        "email": "person@example.com",
        "profile": {
            "phone": "+91-9999999999",
            "date_of_birth": "2000-01-01",
            "safe": "keep",
        },
    }

    redacted = _redact_approval_payload(payload)

    assert redacted["email"] == "[REDACTED]"
    assert redacted["profile"]["phone"] == "[REDACTED]"
    assert redacted["profile"]["date_of_birth"] == "[REDACTED]"
    assert redacted["profile"]["safe"] == "keep"
