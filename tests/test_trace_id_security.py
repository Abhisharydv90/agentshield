from starlette.requests import Request

from app.middleware.trace import get_trace_id


def _request(value: str | None) -> Request:
    headers = [] if value is None else [(b"x-trace-id", value.encode())]
    return Request({"type": "http", "headers": headers})


def test_trace_id_accepts_safe_value():
    value = "trace-01:abc_DEF.9"
    assert get_trace_id(_request(value)) == value


def test_trace_id_rejects_oversized_value():
    value = "a" * 129
    result = get_trace_id(_request(value))
    assert result != value
    assert len(result) == 36


def test_trace_id_rejects_control_characters():
    result = get_trace_id(_request("safe\nforged-log"))
    assert result != "safe\nforged-log"
