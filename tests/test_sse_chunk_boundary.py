import pytest

from app.proxy import outbound


async def _chunks():
    payload = (
        '{"choices":[{"delta":{"tool_calls":[{"index":0,'
        '"id":"call_1","function":{"name":"db.query",'
        '"arguments":"{\\"query\\":\\"SELECT * FROM '
        'billing_invoices\\"}"}}]},"finish_reason":"tool_calls"}]}'
    ).encode()
    event = b"data: " + payload + b"\n\n"
    midpoint = len(event) // 2
    yield event[:midpoint]
    yield event[midpoint:]


@pytest.mark.asyncio
async def test_sse_event_split_across_network_chunks_is_not_forwarded_partially(monkeypatch):
    async def allow(*args, **kwargs):
        return {
            "decision": "allow",
            "risk": 0.0,
            "reason": "test",
            "category": "benign",
            "policy_version": "1",
        }

    monkeypatch.setattr(outbound, "execute_tool_with_judge", allow)

    from app.policy.dsl import Policy
    import uuid

    results = []
    async for chunk in outbound.process_outbound_stream(
        upstream_iterator=_chunks(),
        policy=Policy(name="p", version="1", rules=[]),
        policy_version="1",
        trace_id="trace-1",
        tenant_id=uuid.uuid4(),
        agent_scopes=["agent:invoke", "tool:read"],
        agent_id=uuid.uuid4(),
    ):
        results.append(chunk)

    assert len(results) == 1
    combined = b"".join(results)
    assert b"SELECT * FROM billing_invoices" in combined
    assert b"tool_call_denied" not in combined
