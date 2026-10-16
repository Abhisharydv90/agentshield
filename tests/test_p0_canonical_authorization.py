"""P0-4 regression coverage for canonical authority propagation."""

from __future__ import annotations

import uuid

import pytest

from app.policy.dsl import Policy
from app.proxy import outbound
from app.security.context import SecurityContext
from app.security.delegation.model import AuthorityState


def _context() -> SecurityContext:
    authority = AuthorityState.from_values(
        capabilities={"tool:read"},
        operations={"read"},
    )
    return SecurityContext(
        tenant_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        trace_id="trace-p0-4",
        capabilities=authority.capabilities,
        authority=authority,
        policy_hash="a" * 64,
        authority_token_hash="b" * 64,
        provenance={"source": "test"},
    )


@pytest.mark.asyncio
async def test_streaming_tool_authorization_receives_authority_context(monkeypatch):
    context = _context()
    seen = []

    async def fake_execute_tool_with_judge(**kwargs):
        seen.append(kwargs["authority_context"])
        return {
            "decision": "allow",
            "reason": "ok",
            "action_fingerprint": "c" * 64,
        }

    class FakeGate:
        def __init__(self):
            self.done = False

        def feed(self, _chunk):
            if self.done:
                return [], []
            self.done = True
            return [], [{
                "id": "call-1",
                "name": "db.query",
                "arguments": {"table": "billing_invoices"},
                "index": 0,
            }]

    async def upstream():
        yield (
            b"data: {\"choices\": [{\"delta\": {}, "
            b"\"finish_reason\": \"tool_calls\"}]}\n\n"
        )

    monkeypatch.setattr(outbound, "StreamingToolCallGate", FakeGate)
    monkeypatch.setattr(
        outbound,
        "execute_tool_with_judge",
        fake_execute_tool_with_judge,
    )

    chunks = [
        chunk
        async for chunk in outbound.process_outbound_stream(
            upstream(),
            Policy(name="p", version="1", rules=[]),
            "1",
            "trace-p0-4",
            context.tenant_id,
            context.capabilities,
            agent_id=context.agent_id,
            authority_context=context,
        )
    ]

    assert chunks
    assert seen == [context]


@pytest.mark.asyncio
async def test_non_streaming_tool_authorization_receives_authority_context(monkeypatch):
    context = _context()
    seen = []

    async def fake_execute_tool_with_judge(**kwargs):
        seen.append(kwargs["authority_context"])
        return {
            "decision": "allow",
            "reason": "ok",
            "action_fingerprint": "c" * 64,
        }

    monkeypatch.setitem(
        outbound.authorize_non_streaming_response.__globals__,
        "execute_tool_with_judge",
        fake_execute_tool_with_judge,
    )
    monkeypatch.setattr(
        outbound,
        "_safe_tool_call_from_openai",
        lambda _tool_call: {
            "id": "call-1",
            "name": "db.query",
            "arguments": {"table": "billing_invoices"},
        },
    )

    body = b'{"choices":[{"message":{"tool_calls":[{"id":"call-1","function":{}}]}}]}'

    result = await outbound.authorize_non_streaming_response(
        body=body,
        policy=Policy(name="p", version="1", rules=[]),
        policy_version="1",
        trace_id="trace-p0-4",
        tenant_id=context.tenant_id,
        agent_scopes=context.capabilities,
        agent_id=context.agent_id,
        authority_context=context,
    )

    assert result is None
    assert seen == [context]
