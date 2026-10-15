"""
Runtime approval bridge tests.

These tests verify that the runtime outbound layer:

1. Carries agent_id into the security decision pipeline.
2. Surfaces approval metadata when a tool call requires approval.
3. Stops the proposed tool call instead of forwarding it.
4. Applies the same behavior to streaming and non-streaming paths.

The actual persisted approval lifecycle is tested separately by
the SecurityDecisionEngine tests.
"""

from __future__ import annotations

import json
import uuid

import pytest

from app.policy.dsl import EXAMPLE_POLICY
from app.proxy import outbound


APPROVAL_ID = "approval-test-001"
ACTION_FINGERPRINT = "fingerprint-test-001"
POLICY_VERSION = "7.0.0"
TRACE_ID = "trace-test-001"


async def _fake_execute_tool_with_judge(
    **kwargs,
):
    """
    Fake the lower security decision call.

    The important assertion is that outbound.py passes the authenticated
    agent_id all the way through to the decision pipeline.
    """

    _fake_execute_tool_with_judge.captured = kwargs

    return {
        "decision": "approval_required",
        "reason": "human_approval_required",
        "category": "privilege_escalation",
        "approval_id": APPROVAL_ID,
        "action_fingerprint": ACTION_FINGERPRINT,
        "policy_version": POLICY_VERSION,
    }


async def _collect(
    iterator,
) -> list[bytes]:
    chunks: list[bytes] = []

    async for chunk in iterator:
        chunks.append(chunk)

    return chunks


@pytest.mark.asyncio
async def test_non_streaming_passes_agent_id_and_surfaces_approval(
    monkeypatch,
):
    """
    Non-streaming tool proposals must carry agent_id into the security
    decision pipeline and return approval metadata to the caller.
    """

    monkeypatch.setattr(
        outbound,
        "execute_tool_with_judge",
        _fake_execute_tool_with_judge,
    )

    agent_id = uuid.uuid4()
    tenant_id = uuid.uuid4()

    body = json.dumps(
        {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "call-001",
                                "type": "function",
                                "function": {
                                    "name": "db.query",
                                    "arguments": json.dumps(
                                        {
                                            "query": "SELECT 1"
                                        }
                                    ),
                                },
                            }
                        ]
                    }
                }
            ]
        }
    ).encode(
        "utf-8"
    )

    result = await outbound.authorize_non_streaming_response(
        body=body,
        policy=EXAMPLE_POLICY,
        policy_version=POLICY_VERSION,
        trace_id=TRACE_ID,
        tenant_id=tenant_id,
        agent_scopes=[
            "agent:invoke",
            "tool:read",
        ],
        agent_id=agent_id,
    )

    captured = getattr(
        _fake_execute_tool_with_judge,
        "captured",
        None,
    )

    assert captured is not None

    assert captured["agent_id"] == agent_id

    assert result is not None

    assert result["error"] == (
        "tool_call_approval_required"
    )

    assert result["approval_id"] == (
        APPROVAL_ID
    )

    assert result["action_fingerprint"] == (
        ACTION_FINGERPRINT
    )

    assert result["policy_version"] == (
        POLICY_VERSION
    )

    assert result["trace_id"] == (
        TRACE_ID
    )


@pytest.mark.asyncio
async def test_streaming_passes_agent_id_and_stops_on_approval(
    monkeypatch,
):
    """
    Streaming tool proposals must also carry agent_id into the decision
    pipeline and stop when human approval is required.

    The real StreamingToolCallGate is replaced here only so this test
    focuses on outbound runtime propagation rather than re-testing the
    gate's parsing logic.
    """

    monkeypatch.setattr(
        outbound,
        "execute_tool_with_judge",
        _fake_execute_tool_with_judge,
    )

    class FakeStreamingToolCallGate:
        def feed(
            self,
            chunk,
        ):
            return (
                [],
                [
                    {
                        "id": "call-stream-001",
                        "name": "db.query",
                        "arguments": {
                            "query": "SELECT 1"
                        },
                    }
                ],
            )

    monkeypatch.setattr(
        outbound,
        "StreamingToolCallGate",
        FakeStreamingToolCallGate,
    )

    agent_id = uuid.uuid4()
    tenant_id = uuid.uuid4()

    async def upstream():
        payload = {
            "choices": []
        }

        yield (
            "data: "
            + json.dumps(
                payload
            )
            + "\n\n"
        ).encode(
            "utf-8"
        )

    chunks = await _collect(
        outbound.process_outbound_stream(
            upstream_iterator=upstream(),
            policy=EXAMPLE_POLICY,
            policy_version=POLICY_VERSION,
            trace_id=TRACE_ID,
            tenant_id=tenant_id,
            agent_scopes=[
                "agent:invoke",
                "tool:read",
            ],
            agent_id=agent_id,
        )
    )

    captured = getattr(
        _fake_execute_tool_with_judge,
        "captured",
        None,
    )

    assert captured is not None

    assert captured["agent_id"] == agent_id

    combined = b"".join(
        chunks
    ).decode(
        "utf-8"
    )

    assert (
        "tool_call_approval_required"
        in combined
    )

    assert (
        APPROVAL_ID
        in combined
    )

    assert (
        ACTION_FINGERPRINT
        in combined
    )

    assert (
        POLICY_VERSION
        in combined
    )

    assert (
        "data: [DONE]"
        in combined
    )

    # The actual proposed tool call must not be reconstructed
    # and forwarded after an approval-required decision.
    assert (
        '"name": "db.query"'
        not in combined
    )