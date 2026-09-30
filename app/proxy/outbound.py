"""
Outbound Judge Pipeline

Intercepts LLM responses, buffers streaming tool calls, and evaluates each
completed call against the policy engine + LLM judge before execution.
"""

from __future__ import annotations

import json
import uuid as _uuid
from typing import AsyncIterator

from app.security.judge.stream_buffer import StreamingToolCallGate
from app.security.judge.evaluate import execute_tool_with_judge
from app.policy.dsl import Policy
from app.telemetry.audit import write_event
from app.db.session import async_session


async def process_outbound_stream(
    upstream_iterator: AsyncIterator[bytes],
    policy: Policy,
    policy_version: str,
    trace_id: str,
    tenant_id: _uuid.UUID,
) -> AsyncIterator[bytes]:
    """
    Consume the raw SSE stream from the upstream LLM.

    - Buffer tool_call deltas via StreamingToolCallGate.
    - When a complete tool call arrives, run it through the judge.
    - Yield approved chunks downstream.
    - Emit a denial frame and halt the stream if the judge blocks.
    """
    gate = StreamingToolCallGate()

    async for raw_chunk in upstream_iterator:
        text = raw_chunk.decode("utf-8", errors="replace")

        for line in text.split("\n"):
            if not line.strip():
                continue

            if not line.startswith("data: "):
                yield (line + "\n").encode("utf-8")
                continue

            payload = line[6:]

            if payload.strip() == "[DONE]":
                yield b"data: [DONE]\n\n"
                continue

            try:
                chunk = json.loads(payload)
            except json.JSONDecodeError:
                yield (line + "\n").encode("utf-8")
                continue

            passthrough, completed_calls = gate.feed(chunk)

            for p in passthrough:
                yield p.encode("utf-8")

            for call in completed_calls:
                verdict = await execute_tool_with_judge(
                    raw_tool_call=call,
                    policy=policy,
                    policy_version=policy_version,
                    tenant_id=tenant_id,
                    trace_id=trace_id,
                )

                if verdict["decision"] == "deny":
                    denial = {
                        "error": "tool_call_denied",
                        "reason": verdict["reason"],
                        "trace_id": trace_id,
                    }
                    yield f"data: {json.dumps(denial)}\n\n".encode("utf-8")
                    yield b"data: [DONE]\n\n"
                    return

                allowed_frame = {"tool_call": call, "verdict": verdict}
                yield f"data: {json.dumps(allowed_frame)}\n\n".encode("utf-8")