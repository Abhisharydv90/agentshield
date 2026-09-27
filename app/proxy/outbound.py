"""
Outbound Judge Pipeline
Intercepts LLM responses, buffers streaming tool calls, and evaluates each
completed call against the policy engine + LLM judge before execution.
"""
import json
from typing import AsyncIterator
from app.config import settings
from app.security.judge.stream_buffer import StreamingToolCallGate
from app.security.judge.evaluate import execute_tool_with_judge
from app.policy.dsl import Policy, EXAMPLE_POLICY
from app.telemetry.audit import write_event
from app.db.session import async_session


async def process_outbound_stream(
    upstream_iterator: AsyncIterator[bytes],
    policy: Policy,
    policy_version: str,
    trace_id: str,
) -> AsyncIterator[bytes]:
    """
    Consumes the raw SSE stream from the upstream LLM.
    - Buffers tool_call deltas via StreamingToolCallGate.
    - When a complete tool call arrives, runs it through the judge.
    - Yields approved chunks downstream.
    - Emits a denial frame if the judge blocks the call.
    """
    gate = StreamingToolCallGate()
    buffer = ""
    in_tool_call = False

    async for raw_chunk in upstream_iterator:
        text = raw_chunk.decode("utf-8", errors="replace")

        # SSE streams are line-delimited. We handle one line at a time.
        for line in text.split("\n"):
            if not line.strip():
                continue

            if not line.startswith("data: "):
                # Non-data lines (comments, etc.) — pass through as-is
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

            # Emit passthrough chunks immediately (text tokens, etc.)
            for p in passthrough:
                yield p.encode("utf-8")

            # If we have complete tool calls, judge them
            for call in completed_calls:
                verdict = await execute_tool_with_judge(
                    raw_tool_call=call,
                    policy=policy,
                    policy_version=policy_version,
                )

                if verdict["decision"] == "deny":
                    # Log and refuse
                    await _log_block(trace_id, verdict)
                    denial = {
                        "error": "tool_call_denied",
                        "reason": verdict["reason"],
                        "trace_id": trace_id,
                    }
                    yield f"data: {json.dumps(denial)}\n\n".encode("utf-8")
                    yield b"data: [DONE]\n\n"
                    return  # Halt the stream. No tool execution.

                # Allowed — forward the complete tool call downstream
                allowed_frame = {"tool_call": call, "verdict": verdict}
                yield f"data: {json.dumps(allowed_frame)}\n\n".encode("utf-8")


async def _log_block(trace_id: str, verdict: dict):
    """Writes a blocked tool call to the audit log."""
    try:
        async with async_session() as session:
            await write_event(
                session=session,
                request_id=trace_id,
                threat_category=verdict.get("category", "unauthorized_tool"),
                action_taken="blocked",
                evaluator_reasoning=verdict.get("reason", "judge_denied"),
            )
    except Exception as e:
        print(f"CRITICAL: Failed to log outbound block: {e}")