"""
Outbound tool-call authorization.

Tool-call proposals are buffered/inspected before they are exposed
to the downstream Agent.

The Security Decision Engine receives the authenticated Agent ID so
the action is bound to the actual runtime identity.
"""

from __future__ import annotations

import json
import uuid as _uuid
from typing import (
    Any,
    AsyncIterator,
    Iterable,
)

from app.policy.dsl import Policy
from app.security.judge.evaluate import (
    execute_tool_with_judge,
)
from app.security.judge.stream_buffer import (
    StreamingToolCallGate,
)


# ============================================================
# OpenAI-compatible tool-call normalization
# ============================================================

def _safe_tool_call_from_openai(
    tool_call: dict[str, Any],
) -> dict[str, Any] | None:
    """
    Convert an OpenAI-compatible tool call into AgentShield's
    canonical raw-call shape.
    """

    if not isinstance(
        tool_call,
        dict,
    ):
        return None

    function = tool_call.get(
        "function"
    )

    if not isinstance(
        function,
        dict,
    ):
        return None

    name = function.get(
        "name"
    )

    if not name:
        return None

    raw_arguments = (
        function.get(
            "arguments"
        )
        or "{}"
    )

    if isinstance(
        raw_arguments,
        str,
    ):

        try:

            arguments = json.loads(
                raw_arguments
            )

        except json.JSONDecodeError:

            arguments = raw_arguments

    else:

        arguments = raw_arguments

    return {
        "id":
            tool_call.get(
                "id"
            ),
        "name":
            str(name),
        "arguments":
            arguments,
    }


# ============================================================
# Streaming authorization
# ============================================================

async def process_outbound_stream(
    upstream_iterator: AsyncIterator[bytes],
    policy: Policy,
    policy_version: str,
    trace_id: str,
    tenant_id: _uuid.UUID,
    agent_scopes: Iterable[str],
    agent_id: _uuid.UUID | None = None,
) -> AsyncIterator[bytes]:

    gate = StreamingToolCallGate()

    async for raw_chunk in upstream_iterator:

        text = raw_chunk.decode(
            "utf-8",
            errors="replace",
        )

        for line in text.split(
            "\n"
        ):

            if not line.strip():
                continue

            if not line.startswith(
                "data: "
            ):

                yield (
                    line
                    + "\n"
                ).encode(
                    "utf-8"
                )

                continue

            payload = line[
                6:
            ]

            if payload.strip() == "[DONE]":

                yield (
                    b"data: [DONE]\n\n"
                )

                continue

            try:

                chunk = json.loads(
                    payload
                )

            except json.JSONDecodeError:

                yield (
                    line
                    + "\n"
                ).encode(
                    "utf-8"
                )

                continue

            (
                passthrough,
                completed_calls,
            ) = gate.feed(
                chunk
            )

            for safe_chunk in passthrough:

                yield safe_chunk.encode(
                    "utf-8"
                )

            if not completed_calls:
                continue

            approved_calls = []

            for call in completed_calls:

                verdict = (
                    await execute_tool_with_judge(
                        raw_tool_call={
                            "id":
                                call.get(
                                    "id"
                                ),
                            "name":
                                call.get(
                                    "name"
                                ),
                            "arguments":
                                call.get(
                                    "arguments"
                                ),
                        },
                        policy=
                            policy,
                        policy_version=
                            policy_version,
                        tenant_id=
                            tenant_id,
                        trace_id=
                            trace_id,
                        agent_scopes=
                            agent_scopes,
                        agent_id=
                            agent_id,
                    )
                )

                decision = verdict.get(
                    "decision"
                )

                if decision != "allow":

                    if decision == "deny":
                        error_name = (
                            "tool_call_denied"
                        )

                    elif (
                        decision
                        == "approval_required"
                    ):
                        error_name = (
                            "tool_call_approval_required"
                        )

                    else:
                        error_name = (
                            "tool_call_blocked"
                        )

                    denial = {
                        "error":
                            error_name,
                        "reason":
                            verdict.get(
                                "reason"
                            ),
                        "category":
                            verdict.get(
                                "category"
                            ),
                        "missing_capabilities":
                            verdict.get(
                                "missing_capabilities"
                            ),
                        "approval_id":
                            verdict.get(
                                "approval_id"
                            ),
                        "action_fingerprint":
                            verdict.get(
                                "action_fingerprint"
                            ),
                        "policy_version":
                            verdict.get(
                                "policy_version"
                            ),
                        "trace_id":
                            trace_id,
                    }

                    yield (
                        "data: "
                        + json.dumps(
                            denial,
                            ensure_ascii=False,
                        )
                        + "\n\n"
                    ).encode(
                        "utf-8"
                    )

                    yield (
                        b"data: [DONE]\n\n"
                    )

                    return

                approved_calls.append(
                    call
                )

            # ------------------------------------------------
            # Only approved calls become visible downstream.
            # ------------------------------------------------

            tool_call_deltas = []

            for call in approved_calls:

                arguments = call.get(
                    "arguments",
                    {},
                )

                if not isinstance(
                    arguments,
                    str,
                ):

                    arguments = json.dumps(
                        arguments,
                        ensure_ascii=False,
                        separators=(
                            ",",
                            ":",
                        ),
                    )

                tool_call_deltas.append(
                    {
                        "index":
                            call.get(
                                "index",
                                len(
                                    tool_call_deltas
                                ),
                            ),
                        "id":
                            call.get(
                                "id"
                            ),
                        "type":
                            "function",
                        "function":
                            {
                                "name":
                                    call.get(
                                        "name",
                                        "unknown",
                                    ),
                                "arguments":
                                    arguments,
                            },
                    }
                )

            reconstructed = {
                "choices": [
                    {
                        "delta": {
                            "tool_calls":
                                tool_call_deltas,
                        },
                        "finish_reason":
                            "tool_calls",
                    }
                ]
            }

            yield (
                "data: "
                + json.dumps(
                    reconstructed,
                    ensure_ascii=False,
                )
                + "\n\n"
            ).encode(
                "utf-8"
            )


# ============================================================
# Non-streaming authorization
# ============================================================

async def authorize_non_streaming_response(
    body: bytes,
    policy: Policy,
    policy_version: str,
    trace_id: str,
    tenant_id: _uuid.UUID,
    agent_scopes: Iterable[str],
    agent_id: _uuid.UUID | None = None,
) -> dict | None:

    try:

        payload = json.loads(
            body
        )

    except (
        json.JSONDecodeError,
        TypeError,
    ):

        return None

    if not isinstance(
        payload,
        dict,
    ):
        return None

    proposed_calls = []

    for choice in payload.get(
        "choices",
        [],
    ):

        if not isinstance(
            choice,
            dict,
        ):
            continue

        message = choice.get(
            "message"
        )

        if not isinstance(
            message,
            dict,
        ):
            continue

        for tool_call in (
            message.get(
                "tool_calls"
            )
            or []
        ):

            normalized = (
                _safe_tool_call_from_openai(
                    tool_call
                )
            )

            if normalized is not None:

                proposed_calls.append(
                    normalized
                )

        function_call = message.get(
            "function_call"
        )

        if isinstance(
            function_call,
            dict,
        ):

            normalized = (
                _safe_tool_call_from_openai(
                    {
                        "function":
                            function_call
                    }
                )
            )

            if normalized is not None:

                proposed_calls.append(
                    normalized
                )

    if not proposed_calls:
        return None

    for call in proposed_calls:

        verdict = (
            await execute_tool_with_judge(
                raw_tool_call=call,
                policy=policy,
                policy_version=
                    policy_version,
                tenant_id=tenant_id,
                trace_id=trace_id,
                agent_scopes=
                    agent_scopes,
                agent_id=
                    agent_id,
            )
        )

        if verdict.get(
            "decision"
        ) != "allow":

            decision = verdict.get(
                "decision"
            )

            if decision == "deny":
                error_name = (
                    "tool_call_denied"
                )

            elif (
                decision
                == "approval_required"
            ):
                error_name = (
                    "tool_call_approval_required"
                )

            else:
                error_name = (
                    "tool_call_blocked"
                )

            return {
                "error":
                    error_name,
                "reason":
                    verdict.get(
                        "reason"
                    ),
                "category":
                    verdict.get(
                        "category"
                    ),
                "missing_capabilities":
                    verdict.get(
                        "missing_capabilities"
                    ),
                "approval_id":
                    verdict.get(
                        "approval_id"
                    ),
                "action_fingerprint":
                    verdict.get(
                        "action_fingerprint"
                    ),
                "policy_version":
                    verdict.get(
                        "policy_version"
                    ),
                "trace_id":
                    trace_id,
            }

    return None