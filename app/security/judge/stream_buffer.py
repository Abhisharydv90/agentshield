"""
Streaming tool-call security gate.

Critical rule:

    Tool-call fragments must NEVER be forwarded to the client
    before AgentShield has evaluated the complete call.

Non-tool response content can continue through normally.

When a tool-call sequence completes, the gate returns the complete
tool call to the security pipeline and does NOT forward the original
tool-call fragments.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any


# ============================================================
# Accumulator
# ============================================================


@dataclass
class ToolCallAccumulator:

    index: int

    id: str | None = None

    name: str | None = None

    arguments_buf: list[str] = field(
        default_factory=list
    )

    def merge(
        self,
        delta: dict[str, Any],
    ) -> None:

        if delta.get(
            "id"
        ):
            self.id = str(
                delta["id"]
            )

        function = delta.get(
            "function"
        )

        if not isinstance(
            function,
            dict,
        ):
            return

        if function.get(
            "name"
        ):
            self.name = str(
                function["name"]
            )

        arguments = function.get(
            "arguments"
        )

        if arguments is not None:

            self.arguments_buf.append(
                str(arguments)
            )

    def complete(
        self,
    ) -> dict[str, Any]:

        raw_arguments = (
            "".join(
                self.arguments_buf
            )
            or "{}"
        )

        try:

            arguments = json.loads(
                raw_arguments
            )

        except json.JSONDecodeError:

            # Leave malformed JSON to the deterministic
            # normalizer/security contract rather than
            # attempting to repair attacker-controlled data.
            arguments = raw_arguments

        return {
            "index":
                self.index,
            "id":
                self.id,
            "name":
                self.name or "unknown",
            "arguments":
                arguments,
        }


# ============================================================
# Streaming gate
# ============================================================


class StreamingToolCallGate:

    def __init__(self) -> None:

        self._accs: dict[
            int,
            ToolCallAccumulator,
        ] = {}

    def feed(
        self,
        chunk: dict[str, Any],
    ) -> tuple[
        list[str],
        list[dict[str, Any]],
    ]:
        """
        Return:

            passthrough_chunks
            completed_tool_calls

        Tool-call fragments are removed from passthrough data.

        The final finish_reason='tool_calls' chunk is also withheld
        until the security pipeline has made its decision.
        """

        passthrough: list[str] = []

        completed: list[
            dict[str, Any]
        ] = []

        safe_chunk = copy.deepcopy(
            chunk
        )

        safe_choices = []

        tool_call_finished = False

        for choice in safe_chunk.get(
            "choices",
            [],
        ):

            safe_choice = copy.deepcopy(
                choice
            )

            delta = safe_choice.get(
                "delta"
            ) or {}

            tool_calls = (
                delta.get(
                    "tool_calls"
                )
                or []
            )

            # ------------------------------------------------
            # Buffer tool-call fragments
            # ------------------------------------------------

            for tool_call in tool_calls:

                index = int(
                    tool_call.get(
                        "index",
                        0,
                    )
                )

                accumulator = (
                    self._accs.setdefault(
                        index,
                        ToolCallAccumulator(
                            index=index
                        ),
                    )
                )

                accumulator.merge(
                    tool_call
                )

            # ------------------------------------------------
            # Remove tool-call fragments from downstream data
            # ------------------------------------------------

            if tool_calls:

                safe_delta = copy.deepcopy(
                    delta
                )

                safe_delta.pop(
                    "tool_calls",
                    None,
                )

                safe_choice[
                    "delta"
                ] = safe_delta

            # ------------------------------------------------
            # Completion
            # ------------------------------------------------

            if (
                choice.get(
                    "finish_reason"
                )
                == "tool_calls"
            ):

                tool_call_finished = True

                safe_choice[
                    "finish_reason"
                ] = None

            safe_choices.append(
                safe_choice
            )

        # -----------------------------------------------------
        # Emit completed calls
        # -----------------------------------------------------

        if tool_call_finished:

            completed = [
                accumulator.complete()
                for accumulator
                in sorted(
                    self._accs.values(),
                    key=lambda item:
                        item.index,
                )
            ]

            self._accs.clear()

        # -----------------------------------------------------
        # Only forward a safe chunk when it contains meaningful
        # non-tool content.
        # -----------------------------------------------------

        if safe_choices:

            meaningful_choices = []

            for choice in safe_choices:

                delta = (
                    choice.get(
                        "delta"
                    )
                    or {}
                )

                finish_reason = (
                    choice.get(
                        "finish_reason"
                    )
                )

                meaningful = bool(
                    delta
                ) or (
                    finish_reason
                    not in {
                        None,
                    }
                )

                if meaningful:
                    meaningful_choices.append(
                        choice
                    )

            if meaningful_choices:

                safe_chunk[
                    "choices"
                ] = meaningful_choices

                passthrough.append(
                    (
                        "data: "
                        + json.dumps(
                            safe_chunk,
                            ensure_ascii=False,
                        )
                        + "\n\n"
                    )
                )

        return (
            passthrough,
            completed,
        )