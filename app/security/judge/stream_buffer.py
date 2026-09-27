import json
from dataclasses import dataclass, field
from typing import AsyncIterator

@dataclass
class ToolCallAccumulator:
    index: int
    id: str | None = None
    name: str | None = None
    arguments_buf: list[str] = field(default_factory=list)

    def merge(self, delta: dict):
        if "id" in delta: self.id = delta["id"]
        if "function" in delta:
            fn = delta["function"]
            if "name" in fn and fn["name"]:
                self.name = fn["name"]
            if "arguments" in fn and fn["arguments"] is not None:
                self.arguments_buf.append(fn["arguments"])

    def complete(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "arguments": json.loads("".join(self.arguments_buf) or "{}"),
        }

class StreamingToolCallGate:
    """
    Consumes raw SSE chunks. Yields chunks downstream EXCEPT tool_call deltas,
    which are buffered. When finish_reason == 'tool_calls' arrives, every
    accumulated call is emitted as one complete JSON object for judging.
    """
    def __init__(self):
        self._accs: dict[int, ToolCallAccumulator] = {}

    def feed(self, chunk: dict) -> tuple[list[str], list[dict]]:
        """
        Returns (passthrough_chunks, completed_tool_calls).
        passthrough_chunks: SSE chunks safe to forward to the client immediately.
        completed_tool_calls: complete tool calls that MUST be judged before forward.
        """
        passthrough: list[str] = []
        completed: list[dict] = []

        for choice in chunk.get("choices", []):
            delta = choice.get("delta", {}) or {}
            tc_deltas = delta.get("tool_calls") or []
            for tc in tc_deltas:
                idx = tc.get("index", 0)
                self._accs.setdefault(idx, ToolCallAccumulator(index=idx)).merge(tc)
            if choice.get("finish_reason") == "tool_calls":
                completed = [a.complete() for a in sorted(self._accs.values(), key=lambda x: x.index)]
                self._accs.clear()
                # Emit a sanitized finish chunk with NO tool_call payload.
                chunk["choices"][0]["delta"] = {}
            passthrough.append(f"data: {json.dumps(chunk)}\n\n")
        return passthrough, completed