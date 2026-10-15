"""At-least-once event-bus contracts with explicit deduplication."""

from __future__ import annotations

import asyncio
from collections import defaultdict

from .contracts import EventEnvelope


class EventBusError(RuntimeError):
    pass


class InMemoryEventBus:
    """Deterministic reference event bus.

    Semantics:
      * tenant-scoped topics
      * monotonic sequence per (tenant, topic, partition)
      * bounded publication batch
      * at-least-once delivery when consumed by cursor
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._sequences: dict[tuple[str, str, str], int] = defaultdict(int)
        self._events: dict[tuple[str, str, str], list[EventEnvelope]] = defaultdict(list)

    async def publish(
        self,
        events: list[EventEnvelope],
        *,
        max_batch_size: int = 100,
    ) -> list[EventEnvelope]:
        if len(events) > max_batch_size:
            raise EventBusError("event batch exceeds configured limit")

        published: list[EventEnvelope] = []

        async with self._lock:
            for incoming in events:
                key = (
                    str(incoming.tenant_id),
                    incoming.topic,
                    incoming.partition_key,
                )
                sequence = self._sequences[key]
                if incoming.sequence != sequence:
                    raise EventBusError(
                        f"non-contiguous event sequence for {key}: "
                        f"expected {sequence}, got {incoming.sequence}"
                    )
                self._sequences[key] += 1
                self._events[key].append(incoming)
                published.append(incoming)

        return published

    async def read(
        self,
        *,
        tenant_id: str,
        topic: str,
        partition_key: str,
        after_sequence: int = -1,
        limit: int = 100,
    ) -> list[EventEnvelope]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")

        key = (tenant_id, topic, partition_key)
        async with self._lock:
            events = list(self._events.get(key, []))

        return [
            event
            for event in events
            if event.sequence > after_sequence
        ][:limit]
