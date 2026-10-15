"""
AURAGENT Gateway observability.

This layer records low-cardinality operational metrics.

Do not place:
- API keys
- passwords
- secrets
- raw model prompts
- evaluator reasoning
- arbitrary payloads

into Gateway metrics.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class GatewayObservation:
    target_kind: str
    target_name: str
    status_code: int
    latency_ms: float
    outcome: str


class GatewayMetrics:
    """
    Process-local metrics accumulator.

    Phase 13 can replace this with Prometheus/OpenTelemetry counters.
    """

    def __init__(self) -> None:
        self._counters: defaultdict[
            tuple[str, str, str],
            int,
        ] = defaultdict(int)

        self._latency_total_ms = 0.0
        self._request_total = 0

        self._lock = asyncio.Lock()

    async def observe(
        self,
        observation: GatewayObservation,
    ) -> None:
        async with self._lock:
            self._counters[
                (
                    observation.target_kind,
                    observation.outcome,
                    str(observation.status_code),
                )
            ] += 1

            self._latency_total_ms += (
                observation.latency_ms
            )

            self._request_total += 1

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            average_latency = (
                self._latency_total_ms
                / self._request_total
                if self._request_total
                else 0.0
            )

            return {
                "requests_total": (
                    self._request_total
                ),
                "average_latency_ms": (
                    round(
                        average_latency,
                        3,
                    )
                ),
                "counters": {
                    "|".join(key): value
                    for key, value
                    in self._counters.items()
                },
            }


gateway_metrics = GatewayMetrics()


def monotonic_ms() -> float:
    return time.perf_counter() * 1000.0