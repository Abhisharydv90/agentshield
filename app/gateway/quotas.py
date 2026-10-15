"""
AURAGENT Gateway quota manager.

Current implementation:
    process-local fixed-window request quota + concurrency quota.

This is intentionally behind a small interface so Phase 13 can replace
it with Redis/distributed rate limiting without changing Gateway APIs.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass


# ============================================================
# Configuration
# ============================================================

DEFAULT_REQUESTS_PER_MINUTE = int(
    os.getenv(
        "AURAGENT_GATEWAY_REQUESTS_PER_MINUTE",
        "120",
    )
)

DEFAULT_CONCURRENT_REQUESTS = int(
    os.getenv(
        "AURAGENT_GATEWAY_MAX_CONCURRENT",
        "16",
    )
)


@dataclass(frozen=True, slots=True)
class QuotaDecision:
    allowed: bool
    remaining: int
    retry_after_seconds: int
    reason: str | None = None


@dataclass(slots=True)
class _Bucket:
    window_start: float
    requests: int = 0
    inflight: int = 0


class GatewayQuotaManager:
    """
    Tenant/agent scoped quota manager.

    Identity dimension:

        tenant_id + agent_id

    This prevents one agent from consuming the entire tenant budget
    accidentally.
    """

    WINDOW_SECONDS = 60.0

    def __init__(
        self,
        *,
        requests_per_minute: int = DEFAULT_REQUESTS_PER_MINUTE,
        max_concurrent: int = DEFAULT_CONCURRENT_REQUESTS,
    ) -> None:
        if requests_per_minute < 1:
            raise ValueError(
                "requests_per_minute_invalid"
            )

        if max_concurrent < 1:
            raise ValueError(
                "max_concurrent_invalid"
            )

        self.requests_per_minute = (
            requests_per_minute
        )

        self.max_concurrent = (
            max_concurrent
        )

        self._buckets: dict[
            tuple[uuid.UUID, uuid.UUID],
            _Bucket,
        ] = {}

        self._lock = asyncio.Lock()

    async def acquire(
        self,
        *,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
    ) -> QuotaDecision:
        now = time.monotonic()

        key = (
            tenant_id,
            agent_id,
        )

        async with self._lock:
            bucket = self._buckets.get(
                key
            )

            if bucket is None:
                bucket = _Bucket(
                    window_start=now
                )
                self._buckets[
                    key
                ] = bucket

            elapsed = (
                now - bucket.window_start
            )

            if elapsed >= self.WINDOW_SECONDS:
                bucket.window_start = now
                bucket.requests = 0

            if (
                bucket.inflight
                >= self.max_concurrent
            ):
                return QuotaDecision(
                    allowed=False,
                    remaining=max(
                        0,
                        self.requests_per_minute
                        - bucket.requests,
                    ),
                    retry_after_seconds=1,
                    reason="concurrency_limit",
                )

            if (
                bucket.requests
                >= self.requests_per_minute
            ):
                retry_after = max(
                    1,
                    int(
                        self.WINDOW_SECONDS
                        - (
                            now
                            - bucket.window_start
                        )
                    )
                )

                return QuotaDecision(
                    allowed=False,
                    remaining=0,
                    retry_after_seconds=retry_after,
                    reason="request_rate_limit",
                )

            bucket.requests += 1
            bucket.inflight += 1

            return QuotaDecision(
                allowed=True,
                remaining=(
                    self.requests_per_minute
                    - bucket.requests
                ),
                retry_after_seconds=0,
            )

    async def release(
        self,
        *,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
    ) -> None:
        key = (
            tenant_id,
            agent_id,
        )

        async with self._lock:
            bucket = self._buckets.get(
                key
            )

            if bucket is None:
                return

            bucket.inflight = max(
                0,
                bucket.inflight - 1,
            )

    async def snapshot(
        self,
        *,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
    ) -> dict:
        key = (
            tenant_id,
            agent_id,
        )

        async with self._lock:
            bucket = self._buckets.get(
                key
            )

            if bucket is None:
                return {
                    "requests_per_minute": (
                        self.requests_per_minute
                    ),
                    "requests_used": 0,
                    "remaining": (
                        self.requests_per_minute
                    ),
                    "inflight": 0,
                    "max_concurrent": (
                        self.max_concurrent
                    ),
                }

            now = time.monotonic()

            if (
                now - bucket.window_start
                >= self.WINDOW_SECONDS
            ):
                return {
                    "requests_per_minute": (
                        self.requests_per_minute
                    ),
                    "requests_used": 0,
                    "remaining": (
                        self.requests_per_minute
                    ),
                    "inflight": bucket.inflight,
                    "max_concurrent": (
                        self.max_concurrent
                    ),
                }

            return {
                "requests_per_minute": (
                    self.requests_per_minute
                ),
                "requests_used": bucket.requests,
                "remaining": max(
                    0,
                    self.requests_per_minute
                    - bucket.requests,
                ),
                "inflight": bucket.inflight,
                "max_concurrent": (
                    self.max_concurrent
                ),
            }


quota_manager = GatewayQuotaManager()