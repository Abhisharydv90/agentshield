"""
Redis-backed sliding-window rate limiter.

Security notes:

- Never blindly trust X-Forwarded-For.
- Prefer the ASGI peer address.
- A trusted proxy can explicitly provide a sanitized client IP.
- Redis failure behavior is configurable.
"""

from __future__ import annotations

import json
import time
from typing import Any

from app.config import settings
from app.security.pii.vault import _get_redis


# ============================================================
# Rules
# ============================================================

RULES: list[
    tuple[str, int, int]
] = [
    ("/api/auth/signup", 5, 3600),
    ("/api/auth/login", 10, 300),
    ("/api/auth/", 30, 60),
    ("/v1/", 120, 60),
    ("/api/", 300, 60),
]


# ============================================================
# Client IP
# ============================================================

def _client_ip(
    scope: dict,
    headers: dict[str, str],
) -> str:
    """
    Determine the rate-limit identity.

    Do NOT blindly trust arbitrary X-Forwarded-For headers.

    AGENTSHIELD_CLIENT_IP may be populated by a trusted
    reverse proxy after it has sanitized the connection metadata.
    """

    trusted_proxy_ip = headers.get(
        "x-agentshield-client-ip",
        "",
    ).strip()

    if trusted_proxy_ip:
        return trusted_proxy_ip

    client = scope.get(
        "client"
    )

    if client:
        host = str(client[0]).strip()

        if host:
            return host

    return "unknown"


# ============================================================
# Middleware
# ============================================================

class RateLimitMiddleware:

    def __init__(
        self,
        app: Any,
    ) -> None:
        self.app = app

    async def __call__(
        self,
        scope: dict,
        receive: Any,
        send: Any,
    ) -> None:

        if scope["type"] != "http":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        path = scope.get(
            "path",
            "",
        )

        method = scope.get(
            "method",
            "",
        )

        if method == "OPTIONS":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        # -----------------------------------------------------
        # Match rule
        # -----------------------------------------------------

        rule = None

        for prefix, limit, window in RULES:

            if path.startswith(prefix):

                rule = (
                    prefix,
                    limit,
                    window,
                )

                break

        if rule is None:

            await self.app(
                scope,
                receive,
                send,
            )

            return

        prefix, limit, window = rule

        # -----------------------------------------------------
        # Headers
        # -----------------------------------------------------

        headers = {
            key.decode("latin-1").lower():
            value.decode("latin-1")
            for key, value
            in scope.get("headers", [])
        }

        ip = _client_ip(
            scope,
            headers,
        )

        redis = _get_redis()

        # -----------------------------------------------------
        # Redis unavailable
        # -----------------------------------------------------

        if redis is None:

            if settings.RATE_LIMIT_FAIL_OPEN:

                await self.app(
                    scope,
                    receive,
                    send,
                )

                return

            await self._reject(
                send,
                retry_after=5,
            )

            return

        # -----------------------------------------------------
        # Sliding window
        # -----------------------------------------------------

        key = (
            f"ratelimit:"
            f"{prefix}:"
            f"{ip}"
        )

        now = time.time()

        reset_at = int(
            now + window
        )

        try:

            pipe = redis.pipeline()

            pipe.zremrangebyscore(
                key,
                0,
                now - window,
            )

            pipe.zadd(
                key,
                {
                    f"{now}:{time.time_ns()}": now
                },
            )

            pipe.zcard(key)

            pipe.expire(
                key,
                window,
            )

            pipe.zrange(
                key,
                0,
                0,
                withscores=True,
            )

            (
                _removed,
                _added,
                count,
                _expired,
                oldest,
            ) = await pipe.execute()

            if oldest:

                oldest_ts = float(
                    oldest[0][1]
                )

                reset_at = int(
                    oldest_ts + window
                )

            retry_after = max(
                1,
                reset_at - int(now),
            )

            remaining = max(
                0,
                limit - int(count),
            )

            # -------------------------------------------------
            # Limit exceeded
            # -------------------------------------------------

            if count > limit:

                body = json.dumps(
                    {
                        "error":
                            "rate_limit_exceeded",
                        "status": 429,
                        "retry_after":
                            retry_after,
                    }
                ).encode()

                await send(
                    {
                        "type":
                            "http.response.start",
                        "status": 429,
                        "headers": [
                            (
                                b"content-type",
                                b"application/json",
                            ),
                            (
                                b"cache-control",
                                b"no-store",
                            ),
                            (
                                b"retry-after",
                                str(
                                    retry_after
                                ).encode(),
                            ),
                            (
                                b"x-ratelimit-limit",
                                str(
                                    limit
                                ).encode(),
                            ),
                            (
                                b"x-ratelimit-remaining",
                                b"0",
                            ),
                            (
                                b"x-ratelimit-reset",
                                str(
                                    reset_at
                                ).encode(),
                            ),
                            (
                                b"content-length",
                                str(
                                    len(body)
                                ).encode(),
                            ),
                        ],
                    }
                )

                await send(
                    {
                        "type":
                            "http.response.body",
                        "body": body,
                    }
                )

                return

        except Exception:

            # Do not expose Redis internals.
            #
            # In production we fail closed unless the operator
            # explicitly chooses RATE_LIMIT_FAIL_OPEN=true.

            if settings.RATE_LIMIT_FAIL_OPEN:

                await self.app(
                    scope,
                    receive,
                    send,
                )

                return

            await self._reject(
                send,
                retry_after=5,
            )

            return

        # -----------------------------------------------------
        # Normal response headers
        # -----------------------------------------------------

        async def send_wrapper(
            message: dict,
        ) -> None:

            if (
                message["type"]
                == "http.response.start"
            ):

                response_headers = list(
                    message.get(
                        "headers",
                        [],
                    )
                )

                response_headers.extend(
                    [
                        (
                            b"x-ratelimit-limit",
                            str(
                                limit
                            ).encode(),
                        ),
                        (
                            b"x-ratelimit-remaining",
                            str(
                                remaining
                            ).encode(),
                        ),
                        (
                            b"x-ratelimit-reset",
                            str(
                                reset_at
                            ).encode(),
                        ),
                    ]
                )

                message[
                    "headers"
                ] = response_headers

            await send(message)

        await self.app(
            scope,
            receive,
            send_wrapper,
        )

    # ========================================================
    # Reject
    # ========================================================

    async def _reject(
        self,
        send: Any,
        retry_after: int,
    ) -> None:

        body = json.dumps(
            {
                "error":
                    "rate_limiter_unavailable",
                "status": 503,
                "retry_after":
                    retry_after,
            }
        ).encode()

        await send(
            {
                "type":
                    "http.response.start",
                "status": 503,
                "headers": [
                    (
                        b"content-type",
                        b"application/json",
                    ),
                    (
                        b"retry-after",
                        str(
                            retry_after
                        ).encode(),
                    ),
                    (
                        b"cache-control",
                        b"no-store",
                    ),
                    (
                        b"content-length",
                        str(
                            len(body)
                        ).encode(),
                    ),
                ],
            }
        )

        await send(
            {
                "type":
                    "http.response.body",
                "body": body,
            }
        )