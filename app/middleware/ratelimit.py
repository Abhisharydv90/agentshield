"""
Rate limiting middleware — Redis-backed sliding window.

Prevents credential stuffing, brute-force, and API abuse.
Limits by (path-prefix, client-ip). Returns 429 with Retry-After when exceeded.
"""

from __future__ import annotations

import time
from typing import Any

from app.security.pii.vault import _get_redis


# (path_prefix, max_requests, window_seconds)
RULES: list[tuple[str, int, int]] = [
    ("/api/auth/signup", 5, 3600),    # 5 signups/hour per IP
    ("/api/auth/login", 10, 300),     # 10 login attempts / 5 min per IP
    ("/api/auth/", 30, 60),           # 30 other auth calls / min
    ("/v1/", 120, 60),                # 120 chat completions / min
    ("/api/", 300, 60),               # 300 dashboard reads / min
]


class RateLimitMiddleware:
    """Pure ASGI middleware — SSE-safe."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "")

        if method == "OPTIONS":
            await self.app(scope, receive, send)
            return

        # Find matching rule
        rule = None
        for prefix, limit, window in RULES:
            if path.startswith(prefix):
                rule = (prefix, limit, window)
                break

        if rule is None:
            await self.app(scope, receive, send)
            return

        prefix, limit, window = rule

        # Client IP
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        ip = headers.get("x-forwarded-for", "").split(",")[0].strip()
        if not ip:
            client = scope.get("client") or ("unknown", 0)
            ip = client[0]

        key = f"ratelimit:{prefix}:{ip}"

        r = _get_redis()
        if r is None:
            # Redis down — fail open (better than blocking all traffic)
            await self.app(scope, receive, send)
            return

        try:
            # Sliding window counter
            now = time.time()
            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, now - window)
            pipe.zadd(key, {str(now): now})
            pipe.zcard(key)
            pipe.expire(key, window)
            _, _, count, _ = await pipe.execute()

            if count > limit:
                retry_after = int(window - (now - (now - window)))
                body = (
                    b'{"error":"rate_limit_exceeded","status":429,'
                    b'"retry_after":' + str(retry_after).encode() + b"} "
                )
                await send({
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"retry-after", str(retry_after).encode()),
                        (b"content-length", str(len(body)).encode()),
                    ],
                })
                await send({"type": "http.response.body", "body": body})
                return
        except Exception as e:
            # Rate limiter must never take down the app
            print(f"WARN: rate limiter error: {e}")

        await self.app(scope, receive, send)