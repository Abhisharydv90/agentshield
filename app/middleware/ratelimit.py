"""
Rate limiting middleware — Redis-backed sliding window.

Prevents credential stuffing, brute-force, and API abuse.
Limits by (path-prefix, client-ip).

Headers added to every response that matches a rule:
  X-RateLimit-Limit      — max requests allowed in the window
  X-RateLimit-Remaining  — how many are left in the current window
  X-RateLimit-Reset      — unix epoch when the window resets
  Retry-After            — seconds to wait (only on 429)

Behavior:
  - Redis down → fail open. A rate limiter must never take down the app.
  - OPTIONS requests skip the limiter entirely (CORS preflight).
  - The sliding window uses a sorted set per (prefix, ip); the score is the
    request timestamp so we can expire individual entries as they age out.
"""

from __future__ import annotations

import json
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

        # --- Match the most specific rule (rules are ordered longest-first) ---
        rule = None
        for prefix, limit, window in RULES:
            if path.startswith(prefix):
                rule = (prefix, limit, window)
                break

        if rule is None:
            await self.app(scope, receive, send)
            return

        prefix, limit, window = rule

        # --- Client IP (respect X-Forwarded-For from Railway/Vercel proxies) ---
        headers = {
            k.decode().lower(): v.decode()
            for k, v in scope.get("headers", [])
        }
        ip = headers.get("x-forwarded-for", "").split(",")[0].strip()
        if not ip:
            client = scope.get("client") or ("unknown", 0)
            ip = client[0]

        r = _get_redis()
        if r is None:
            # Fail open — Redis down should not block all traffic
            await self.app(scope, receive, send)
            return

        key = f"ratelimit:{prefix}:{ip}"
        now = time.time()
        reset_at = int(now + window)
        remaining = limit

        try:
            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, now - window)
            pipe.zadd(key, {str(now): now})
            pipe.zcard(key)
            pipe.expire(key, window)
            pipe.zrange(key, 0, 0, withscores=True)
            _, _, count, _, oldest = await pipe.execute()

            # Oldest surviving entry determines when this window resets
            if oldest:
                oldest_ts = float(oldest[0][1])
                reset_at = int(oldest_ts + window)
                retry_after = max(1, reset_at - int(now))
            else:
                retry_after = window

            remaining = max(0, limit - int(count))

            # --- Over the limit: 429 with headers and a JSON body ---
            if count > limit:
                body = json.dumps({
                    "error": "rate_limit_exceeded",
                    "status": 429,
                    "retry_after": retry_after,
                }).encode()
                await send({
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"retry-after", str(retry_after).encode()),
                        (b"x-ratelimit-limit", str(limit).encode()),
                        (b"x-ratelimit-remaining", b"0"),
                        (b"x-ratelimit-reset", str(reset_at).encode()),
                        (b"content-length", str(len(body)).encode()),
                    ],
                })
                await send({"type": "http.response.body", "body": body})
                return

        except Exception as e:
            # Rate limiter must never take down the app
            print(f"WARN: rate limiter error: {e}")
            await self.app(scope, receive, send)
            return

        # --- Under the limit: wrap send to inject headers on the real response ---
        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start":
                resp_headers = list(message.get("headers", []))
                resp_headers.append((b"x-ratelimit-limit", str(limit).encode()))
                resp_headers.append((b"x-ratelimit-remaining", str(remaining).encode()))
                resp_headers.append((b"x-ratelimit-reset", str(reset_at).encode()))
                message["headers"] = resp_headers
            await send(message)

        await self.app(scope, receive, send_wrapper)