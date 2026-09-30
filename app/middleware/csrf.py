"""
CSRF protection using the double-submit cookie pattern.

- On every GET/HEAD/OPTIONS request to /api/*, we ensure a `csrf_token`
  cookie is set (readable by JS, not HttpOnly).
- On state-changing requests (POST/PUT/PATCH/DELETE) to /api/*, the client
  must send the same token in the `X-CSRF-Token` header.
- Login/signup/logout are exempt because there's no session yet.
"""

from __future__ import annotations

import hmac
import secrets
from typing import Any

COOKIE_NAME = "agentshield_csrf"
HEADER_NAME = "x-csrf-token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Endpoints that are exempt from CSRF checks (no session to protect)
_EXEMPT_PREFIXES = (
    "/api/auth/signup",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/2fa/challenge",  # uses a pending token, not a session
)


def _generate_token() -> str:
    return secrets.token_urlsafe(32)


def _parse_cookies(header: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in header.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k] = v
    return out


class CSRFMiddleware:
    """Pure ASGI middleware."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope.get("path", "")
        headers = {
            k.decode().lower(): v.decode()
            for k, v in scope.get("headers", [])
        }
        cookies = _parse_cookies(headers.get("cookie", ""))

        is_api = path.startswith("/api/")
        is_exempt = any(path.startswith(p) for p in _EXEMPT_PREFIXES)

        # Enforce CSRF on state-changing API requests
        needs_check = (
            is_api
            and not is_exempt
            and method not in SAFE_METHODS
        )

        if needs_check:
            cookie_token = cookies.get(COOKIE_NAME, "")
            header_token = headers.get(HEADER_NAME, "")
            if not cookie_token or not header_token:
                await self._reject(send, "csrf_missing")
                return
            if not hmac.compare_digest(cookie_token, header_token):
                await self._reject(send, "csrf_mismatch")
                return

        # Ensure the CSRF cookie is set on every API response if missing
        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start" and is_api:
                if not cookies.get(COOKIE_NAME):
                    token = _generate_token()
                    cookie_value = (
                        f"{COOKIE_NAME}={token}; Path=/; "
                        f"SameSite=Lax; Max-Age=86400"
                    )
                    resp_headers = list(message.get("headers", []))
                    resp_headers.append((b"set-cookie", cookie_value.encode()))
                    message["headers"] = resp_headers
            await send(message)

        await self.app(scope, receive, send_wrapper)

    async def _reject(self, send: Any, reason: str) -> None:
        import json
        body = json.dumps({"error": reason, "status": 403}).encode()
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})