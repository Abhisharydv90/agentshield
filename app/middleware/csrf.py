"""
CSRF protection using the double-submit cookie pattern.

- On any GET /api/auth/* request, we set a `csrf_token` cookie (not HttpOnly).
- On any POST/PUT/PATCH/DELETE, the client must send the same token
  in the `X-CSRF-Token` header.
- Token mismatch → 403.
"""

from __future__ import annotations

import hmac
import secrets
from typing import Any

COOKIE_NAME = "agentshield_csrf"
HEADER_NAME = "x-csrf-token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _generate_token() -> str:
    return secrets.token_urlsafe(32)


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
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        cookies = _parse_cookies(headers.get("cookie", ""))

        # Only enforce on state-changing requests to /api/*
        needs_check = (
            method not in SAFE_METHODS
            and path.startswith("/api/")
            and not path.startswith("/api/auth/signup")   # signup has no session yet
            and not path.startswith("/api/auth/login")    # login is the token source
            and not path.startswith("/api/auth/logout")   # logout is idempotent
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

        # Wrap send so we can set the CSRF cookie on every API response
        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start" and path.startswith("/api/"):
                resp_headers = list(message.get("headers", []))
                existing = {k.decode().lower() for k, _ in resp_headers}
                if COOKIE_NAME not in existing and f"set-cookie" not in existing:
                    token = cookies.get(COOKIE_NAME) or _generate_token()
                    cookie_value = (
                        f"{COOKIE_NAME}={token}; Path=/; "
                        f"SameSite=Lax; Max-Age=86400"
                    )
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


def _parse_cookies(header: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in header.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k] = v
    return out