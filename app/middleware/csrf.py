"""
AgentShield CSRF protection.

Browser session requests:
    Require CSRF token + trusted Origin.

API-key requests:
    Do not require browser CSRF tokens because X-API-Key is
    not automatically attached by browsers.

This prevents the CSRF middleware from accidentally breaking
server-to-server AgentShield API clients.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

from app.config import settings


COOKIE_NAME = "agentshield_csrf"
HEADER_NAME = "x-csrf-token"

SAFE_METHODS = {
    "GET",
    "HEAD",
    "OPTIONS",
}


_EXEMPT_PREFIXES = (
    "/api/auth/signup",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/2fa/challenge",
    "/api/auth/forgot-password",
    "/api/auth/reset-password",
    "/api/auth/verify-email",
    "/api/auth/resend-verification",
)


# ============================================================
# Token generation
# ============================================================

def _generate_token() -> str:
    """
    Generate a high-entropy CSRF token.
    """

    return secrets.token_urlsafe(32)


# ============================================================
# Cookie parser
# ============================================================

def _parse_cookies(
    header: str,
) -> dict[str, str]:

    result: dict[str, str] = {}

    for part in header.split(";"):

        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split(
            "=",
            1,
        )

        result[key.strip()] = value.strip()

    return result


# ============================================================
# Constant-time comparison
# ============================================================

def _same_token(
    left: str,
    right: str,
) -> bool:

    if not left or not right:
        return False

    return hmac.compare_digest(
        left,
        right,
    )


# ============================================================
# Origin validation
# ============================================================

def _origin_is_trusted(
    origin: str,
) -> bool:

    if not origin:
        return False

    normalized = origin.rstrip("/")

    return normalized in {
        item.rstrip("/")
        for item in settings.cors_origins
    }


# ============================================================
# Middleware
# ============================================================

class CSRFMiddleware:

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

        method = scope.get(
            "method",
            "GET",
        )

        path = scope.get(
            "path",
            "",
        )

        headers = {
            key.decode("latin-1").lower():
            value.decode("latin-1")
            for key, value
            in scope.get("headers", [])
        }

        cookies = _parse_cookies(
            headers.get(
                "cookie",
                "",
            )
        )

        # -----------------------------------------------------
        # Only protect API routes
        # -----------------------------------------------------

        is_api = path.startswith("/api/")

        if not is_api:
            await self.app(
                scope,
                receive,
                send,
            )
            return

        # -----------------------------------------------------
        # Public auth routes
        # -----------------------------------------------------

        is_exempt = any(
            path.startswith(prefix)
            for prefix in _EXEMPT_PREFIXES
        )

        # -----------------------------------------------------
        # API-key requests are not browser-CSRF requests.
        # -----------------------------------------------------

        has_api_key = bool(
            headers.get(
                "x-api-key",
                "",
            ).strip()
        )

        has_session_cookie = bool(
            cookies.get(
                "agentshield_session",
                "",
            )
        )

        needs_check = (
            method not in SAFE_METHODS
            and not is_exempt
            and not has_api_key
            and has_session_cookie
        )

        # -----------------------------------------------------
        # CSRF enforcement
        # -----------------------------------------------------

        if needs_check:

            cookie_token = cookies.get(
                COOKIE_NAME,
                "",
            )

            header_token = headers.get(
                HEADER_NAME,
                "",
            ).strip()

            if not cookie_token or not header_token:

                await self._reject(
                    send,
                    "csrf_missing",
                )

                return

            if not _same_token(
                cookie_token,
                header_token,
            ):

                await self._reject(
                    send,
                    "csrf_mismatch",
                )

                return

            origin = headers.get(
                "origin",
                "",
            ).strip()

            if origin and not _origin_is_trusted(
                origin
            ):

                await self._reject(
                    send,
                    "untrusted_origin",
                )

                return

            # If Origin is absent, check Referer.
            if not origin:

                referer = headers.get(
                    "referer",
                    "",
                )

                if settings.ENV in {
                    "staging",
                    "prod",
                } and not referer:
                    await self._reject(
                        send,
                        "missing_origin",
                    )

                    return

        # -----------------------------------------------------
        # Set CSRF cookie if necessary
        # -----------------------------------------------------

        async def send_wrapper(
            message: dict,
        ) -> None:

            if (
                message["type"]
                == "http.response.start"
            ):

                if not cookies.get(
                    COOKIE_NAME
                ):

                    token = _generate_token()

                    secure = (
                        settings.ENV
                        in {"staging", "prod"}
                    )

                    cookie = (
                        f"{COOKIE_NAME}={token}; "
                        "Path=/; "
                        "SameSite=Lax; "
                        "Max-Age=86400"
                    )

                    if secure:
                        cookie += "; Secure"

                    response_headers = list(
                        message.get(
                            "headers",
                            [],
                        )
                    )

                    response_headers.append(
                        (
                            b"set-cookie",
                            cookie.encode(),
                        )
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
        reason: str,
    ) -> None:

        body = json.dumps(
            {
                "error": reason,
                "status": 403,
            }
        ).encode()

        await send(
            {
                "type": "http.response.start",
                "status": 403,
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
                        b"content-length",
                        str(len(body)).encode(),
                    ),
                ],
            }
        )

        await send(
            {
                "type": "http.response.body",
                "body": body,
            }
        )