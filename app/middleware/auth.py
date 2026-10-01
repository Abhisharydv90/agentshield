"""
AgentShield authentication middleware.

Authentication order:

1. X-API-Key
2. Browser session cookie
3. Development-only default tenant

Production never falls back to a default tenant.

Security properties:

- Invalid credentials fail closed.
- Suspended tenants are rejected.
- Session JWT must contain a valid tenant.
- API keys are hashed before lookup.
- Authentication does not trust client-provided tenant IDs.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from sqlalchemy import select

from app.config import settings
from app.db.models import APIKey, Tenant
from app.db.session import async_session
from app.security.api_keys import hash_key
from app.security.sessions import decode_session_token


log = logging.getLogger("agentshield.auth")


# ============================================================
# Public/unauthenticated paths
# ============================================================

_WHITELIST = {
    "/",
    "/health",
    "/ready",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
}


def _is_whitelisted(path: str) -> bool:
    if path in _WHITELIST:
        return True

    if path.startswith("/docs"):
        return True

    if path.startswith("/redoc"):
        return True

    if path.startswith("/openapi"):
        return True

    if path.startswith("/_next"):
        return True

    # Authentication endpoints are intentionally public.
    if path.startswith("/api/auth/"):
        return True

    return False


# ============================================================
# Cookie parsing
# ============================================================

def _parse_cookies(
    header: str,
) -> dict[str, str]:

    cookies: dict[str, str] = {}

    for part in header.split(";"):
        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split(
            "=",
            1,
        )

        cookies[key.strip()] = value.strip()

    return cookies


# ============================================================
# Middleware
# ============================================================

class AuthMiddleware:
    """
    Pure ASGI middleware.

    Pure ASGI is intentional because AgentShield supports
    streaming/SSE responses.
    """

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

        # -----------------------------------------------------
        # CORS preflight
        # -----------------------------------------------------

        if method == "OPTIONS":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        # -----------------------------------------------------
        # Public endpoints
        # -----------------------------------------------------

        if _is_whitelisted(path):
            await self.app(
                scope,
                receive,
                send,
            )
            return

        # -----------------------------------------------------
        # Headers
        # -----------------------------------------------------

        headers = {
            key.decode("latin-1").lower():
            value.decode("latin-1")
            for key, value
            in scope.get("headers", [])
        }

        raw_api_key = headers.get(
            "x-api-key",
            "",
        ).strip()

        cookies = _parse_cookies(
            headers.get(
                "cookie",
                "",
            )
        )

        tenant: Tenant | None = None

        # =====================================================
        # 1. API key authentication
        # =====================================================

        if raw_api_key:

            tenant = await self._resolve_tenant_by_key(
                raw_api_key
            )

            if tenant is None:
                await self._unauthorized(
                    send,
                    "invalid_credentials",
                )
                return

        # =====================================================
        # 2. Browser session authentication
        # =====================================================

        if tenant is None:

            raw_session = cookies.get(
                "agentshield_session",
                "",
            )

            if raw_session:

                tenant = await self._resolve_tenant_by_session(
                    raw_session
                )

                if tenant is None:
                    await self._unauthorized(
                        send,
                        "invalid_credentials",
                    )
                    return

        # =====================================================
        # 3. Development fallback
        # =====================================================

        if tenant is None:

            if settings.ENV != "dev":
                await self._unauthorized(
                    send,
                    "missing_credentials",
                )
                return

            tenant = await self._resolve_default_tenant()

            if tenant is None:
                await self._unauthorized(
                    send,
                    "authentication_required",
                )
                return

        # =====================================================
        # Attach authenticated tenant
        # =====================================================

        state = scope.setdefault(
            "state",
            {},
        )

        state["tenant"] = tenant

        await self.app(
            scope,
            receive,
            send,
        )

    # ========================================================
    # API key resolver
    # ========================================================

    async def _resolve_tenant_by_key(
        self,
        raw_key: str,
    ) -> Tenant | None:

        from datetime import datetime, timezone

        key_hash = hash_key(raw_key)

        try:

            async with async_session() as session:

                stmt = (
                    select(
                        APIKey,
                        Tenant,
                    )
                    .join(
                        Tenant,
                        Tenant.tenant_id
                        == APIKey.tenant_id,
                    )
                    .where(
                        APIKey.key_hash
                        == key_hash
                    )
                    .where(
                        APIKey.revoked.is_(False)
                    )
                    .where(
                        Tenant.status
                        == "active"
                    )
                )

                row = (
                    await session.execute(stmt)
                ).first()

                if row is None:
                    return None

                api_key, tenant = row

                api_key.last_used_at = (
                    datetime.now(timezone.utc)
                )

                await session.commit()

                return tenant

        except Exception:
            log.exception(
                "API key authentication lookup failed"
            )

            # Fail closed.
            return None

    # ========================================================
    # Session resolver
    # ========================================================

    async def _resolve_tenant_by_session(
        self,
        raw_session: str,
    ) -> Tenant | None:

        try:

            payload = decode_session_token(
                raw_session
            )

            if payload is None:
                return None

            tenant_id_raw = payload.get(
                "tenant_id"
            )

            if not tenant_id_raw:
                return None

            try:
                tenant_id = uuid.UUID(
                    str(tenant_id_raw)
                )
            except ValueError:
                return None

            async with async_session() as session:

                stmt = select(Tenant).where(
                    Tenant.tenant_id
                    == tenant_id
                )

                tenant = (
                    await session.execute(stmt)
                ).scalar_one_or_none()

                if tenant is None:
                    return None

                if tenant.status != "active":
                    return None

                return tenant

        except Exception:
            log.exception(
                "Session authentication lookup failed"
            )

            return None

    # ========================================================
    # Development tenant
    # ========================================================

    async def _resolve_default_tenant(
        self,
    ) -> Tenant | None:

        try:

            async with async_session() as session:

                stmt = select(Tenant).where(
                    Tenant.slug == settings.DEFAULT_TENANT
                )

                return (
                    await session.execute(stmt)
                ).scalar_one_or_none()

        except Exception:
            log.exception(
                "Default tenant lookup failed"
            )

            return None

    # ========================================================
    # Response helpers
    # ========================================================

    async def _unauthorized(
        self,
        send: Any,
        reason: str,
    ) -> None:

        body = json.dumps(
            {
                "error": reason,
                "status": 401,
            }
        ).encode()

        await send(
            {
                "type": "http.response.start",
                "status": 401,
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