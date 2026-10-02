"""
AgentShield authentication middleware.

Authentication order:

1. X-API-Key
2. Browser session cookie
3. Development-only default tenant

Authentication produces a principal in ASGI state:

    request.state.tenant
    request.state.user
    request.state.api_key
    request.state.auth_type

Important security separation:

    Human session
        -> User
        -> Tenant
        -> RBAC

    API key
        -> APIKey
        -> Tenant
        -> Agent authorization later

API-key authenticated requests do NOT become human users.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from sqlalchemy import select

from app.config import settings
from app.db.models import APIKey, Tenant, User
from app.db.session import async_session
from app.security.api_keys import hash_key
from app.security.sessions import decode_session_token


log = logging.getLogger(
    "agentshield.auth"
)


# ============================================================
# Public paths
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


def _is_whitelisted(
    path: str,
) -> bool:
    """
    Determine whether an endpoint can be reached without
    authentication.
    """

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

    # Authentication endpoints contain their own authentication
    # state machine and therefore remain publicly reachable.
    if path.startswith("/api/auth/"):
        return True

    return False


# ============================================================
# Cookie parser
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
    Pure ASGI authentication middleware.

    Pure ASGI is used so streaming/SSE responses remain safe.
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

        # ----------------------------------------------------
        # CORS preflight
        # ----------------------------------------------------

        if method == "OPTIONS":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        # ----------------------------------------------------
        # Public paths
        # ----------------------------------------------------

        if _is_whitelisted(path):
            await self.app(
                scope,
                receive,
                send,
            )
            return

        # ----------------------------------------------------
        # Request headers
        # ----------------------------------------------------

        headers = {
            key.decode(
                "latin-1"
            ).lower(): value.decode(
                "latin-1"
            )
            for key, value
            in scope.get(
                "headers",
                [],
            )
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
        user: User | None = None
        api_key: APIKey | None = None
        auth_type: str | None = None

        # ====================================================
        # 1. API-key authentication
        # ====================================================

        if raw_api_key:

            resolved = await self._resolve_tenant_by_key(
                raw_api_key
            )

            if resolved is None:
                await self._unauthorized(
                    send,
                    "invalid_credentials",
                )
                return

            tenant, api_key = resolved
            auth_type = "api_key"

        # ====================================================
        # 2. Browser-session authentication
        # ====================================================

        if tenant is None:

            raw_session = cookies.get(
                "agentshield_session",
                "",
            )

            if raw_session:

                resolved = await self._resolve_user_by_session(
                    raw_session
                )

                if resolved is None:
                    await self._unauthorized(
                        send,
                        "invalid_credentials",
                    )
                    return

                user, tenant = resolved
                auth_type = "session"

        # ====================================================
        # 3. Development-only fallback
        # ====================================================

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

            auth_type = "dev_fallback"

        # ====================================================
        # Attach principal state
        # ====================================================

        state = scope.setdefault(
            "state",
            {},
        )

        state["tenant"] = tenant
        state["user"] = user
        state["api_key"] = api_key
        state["auth_type"] = auth_type

        await self.app(
            scope,
            receive,
            send,
        )

    # ========================================================
    # API-key resolver
    # ========================================================

    async def _resolve_tenant_by_key(
        self,
        raw_key: str,
    ) -> tuple[Tenant, APIKey] | None:

        from datetime import datetime, timezone

        key_hash = hash_key(
            raw_key
        )

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
                    await session.execute(
                        stmt
                    )
                ).first()

                if row is None:
                    return None

                api_key, tenant = row

                api_key.last_used_at = (
                    datetime.now(
                        timezone.utc
                    )
                )

                await session.commit()

                return (
                    tenant,
                    api_key,
                )

        except Exception:
            log.exception(
                "API key authentication lookup failed"
            )

            # Never convert an authentication database failure
            # into successful authentication.
            return None

    # ========================================================
    # Browser-session resolver
    # ========================================================

    async def _resolve_user_by_session(
        self,
        raw_session: str,
    ) -> tuple[User, Tenant] | None:

        try:

            payload = decode_session_token(
                raw_session
            )

            if payload is None:
                return None

            # ------------------------------------------------
            # UUID validation
            # ------------------------------------------------

            try:

                user_id = uuid.UUID(
                    str(payload["sub"])
                )

                tenant_id = uuid.UUID(
                    str(payload["tenant_id"])
                )

            except (
                KeyError,
                TypeError,
                ValueError,
            ):
                return None

            # ------------------------------------------------
            # Session-version validation
            # ------------------------------------------------

            session_version = payload.get(
                "session_version"
            )

            if not isinstance(
                session_version,
                int,
            ):
                return None

            # ------------------------------------------------
            # Database validation
            # ------------------------------------------------

            async with async_session() as session:

                user_stmt = select(
                    User
                ).where(
                    User.user_id
                    == user_id
                )

                user = (
                    await session.execute(
                        user_stmt
                    )
                ).scalar_one_or_none()

                if user is None:
                    return None

                if user.status != "active":
                    return None

                if user.tenant_id != tenant_id:
                    return None

                # Old sessions are revoked when the database
                # session version changes.
                if (
                    user.session_version
                    != session_version
                ):
                    return None

                tenant_stmt = select(
                    Tenant
                ).where(
                    Tenant.tenant_id
                    == tenant_id
                )

                tenant = (
                    await session.execute(
                        tenant_stmt
                    )
                ).scalar_one_or_none()

                if tenant is None:
                    return None

                if tenant.status != "active":
                    return None

                return (
                    user,
                    tenant,
                )

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
                    Tenant.slug
                    == settings.DEFAULT_TENANT
                )

                return (
                    await session.execute(
                        stmt
                    )
                ).scalar_one_or_none()

        except Exception:
            log.exception(
                "Default tenant lookup failed"
            )

            return None

    # ========================================================
    # 401 response
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
                "type":
                    "http.response.start",
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