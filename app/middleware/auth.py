"""
API key + session authentication middleware.

Reads credentials in this order:
  1. X-API-Key header  (server-to-server agents)
  2. agentshield_session cookie  (browser dashboard)
  3. Dev fallback: default tenant when ENV != prod

Attaches `scope["state"]["tenant"]` for downstream handlers.
Paths in _WHITELIST and /api/auth/* skip auth entirely.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy import select

from app.config import settings
from app.db.session import async_session
from app.db.models import Tenant, APIKey
from app.security.api_keys import hash_key
from app.security.sessions import decode_session_token

log = logging.getLogger("agentshield.auth")

# Paths that don't require credentials
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
    if path.startswith("/docs") or path.startswith("/redoc"):
        return True
    if path.startswith("/openapi"):
        return True
    if path.startswith("/_next"):
        return True
    if path.startswith("/api/auth/"):
        return True
    return False


def _parse_cookies(header: str) -> dict[str, str]:
    """Parse a Cookie header into a dict."""
    out: dict[str, str] = {}
    for part in header.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k] = v
    return out


class AuthMiddleware:
    """Pure ASGI middleware — safe for SSE streaming responses."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "")

        # CORS preflight bypasses auth
        if method == "OPTIONS":
            await self.app(scope, receive, send)
            return

        # Whitelisted paths bypass auth
        if _is_whitelisted(path):
            await self.app(scope, receive, send)
            return

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        raw_key = headers.get("x-api-key", "").strip()
        cookies = _parse_cookies(headers.get("cookie", ""))

        tenant: Tenant | None = None

        # --- Path 1: API key (server-to-server) ---
        if raw_key:
            tenant = await self._resolve_tenant_by_key(raw_key)
            if tenant is None:
                await self._unauthorized(send, "invalid_api_key")
                return

        # --- Path 2: Session cookie (browser) ---
        if tenant is None:
            raw_session = cookies.get("agentshield_session", "")
            if raw_session:
                tenant = await self._resolve_tenant_by_session(raw_session)
                if tenant is None:
                    await self._unauthorized(send, "invalid_session")
                    return

        # --- Path 3: Dev fallback ---
        if tenant is None:
            if settings.ENV == "prod":
                await self._unauthorized(send, "missing_credentials")
                return
            tenant = await self._resolve_default_tenant()
            if tenant is None:
                await self._unauthorized(send, "no_default_tenant")
                return

        # Attach to scope state
        state = scope.setdefault("state", {})
        state["tenant"] = tenant

        await self.app(scope, receive, send)

    # --------------------------------------------------------
    # Resolvers
    # --------------------------------------------------------

    async def _resolve_tenant_by_key(self, raw_key: str) -> Tenant | None:
        """Look up the tenant for a given API key."""
        from datetime import datetime, timezone

        key_hash = hash_key(raw_key)
        try:
            async with async_session() as session:
                stmt = (
                    select(APIKey, Tenant)
                    .join(Tenant, Tenant.tenant_id == APIKey.tenant_id)
                    .where(APIKey.key_hash == key_hash)
                    .where(APIKey.revoked.is_(False))
                    .where(Tenant.status == "active")
                )
                row = (await session.execute(stmt)).first()
                if row is None:
                    return None
                api_key, tenant = row
                api_key.last_used_at = datetime.now(timezone.utc)
                await session.commit()
                return tenant
        except Exception as e:
            log.exception("Auth key lookup failed: %s", e)
            return None

    async def _resolve_tenant_by_session(self, raw_session: str) -> Tenant | None:
        """Look up the tenant from a session JWT cookie."""
        try:
            payload = decode_session_token(raw_session)
            if payload is None:
                return None
            tenant_id_str = payload.get("tenant_id")
            if not tenant_id_str:
                return None
            async with async_session() as session:
                stmt = select(Tenant).where(
                    Tenant.tenant_id == uuid.UUID(tenant_id_str)
                )
                t = (await session.execute(stmt)).scalar_one_or_none()
                if t is None or t.status != "active":
                    return None
                return t
        except Exception as e:
            log.exception("Session tenant lookup failed: %s", e)
            return None

    async def _resolve_default_tenant(self) -> Tenant | None:
        """In dev mode, fall back to the tenant with slug='default'."""
        try:
            async with async_session() as session:
                stmt = select(Tenant).where(Tenant.slug == "default")
                return (await session.execute(stmt)).scalar_one_or_none()
        except Exception as e:
            log.exception("Default tenant lookup failed: %s", e)
            return None

    # --------------------------------------------------------
    # Helpers
    # --------------------------------------------------------

    async def _unauthorized(self, send: Any, reason: str) -> None:
        """Send a 401 JSON response."""
        import json

        body = json.dumps({"error": reason, "status": 401}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})