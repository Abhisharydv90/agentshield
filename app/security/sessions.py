"""
Session and token management using signed JWTs.

Two token types:
  1. Session tokens   — long-lived (7 days), stored in an HttpOnly cookie.
                        Carries user_id, tenant_id, email, role.
  2. 2FA pending      — short-lived (5 min), returned in the login response
                        when the user has TOTP enabled. Exchange for a real
                        session by hitting /api/auth/2fa/challenge.

Stateless — no session table needed. Signed with SECRET_KEY from settings.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import jwt

from app.config import settings


# ============================================================
# Constants
# ============================================================

SESSION_TTL_HOURS = 24 * 7       # one week
TWO_FA_TTL_MINUTES = 5           # pending 2FA token is short-lived
COOKIE_NAME = "agentshield_session"
CSRF_COOKIE_NAME = "agentshield_csrf"
ALGORITHM = "HS256"

TokenType = Literal["session", "2fa_pending"]


# ============================================================
# Internals
# ============================================================

def _secret() -> str:
    """Return the signing secret. Falls back to a dev default."""
    return getattr(settings, "SECRET_KEY", "dev-secret-change-me-in-prod")


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


# ============================================================
# Session tokens
# ============================================================

def create_session_token(
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    email: str,
    role: str,
) -> str:
    """Create a long-lived session JWT for a fully-authenticated user."""
    now = _now_ts()
    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "email": email,
        "role": role,
        "type": "session",
        "iat": now,
        "exp": now + SESSION_TTL_HOURS * 3600,
    }
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM)


def decode_session_token(token: str) -> dict[str, Any] | None:
    """Decode and validate a JWT. Returns None if invalid or expired."""
    try:
        payload = jwt.decode(token, _secret(), algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

    # Reject 2FA pending tokens from being used as session tokens
    if payload.get("type") == "2fa_pending":
        return None

    return payload


# ============================================================
# 2FA pending tokens
# ============================================================

def create_2fa_pending_token(user_id: uuid.UUID) -> str:
    """
    Create a short-lived token for the middle of a 2FA flow.

    Given out after the password check succeeds but before the TOTP code
    is verified. The client must exchange it at /api/auth/2fa/challenge.
    """
    now = _now_ts()
    payload = {
        "sub": str(user_id),
        "type": "2fa_pending",
        "iat": now,
        "exp": now + TWO_FA_TTL_MINUTES * 60,
    }
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM)


def decode_2fa_pending_token(token: str) -> dict[str, Any] | None:
    """Decode a 2FA pending token. Returns None if invalid or wrong type."""
    try:
        payload = jwt.decode(token, _secret(), algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

    if payload.get("type") != "2fa_pending":
        return None

    return payload


# ============================================================
# Cookie helpers
# ============================================================

def session_cookie_kwargs() -> dict[str, Any]:
    """Cookie flags for setting the session cookie."""
    return {
        "key": COOKIE_NAME,
        "max_age": SESSION_TTL_HOURS * 3600,
        "httponly": True,
        "samesite": "lax",
        "secure": getattr(settings, "ENV", "dev") == "prod",
        "path": "/",
    }


def csrf_cookie_kwargs() -> dict[str, Any]:
    """Cookie flags for the CSRF double-submit token (readable by JS)."""
    return {
        "key": CSRF_COOKIE_NAME,
        "max_age": 86400,
        "httponly": False,
        "samesite": "lax",
        "secure": getattr(settings, "ENV", "dev") == "prod",
        "path": "/",
    }