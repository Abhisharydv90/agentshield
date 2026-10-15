"""
AgentShield session token management.

Token types:

1. session
   Fully authenticated browser session.

2. 2fa_pending
   Short-lived token issued after password verification but before
   TOTP verification.

Security properties:

- Explicit HS256 algorithm.
- Required JWT claims.
- Short-lived 2FA token.
- No algorithm confusion.
- No development secret fallback.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

import jwt

from app.config import settings


COOKIE_NAME = "agentshield_session"
CSRF_COOKIE_NAME = "agentshield_csrf"

ALGORITHM = "HS256"

SESSION_TTL_HOURS = settings.SESSION_TTL_HOURS
TWO_FA_TTL_MINUTES = 5

TokenType = Literal[
    "session",
    "2fa_pending",
]


# ============================================================
# Internal helpers
# ============================================================

def _secret() -> str:
    """
    Return the configured signing secret.

    There is intentionally NO development fallback here.
    """

    secret = settings.SECRET_KEY.strip()

    if not secret:
        raise RuntimeError(
            "SECRET_KEY is not configured."
        )

    return secret


def _now_ts() -> int:
    return int(
        datetime.now(timezone.utc).timestamp()
    )


# ============================================================
# Session tokens
# ============================================================

def create_session_token(
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    email: str,
    role: str,
    session_version: int = 0,
) -> str:
    """
    Create an authenticated session token.

    session_version allows us to invalidate all existing sessions
    for a user later by incrementing the database value.
    """

    now = _now_ts()

    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "email": email,
        "role": role,
        "session_version": session_version,
        "type": "session",
        "iat": now,
        "nbf": now,
        "exp": now + SESSION_TTL_HOURS * 3600,
        "jti": str(uuid.uuid4()),
    }

    return jwt.encode(
        payload,
        _secret(),
        algorithm=ALGORITHM,
    )


def decode_session_token(
    token: str,
) -> dict[str, Any] | None:
    """
    Decode and validate a session JWT.

    Returns None for every invalid token.
    """

    try:
        payload = jwt.decode(
            token,
            _secret(),
            algorithms=[ALGORITHM],
            options={
                "require": [
                    "sub",
                    "tenant_id",
                    "type",
                    "iat",
                    "nbf",
                    "exp",
                    "jti",
                ]
            },
        )

    except jwt.PyJWTError:
        return None

    if payload.get("type") != "session":
        return None

    if not payload.get("sub"):
        return None

    if not payload.get("tenant_id"):
        return None

    return payload


# ============================================================
# 2FA pending tokens
# ============================================================

def create_2fa_pending_token(
    user_id: uuid.UUID,
) -> str:
    """
    Create a short-lived token for the second authentication step.
    """

    now = _now_ts()

    payload = {
        "sub": str(user_id),
        "type": "2fa_pending",
        "iat": now,
        "nbf": now,
        "exp": now + TWO_FA_TTL_MINUTES * 60,
        "jti": str(uuid.uuid4()),
    }

    return jwt.encode(
        payload,
        _secret(),
        algorithm=ALGORITHM,
    )


def decode_2fa_pending_token(
    token: str,
) -> dict[str, Any] | None:
    """
    Decode a pending 2FA token.
    """

    try:
        payload = jwt.decode(
            token,
            _secret(),
            algorithms=[ALGORITHM],
            options={
                "require": [
                    "sub",
                    "type",
                    "iat",
                    "nbf",
                    "exp",
                    "jti",
                ]
            },
        )

    except jwt.PyJWTError:
        return None

    if payload.get("type") != "2fa_pending":
        return None

    if not payload.get("sub"):
        return None

    return payload


# ============================================================
# Cookie configuration
# ============================================================

def session_cookie_kwargs() -> dict[str, Any]:
    """
    Browser cookie configuration for the authenticated session.
    """

    secure = settings.ENV in {
        "staging",
        "prod",
    }

    return {
        "key": COOKIE_NAME,
        "max_age": SESSION_TTL_HOURS * 3600,
        "httponly": True,
        "secure": secure,
        "samesite": "lax",
        "path": "/",
    }


def csrf_cookie_kwargs() -> dict[str, Any]:
    """
    CSRF cookie configuration.

    This cookie must be readable by the frontend.
    """

    secure = settings.ENV in {
        "staging",
        "prod",
    }

    return {
        "key": CSRF_COOKIE_NAME,
        "max_age": 86400,
        "httponly": False,
        "secure": secure,
        "samesite": "lax",
        "path": "/",
    }