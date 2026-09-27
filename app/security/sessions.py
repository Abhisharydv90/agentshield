"""
Session tokens using signed JWTs.

- Short-lived access tokens (24h) stored in an HttpOnly cookie.
- Stateless — no session table needed.
- Signed with SECRET_KEY from settings (add to config if missing).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from app.config import settings


SESSION_TTL_HOURS = 24 * 7  # one week
COOKIE_NAME = "agentshield_session"
ALGORITHM = "HS256"


def _secret() -> str:
    # Add SECRET_KEY to app/config.py — fallback keeps dev working
    return getattr(settings, "SECRET_KEY", "dev-secret-change-me-in-prod")


def create_session_token(
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    email: str,
    role: str,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "email": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=SESSION_TTL_HOURS)).timestamp()),
    }
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM)


def decode_session_token(token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(token, _secret(), algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None