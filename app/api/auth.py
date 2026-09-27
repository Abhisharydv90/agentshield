"""
Authentication endpoints.

Endpoints:
  POST /api/auth/signup        → creates Tenant + User + first APIKey + session cookie
  POST /api/auth/login         → verifies password, returns session cookie
  POST /api/auth/logout        → clears the session cookie
  GET  /api/auth/me            → returns the current user (dashboard bootstrap)
  POST /api/auth/refresh       → issues a fresh session cookie (sliding window)
  POST /api/auth/change-password → authenticated password change

Security notes:
  - Passwords are hashed with Argon2id (see app.security.passwords).
  - Session cookies are HttpOnly, SameSite=Lax, and short-lived JWTs.
  - Email validation allows `.test` reserved TLD in dev only.
  - Login failures return generic `invalid_credentials` (no user enumeration).
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from email_validator import validate_email, EmailNotValidError
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.config import settings
from app.db.session import async_session
from app.db.models import User, Tenant, APIKey
from app.security.passwords import hash_password, verify_password, needs_rehash
from app.security.sessions import (
    create_session_token,
    decode_session_token,
    COOKIE_NAME,
    SESSION_TTL_HOURS,
)
from app.security.api_keys import generate_key, hash_key, key_prefix


router = APIRouter(prefix="/api/auth", tags=["auth"])


# ============================================================
# Helpers
# ============================================================

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_email_value(v: str) -> str:
    """
    Validate and normalize an email address.

    In dev/staging we allow reserved TLDs like `.test` (RFC 6761) so local
    tests can run without registering domains. In prod we use the strict
    default (check_deliverability=False still — we don't want to block
    signups on DNS hiccups).
    """
    v = (v or "").strip()
    if not _EMAIL_RE.match(v):
        raise ValueError("Invalid email format")

    try:
        result = validate_email(
            v,
            check_deliverability=False,
            test_environment=(settings.ENV != "prod"),
        )
        return result.normalized.lower()
    except EmailNotValidError as e:
        raise ValueError(str(e))


def _validate_password_strength(v: str) -> str:
    """Enforce a minimal password policy: length + has a letter + has a digit."""
    if len(v) < 8:
        raise ValueError("Password must be at least 8 characters")
    if len(v) > 200:
        raise ValueError("Password is too long")
    if not any(c.isalpha() for c in v):
        raise ValueError("Password must contain a letter")
    if not any(c.isdigit() for c in v):
        raise ValueError("Password must contain a digit")
    return v


def _slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s[:48] or "tenant"


async def _unique_slug(session, base: str) -> str:
    slug = base
    i = 1
    while True:
        exists = (
            await session.execute(select(Tenant).where(Tenant.slug == slug))
        ).scalar_one_or_none()
        if not exists:
            return slug
        i += 1
        slug = f"{base}-{i}"


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_HOURS * 3600,
        httponly=True,
        samesite="lax",
        secure=(settings.ENV == "prod"),
        path="/",
    )


def _client_meta(request: Request) -> dict[str, Any]:
    """Capture request metadata for audit logs (no PII beyond IP)."""
    return {
        "ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent", "")[:200],
        "origin": request.headers.get("origin"),
    }


async def _write_auth_event(
    tenant_id: uuid.UUID,
    category: str,
    action: str,
    reasoning: str,
    request_id: str | None = None,
) -> None:
    """Best-effort audit log write. Never raises — auth must not fail if audit does."""
    try:
        from app.telemetry.audit import write_event
        async with async_session() as session:
            await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id=request_id,
                threat_category=category,
                action_taken=action,
                evaluator_reasoning=reasoning,
            )
    except Exception as e:
        print(f"WARN: auth audit log failed: {e}")


def _user_payload(user: User, tenant: Tenant) -> dict[str, Any]:
    return {
        "user_id": str(user.user_id),
        "tenant_id": str(tenant.tenant_id),
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "tenant_slug": tenant.slug,
    }


# ============================================================
# Schemas
# ============================================================

class SignupRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=200)
    name: str = Field(min_length=1, max_length=200)
    tenant_name: str = Field(min_length=1, max_length=200)

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        return _validate_email_value(v)

    @field_validator("password")
    @classmethod
    def _password_ok(cls, v: str) -> str:
        return _validate_password_strength(v)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=200)

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        return _validate_email_value(v)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=8, max_length=200)

    @field_validator("new_password")
    @classmethod
    def _password_ok(cls, v: str) -> str:
        return _validate_password_strength(v)


class UserOut(BaseModel):
    user_id: str
    tenant_id: str
    email: str
    name: str
    role: str
    tenant_slug: str


# ============================================================
# Signup
# ============================================================

@router.post("/signup", response_model=None)
async def signup(req: SignupRequest, request: Request, response: Response) -> dict:
    meta = _client_meta(request)

    async with async_session() as session:
        # Email uniqueness
        existing = (
            await session.execute(select(User).where(User.email == req.email))
        ).scalar_one_or_none()
        if existing is not None:
            raise HTTPException(status_code=400, detail="email_already_registered")

        # Create tenant
        slug = await _unique_slug(session, _slugify(req.tenant_name))
        tenant = Tenant(slug=slug, name=req.tenant_name.strip())
        session.add(tenant)
        await session.flush()

        # Create owner user
        user = User(
            tenant_id=tenant.tenant_id,
            email=req.email,
            password_hash=hash_password(req.password),
            name=req.name.strip(),
            role="owner",
            email_verified=False,
        )
        session.add(user)
        await session.flush()

        # Issue the tenant's first API key
        raw_key = generate_key(live=False)
        api_key = APIKey(
            tenant_id=tenant.tenant_id,
            name="default",
            key_prefix=key_prefix(raw_key),
            key_hash=hash_key(raw_key),
        )
        session.add(api_key)
        await session.commit()

        user_payload = _user_payload(user, tenant)

    # Audit log (best effort, outside the transaction)
    await _write_auth_event(
        tenant_id=tenant.tenant_id,
        category="other",
        action="allowed",
        reasoning=f"signup: {meta['ip']} · {meta['user_agent'][:60]}",
    )

    # Session cookie
    token = create_session_token(user.user_id, tenant.tenant_id, user.email, user.role)
    _set_session_cookie(response, token)

    return {
        "user": user_payload,
        "api_key": raw_key,  # shown once
    }


# ============================================================
# Login
# ============================================================

@router.post("/login", response_model=None)
async def login(req: LoginRequest, request: Request, response: Response) -> dict:
    meta = _client_meta(request)

    async with async_session() as session:
        user = (
            await session.execute(select(User).where(User.email == req.email))
        ).scalar_one_or_none()

        # Constant-time defense: even if the user doesn't exist, we run a
        # dummy password verify to prevent timing-based user enumeration.
        if user is None:
            hash_password(req.password)  # burn ~50ms
            raise HTTPException(status_code=401, detail="invalid_credentials")

        if user.status != "active":
            raise HTTPException(status_code=403, detail=f"account_{user.status}")

        if not verify_password(req.password, user.password_hash):
            raise HTTPException(status_code=401, detail="invalid_credentials")

        # Opportunistically upgrade old hashes
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(req.password)

        tenant = (
            await session.execute(
                select(Tenant).where(Tenant.tenant_id == user.tenant_id)
            )
        ).scalar_one_or_none()
        if tenant is None or tenant.status != "active":
            raise HTTPException(status_code=403, detail="tenant_inactive")

        user.last_login_at = datetime.now(timezone.utc)
        await session.commit()

        user_payload = _user_payload(user, tenant)

    await _write_auth_event(
        tenant_id=tenant.tenant_id,
        category="other",
        action="allowed",
        reasoning=f"login: {meta['ip']} · {meta['user_agent'][:60]}",
    )

    token = create_session_token(user.user_id, tenant.tenant_id, user.email, user.role)
    _set_session_cookie(response, token)

    return {"user": user_payload}


# ============================================================
# Logout
# ============================================================

@router.post("/logout")
async def logout(response: Response) -> dict:
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


# ============================================================
# Me
# ============================================================

async def _resolve_session(request: Request) -> tuple[User, Tenant]:
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        raise HTTPException(status_code=401, detail="not_authenticated")

    payload = decode_session_token(raw)
    if payload is None:
        raise HTTPException(status_code=401, detail="session_expired")

    async with async_session() as session:
        user = (
            await session.execute(
                select(User).where(User.user_id == uuid.UUID(payload["sub"]))
            )
        ).scalar_one_or_none()
        if user is None or user.status != "active":
            raise HTTPException(status_code=401, detail="user_inactive")

        tenant = (
            await session.execute(
                select(Tenant).where(Tenant.tenant_id == user.tenant_id)
            )
        ).scalar_one_or_none()
        if tenant is None or tenant.status != "active":
            raise HTTPException(status_code=401, detail="tenant_inactive")

    return user, tenant


@router.get("/me", response_model=UserOut)
async def me(request: Request) -> UserOut:
    user, tenant = await _resolve_session(request)
    return UserOut(**_user_payload(user, tenant))


# ============================================================
# Refresh (sliding session)
# ============================================================

@router.post("/refresh")
async def refresh(request: Request, response: Response) -> dict:
    user, tenant = await _resolve_session(request)
    token = create_session_token(user.user_id, tenant.tenant_id, user.email, user.role)
    _set_session_cookie(response, token)
    return {"ok": True, "user": _user_payload(user, tenant)}


# ============================================================
# Change password
# ============================================================

@router.post("/change-password")
async def change_password(
    req: ChangePasswordRequest, request: Request, response: Response
) -> dict:
    user, tenant = await _resolve_session(request)

    async with async_session() as session:
        # Re-fetch within this session to get a bound instance
        db_user = (
            await session.execute(select(User).where(User.user_id == user.user_id))
        ).scalar_one()

        if not verify_password(req.current_password, db_user.password_hash):
            raise HTTPException(status_code=401, detail="invalid_current_password")

        if verify_password(req.new_password, db_user.password_hash):
            raise HTTPException(status_code=400, detail="password_unchanged")

        db_user.password_hash = hash_password(req.new_password)
        await session.commit()

    await _write_auth_event(
        tenant_id=tenant.tenant_id,
        category="other",
        action="allowed",
        reasoning="password_changed",
    )

    # Invalidate the old session, issue a new one
    response.delete_cookie(COOKIE_NAME, path="/")
    token = create_session_token(user.user_id, tenant.tenant_id, user.email, user.role)
    _set_session_cookie(response, token)

    return {"ok": True}