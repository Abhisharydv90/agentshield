"""
Authentication endpoints.

Endpoints:
  POST /api/auth/signup              → creates Tenant + User + first APIKey + session cookie
  POST /api/auth/login               → verifies password, returns session cookie OR 2FA challenge
  POST /api/auth/logout              → clears the session cookie
  GET  /api/auth/me                  → returns the current user (dashboard bootstrap)
  POST /api/auth/refresh             → issues a fresh session cookie (sliding window)
  POST /api/auth/change-password     → authenticated password change

  2FA (TOTP):
  POST /api/auth/2fa/setup           → begin enrollment, returns secret + QR
  POST /api/auth/2fa/verify-setup    → confirm enrollment, returns recovery codes
  POST /api/auth/2fa/disable         → disable 2FA (requires valid code)
  POST /api/auth/2fa/challenge       → complete login when 2FA is enabled
  GET  /api/auth/2fa/status          → is 2FA enabled for current user?

Security notes:
  - Passwords are hashed with Argon2id (see app.security.passwords).
  - Session cookies are HttpOnly, SameSite=Lax, Secure in prod.
  - Email validation allows `.test` reserved TLD in dev only.
  - Login failures return generic `invalid_credentials` (no user enumeration).
  - 2FA pending tokens are short-lived (5 min) and cannot be used as session tokens.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from email_validator import validate_email, EmailNotValidError
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, update

from app.config import settings
from app.db.session import async_session
from app.db.models import User, Tenant, APIKey, TOTPCredential, AuthToken
from app.email.sender import send_email
from app.email.templates import (
    password_reset_email,
    email_verification_email,
)
from app.security.passwords import hash_password, verify_password, needs_rehash
from app.security.sessions import (
    create_session_token,
    create_2fa_pending_token,
    decode_session_token,
    decode_2fa_pending_token,
    COOKIE_NAME,
    SESSION_TTL_HOURS,
    session_cookie_kwargs,
)
from app.security.api_keys import generate_key, hash_key, key_prefix
from app.security.totp import (
    generate_secret,
    provisioning_uri,
    qr_code_data_url,
    verify_totp,
    generate_recovery_codes,
)


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
    """Enforce a minimal password policy: length + letter + digit."""
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
    """Set the session cookie with consistent flags."""
    response.set_cookie(value=token, **session_cookie_kwargs())


def _delete_session_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


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
        "email_verified": user.email_verified,
    }


async def _resolve_session(
    request: Request,
) -> tuple[User, Tenant]:
    """
    Resolve and validate the authenticated browser session.

    Cryptographic validation happens first through the JWT decoder.

    Database validation then checks:

    - user exists
    - user is active
    - tenant exists
    - tenant is active
    - JWT user ID matches database user
    - JWT tenant ID matches database tenant
    - JWT session_version matches the current database version

    The final check gives us server-side session revocation.
    """

    raw = request.cookies.get(COOKIE_NAME)

    if not raw:
        raise HTTPException(
            status_code=401,
            detail="not_authenticated",
        )

    payload = decode_session_token(raw)

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="invalid_session",
        )

    # ---------------------------------------------------------
    # Validate UUIDs before touching the database.
    # ---------------------------------------------------------

    try:
        user_id = uuid.UUID(
            str(payload["sub"])
        )

        tenant_id = uuid.UUID(
            str(payload["tenant_id"])
        )

    except (
        KeyError,
        ValueError,
        TypeError,
    ):
        raise HTTPException(
            status_code=401,
            detail="invalid_session",
        )

    token_session_version = payload.get(
        "session_version"
    )

    if not isinstance(
        token_session_version,
        int,
    ):
        raise HTTPException(
            status_code=401,
            detail="invalid_session",
        )

    # ---------------------------------------------------------
    # Database validation
    # ---------------------------------------------------------

    async with async_session() as session:

        user = (
            await session.execute(
                select(User).where(
                    User.user_id == user_id
                )
            )
        ).scalar_one_or_none()

        if user is None:
            raise HTTPException(
                status_code=401,
                detail="invalid_session",
            )

        if user.status != "active":
            raise HTTPException(
                status_code=401,
                detail="user_inactive",
            )

        # -----------------------------------------------------
        # Server-side session revocation
        # -----------------------------------------------------

        if (
            user.session_version
            != token_session_version
        ):
            raise HTTPException(
                status_code=401,
                detail="session_revoked",
            )

        # -----------------------------------------------------
        # Tenant must match the token.
        # -----------------------------------------------------

        if user.tenant_id != tenant_id:
            raise HTTPException(
                status_code=401,
                detail="invalid_session",
            )

        tenant = (
            await session.execute(
                select(Tenant).where(
                    Tenant.tenant_id
                    == user.tenant_id
                )
            )
        ).scalar_one_or_none()

        if tenant is None:
            raise HTTPException(
                status_code=401,
                detail="invalid_session",
            )

        if tenant.status != "active":
            raise HTTPException(
                status_code=401,
                detail="tenant_inactive",
            )

    return user, tenant


# ============================================================
# Auth token helpers (password reset + email verification)
# ============================================================

def _generate_token() -> str:
    """Cryptographically random URL-safe token — 43 chars, ~256 bits."""
    return secrets.token_urlsafe(32)


def _hash_token(raw: str) -> str:
    """SHA-256 hex digest of a raw token. Only this is stored."""
    return hashlib.sha256(raw.encode()).hexdigest()


async def _issue_token(
    session,
    user_id: uuid.UUID,
    kind: str,
    ttl_seconds: int,
    request_ip: str | None = None,
) -> str:
    """Create and persist a token. Returns the raw value (shown once)."""
    raw = _generate_token()
    session.add(AuthToken(
        user_id=user_id,
        kind=kind,
        token_hash=_hash_token(raw),
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
        request_ip=request_ip,
    ))
    await session.commit()
    return raw


async def _consume_token(session, raw: str, kind: str) -> AuthToken | None:
    """Find, validate, and mark-used a token. None if invalid/expired/used."""
    tok = (
        await session.execute(
            select(AuthToken).where(
                AuthToken.token_hash == _hash_token(raw),
                AuthToken.kind == kind,
            )
        )
    ).scalar_one_or_none()

    if tok is None or tok.used_at is not None:
        return None
    if tok.expires_at < datetime.now(timezone.utc):
        return None

    tok.used_at = datetime.now(timezone.utc)
    return tok


async def _invalidate_other_tokens(
    session, user_id: uuid.UUID, kind: str, keep_id: uuid.UUID
) -> None:
    """Mark all other unused tokens of this kind as consumed."""
    await session.execute(
        update(AuthToken)
        .where(
            AuthToken.user_id == user_id,
            AuthToken.kind == kind,
            AuthToken.used_at.is_(None),
            AuthToken.token_id != keep_id,
        )
        .values(used_at=datetime.now(timezone.utc))
    )


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


class Verify2FARequest(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class Complete2FARequest(BaseModel):
    pending_token: str = Field(min_length=10)
    code: str = Field(min_length=6, max_length=12)


class UserOut(BaseModel):
    user_id: str
    tenant_id: str
    email: str
    name: str
    role: str
    tenant_slug: str
    email_verified: bool


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        return _validate_email_value(v)


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    new_password: str = Field(min_length=8, max_length=200)

    @field_validator("new_password")
    @classmethod
    def _password_ok(cls, v: str) -> str:
        return _validate_password_strength(v)


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=10, max_length=200)


class ResendVerificationRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        return _validate_email_value(v)


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
        await session.flush()

        # Issue email verification token in the same transaction
        verify_raw = await _issue_token(
            session,
            user.user_id,
            "email_verification",
            ttl_seconds=settings.EMAIL_VERIFICATION_TTL_HOURS * 3600,
            request_ip=meta["ip"],
        )
        user_name = user.name
        user_email = user.email

        await session.commit()
        user_payload = _user_payload(user, tenant)

    # Audit log (best effort)
    await _write_auth_event(
        tenant_id=tenant.tenant_id,
        category="other",
        action="allowed",
        reasoning=f"signup: {meta['ip']} · {meta['user_agent'][:60]}",
    )

    # Send verification email (best effort — never blocks signup)
    verify_url = f"{settings.APP_BASE_URL}/verify-email?token={verify_raw}"
    html, text = email_verification_email(user_name, verify_url)
    send_email(user_email, "Verify your AgentShield email", html, text)

    # Session cookie
    token = create_session_token(
    user.user_id,
    tenant.tenant_id,
    user.email,
    user.role,
    session_version=user.session_version,
)
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

        # Constant-time defense against user enumeration.
        if user is None:
            hash_password(req.password)  # burn ~50ms
            raise HTTPException(status_code=401, detail="invalid_credentials")

        if user.status != "active":
            raise HTTPException(status_code=403, detail=f"account_{user.status}")

        # --- Account lockout ---
        now = datetime.now(timezone.utc)

        # Already locked? Reject before touching the password hash.
        if user.locked_until is not None and user.locked_until > now:
            remaining_min = int(
                (user.locked_until - now).total_seconds() / 60
            ) + 1
            await _write_auth_event(
                tenant_id=user.tenant_id,
                category="other",
                action="blocked",
                reasoning=(
                    f"login_locked: {meta['ip']} · {remaining_min}m remaining"
                ),
            )
            raise HTTPException(
                status_code=423,
                detail=f"account_locked_try_again_in_{remaining_min}_minutes",
            )

        if not verify_password(req.password, user.password_hash):
            user.failed_login_attempts += 1

            if user.failed_login_attempts >= settings.LOCKOUT_THRESHOLD:
                user.locked_until = now + timedelta(
                    minutes=settings.LOCKOUT_DURATION_MINUTES
                )
                await session.commit()
                await _write_auth_event(
                    tenant_id=user.tenant_id,
                    category="other",
                    action="blocked",
                    reasoning=(
                        f"account_locked: {meta['ip']} · "
                        f"{user.failed_login_attempts} attempts"
                    ),
                )
                raise HTTPException(
                    status_code=423,
                    detail=(
                        f"account_locked_for_"
                        f"{settings.LOCKOUT_DURATION_MINUTES}_minutes"
                    ),
                )

            await session.commit()
            raise HTTPException(
                status_code=401, detail="invalid_credentials"
            )

        # --- Success — clear counters ---
        user.failed_login_attempts = 0
        user.locked_until = None

        # Opportunistically upgrade old password hashes
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(req.password)

        tenant = (
            await session.execute(
                select(Tenant).where(Tenant.tenant_id == user.tenant_id)
            )
        ).scalar_one_or_none()
        if tenant is None or tenant.status != "active":
            raise HTTPException(status_code=403, detail="tenant_inactive")

        # Check if 2FA is enabled
        cred = await session.get(TOTPCredential, user.user_id)
        twofa_enabled = cred is not None and cred.verified_at is not None

        user.last_login_at = datetime.now(timezone.utc)
        await session.commit()

        user_payload = _user_payload(user, tenant)

    # --- 2FA path ---
    if twofa_enabled:
        pending = create_2fa_pending_token(user.user_id)
        await _write_auth_event(
            tenant_id=tenant.tenant_id,
            category="other",
            action="allowed",
            reasoning=f"login_pending_2fa: {meta['ip']}",
        )
        return {
            "requires_2fa": True,
            "pending_token": pending,
        }

    # --- Normal path ---
    await _write_auth_event(
        tenant_id=tenant.tenant_id,
        category="other",
        action="allowed",
        reasoning=f"login: {meta['ip']} · {meta['user_agent'][:60]}",
    )

    token = create_session_token(
    user.user_id,
    tenant.tenant_id,
    user.email,
    user.role,
    session_version=user.session_version,
)
    _set_session_cookie(response, token)

    return {"user": user_payload, "requires_2fa": False}


# ============================================================
# Logout
# ============================================================

@router.post("/logout")
async def logout(response: Response) -> dict:
    _delete_session_cookie(response)
    return {"ok": True}


# ============================================================
# Me
# ============================================================

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
    token = create_session_token(
    user.user_id,
    tenant.tenant_id,
    user.email,
    user.role,
    session_version=user.session_version,
)
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
        db_user = (
            await session.execute(select(User).where(User.user_id == user.user_id))
        ).scalar_one()

        if not verify_password(req.current_password, db_user.password_hash):
            raise HTTPException(status_code=401, detail="invalid_current_password")

        if verify_password(req.new_password, db_user.password_hash):
            raise HTTPException(status_code=400, detail="password_unchanged")

        db_user.password_hash = hash_password(
            req.new_password
        )

        db_user.session_version += 1

        
        await session.commit()

    await _write_auth_event(
        tenant_id=tenant.tenant_id,
        category="other",
        action="allowed",
        reasoning="password_changed",
    )

    # Rotate the session cookie
    _delete_session_cookie(response)
    token = create_session_token(
    user.user_id,
    tenant.tenant_id,
    user.email,
    user.role,
    session_version=user.session_version,
)
    _set_session_cookie(response, token)

    return {"ok": True}


# ============================================================
# TOTP 2FA
# ============================================================

@router.get("/2fa/status")
async def get_2fa_status(request: Request) -> dict:
    """Return whether 2FA is enabled for the current user."""
    user, _ = await _resolve_session(request)
    async with async_session() as session:
        cred = await session.get(TOTPCredential, user.user_id)
        enabled = cred is not None and cred.verified_at is not None
    return {"enabled": enabled}


@router.post("/2fa/setup")
async def setup_2fa(request: Request) -> dict:
    """Begin enrollment. Returns secret + QR code (not yet active)."""
    user, _ = await _resolve_session(request)

    async with async_session() as session:
        existing = await session.get(TOTPCredential, user.user_id)
        if existing is not None and existing.verified_at is not None:
            raise HTTPException(status_code=400, detail="2fa_already_enabled")

        secret = generate_secret()
        uri = provisioning_uri(secret, user.email)

        if existing is not None:
            existing.secret = secret
        else:
            session.add(TOTPCredential(user_id=user.user_id, secret=secret))
        await session.commit()

    return {
        "secret": secret,
        "qr_data_url": qr_code_data_url(uri),
        "otpauth_uri": uri,
    }


@router.post("/2fa/verify-setup")
async def verify_2fa_setup(
    req: Verify2FARequest, request: Request
) -> dict:
    """Confirm enrollment by verifying a code. Returns one-time recovery codes."""
    user, tenant = await _resolve_session(request)

    async with async_session() as session:
        cred = await session.get(TOTPCredential, user.user_id)
        if cred is None:
            raise HTTPException(status_code=400, detail="2fa_not_setup")
        if cred.verified_at is not None:
            raise HTTPException(status_code=400, detail="2fa_already_enabled")

        if not verify_totp(cred.secret, req.code):
            raise HTTPException(status_code=400, detail="invalid_code")

        recovery = generate_recovery_codes(8)
        cred.recovery_codes_hash = [
            hashlib.sha256(c.encode()).hexdigest() for c in recovery
        ]
        cred.verified_at = datetime.now(timezone.utc)
        await session.commit()

    await _write_auth_event(
        tenant_id=tenant.tenant_id,
        category="other",
        action="allowed",
        reasoning="2fa_enabled",
    )

    return {"ok": True, "recovery_codes": recovery}


@router.post("/2fa/disable")
async def disable_2fa(req: Verify2FARequest, request: Request) -> dict:
    """Disable 2FA. Requires a valid TOTP code (or recovery code)."""
    user, tenant = await _resolve_session(request)

    async with async_session() as session:
        cred = await session.get(TOTPCredential, user.user_id)
        if cred is None or cred.verified_at is None:
            raise HTTPException(status_code=400, detail="2fa_not_enabled")

        code = req.code.strip().replace(" ", "").upper()
        ok = verify_totp(cred.secret, code)

        if not ok and len(code) == 10:
            hashed = hashlib.sha256(code.encode()).hexdigest()
            ok = hashed in cred.recovery_codes_hash

        if not ok:
            raise HTTPException(status_code=400, detail="invalid_code")

        await session.delete(cred)
        await session.commit()

    await _write_auth_event(
        tenant_id=tenant.tenant_id,
        category="other",
        action="allowed",
        reasoning="2fa_disabled",
    )

    return {"ok": True}


@router.post("/2fa/challenge")
async def complete_2fa(
    req: Complete2FARequest, response: Response
) -> dict:
    """
    Second step of a 2FA login.

    Client sends the pending_token from /login plus the current TOTP code
    (or a one-time recovery code). On success, we issue the real session cookie.
    """
    payload = decode_2fa_pending_token(req.pending_token)
    if payload is None:
        raise HTTPException(status_code=401, detail="invalid_pending_token")

    async with async_session() as session:
        user = (
            await session.execute(
                select(User).where(User.user_id == uuid.UUID(payload["sub"]))
            )
        ).scalar_one_or_none()
        if user is None or user.status != "active":
            raise HTTPException(status_code=401, detail="user_inactive")

        cred = await session.get(TOTPCredential, user.user_id)
        if cred is None or cred.verified_at is None:
            raise HTTPException(status_code=400, detail="2fa_not_enabled")

        code = req.code.strip().replace(" ", "").upper()
        ok = verify_totp(cred.secret, code)

        # Fall back to a one-time recovery code
        if not ok and len(code) == 10:
            hashed = hashlib.sha256(code.encode()).hexdigest()
            if hashed in cred.recovery_codes_hash:
                remaining = [c for c in cred.recovery_codes_hash if c != hashed]
                cred.recovery_codes_hash = remaining
                await session.commit()
                ok = True

        if not ok:
            raise HTTPException(status_code=401, detail="invalid_code")

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
        reasoning="2fa_challenge_success",
    )

    token = create_session_token(
    user.user_id,
    tenant.tenant_id,
    user.email,
    user.role,
    session_version=user.session_version,
)
    _set_session_cookie(response, token)

    return {"user": user_payload, "requires_2fa": False}


# ============================================================
# Password reset
# ============================================================

@router.post("/forgot-password")
async def forgot_password(
    req: ForgotPasswordRequest, request: Request
) -> dict:
    """
    Send a password reset email. Always returns ok — never leaks
    whether an email is registered.
    """
    meta = _client_meta(request)

    async with async_session() as session:
        user = (
            await session.execute(select(User).where(User.email == req.email))
        ).scalar_one_or_none()

        if user is None or user.status != "active":
            return {"ok": True}

        raw = await _issue_token(
            session,
            user.user_id,
            "password_reset",
            ttl_seconds=settings.PASSWORD_RESET_TTL_MINUTES * 60,
            request_ip=meta["ip"],
        )
        user_name = user.name
        user_email = user.email
        user_tenant_id = user.tenant_id

    reset_url = f"{settings.APP_BASE_URL}/reset-password?token={raw}"
    html, text = password_reset_email(user_name, reset_url)
    send_email(user_email, "Reset your AgentShield password", html, text)

    await _write_auth_event(
        tenant_id=user_tenant_id,
        category="other",
        action="allowed",
        reasoning=f"password_reset_requested: {meta['ip']}",
    )

    return {"ok": True}


@router.post("/reset-password")
async def reset_password(req: ResetPasswordRequest) -> dict:
    async with async_session() as session:
        tok = await _consume_token(session, req.token, "password_reset")
        if tok is None:
            raise HTTPException(status_code=400, detail="invalid_or_expired_token")

        user = await session.get(User, tok.user_id)
        if user is None or user.status != "active":
            raise HTTPException(status_code=400, detail="invalid_token")

        user.password_hash = hash_password(
             req.new_password
        )  
        # Password reset is a security boundary.
        # Every previously issued browser session must
        # become invalid immediately.
        user.session_version += 1

        # Clear brute-force lockout.
        user.failed_login_attempts = 0
        user.locked_until = None

        await _invalidate_other_tokens(
            session, user.user_id, "password_reset", tok.token_id
        )
        await session.commit()

        tenant_id = user.tenant_id

    await _write_auth_event(
        tenant_id=tenant_id,
        category="other",
        action="allowed",
        reasoning="password_reset_completed",
    )

    return {"ok": True}


# ============================================================
# Email verification
# ============================================================

@router.post("/verify-email")
async def verify_email(req: VerifyEmailRequest) -> dict:
    async with async_session() as session:
        tok = await _consume_token(session, req.token, "email_verification")
        if tok is None:
            raise HTTPException(status_code=400, detail="invalid_or_expired_token")

        user = await session.get(User, tok.user_id)
        if user is None:
            raise HTTPException(status_code=400, detail="invalid_token")

        user.email_verified = True
        await session.commit()
        tenant_id = user.tenant_id

    await _write_auth_event(
        tenant_id=tenant_id,
        category="other",
        action="allowed",
        reasoning="email_verified",
    )

    return {"ok": True}


@router.post("/resend-verification")
async def resend_verification(
    req: ResendVerificationRequest, request: Request
) -> dict:
    """
    Resend the verification email. Rate-limited to one per minute per user;
    always returns ok to prevent enumeration.
    """
    async with async_session() as session:
        user = (
            await session.execute(select(User).where(User.email == req.email))
        ).scalar_one_or_none()

        if user is None or user.status != "active" or user.email_verified:
            return {"ok": True}

        # Rate limit: refuse if a fresh unused token exists from <60s ago
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
        recent = (
            await session.execute(
                select(AuthToken).where(
                    AuthToken.user_id == user.user_id,
                    AuthToken.kind == "email_verification",
                    AuthToken.used_at.is_(None),
                    AuthToken.created_at > cutoff,
                )
            )
        ).scalar_one_or_none()

        if recent is not None:
            return {"ok": True}

        raw = await _issue_token(
            session,
            user.user_id,
            "email_verification",
            ttl_seconds=settings.EMAIL_VERIFICATION_TTL_HOURS * 3600,
            request_ip=request.client.host if request.client else None,
        )
        user_name = user.name
        user_email = user.email

    verify_url = f"{settings.APP_BASE_URL}/verify-email?token={raw}"
    html, text = email_verification_email(user_name, verify_url)
    send_email(user_email, "Verify your AgentShield email", html, text)

    return {"ok": True}