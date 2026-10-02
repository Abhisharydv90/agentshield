"""
Session revocation tests.

Proves that changing User.session_version invalidates previously
issued browser session JWTs.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.api.auth import _resolve_session
from app.db.models import Tenant, User
from app.db.session import async_session
from app.security.passwords import hash_password
from app.security.sessions import (
    COOKIE_NAME,
    create_session_token,
)


def _request_with_cookie(token: str):
    """
    Build a minimal Starlette Request containing the session cookie.
    """

    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/auth/me",
        "headers": [
            (
                b"cookie",
                f"{COOKIE_NAME}={token}".encode(),
            )
        ],
    }

    return Request(
        scope,
    )


@pytest.mark.asyncio
async def test_old_session_is_revoked_after_session_version_changes():
    async with async_session() as session:
        tenant = Tenant(
            slug=f"session-test-{uuid.uuid4().hex[:10]}",
            name="Session Test Tenant",
        )

        session.add(tenant)
        await session.flush()

        user = User(
            tenant_id=tenant.tenant_id,
            email=f"{uuid.uuid4().hex[:10]}@example.test",
            password_hash=hash_password("TestPassword123"),
            name="Session Tester",
            role="owner",
            email_verified=True,
            session_version=0,
        )

        session.add(user)
        await session.commit()

        user_id = user.user_id
        tenant_id = tenant.tenant_id

    # ---------------------------------------------------------
    # Issue session version 0
    # ---------------------------------------------------------

    old_token = create_session_token(
        user_id,
        tenant_id,
        user.email,
        user.role,
        session_version=0,
    )

    request = _request_with_cookie(old_token)

    # The old token should initially work.
    resolved_user, resolved_tenant = await _resolve_session(
        request
    )

    assert resolved_user.user_id == user_id
    assert resolved_tenant.tenant_id == tenant_id

    # ---------------------------------------------------------
    # Revoke every old session
    # ---------------------------------------------------------

    async with async_session() as session:
        db_user = (
            await session.execute(
                select(User).where(
                    User.user_id == user_id
                )
            )
        ).scalar_one()

        db_user.session_version += 1

        await session.commit()

    # ---------------------------------------------------------
    # Old token must now fail
    # ---------------------------------------------------------

    revoked_request = _request_with_cookie(
        old_token
    )

    with pytest.raises(Exception) as exc_info:
        await _resolve_session(
            revoked_request
        )

    assert "session_revoked" in str(
        exc_info.value
    )

    # ---------------------------------------------------------
    # Cleanup
    #
    # The database FK from users -> tenants uses ON DELETE CASCADE,
    # so deleting the tenant is sufficient. We intentionally do not
    # issue a separate DELETE for the user.
    # ---------------------------------------------------------

    async with async_session() as session:
        db_tenant = await session.get(
            Tenant,
            tenant_id,
        )

        if db_tenant is not None:
            await session.delete(db_tenant)

        await session.commit()