"""
Runtime agent-security integration tests.

These tests prove that:

1. An API key cannot administer the tenant.
2. An unbound API key cannot invoke the runtime.
3. An Agent without agent:invoke cannot invoke the runtime.
4. A suspended Agent cannot invoke the runtime.

The tests intentionally stop before the upstream LLM call.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.models import (
    APIKey,
    Agent,
    Tenant,
)
from app.db.session import async_session
from app.main import app
from app.security.api_keys import (
    generate_key,
    hash_key,
    key_prefix,
)


@pytest.fixture
async def agent_security_fixture():

    async with async_session() as session:

        tenant = Tenant(
            slug=(
                "agent-security-"
                f"{uuid.uuid4().hex[:10]}"
            ),
            name="Agent Security Test",
        )

        session.add(
            tenant
        )

        await session.flush()

        raw_unbound_key = generate_key(
            live=False
        )

        raw_no_invoke_key = generate_key(
            live=False
        )

        raw_suspended_key = generate_key(
            live=False
        )

        key_unbound = APIKey(
            tenant_id=tenant.tenant_id,
            name="unbound",
            key_prefix=
                key_prefix(
                    raw_unbound_key
                ),
            key_hash=
                hash_key(
                    raw_unbound_key
                ),
        )

        key_no_invoke = APIKey(
            tenant_id=tenant.tenant_id,
            name="no-invoke",
            key_prefix=
                key_prefix(
                    raw_no_invoke_key
                ),
            key_hash=
                hash_key(
                    raw_no_invoke_key
                ),
        )

        key_suspended = APIKey(
            tenant_id=tenant.tenant_id,
            name="suspended",
            key_prefix=
                key_prefix(
                    raw_suspended_key
                ),
            key_hash=
                hash_key(
                    raw_suspended_key
                ),
        )

        session.add_all(
            [
                key_unbound,
                key_no_invoke,
                key_suspended,
            ]
        )

        await session.flush()

        agent_no_invoke = Agent(
            tenant_id=tenant.tenant_id,
            name="No Invoke Agent",
            description="Agent without runtime invoke capability",
            scopes=["tool:read"],
            status="active",
            api_key_id=key_no_invoke.key_id,
        )

        agent_suspended = Agent(
            tenant_id=tenant.tenant_id,
            name="Suspended Agent",
            description="Suspended runtime agent",
            scopes=["agent:invoke"],
            status="suspended",
            api_key_id=key_suspended.key_id,
        )

        session.add_all(
            [
                agent_no_invoke,
                agent_suspended,
            ]
        )

        await session.commit()

        yield {
            "unbound_key":
                raw_unbound_key,
            "no_invoke_key":
                raw_no_invoke_key,
            "suspended_key":
                raw_suspended_key,
        }

        db_tenant = await session.get(
            Tenant,
            tenant.tenant_id,
        )

        if db_tenant is not None:
            await session.delete(
                db_tenant
            )

        await session.commit()


async def _post_runtime(
    client: AsyncClient,
    api_key: str,
):

    return await client.post(
        "/v1/chat/completions",
        headers={
            "X-API-Key":
                api_key,
            "Content-Type":
                "application/json",
        },
        json={
            "model": "test-model",
            "messages": [
                {
                    "role": "user",
                    "content":
                        "Hello AgentShield",
                }
            ],
        },
    )


@pytest.mark.asyncio
async def test_api_key_cannot_access_tenant_management(
    agent_security_fixture,
):

    transport = ASGITransport(
        app=app
    )

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:

        response = await client.get(
            "/api/tenant/agents",
            headers={
                "X-API-Key":
                    agent_security_fixture[
                        "unbound_key"
                    ]
            },
        )

    assert response.status_code == 403

    assert (
        response.json()["error"]
        == "human_session_required"
    )


@pytest.mark.asyncio
async def test_unbound_api_key_cannot_invoke_runtime(
    agent_security_fixture,
):

    transport = ASGITransport(
        app=app
    )

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:

        response = await _post_runtime(
            client,
            agent_security_fixture[
                "unbound_key"
            ],
        )

    assert response.status_code == 403

    assert (
        response.json()["error"]
        == "agent_identity_required"
    )


@pytest.mark.asyncio
async def test_agent_without_invoke_capability_is_blocked(
    agent_security_fixture,
):

    transport = ASGITransport(
        app=app
    )

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:

        response = await _post_runtime(
            client,
            agent_security_fixture[
                "no_invoke_key"
            ],
        )

    assert response.status_code == 403

    body = response.json()

    assert body["error"] == "capability_required"

    assert (
        body["capability"]
        == "agent:invoke"
    )


@pytest.mark.asyncio
async def test_suspended_agent_is_blocked(
    agent_security_fixture,
):

    transport = ASGITransport(
        app=app
    )

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:

        response = await _post_runtime(
            client,
            agent_security_fixture[
                "suspended_key"
            ],
        )

    assert response.status_code == 403

    assert (
        response.json()["error"]
        == "agent_inactive"
    )