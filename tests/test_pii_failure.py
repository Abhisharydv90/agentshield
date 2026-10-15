"""
PII vault failure tests.

Security invariant:

    PII vault unavailable
        ->
    request receives HTTP 503
        ->
    request is not forwarded upstream

The credential used here belongs to an active Agent with the
agent:invoke capability so that the request reaches the PII layer.
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
from app.proxy import router as proxy_router
from app.security.api_keys import (
    generate_key,
    hash_key,
    key_prefix,
)
from app.security.pii.vault import (
    PIIVaultUnavailableError,
)


@pytest.fixture
async def pii_failure_credentials():

    async with async_session() as session:

        tenant = Tenant(
            slug=(
                "pii-failure-"
                f"{uuid.uuid4().hex[:10]}"
            ),
            name="PII Failure Test",
        )

        session.add(tenant)

        await session.flush()

        raw_key = generate_key(
            live=False
        )

        api_key = APIKey(
            tenant_id=tenant.tenant_id,
            name="pii-failure-key",
            key_prefix=key_prefix(
                raw_key
            ),
            key_hash=hash_key(
                raw_key
            ),
        )

        session.add(api_key)

        await session.flush()

        # Create a real runtime identity.
        #
        # The API key remains the credential while the Agent provides
        # the runtime identity and capabilities.
        agent = Agent(
            tenant_id=tenant.tenant_id,
            name="PII Failure Test Agent",
            description=(
                "Agent used to exercise the PII fail-closed boundary."
            ),
            scopes=[
                "agent:invoke",
            ],
            status="active",
            api_key_id=api_key.key_id,
        )

        session.add(agent)

        await session.commit()

        tenant_id = tenant.tenant_id

    yield raw_key

    async with async_session() as session:

        tenant = await session.get(
            Tenant,
            tenant_id,
        )

        if tenant is not None:
            await session.delete(
                tenant
            )

        await session.commit()


@pytest.mark.asyncio
async def test_pii_vault_failure_returns_503(
    pii_failure_credentials,
    monkeypatch,
):

    class BrokenRedactor:

        async def redact(
            self,
            body: dict,
            trace_id: str,
        ):
            raise PIIVaultUnavailableError(
                "simulated Redis outage"
            )

    monkeypatch.setattr(
        proxy_router,
        "get_redactor",
        lambda tenant: BrokenRedactor(),
    )

    transport = ASGITransport(
        app=app
    )

    body = {
        "model": "test-model",
        "messages": [
            {
                "role": "user",
                "content": (
                    "hello from the PII "
                    "failure test"
                ),
            }
        ],
    }

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:

        response = await client.post(
            "/v1/chat/completions",
            headers={
                "X-API-Key": (
                    pii_failure_credentials
                )
            },
            json=body,
        )

    assert response.status_code == 503

    payload = response.json()

    assert payload["error"] == (
        "pii_vault_unavailable"
    )

    assert payload["status"] == 503

    assert (
        "not forwarded"
        in payload["message"]
    )

    assert payload["trace_id"]