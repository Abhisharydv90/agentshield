"""Proves tenants cannot see each other's data."""

import uuid
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.db.session import async_session
from app.db.models import Tenant, SecurityEvent, APIKey
from app.security.api_keys import generate_key, hash_key, key_prefix
from app.telemetry.audit import write_event


@pytest.fixture
async def two_tenants():
    async with async_session() as session:
        a = Tenant(slug=f"test-a-{uuid.uuid4().hex[:8]}", name="Tenant A")
        b = Tenant(slug=f"test-b-{uuid.uuid4().hex[:8]}", name="Tenant B")
        session.add_all([a, b])
        await session.flush()

        raw_a = generate_key(live=False)
        raw_b = generate_key(live=False)

        session.add_all([
            APIKey(tenant_id=a.tenant_id, name="key-a", key_prefix=key_prefix(raw_a), key_hash=hash_key(raw_a)),
            APIKey(tenant_id=b.tenant_id, name="key-b", key_prefix=key_prefix(raw_b), key_hash=hash_key(raw_b)),
        ])
        await session.commit()

        await write_event(session, a.tenant_id, "req-a", "injection_attempt", "blocked", "tenant A event")
        await write_event(session, b.tenant_id, "req-b", "pii_leak", "redacted", "tenant B event")

        yield {"a": (a, raw_a), "b": (b, raw_b)}

        await session.execute(SecurityEvent.__table__.delete().where(SecurityEvent.tenant_id.in_([a.tenant_id, b.tenant_id])))
        await session.execute(APIKey.__table__.delete().where(APIKey.tenant_id.in_([a.tenant_id, b.tenant_id])))
        await session.execute(Tenant.__table__.delete().where(Tenant.tenant_id.in_([a.tenant_id, b.tenant_id])))
        await session.commit()


@pytest.mark.asyncio
async def test_tenant_a_cannot_see_b_events(two_tenants):
    (_, key_a) = two_tenants["a"]
    (_, key_b) = two_tenants["b"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        a_events = (await client.get("/api/events", headers={"X-API-Key": key_a})).json()
        b_events = (await client.get("/api/events", headers={"X-API-Key": key_b})).json()
    a_ids = {e["request_id"] for e in a_events}
    b_ids = {e["request_id"] for e in b_events}
    assert "req-a" in a_ids
    assert "req-b" not in a_ids       # CRITICAL
    assert "req-b" in b_ids
    assert "req-a" not in b_ids


@pytest.mark.asyncio
async def test_metrics_are_scoped_per_tenant(two_tenants):
    (_, key_a) = two_tenants["a"]
    (_, key_b) = two_tenants["b"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        ra = (await client.get("/api/metrics", headers={"X-API-Key": key_a})).json()
        rb = (await client.get("/api/metrics", headers={"X-API-Key": key_b})).json()
    assert ra["total_events"] == 1
    assert rb["total_events"] == 1
    assert "injection_attempt" in ra["by_category"]
    assert "pii_leak" in rb["by_category"]
    assert "pii_leak" not in ra["by_category"]


@pytest.mark.asyncio
async def test_invalid_key_rejected():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/events", headers={"X-API-Key": "ask_test_totally_fake"})
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_audit_chain_scoped_per_tenant(two_tenants):
    (_, key_a) = two_tenants["a"]
    (_, key_b) = two_tenants["b"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        ra = (await client.get("/api/audit/verify", headers={"X-API-Key": key_a})).json()
        rb = (await client.get("/api/audit/verify", headers={"X-API-Key": key_b})).json()
    assert ra["valid"] is True
    assert rb["valid"] is True
    assert ra["length"] == 1
    assert rb["length"] == 1