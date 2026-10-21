"""Phase 3 Gateway regression tests for route configuration and quota safety."""

import uuid

import pytest

from app.gateway.quotas import GatewayQuotaManager
from app.gateway.routing.a2a import A2ARoute, A2ARouteError, A2ARouter
from app.gateway.routing.mcp import MCPRoute, MCPRouteError, MCPRouter
from app.gateway.routing.model import ModelRoute, ModelRouteError, ModelRouteRegistry


def test_model_route_rejects_absolute_chat_path():
    route = ModelRoute(name="safe", provider="openai-compatible", base_url="https://models.example.test", chat_path="//evil.example/path")
    with pytest.raises(ModelRouteError, match="invalid_model_route_path"):
        ModelRouteRegistry._validate_route(route)


def test_model_route_rejects_authorization_header_override():
    route = ModelRoute(name="safe", provider="openai-compatible", base_url="https://models.example.test", static_headers={"Authorization": "Bearer attacker"})
    with pytest.raises(ModelRouteError, match="reserved_model_header"):
        ModelRouteRegistry._validate_route(route)


def test_model_route_rejects_url_credentials():
    route = ModelRoute(name="safe", provider="openai-compatible", base_url="https://user:secret@models.example.test")
    with pytest.raises(ModelRouteError, match="url_components"):
        ModelRouteRegistry._validate_route(route)


def test_mcp_route_rejects_reserved_identity_header():
    route = MCPRoute(name="safe", url="https://mcp.example.test", headers={"X-AURAGENT-Agent": "spoofed"})
    with pytest.raises(MCPRouteError, match="reserved_mcp_header"):
        MCPRouter._validate(route)


def test_a2a_route_rejects_newline_in_header_value():
    route = A2ARoute(name="safe", url="https://a2a.example.test", headers={"X-Extra": "safe\\r\\nX-Injected: yes"})
    with pytest.raises(A2ARouteError, match="invalid_a2a_header_value"):
        A2ARouter._validate(route)


@pytest.mark.asyncio
async def test_quota_release_is_idempotent_and_never_negative():
    manager = GatewayQuotaManager(requests_per_minute=2, max_concurrent=1)
    tenant_id, agent_id = uuid.uuid4(), uuid.uuid4()
    assert (await manager.acquire(tenant_id=tenant_id, agent_id=agent_id)).allowed
    assert not (await manager.acquire(tenant_id=tenant_id, agent_id=agent_id)).allowed
    await manager.release(tenant_id=tenant_id, agent_id=agent_id)
    await manager.release(tenant_id=tenant_id, agent_id=agent_id)
    snapshot = await manager.snapshot(tenant_id=tenant_id, agent_id=agent_id)
    assert snapshot["inflight"] == 0
