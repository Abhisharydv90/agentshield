"""Regression coverage for canonical MCP/A2A transport authorization."""

from __future__ import annotations

import uuid

import pytest

from app.gateway.routing.a2a import A2ARoute, A2ARouter
from app.gateway.routing.mcp import MCPRoute, MCPRouter


class _FakeResponse:
    status_code = 200
    content = b'{"ok":true}'
    headers = {"content-type": "application/json"}
    text = '{"ok":true}'

    @staticmethod
    def json():
        return {"ok": True}


class _FakeClient:
    calls: list[dict] = []

    def __init__(self, *args, **kwargs):
        self.calls = _FakeClient.calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return _FakeResponse()


@pytest.mark.asyncio
async def test_mcp_denies_before_network_without_tool_execute(monkeypatch):
    router = MCPRouter()
    router._routes["secure"] = MCPRoute(
        name="secure",
        url="https://mcp.example.test/rpc",
    )

    async def unexpected_client(*args, **kwargs):
        raise AssertionError("network must not be opened")

    monkeypatch.setattr(
        "app.gateway.routing.mcp.httpx.AsyncClient",
        unexpected_client,
    )

    result = await router.dispatch(
        route_name="secure",
        trace_id="trace-mcp-deny",
        tenant_id=str(uuid.uuid4()),
        agent_id=str(uuid.uuid4()),
        agent_scopes={"agent:invoke", "network:egress"},
        payload={"method": "tools/call", "params": {"name": "dangerous"}},
    )

    assert result["status_code"] == 403
    assert result["error"] == "missing_capabilities"


@pytest.mark.asyncio
async def test_mcp_ignores_payload_url_and_uses_configured_route(monkeypatch):
    router = MCPRouter()
    router._routes["secure"] = MCPRoute(
        name="secure",
        url="https://mcp.example.test/rpc",
    )
    _FakeClient.calls.clear()
    monkeypatch.setattr(
        "app.gateway.routing.mcp.httpx.AsyncClient",
        _FakeClient,
    )

    result = await router.dispatch(
        route_name="secure",
        trace_id="trace-mcp-allow",
        tenant_id=str(uuid.uuid4()),
        agent_id=str(uuid.uuid4()),
        agent_scopes={"agent:invoke", "tool:execute", "network:egress"},
        payload={"method": "tools/call", "params": {"url": "http://127.0.0.1:8080"}},
    )

    assert result["status_code"] == 200
    assert _FakeClient.calls[0]["url"] == "https://mcp.example.test/rpc"


@pytest.mark.asyncio
async def test_a2a_denies_before_network_without_network_egress(monkeypatch):
    router = A2ARouter()
    router._routes["peer"] = A2ARoute(
        name="peer",
        url="https://a2a.example.test/receive",
    )

    async def unexpected_client(*args, **kwargs):
        raise AssertionError("network must not be opened")

    monkeypatch.setattr(
        "app.gateway.routing.a2a.httpx.AsyncClient",
        unexpected_client,
    )

    result = await router.dispatch(
        route_name="peer",
        tenant_id=str(uuid.uuid4()),
        agent_id=str(uuid.uuid4()),
        trace_id="trace-a2a-deny",
        agent_scopes={"agent:invoke", "tool:execute"},
        payload={"task": "transfer"},
    )

    assert result["status_code"] == 403
    assert result["error"] == "missing_capabilities"


@pytest.mark.asyncio
async def test_a2a_binds_sender_identity_to_envelope(monkeypatch):
    router = A2ARouter()
    router._routes["peer"] = A2ARoute(
        name="peer",
        url="https://a2a.example.test/receive",
    )
    _FakeClient.calls.clear()
    monkeypatch.setattr(
        "app.gateway.routing.a2a.httpx.AsyncClient",
        _FakeClient,
    )

    tenant_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())
    result = await router.dispatch(
        route_name="peer",
        tenant_id=tenant_id,
        agent_id=agent_id,
        trace_id="trace-a2a-allow",
        agent_scopes={"agent:invoke", "tool:execute", "network:egress"},
        payload={"task": "transfer"},
    )

    assert result["status_code"] == 200
    envelope = _FakeClient.calls[0]["json"]
    assert _FakeClient.calls[0]["url"] == "https://a2a.example.test/receive"
    assert envelope["tenant_id"] == tenant_id
    assert envelope["sender_agent_id"] == agent_id
