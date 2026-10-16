"""Canonical authorization gate for gateway-owned external transports.

MCP and A2A are network transports, not alternate security planes. This
adapter converts a configured transport into the existing Tool Fabric so
capability, network-scope, risk and Security Kernel decisions happen before
the upstream connection is opened.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Iterable
from urllib.parse import urlparse

from app.security.context import SecurityContext
from app.security.delegation.model import AuthorityState
from app.security.identity.crypto import sha256_hex
from app.tools.contracts import ToolInvocation, ToolKind, ToolResult, ToolManifest
from app.tools.dispatcher import ToolDispatcher
from app.tools.registry import RegisteredTool


class _SingleToolRegistry:
    """Minimal registry adapter exposing one configured transport tool."""

    def __init__(self, tool: RegisteredTool) -> None:
        self._tool = tool

    def get(self, name: str) -> RegisteredTool:
        if name != self._tool.manifest.name:
            from app.tools.registry import ToolNotFoundError
            raise ToolNotFoundError(name)
        return self._tool


async def authorize_external_transport(
    *,
    protocol: str,
    tool_name: str,
    route_name: str,
    route_url: str,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    agent_scopes: Iterable[str],
    trace_id: str,
    payload,
    kind: ToolKind,
    send: Callable[[], Awaitable[object]],
) -> ToolResult:
    """Authorize one configured external transport before network I/O."""

    parsed = urlparse(route_url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme not in {"http", "https"} or not host:
        return ToolResult(
            decision="deny",
            reason="invalid_network_target",
            tool_name=tool_name,
            operation="external_call",
            call_id="invalid-route",
            error_code="network_denied",
        )

    capabilities = frozenset(
        str(value).strip()
        for value in agent_scopes
        if str(value).strip()
    )

    authority = AuthorityState.from_values(
        capabilities=capabilities,
        operations={"external_call"},
        resources={route_url},
        network_scopes={host},
        delegation_depth=0,
        risk_ceiling=100.0,
    )

    transport_policy_hash = sha256_hex(
        {
            "schema": "auragent.gateway-transport-policy.v1",
            "protocol": protocol,
            "route_name": route_name,
            "route_url": route_url,
        }
    )

    context = SecurityContext(
        tenant_id=tenant_id,
        agent_id=agent_id,
        trace_id=trace_id,
        capabilities=capabilities,
        authority=authority,
        policy_hash=transport_policy_hash,
        authority_token_hash=None,
        provenance={
            "source": "gateway_transport",
            "protocol": protocol,
            "route_name": route_name,
        },
    )

    manifest = ToolManifest(
        name=tool_name,
        version="1.0.0",
        description=f"Configured {protocol} gateway transport",
        kind=kind,
        operations=frozenset({"external_call"}),
        required_capabilities=frozenset(
            {
                "agent:invoke",
                "tool:execute",
                "network:egress",
            }
        ),
        resource_patterns=frozenset({route_url}),
        network_domains=frozenset({host}),
        external_content=True,
        metadata={
            "route_name": route_name,
            "route_url": route_url,
            "protocol": protocol,
        },
    )

    async def handler(_invocation, _context):
        return await send()

    registry = _SingleToolRegistry(
        RegisteredTool(
            manifest=manifest,
            handler=handler,
        )
    )

    invocation = ToolInvocation(
        tool_name=tool_name,
        operation="external_call",
        arguments={
            "protocol": protocol,
            "route_name": route_name,
            "payload": payload,
        },
        resource=route_url,
        target_url=route_url,
    )

    return await ToolDispatcher(
        registry=registry,
    ).dispatch(
        invocation,
        context,
    )
