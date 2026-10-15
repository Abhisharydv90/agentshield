"""Phase 5 deterministic unit coverage; full suite is intentionally deferred."""

from __future__ import annotations

import uuid

import pytest

from app.security.context import SecurityContext
from app.security.delegation.model import AuthorityState
from app.tools.contracts import ToolInvocation, ToolKind, ToolManifest
from app.tools.dispatcher import ToolDispatcher
from app.tools.registry import ToolRegistry
from app.tools.resources import ResourceAuthorizer


def _context(**overrides) -> SecurityContext:
    authority = AuthorityState.from_values(
        capabilities={"tool:read", "tool:execute", "network:egress", "secret:use"},
        operations={"read", "execute", "external_call"},
        resources={"db://tenant-1/"},
        data_scopes={"data://tenant-1/"},
        network_scopes={"example.com"},
        delegation_depth=1,
        risk_ceiling=100.0,
    )
    values = {
        "tenant_id": uuid.uuid4(),
        "agent_id": uuid.uuid4(),
        "trace_id": "trace-phase5",
        "capabilities": frozenset(authority.capabilities),
        "authority": authority,
        "policy_hash": "a" * 64,
        "authority_token_hash": "b" * 64,
        "provenance": {"test": True},
    }
    values.update(overrides)
    return SecurityContext(**values)


@pytest.mark.asyncio
async def test_registry_and_dispatch_allow_authorized_tool():
    registry = ToolRegistry()

    async def handler(invocation, context):
        return {"ok": True}

    await registry.register(
        ToolManifest(
            name="db.read",
            version="1.0.0",
            kind=ToolKind.INTERNAL,
            operations=frozenset({"read"}),
            required_capabilities=frozenset({"tool:read"}),
            resource_patterns=frozenset({"db://tenant-1/"}),
        ),
        handler,
    )

    result = await ToolDispatcher(registry=registry).dispatch(
        ToolInvocation(
            tool_name="db.read",
            operation="read",
            resource="db://tenant-1/users",
        ),
        _context(),
    )
    assert result.allowed
    assert result.value == {"ok": True}


@pytest.mark.asyncio
async def test_dispatch_denies_missing_capability():
    registry = ToolRegistry()
    await registry.register(
        ToolManifest(
            name="db.read",
            version="1.0.0",
            operations=frozenset({"read"}),
            required_capabilities=frozenset({"tool:read"}),
        ),
        lambda invocation, context: {"unexpected": True},
    )

    context = _context(capabilities=frozenset({"tool:execute"}))
    result = await ToolDispatcher(registry=registry).dispatch(
        ToolInvocation(tool_name="db.read", operation="read"),
        context,
    )
    assert result.decision == "deny"
    assert result.error_code == "missing_capabilities"


def test_resource_prefix_is_bounded():
    authority = _context().authority
    authorizer = ResourceAuthorizer()
    assert authorizer.allows(authority, "db://tenant-1/users").allowed
    assert not authorizer.allows(authority, "db://tenant-2/users").allowed


def test_wildcard_resource_is_denied():
    authority = _context().authority
    result = ResourceAuthorizer().allows(authority, "db://tenant-1/*")
    assert not result.allowed
