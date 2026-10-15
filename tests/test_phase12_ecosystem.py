"""Phase 12 Ecosystem Fabric deterministic boundary tests."""

from __future__ import annotations

import asyncio
from uuid import UUID

import pytest
from pydantic import HttpUrl

from app.ecosystem.a2a import (
    A2APolicyError,
    a2a_manifest,
    assert_no_authority_from_peer,
)
from app.ecosystem.contracts import (
    A2AEndpoint,
    EcosystemKind,
    EcosystemManifest,
    MCPServerDescriptor,
    PluginDescriptor,
)
from app.ecosystem.manifest import (
    compute_manifest_hash,
    verify_manifest_hash,
)
from app.ecosystem.mcp import MCPPolicyError, mcp_manifest, validate_mcp_endpoint
from app.ecosystem.plugins import (
    PluginPolicyError,
    assert_plugin_safe,
    canonical_plugin_manifest,
)
from app.ecosystem.registry import EcosystemRegistry
from app.sdk.auragent.client import AURAGENTClient


def manifest() -> EcosystemManifest:
    draft = EcosystemManifest(
        publisher="test",
        name="plugin",
        version="1.0.0",
        kind=EcosystemKind.PLUGIN,
        description="test plugin",
        permissions=["read"],
        requested_capabilities=["tool:read"],
        content_sha256="",
    )
    return draft.model_copy(
        update={"content_sha256": compute_manifest_hash(draft)}
    )


def test_manifest_hash_is_deterministic():
    value = manifest()
    assert verify_manifest_hash(value)
    assert len(value.content_sha256) == 64


def test_registry_is_deterministic_and_idempotent():
    registry = EcosystemRegistry()

    first = asyncio.run(registry.register(manifest()))
    second = asyncio.run(registry.register(manifest()))

    assert first.entry_id == second.entry_id
    assert first.digest_sha256 == second.digest_sha256
    assert first.verified is True


def test_manifest_rejects_tampering():
    value = manifest().model_copy(update={"description": "changed"})
    assert not verify_manifest_hash(value)
    with pytest.raises(ValueError):
        asyncio.run(EcosystemRegistry().register(value))


def test_plugin_forbids_authority_grants():
    descriptor = PluginDescriptor(
        name="unsafe",
        version="1.0.0",
        description="unsafe",
        publisher="test",
        digest_sha256="0" * 64,
        capabilities=["authority:grant"],
    )
    with pytest.raises(PluginPolicyError):
        assert_plugin_safe(descriptor)


def test_plugin_manifest_can_be_canonicalized():
    value = canonical_plugin_manifest(
        name="safe",
        version="1.0.0",
        description="safe",
        publisher="test",
    )
    assert verify_manifest_hash(value)


def test_mcp_requires_https():
    with pytest.raises(MCPPolicyError):
        validate_mcp_endpoint("http://example.com/mcp")


def test_mcp_manifest_is_hashed():
    descriptor = MCPServerDescriptor(
        name="mcp",
        version="1.0.0",
        description="server",
        publisher="test",
        endpoint=HttpUrl("https://example.com/mcp"),
    )
    value = mcp_manifest(descriptor)
    assert verify_manifest_hash(value)


def test_a2a_cannot_advertise_authority_grant():
    peer = A2AEndpoint(
        name="peer",
        version="1.0.0",
        description="peer",
        publisher="test",
        endpoint=HttpUrl("https://example.com/a2a"),
        capabilities=["authority:grant"],
    )
    with pytest.raises(A2APolicyError):
        assert_no_authority_from_peer(peer)


def test_a2a_manifest_is_hashed():
    peer = A2AEndpoint(
        name="peer",
        version="1.0.0",
        description="peer",
        publisher="test",
        endpoint=HttpUrl("https://example.com/a2a"),
    )
    value = a2a_manifest(peer)
    assert verify_manifest_hash(value)


def test_registry_snapshot_changes_when_entry_changes():
    registry = EcosystemRegistry()
    before = asyncio.run(registry.snapshot_hash())
    asyncio.run(registry.register(manifest()))
    after = asyncio.run(registry.snapshot_hash())
    assert before != after


def test_sdk_requires_https_and_blocks_path_traversal():
    with pytest.raises(ValueError):
        AURAGENTClient("http://example.com")

    client = AURAGENTClient("https://example.com")
    with pytest.raises(ValueError):
        client.build_request("/v1/../secrets")


def test_sdk_request_contract_does_not_embed_secrets_in_url():
    client = AURAGENTClient("https://example.com", token="secret")
    request = client.build_request("/v1/ecosystem/discover")
    assert request["url"] == "https://example.com/v1/ecosystem/discover"
    assert "secret" not in request["url"]


def test_plugin_descriptor_hash_is_required():
    descriptor = PluginDescriptor(
        name="safe",
        version="1.0.0",
        description="safe",
        publisher="test",
        digest_sha256="0" * 64,
    )
    with pytest.raises(PluginPolicyError):
        # The zero digest cannot match the canonical manifest.
        from app.ecosystem.plugins import plugin_manifest

        plugin_manifest(descriptor)
