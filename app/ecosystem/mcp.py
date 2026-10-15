"""MCP ecosystem registration contracts.

This module describes external MCP servers but does not invoke them. Actual
tool invocation remains behind the existing Phase 5 Tool Fabric.
"""

from __future__ import annotations

from urllib.parse import urlparse

from .contracts import EcosystemKind, EcosystemManifest, MCPServerDescriptor
from .manifest import with_computed_hash


class MCPPolicyError(ValueError):
    pass


def validate_mcp_endpoint(endpoint: str) -> None:
    parsed = urlparse(endpoint)
    if parsed.scheme != "https":
        raise MCPPolicyError("MCP ecosystem endpoints must use HTTPS")
    if not parsed.hostname:
        raise MCPPolicyError("MCP endpoint hostname is required")
    if parsed.username or parsed.password:
        raise MCPPolicyError("credentials in MCP URLs are forbidden")


def mcp_manifest(
    descriptor: MCPServerDescriptor,
) -> EcosystemManifest:
    endpoint = str(descriptor.endpoint)
    validate_mcp_endpoint(endpoint)

    for resource in descriptor.resource_patterns:
        if resource.strip() == "*":
            raise MCPPolicyError("wildcard MCP resources are forbidden")

    draft = EcosystemManifest(
        publisher=descriptor.publisher,
        name=descriptor.name,
        version=descriptor.version,
        kind=EcosystemKind.MCP,
        description=descriptor.description,
        endpoints=[descriptor.endpoint],
        metadata={
            "transport": descriptor.transport,
            "tools": list(descriptor.tools),
            "resource_patterns": list(descriptor.resource_patterns),
            "verified": descriptor.verified,
        },
        content_sha256="",
    )

    return with_computed_hash(draft)
