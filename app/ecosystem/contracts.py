"""Stable, non-authority-bearing ecosystem contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class EcosystemKind(StrEnum):
    PLUGIN = "plugin"
    MCP = "mcp"
    A2A = "a2a"
    SDK = "sdk"
    INTEGRATION = "integration"


class PluginDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    description: str
    publisher: str
    entrypoint: str | None = None
    permissions: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    digest_sha256: str
    signed: bool = False
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class MCPServerDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    description: str
    publisher: str
    endpoint: HttpUrl
    transport: str = "streamable-http"
    tools: list[str] = Field(default_factory=list)
    resource_patterns: list[str] = Field(default_factory=list)
    digest_sha256: str | None = None
    verified: bool = False
    enabled: bool = True


class A2AEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    description: str
    publisher: str
    endpoint: HttpUrl
    protocol: str = "a2a"
    agent_card_url: HttpUrl | None = None
    capabilities: list[str] = Field(default_factory=list)
    trust_level: str = "unknown"
    verified: bool = False
    enabled: bool = True


class SDKDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    language: str
    package: str
    version: str
    minimum_api_version: str
    repository: HttpUrl | None = None
    documentation: HttpUrl | None = None
    checksum_sha256: str | None = None


class IntegrationDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    provider: str
    category: str
    webhook_supported: bool = False
    oauth_supported: bool = False
    outbound_domains: list[str] = Field(default_factory=list)
    enabled: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class RegistryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entry_id: str
    kind: EcosystemKind
    name: str
    version: str
    publisher: str
    description: str
    digest_sha256: str
    verified: bool
    enabled: bool
    registered_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class EcosystemManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_version: str = "1"
    ecosystem: str = "auragent"
    publisher: str
    name: str
    version: str
    kind: EcosystemKind
    description: str = ""
    homepage: HttpUrl | None = None
    repository: HttpUrl | None = None
    permissions: list[str] = Field(default_factory=list)
    requested_capabilities: list[str] = Field(default_factory=list)
    endpoints: list[HttpUrl] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    content_sha256: str


class CompatibilityResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    compatible: bool
    api_version: str
    required_minimum: str
    message: str


class DiscoveryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entries: list[RegistryEntry]
    next_cursor: str | None = None
