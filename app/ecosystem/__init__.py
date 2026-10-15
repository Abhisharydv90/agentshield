"""AURAGENT Phase 12 — Ecosystem Fabric."""

from .contracts import (
    A2AEndpoint,
    CompatibilityResult,
    EcosystemManifest,
    IntegrationDescriptor,
    MCPServerDescriptor,
    PluginDescriptor,
    RegistryEntry,
    SDKDescriptor,
)
from .registry import EcosystemRegistry
from .service import EcosystemService

__all__ = [
    "A2AEndpoint",
    "CompatibilityResult",
    "EcosystemManifest",
    "IntegrationDescriptor",
    "MCPServerDescriptor",
    "PluginDescriptor",
    "RegistryEntry",
    "SDKDescriptor",
    "EcosystemRegistry",
    "EcosystemService",
]
