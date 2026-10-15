"""Plugin boundary — descriptors only, never arbitrary code execution."""

from __future__ import annotations

from .contracts import EcosystemKind, EcosystemManifest, PluginDescriptor
from .manifest import compute_manifest_hash, with_computed_hash


class PluginPolicyError(ValueError):
    pass


def assert_plugin_safe(descriptor: PluginDescriptor) -> None:
    forbidden = {
        "authority:grant",
        "credential:export",
        "kernel:modify",
        "security:disable",
    }
    requested = {item.casefold() for item in descriptor.capabilities}
    overlap = sorted(requested & forbidden)
    if overlap:
        raise PluginPolicyError(
            f"forbidden plugin capabilities requested: {overlap}"
        )

    if descriptor.entrypoint and (
        descriptor.entrypoint.startswith("/")
        or "\\" in descriptor.entrypoint
        or ":" in descriptor.entrypoint[:3]
    ):
        raise PluginPolicyError(
            "absolute filesystem plugin entrypoints are forbidden"
        )


def plugin_manifest(
    descriptor: PluginDescriptor,
) -> EcosystemManifest:
    assert_plugin_safe(descriptor)

    draft = EcosystemManifest(
        publisher=descriptor.publisher,
        name=descriptor.name,
        version=descriptor.version,
        kind=EcosystemKind.PLUGIN,
        description=descriptor.description,
        permissions=list(descriptor.permissions),
        requested_capabilities=list(descriptor.capabilities),
        metadata={
            **descriptor.metadata,
            "entrypoint": descriptor.entrypoint,
            "signed": descriptor.signed,
        },
        content_sha256="",
    )
    expected = compute_manifest_hash(draft)
    if expected != descriptor.digest_sha256:
        raise PluginPolicyError(
            "plugin digest does not match canonical manifest"
        )
    return with_computed_hash(draft)


def canonical_plugin_manifest(
    *,
    name: str,
    version: str,
    description: str,
    publisher: str,
    permissions: list[str] | None = None,
    capabilities: list[str] | None = None,
) -> EcosystemManifest:
    draft = EcosystemManifest(
        publisher=publisher,
        name=name,
        version=version,
        kind=EcosystemKind.PLUGIN,
        description=description,
        permissions=permissions or [],
        requested_capabilities=capabilities or [],
        content_sha256="",
    )
    return with_computed_hash(draft)
