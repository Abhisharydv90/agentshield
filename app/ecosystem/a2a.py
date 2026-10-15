"""A2A endpoint discovery and trust-boundary helpers."""

from __future__ import annotations

from urllib.parse import urlparse

from .contracts import A2AEndpoint, EcosystemKind, EcosystemManifest
from .manifest import with_computed_hash


class A2APolicyError(ValueError):
    pass


def validate_a2a_endpoint(endpoint: A2AEndpoint) -> None:
    parsed = urlparse(str(endpoint.endpoint))
    if parsed.scheme != "https":
        raise A2APolicyError("A2A endpoints must use HTTPS")
    if parsed.username or parsed.password:
        raise A2APolicyError("credentials in A2A URLs are forbidden")

    if endpoint.trust_level not in {
        "unknown",
        "community",
        "verified",
        "enterprise",
    }:
        raise A2APolicyError("invalid A2A trust level")


def assert_no_authority_from_peer(endpoint: A2AEndpoint) -> None:
    requested = {capability.casefold() for capability in endpoint.capabilities}
    if "authority:grant" in requested:
        raise A2APolicyError(
            "peer agents cannot advertise authority-grant capability"
        )


def a2a_manifest(endpoint: A2AEndpoint) -> EcosystemManifest:
    validate_a2a_endpoint(endpoint)
    assert_no_authority_from_peer(endpoint)

    draft = EcosystemManifest(
        publisher=endpoint.publisher,
        name=endpoint.name,
        version=endpoint.version,
        kind=EcosystemKind.A2A,
        description=endpoint.description,
        endpoints=[endpoint.endpoint],
        requested_capabilities=list(endpoint.capabilities),
        metadata={
            "protocol": endpoint.protocol,
            "agent_card_url": (
                str(endpoint.agent_card_url)
                if endpoint.agent_card_url
                else None
            ),
            "trust_level": endpoint.trust_level,
            "verified": endpoint.verified,
        },
        content_sha256="",
    )
    return with_computed_hash(draft)
