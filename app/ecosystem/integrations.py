"""Vendor-neutral integration allowlist."""

from __future__ import annotations

from fnmatch import fnmatch
from urllib.parse import urlparse

from .contracts import IntegrationDescriptor


class IntegrationPolicyError(ValueError):
    pass


def validate_integration(descriptor: IntegrationDescriptor) -> None:
    if not descriptor.name.strip():
        raise IntegrationPolicyError("integration name is required")
    if not descriptor.provider.strip():
        raise IntegrationPolicyError("integration provider is required")

    for domain in descriptor.outbound_domains:
        value = domain.strip().lower()
        if not value or "/" in value or value == "*":
            raise IntegrationPolicyError(
                "integration outbound domains must be explicit host patterns"
            )

    if descriptor.oauth_supported and not descriptor.metadata.get(
        "secret_reference"
    ):
        raise IntegrationPolicyError(
            "OAuth integrations require a server-side secret reference"
        )


def domain_allowed(host: str, allowed_domains: list[str]) -> bool:
    normalized = host.casefold().rstrip(".")
    return any(
        fnmatch(normalized, pattern.casefold().rstrip("."))
        for pattern in allowed_domains
    )


def endpoint_allowed(url: str, allowed_domains: list[str]) -> bool:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    return domain_allowed(parsed.hostname, allowed_domains)
