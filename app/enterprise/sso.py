"""SAML enterprise SSO trust metadata validation.

Actual SAML assertion processing remains delegated to a hardened identity
provider/library. This layer refuses insecure metadata and establishes the
server-side configuration contract.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

from .contracts import SSOConfiguration


_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


class SSOConfigurationError(ValueError):
    pass


def normalize_fingerprint(value: str) -> str:
    normalized = value.replace(":", "").replace(" ", "").strip().lower()
    if not _SHA256.fullmatch(normalized):
        raise SSOConfigurationError(
            "certificate fingerprint must be a 64-character SHA-256 hex digest"
        )
    return normalized


def validate_sso_configuration(config: SSOConfiguration) -> SSOConfiguration:
    parsed = urlparse(str(config.metadata_url))
    if parsed.scheme != "https":
        raise SSOConfigurationError("SAML metadata URL must use HTTPS")
    if not parsed.hostname:
        raise SSOConfigurationError("SAML metadata hostname is required")
    if parsed.username or parsed.password:
        raise SSOConfigurationError(
            "credentials embedded in SAML metadata URL are forbidden"
        )

    domains = []
    for domain in config.allowed_email_domains:
        value = domain.strip().lower()
        if not value or "/" in value or "@" in value:
            raise SSOConfigurationError("invalid allowed email domain")
        domains.append(value)

    normalized = config.model_copy(
        update={
            "issuer": config.issuer.strip(),
            "audience": config.audience.strip(),
            "certificate_fingerprint_sha256": normalize_fingerprint(
                config.certificate_fingerprint_sha256
            ),
            "allowed_email_domains": sorted(set(domains)),
        }
    )

    if not normalized.issuer or not normalized.audience:
        raise SSOConfigurationError("issuer and audience are required")

    return normalized


def trust_binding_digest(config: SSOConfiguration) -> str:
    validated = validate_sso_configuration(config)
    payload = "|".join(
        [
            str(validated.organization_id),
            validated.protocol.value,
            validated.issuer,
            validated.audience,
            str(validated.metadata_url),
            validated.certificate_fingerprint_sha256,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
