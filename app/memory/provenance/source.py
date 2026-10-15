"""Source provenance and content verification.

The verifier does not fetch arbitrary URLs.  Network retrieval belongs to the
Gateway/Tool Fabric and must happen through those security boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from app.security.identity.crypto import sha256_hex


@dataclass(frozen=True)
class SourceVerification:
    verified: bool
    trust_class: str
    method: str
    content_hash: str
    expected_hash: str | None
    reason: str


@dataclass(frozen=True)
class SourceDescriptor:
    source_type: str
    uri: str | None = None
    title: str | None = None
    expected_content_hash: str | None = None
    metadata: Mapping[str, Any] | None = None


class SourceVerifier:
    """Verify source-bound content without granting it authority."""

    @staticmethod
    def content_hash(content: str) -> str:
        return sha256_hex(content)

    def verify(
        self,
        *,
        content: str,
        source: SourceDescriptor | None,
    ) -> SourceVerification:
        digest = self.content_hash(content)

        if source is None:
            return SourceVerification(
                verified=False,
                trust_class="unverified",
                method="no_source_attestation",
                content_hash=digest,
                expected_hash=None,
                reason="memory has no independently supplied source commitment",
            )

        expected = (
            source.expected_content_hash.lower().strip()
            if source.expected_content_hash
            else None
        )

        if expected and expected != digest:
            return SourceVerification(
                verified=False,
                trust_class="untrusted",
                method="sha256_mismatch",
                content_hash=digest,
                expected_hash=expected,
                reason="source content hash does not match the supplied commitment",
            )

        if expected:
            return SourceVerification(
                verified=True,
                trust_class="verified",
                method="sha256_content_commitment",
                content_hash=digest,
                expected_hash=expected,
                reason="content matches supplied source commitment",
            )

        return SourceVerification(
            verified=False,
            trust_class="unverified",
            method="source_metadata_only",
            content_hash=digest,
            expected_hash=None,
            reason="source is identified but does not carry an independently verifiable content commitment",
        )
