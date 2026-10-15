"""Explicit, opt-in external anchoring for Evidence Fabric.

Anchoring submits only a cryptographic commitment, not raw evidence records.
The caller supplies a precomputed compliance/evidence package hash. The client
is HTTPS-only, disables redirects, requires an explicit host allowlist, bounds
the request body and timeout, and never automatically retries or follows a
redirect to a different host.

No background anchoring is started by this module.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlparse

import httpx


class ExternalAnchorError(RuntimeError):
    """Raised when an external anchoring request cannot be safely completed."""


@dataclass(frozen=True)
class AnchorDocument:
    tenant_id: uuid.UUID
    package_hash: str
    scheme: str = "auragent-evidence-anchor-v1"

    def __post_init__(self) -> None:
        if len(self.package_hash) != 64 or not self.package_hash.isalnum():
            raise ExternalAnchorError("package_hash_must_be_sha256")

    def to_dict(self) -> dict[str, str]:
        return {
            "scheme": self.scheme,
            "tenant_id": str(self.tenant_id),
            "package_hash": self.package_hash.lower(),
        }

    def digest(self) -> str:
        encoded = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class AnchorReceipt:
    provider: str
    package_hash: str
    anchor_id: str
    submitted_at: str
    response_digest: str | None
    status_code: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "package_hash": self.package_hash,
            "anchor_id": self.anchor_id,
            "submitted_at": self.submitted_at,
            "response_digest": self.response_digest,
            "status_code": self.status_code,
        }


def build_anchor_document(
    *,
    tenant_id: uuid.UUID,
    package_hash: str,
) -> AnchorDocument:
    return AnchorDocument(
        tenant_id=tenant_id,
        package_hash=package_hash,
    )


class HttpsAnchorProvider:
    """Opt-in HTTP anchoring provider that sends only the commitment."""

    name = "https-anchor"

    def __init__(
        self,
        *,
        endpoint: str,
        allowed_hosts: Iterable[str],
        timeout_seconds: float = 5.0,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ExternalAnchorError("anchor_endpoint_must_be_https")

        host = parsed.hostname.lower().rstrip(".")
        allowed = {
            value.strip().lower().rstrip(".")
            for value in allowed_hosts
            if value.strip()
        }
        if not allowed or host not in allowed:
            raise ExternalAnchorError("anchor_host_not_allowlisted")

        if not 1.0 <= timeout_seconds <= 30.0:
            raise ExternalAnchorError("anchor_timeout_out_of_bounds")

        self.endpoint = endpoint
        self.allowed_hosts = frozenset(allowed)
        self.timeout_seconds = timeout_seconds

    async def submit(self, document: AnchorDocument) -> AnchorReceipt:
        payload = {
            **document.to_dict(),
            "document_digest": document.digest(),
        }
        body = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        if len(body) > 16 * 1024:
            raise ExternalAnchorError("anchor_request_too_large")

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                follow_redirects=False,
                headers={
                    "content-type": "application/json",
                    "user-agent": "AURAGENT-EvidenceAnchor/1",
                },
            ) as client:
                response = await client.post(
                    self.endpoint,
                    content=body,
                )
        except httpx.HTTPError as exc:
            raise ExternalAnchorError("anchor_transport_failed") from exc

        if response.is_redirect or response.is_error:
            raise ExternalAnchorError(
                f"anchor_provider_rejected:{response.status_code}"
            )

        try:
            response_data = response.json()
        except ValueError as exc:
            raise ExternalAnchorError(
                "anchor_provider_invalid_json"
            ) from exc

        anchor_id = response_data.get("anchor_id")
        if not isinstance(anchor_id, str) or not anchor_id.strip():
            raise ExternalAnchorError("anchor_provider_missing_anchor_id")

        response_digest = hashlib.sha256(
            response.content
        ).hexdigest()

        return AnchorReceipt(
            provider=self.name,
            package_hash=document.package_hash,
            anchor_id=anchor_id,
            submitted_at=datetime.now(timezone.utc).isoformat(),
            response_digest=response_digest,
            status_code=response.status_code,
        )
