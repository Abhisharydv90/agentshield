"""Signed agent credentials and verification.

Credentials are bearer artifacts only for identity claims. They are not
permissions by themselves. Authority is represented separately by an
AuthorityToken and constrained by the agent's stored capability ceiling.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.security.identity.crypto import (
    AgentIdentityDocument,
    IdentityKeyPair,
    canonical_json,
    sha256_hex,
    verify_signature,
)


class CredentialVerificationError(ValueError):
    """Raised when a credential fails structural or cryptographic checks."""


def _epoch(dt: datetime) -> int:
    return int(dt.astimezone(timezone.utc).timestamp())


def _now_epoch() -> int:
    return int(time.time())


@dataclass(frozen=True)
class AgentCredential:
    """Portable signed identity credential."""

    credential_id: uuid.UUID
    tenant_id: uuid.UUID
    agent_id: uuid.UUID
    key_id: str
    public_key: str
    issued_at: int
    expires_at: int
    claims: dict[str, Any]
    issuer: str
    signature: str
    algorithm: str = "Ed25519"

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "schema": "auragent.credential.v1",
            "credential_id": str(self.credential_id),
            "tenant_id": str(self.tenant_id),
            "agent_id": str(self.agent_id),
            "key_id": self.key_id,
            "public_key": self.public_key,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "claims": self.claims,
            "issuer": self.issuer,
            "algorithm": self.algorithm,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.unsigned_payload()
        payload["signature"] = self.signature
        return payload

    @property
    def fingerprint(self) -> str:
        return sha256_hex(self.unsigned_payload())


def issue_agent_credential(
    *,
    identity: AgentIdentityDocument,
    signer: IdentityKeyPair,
    issuer: str,
    ttl_seconds: int = 3600,
    claims: dict[str, Any] | None = None,
) -> AgentCredential:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be greater than zero")
    if identity.algorithm != "Ed25519":
        raise ValueError("unsupported identity algorithm")
    if identity.public_key != signer.public_key_b64:
        raise ValueError("signer public key does not match identity document")

    now = _now_epoch()
    credential = AgentCredential(
        credential_id=uuid.uuid4(),
        tenant_id=identity.tenant_id,
        agent_id=identity.agent_id,
        key_id=identity.key_id,
        public_key=identity.public_key,
        issued_at=now,
        expires_at=now + ttl_seconds,
        claims=dict(claims or {}),
        issuer=issuer,
        signature="",
        algorithm=identity.algorithm,
    )
    signature = signer.sign(credential.unsigned_payload())
    return AgentCredential(**{**credential.__dict__, "signature": signature})


def verify_agent_credential(
    credential: AgentCredential,
    *,
    expected_tenant_id: uuid.UUID | None = None,
    expected_agent_id: uuid.UUID | None = None,
    now_epoch: int | None = None,
    clock_skew_seconds: int = 30,
) -> bool:
    now = _now_epoch() if now_epoch is None else int(now_epoch)
    if credential.algorithm != "Ed25519":
        return False
    if expected_tenant_id is not None and credential.tenant_id != expected_tenant_id:
        return False
    if expected_agent_id is not None and credential.agent_id != expected_agent_id:
        return False
    if credential.expires_at < credential.issued_at:
        return False
    if now + clock_skew_seconds < credential.issued_at:
        return False
    if now - clock_skew_seconds > credential.expires_at:
        return False
    return verify_signature(
        credential.public_key,
        canonical_json(credential.unsigned_payload()),
        credential.signature,
    )
