"""Ed25519 identity and deterministic canonicalization primitives.

Private keys are never persisted by this module. The caller owns key
custody (OS key store, HSM, KMS, secure enclave, or an agent-side vault).
The server may persist only public identity material and fingerprints.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_json(value: Any) -> bytes:
    """Return stable UTF-8 JSON suitable for hashing/signing."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(value: bytes | str | Mapping[str, Any] | list[Any]) -> str:
    """Return a lowercase SHA-256 digest over canonical bytes."""
    if isinstance(value, bytes):
        payload = value
    elif isinstance(value, str):
        payload = value.encode("utf-8")
    else:
        payload = canonical_json(value)
    return hashlib.sha256(payload).hexdigest()


def _b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64u_decode(value: str) -> bytes:
    padded = value.encode("ascii") + b"=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(padded)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    value = value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class IdentityKeyPair:
    """In-memory Ed25519 key pair with safe export helpers."""

    private_key: bytes
    public_key: bytes
    algorithm: str = "Ed25519"

    @classmethod
    def generate(cls) -> "IdentityKeyPair":
        private = Ed25519PrivateKey.generate()
        public = private.public_key()
        return cls(
            private_key=private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ),
            public_key=public.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            ),
        )

    @classmethod
    def from_private_key_b64(cls, private_key_b64: str) -> "IdentityKeyPair":
        private_bytes = _b64u_decode(private_key_b64)
        if len(private_bytes) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 bytes")
        private = Ed25519PrivateKey.from_private_bytes(private_bytes)
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return cls(private_key=private_bytes, public_key=public)

    @property
    def private_key_b64(self) -> str:
        return _b64u_encode(self.private_key)

    @property
    def public_key_b64(self) -> str:
        return _b64u_encode(self.public_key)

    @property
    def fingerprint(self) -> str:
        return sha256_hex(self.public_key)

    def sign(self, payload: bytes | str | Mapping[str, Any]) -> str:
        data = payload if isinstance(payload, (bytes, bytearray)) else (
            payload.encode("utf-8") if isinstance(payload, str) else canonical_json(payload)
        )
        signature = Ed25519PrivateKey.from_private_bytes(self.private_key).sign(data)
        return _b64u_encode(signature)

    def verify(self, payload: bytes | str | Mapping[str, Any], signature_b64: str) -> bool:
        return verify_signature(self.public_key_b64, payload, signature_b64)


@dataclass(frozen=True)
class AgentIdentityDocument:
    """Public, tenant-scoped identity document for an agent."""

    tenant_id: uuid.UUID
    agent_id: uuid.UUID
    key_id: str
    public_key: str
    algorithm: str = "Ed25519"
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    metadata: dict[str, Any] | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "schema": "auragent.identity.v1",
            "tenant_id": str(self.tenant_id),
            "agent_id": str(self.agent_id),
            "key_id": self.key_id,
            "public_key": self.public_key,
            "algorithm": self.algorithm,
            "issued_at": _iso(self.issued_at or utc_now()),
            "expires_at": _iso(self.expires_at) if self.expires_at else None,
            "metadata": self.metadata or {},
        }

    @property
    def fingerprint(self) -> str:
        return sha256_hex(_b64u_decode(self.public_key))


def verify_signature(
    public_key_b64: str,
    payload: bytes | str | Mapping[str, Any],
    signature_b64: str,
) -> bool:
    """Verify an Ed25519 signature without raising on bad signatures."""
    try:
        public_bytes = _b64u_decode(public_key_b64)
        signature = _b64u_decode(signature_b64)
        if len(public_bytes) != 32 or len(signature) != 64:
            return False
        data = payload if isinstance(payload, (bytes, bytearray)) else (
            payload.encode("utf-8") if isinstance(payload, str) else canonical_json(payload)
        )
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, data)
        return True
    except (ValueError, TypeError, InvalidSignature, base64.binascii.Error):
        return False
