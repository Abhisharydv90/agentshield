"""Signed, attenuated authority tokens."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

from app.security.delegation.model import AuthorityState
from app.security.identity.crypto import IdentityKeyPair, canonical_json, sha256_hex, verify_signature


class AuthorityTokenVerificationError(ValueError):
    """Raised when an authority token is malformed or invalid."""


@dataclass(frozen=True)
class AuthorityToken:
    token_id: uuid.UUID
    tenant_id: uuid.UUID
    issuer_agent_id: uuid.UUID
    subject_agent_id: uuid.UUID
    authority: AuthorityState
    policy_hash: str
    parent_token_hash: str | None
    issued_at: int
    expires_at: int
    nonce: str
    signature: str
    algorithm: str = "Ed25519"

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "schema": "auragent.authority-token.v1",
            "token_id": str(self.token_id),
            "tenant_id": str(self.tenant_id),
            "issuer_agent_id": str(self.issuer_agent_id),
            "subject_agent_id": str(self.subject_agent_id),
            "authority": self.authority.to_dict(),
            "policy_hash": self.policy_hash,
            "parent_token_hash": self.parent_token_hash,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "algorithm": self.algorithm,
        }

    @property
    def token_hash(self) -> str:
        return sha256_hex(self.unsigned_payload())

    def to_dict(self) -> dict[str, Any]:
        payload = self.unsigned_payload()
        payload["signature"] = self.signature
        payload["token_hash"] = self.token_hash
        return payload

    @classmethod
    def issue(
        cls,
        *,
        signer: IdentityKeyPair,
        tenant_id: uuid.UUID,
        issuer_agent_id: uuid.UUID,
        subject_agent_id: uuid.UUID,
        authority: AuthorityState,
        policy_hash: str,
        ttl_seconds: int,
        parent_token_hash: str | None = None,
        nonce: str | None = None,
    ) -> "AuthorityToken":
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if parent_token_hash is None and issuer_agent_id != subject_agent_id:
            raise ValueError(
                "delegated token requires parent_token_hash"
            )
        if parent_token_hash is not None and issuer_agent_id == subject_agent_id:
            raise ValueError(
                "delegated token must target a different subject"
            )
        issued = int(time.time())
        unsigned = cls(
            token_id=uuid.uuid4(),
            tenant_id=tenant_id,
            issuer_agent_id=issuer_agent_id,
            subject_agent_id=subject_agent_id,
            authority=authority,
            policy_hash=policy_hash,
            parent_token_hash=parent_token_hash,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
            nonce=nonce or uuid.uuid4().hex,
            signature="",
        )
        return cls(**{**unsigned.__dict__, "signature": signer.sign(unsigned.unsigned_payload())})

    def verify(
        self,
        public_key_b64: str,
        *,
        expected_tenant_id: uuid.UUID | None = None,
        expected_subject_agent_id: uuid.UUID | None = None,
        parent_token: "AuthorityToken | None" = None,
        now_epoch: int | None = None,
        clock_skew_seconds: int = 30,
    ) -> bool:
        now = int(time.time()) if now_epoch is None else int(now_epoch)
        if self.algorithm != "Ed25519":
            return False
        if self.expires_at < self.issued_at:
            return False
        if now + clock_skew_seconds < self.issued_at or now - clock_skew_seconds > self.expires_at:
            return False
        if expected_tenant_id is not None and self.tenant_id != expected_tenant_id:
            return False
        if expected_subject_agent_id is not None and self.subject_agent_id != expected_subject_agent_id:
            return False
        if parent_token is not None:
            if self.tenant_id != parent_token.tenant_id:
                return False
            if self.issuer_agent_id != parent_token.subject_agent_id:
                return False
            if self.subject_agent_id == self.issuer_agent_id:
                return False
            if self.parent_token_hash != parent_token.token_hash:
                return False
            if self.issued_at < parent_token.issued_at:
                return False
            if self.expires_at > parent_token.expires_at:
                return False
            if not self.authority.capabilities:
                return False
        return verify_signature(
            public_key_b64,
            canonical_json(self.unsigned_payload()),
            self.signature,
        )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AuthorityToken":
        try:
            authority_payload = dict(payload["authority"])
            authority = AuthorityState.from_values(
                capabilities=authority_payload.get("capabilities", []),
                operations=authority_payload.get("operations", []),
                resources=authority_payload.get("resources", []),
                data_scopes=authority_payload.get("data_scopes", []),
                network_scopes=authority_payload.get("network_scopes", []),
                budget_cents=authority_payload.get("budget_cents"),
                delegation_depth=int(authority_payload.get("delegation_depth", 0)),
                risk_ceiling=float(authority_payload.get("risk_ceiling", 100.0)),
            )
            return cls(
                token_id=uuid.UUID(str(payload["token_id"])),
                tenant_id=uuid.UUID(str(payload["tenant_id"])),
                issuer_agent_id=uuid.UUID(str(payload["issuer_agent_id"])),
                subject_agent_id=uuid.UUID(str(payload["subject_agent_id"])),
                authority=authority,
                policy_hash=str(payload["policy_hash"]),
                parent_token_hash=payload.get("parent_token_hash"),
                issued_at=int(payload["issued_at"]),
                expires_at=int(payload["expires_at"]),
                nonce=str(payload["nonce"]),
                signature=str(payload["signature"]),
                algorithm=str(payload.get("algorithm", "Ed25519")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorityTokenVerificationError("malformed authority token") from exc
