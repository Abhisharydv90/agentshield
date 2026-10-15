"""Signed decision proofs binding action, authority and policy state."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

from app.security.identity.crypto import IdentityKeyPair, canonical_json, sha256_hex, verify_signature


class DecisionProofVerificationError(ValueError):
    """Raised for malformed decision proofs."""


@dataclass(frozen=True)
class DecisionProof:
    proof_id: uuid.UUID
    tenant_id: uuid.UUID
    agent_id: uuid.UUID
    trace_id: str
    decision: str
    reason: str
    action_hash: str
    policy_hash: str
    capability_hash: str
    authority_token_hash: str
    approval_id: str | None
    risk_score: float
    evidence_root: str | None
    created_at: int
    signature: str
    signer_key_id: str | None = None
    algorithm: str = "Ed25519"

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "schema": "auragent.decision-proof.v1",
            "proof_id": str(self.proof_id),
            "tenant_id": str(self.tenant_id),
            "agent_id": str(self.agent_id),
            "trace_id": self.trace_id,
            "decision": self.decision,
            "reason": self.reason,
            "action_hash": self.action_hash,
            "policy_hash": self.policy_hash,
            "capability_hash": self.capability_hash,
            "authority_token_hash": self.authority_token_hash,
            "approval_id": self.approval_id,
            "risk_score": self.risk_score,
            "evidence_root": self.evidence_root,
            "created_at": self.created_at,
            "signer_key_id": self.signer_key_id,
            "algorithm": self.algorithm,
        }

    @property
    def proof_hash(self) -> str:
        return sha256_hex(self.unsigned_payload())

    def to_dict(self) -> dict[str, Any]:
        payload = self.unsigned_payload()
        payload["signature"] = self.signature
        payload["proof_hash"] = self.proof_hash
        return payload

    @classmethod
    def create(
        cls,
        *,
        signer: IdentityKeyPair | None,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        trace_id: str,
        decision: str,
        reason: str,
        action: Mapping[str, Any],
        policy_hash: str,
        capability_snapshot: Mapping[str, Any] | list[str],
        authority_token_hash: str,
        approval_id: str | None = None,
        risk_score: float = 0.0,
        evidence_root: str | None = None,
        signer_key_id: str | None = None,
    ) -> "DecisionProof":
        action_hash = sha256_hex(action)
        capability_hash = sha256_hex(capability_snapshot)
        created = int(time.time())
        unsigned = cls(
            proof_id=uuid.uuid4(),
            tenant_id=tenant_id,
            agent_id=agent_id,
            trace_id=trace_id,
            decision=str(decision),
            reason=str(reason),
            action_hash=action_hash,
            policy_hash=policy_hash,
            capability_hash=capability_hash,
            authority_token_hash=authority_token_hash,
            approval_id=approval_id,
            risk_score=max(0.0, min(100.0, float(risk_score))),
            evidence_root=evidence_root,
            created_at=created,
            signature="",
            signer_key_id=signer_key_id,
        )
        signature = signer.sign(unsigned.unsigned_payload()) if signer else ""
        return cls(**{**unsigned.__dict__, "signature": signature})

    def verify(self, public_key_b64: str) -> bool:
        if self.algorithm != "Ed25519":
            return False
        if not self.signature:
            return False
        return verify_signature(
            public_key_b64,
            canonical_json(self.unsigned_payload()),
            self.signature,
        )
