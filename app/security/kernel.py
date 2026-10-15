"""AURAGENT Trust & Security Kernel composition root.

This module does not replace AgentShield's existing decision engine. It
provides the durable Phase 4 authority/identity/proof boundary that the
existing engine and later Tool, Memory, Isolation, Evidence, Investigation,
Control Plane, Ecosystem, Scale, Enterprise and Research phases consume.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Mapping

from app.db.models import Agent, AgentIdentity
from app.security.context import SecurityContext
from app.security.delegation.conservation import AuthorityConservationEngine
from app.security.delegation.model import AuthorityState
from app.security.identity.crypto import sha256_hex
from app.security.proofs.authority_token import AuthorityToken, AuthorityTokenVerificationError
from app.security.proofs.decision_proof import DecisionProof
from app.security.proofs.policy_commitment import PolicyCommitment
from app.security.trust.risk import RiskScorer
from app.security.trust.score import TrustScorer


class AuthorityDeniedError(ValueError):
    """Raised when the trust kernel rejects an authority claim."""


@dataclass(frozen=True)
class KernelDecision:
    allowed: bool
    reason: str
    context: SecurityContext | None
    decision_proof: DecisionProof | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "context": self.context.to_dict() if self.context else None,
            "decision_proof": self.decision_proof.to_dict() if self.decision_proof else None,
        }


class SecurityKernel:
    """Central Phase 4 authority gate."""

    def __init__(self) -> None:
        self.conservation = AuthorityConservationEngine()
        self.trust_scorer = TrustScorer()
        self.risk_scorer = RiskScorer()

    @staticmethod
    def agent_base_authority(agent: Agent) -> AuthorityState:
        """Convert the legacy capability list into the Phase 4 authority ceiling."""
        return AuthorityState.from_values(
            capabilities=agent.scopes or [],
            operations={"read", "write", "delete", "execute", "external_call"},
            resources=(),
            data_scopes=(),
            network_scopes=(),
            delegation_depth=0,
            risk_ceiling=100.0,
        )

    def validate_token_against_agent(
        self,
        *,
        token: AuthorityToken,
        identity: AgentIdentity,
        agent: Agent,
        expected_policy_hash: str,
        now_epoch: int | None = None,
    ) -> SecurityContext:
        if token.tenant_id != agent.tenant_id:
            raise AuthorityDeniedError("authority_token_tenant_mismatch")
        if token.subject_agent_id != agent.agent_id:
            raise AuthorityDeniedError("authority_token_subject_mismatch")
        if token.issuer_agent_id != agent.agent_id:
            raise AuthorityDeniedError("authority_token_issuer_mismatch")
        if token.policy_hash != expected_policy_hash:
            raise AuthorityDeniedError("authority_token_policy_mismatch")
        if identity.agent_id != agent.agent_id or identity.tenant_id != agent.tenant_id:
            raise AuthorityDeniedError("identity_binding_mismatch")
        if identity.algorithm != token.algorithm:
            raise AuthorityDeniedError("identity_algorithm_mismatch")
        if not token.verify(
            identity.public_key,
            expected_tenant_id=agent.tenant_id,
            expected_subject_agent_id=agent.agent_id,
            now_epoch=now_epoch,
        ):
            raise AuthorityDeniedError("authority_token_signature_invalid")

        ceiling = self.agent_base_authority(agent)
        conservation = self.conservation.compare(ceiling, token.authority)
        if not conservation.allowed:
            raise AuthorityDeniedError("authority_token_exceeds_agent_ceiling")

        return SecurityContext.from_token(
            token=token,
            trace_id="",
            policy_hash=expected_policy_hash,
        )

    def authorize_action(
        self,
        *,
        context: SecurityContext,
        action: Mapping[str, Any],
        required_capabilities: set[str] | frozenset[str],
        risk_score: float,
        policy_hash: str,
        approval_id: str | None = None,
        evidence_root: str | None = None,
        signer=None,
        signer_key_id: str | None = None,
    ) -> KernelDecision:
        required = frozenset(required_capabilities)
        if context.policy_hash != policy_hash:
            proof = DecisionProof.create(
                signer=signer,
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                trace_id=context.trace_id,
                decision="deny",
                reason="policy_commitment_mismatch",
                action=action,
                policy_hash=policy_hash,
                capability_snapshot=sorted(context.capabilities),
                authority_token_hash=context.authority_token_hash or "none",
                approval_id=approval_id,
                risk_score=risk_score,
                evidence_root=evidence_root,
                signer_key_id=signer_key_id,
            )
            return KernelDecision(False, "policy_commitment_mismatch", context, proof)

        missing = required.difference(context.capabilities)
        if missing:
            proof = DecisionProof.create(
                signer=signer,
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                trace_id=context.trace_id,
                decision="deny",
                reason="missing_authority:" + ",".join(sorted(missing)),
                action=action,
                policy_hash=policy_hash,
                capability_snapshot=sorted(context.capabilities),
                authority_token_hash=context.authority_token_hash or "none",
                approval_id=approval_id,
                risk_score=risk_score,
                evidence_root=evidence_root,
                signer_key_id=signer_key_id,
            )
            return KernelDecision(False, "missing_authority", context, proof)

        if risk_score > context.authority.risk_ceiling:
            reason = "risk_exceeds_authority_ceiling"
            allowed = False
        elif risk_score >= 65.0 and not approval_id:
            reason = "human_approval_required"
            allowed = False
        else:
            reason = "authority_authorized"
            allowed = True

        proof = DecisionProof.create(
            signer=signer,
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            trace_id=context.trace_id,
            decision="allow" if allowed else "deny",
            reason=reason,
            action=action,
            policy_hash=policy_hash,
            capability_snapshot=sorted(context.capabilities),
            authority_token_hash=context.authority_token_hash or "none",
            approval_id=approval_id,
            risk_score=risk_score,
            evidence_root=evidence_root,
            signer_key_id=signer_key_id,
        )
        return KernelDecision(allowed, reason, context, proof)

    @staticmethod
    def policy_hash(policy: Any, *, name: str | None = None, version: str | None = None) -> str:
        return PolicyCommitment.from_policy(policy, name=name, version=version).content_hash

    @staticmethod
    def capability_snapshot_hash(capabilities: set[str] | frozenset[str] | list[str]) -> str:
        return sha256_hex(sorted(set(capabilities)))
