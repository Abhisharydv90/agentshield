"""Serializable request security context shared by Phases 5-15."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from app.security.delegation.model import AuthorityState
from app.security.proofs.authority_token import AuthorityToken


@dataclass(frozen=True)
class SecurityContext:
    tenant_id: uuid.UUID
    agent_id: uuid.UUID
    trace_id: str
    capabilities: frozenset[str]
    authority: AuthorityState
    policy_hash: str
    authority_token_hash: str | None = None
    provenance: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": str(self.tenant_id),
            "agent_id": str(self.agent_id),
            "trace_id": self.trace_id,
            "capabilities": sorted(self.capabilities),
            "authority": self.authority.to_dict(),
            "policy_hash": self.policy_hash,
            "authority_token_hash": self.authority_token_hash,
            "provenance": self.provenance or {},
        }

    @classmethod
    def from_token(
        cls,
        *,
        token: AuthorityToken,
        trace_id: str,
        policy_hash: str,
    ) -> "SecurityContext":
        return cls(
            tenant_id=token.tenant_id,
            agent_id=token.subject_agent_id,
            trace_id=trace_id,
            capabilities=token.authority.capabilities,
            authority=token.authority,
            policy_hash=policy_hash,
            authority_token_hash=token.token_hash,
            provenance={"source": "authority_token"},
        )
