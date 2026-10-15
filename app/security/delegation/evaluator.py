"""Policy/trust/risk-aware delegation evaluator."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from app.security.delegation.conservation import AuthorityConservationEngine
from app.security.delegation.model import AuthorityState, DelegationGrant
from app.security.trust.risk import RiskLevel
from app.security.trust.score import TrustAssessment


@dataclass(frozen=True)
class DelegationDecision:
    allowed: bool
    reason: str
    conservation: dict
    trust_score: float
    risk_score: float
    grant_id: uuid.UUID | None = None


class DelegationEvaluator:
    """Evaluate whether a parent may delegate a bounded authority state."""

    def __init__(self, conservation: AuthorityConservationEngine | None = None) -> None:
        self.conservation = conservation or AuthorityConservationEngine()

    def evaluate(
        self,
        *,
        parent: AuthorityState,
        child: AuthorityState,
        trust: TrustAssessment,
        risk_score: float,
        grant: DelegationGrant | None = None,
        now: datetime | None = None,
    ) -> DelegationDecision:
        now = now or datetime.now(timezone.utc)
        if grant is not None:
            if grant.tenant_id.int == 0 or grant.parent_agent_id.int == 0 or grant.child_agent_id.int == 0:
                return DelegationDecision(False, "invalid_grant_identity", {}, trust.score, risk_score)
            if grant.expires_at < now:
                return DelegationDecision(False, "grant_expired", {}, trust.score, risk_score, grant.grant_id)

        conservation = self.conservation.compare(
            parent,
            child,
            authorized_escalation=bool(grant and grant.escalation_authorized),
        )
        if not conservation.allowed:
            return DelegationDecision(False, "authority_conservation_violation", conservation.to_dict(), trust.score, risk_score, grant.grant_id if grant else None)
        if trust.score < 60.0:
            return DelegationDecision(False, "insufficient_trust", conservation.to_dict(), trust.score, risk_score, grant.grant_id if grant else None)
        if risk_score > child.risk_ceiling:
            return DelegationDecision(False, "risk_exceeds_child_ceiling", conservation.to_dict(), trust.score, risk_score, grant.grant_id if grant else None)
        if risk_score >= 85.0 and child.risk_ceiling < risk_score:
            return DelegationDecision(False, "critical_risk", conservation.to_dict(), trust.score, risk_score, grant.grant_id if grant else None)
        if trust.score < 85.0 and risk_score >= 65.0:
            return DelegationDecision(False, "high_risk_requires_stronger_trust", conservation.to_dict(), trust.score, risk_score, grant.grant_id if grant else None)
        return DelegationDecision(True, "delegation_authorized", conservation.to_dict(), trust.score, risk_score, grant.grant_id if grant else None)
