"""Deterministic trust scoring.

Trust is an assessment signal, not authority. A high trust score never
creates a capability that is absent from the authority state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class TrustFactor:
    name: str
    value: float
    weight: float
    reason: str = ""

    def normalized_value(self) -> float:
        return max(0.0, min(100.0, float(self.value)))


@dataclass(frozen=True)
class TrustAssessment:
    score: float
    tier: str
    factors: tuple[TrustFactor, ...]

    @property
    def is_acceptable(self) -> bool:
        return self.score >= 60.0


class TrustScorer:
    """Weighted deterministic trust evaluator."""

    def assess(self, factors: Iterable[TrustFactor]) -> TrustAssessment:
        items = tuple(factors)
        if not items:
            return TrustAssessment(score=0.0, tier="unknown", factors=())
        weight_total = sum(max(0.0, f.weight) for f in items)
        if weight_total <= 0:
            return TrustAssessment(score=0.0, tier="unknown", factors=items)
        score = sum(f.normalized_value() * max(0.0, f.weight) for f in items) / weight_total
        if score >= 85:
            tier = "high"
        elif score >= 60:
            tier = "medium"
        elif score >= 35:
            tier = "low"
        else:
            tier = "untrusted"
        return TrustAssessment(score=round(score, 4), tier=tier, factors=items)

    def from_signals(
        self,
        *,
        identity_verified: bool,
        policy_compliant: bool,
        evidence_integrity: bool,
        recent_security_incidents: int = 0,
        delegation_violations: int = 0,
    ) -> TrustAssessment:
        incident_penalty = max(0, recent_security_incidents) * 15.0
        delegation_penalty = max(0, delegation_violations) * 20.0
        return self.assess(
            [
                TrustFactor("identity", 100.0 if identity_verified else 0.0, 0.30),
                TrustFactor("policy_compliance", 100.0 if policy_compliant else 0.0, 0.25),
                TrustFactor("evidence_integrity", 100.0 if evidence_integrity else 0.0, 0.20),
                TrustFactor("operational_history", max(0.0, 100.0 - incident_penalty), 0.15),
                TrustFactor("delegation_safety", max(0.0, 100.0 - delegation_penalty), 0.10),
            ]
        )
