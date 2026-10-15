"""Deterministic runtime risk assessment.

Risk is a control signal and never grants authority. Lower scores are safer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class RiskFactor:
    name: str
    score: float
    weight: float
    reason: str = ""

    def bounded_score(self) -> float:
        return max(0.0, min(100.0, float(self.score)))


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    level: RiskLevel
    factors: tuple[RiskFactor, ...]
    requires_approval: bool


class RiskScorer:
    """Weighted risk model with deterministic thresholds."""

    def assess(self, factors: Iterable[RiskFactor]) -> RiskAssessment:
        items = tuple(factors)
        if not items:
            return RiskAssessment(0.0, RiskLevel.LOW, (), False)
        weight_total = sum(max(0.0, f.weight) for f in items)
        if weight_total <= 0:
            score = 0.0
        else:
            score = sum(f.bounded_score() * max(0.0, f.weight) for f in items) / weight_total
        score = round(score, 4)
        if score >= 85:
            level = RiskLevel.CRITICAL
        elif score >= 65:
            level = RiskLevel.HIGH
        elif score >= 35:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW
        return RiskAssessment(
            score=score,
            level=level,
            factors=items,
            requires_approval=score >= 65.0,
        )

    def from_action(
        self,
        *,
        operation: str,
        network_egress: bool = False,
        sensitive_resource: bool = False,
        destructive: bool = False,
        external_content_influence: bool = False,
    ) -> RiskAssessment:
        op = operation.strip().lower()
        return self.assess(
            [
                RiskFactor("operation", 70.0 if op in {"delete", "execute"} else 20.0, 0.30),
                RiskFactor("network", 65.0 if network_egress else 0.0, 0.15),
                RiskFactor("sensitive_resource", 80.0 if sensitive_resource else 0.0, 0.20),
                RiskFactor("destructive", 100.0 if destructive else 0.0, 0.25),
                RiskFactor("external_content", 55.0 if external_content_influence else 0.0, 0.10),
            ]
        )
