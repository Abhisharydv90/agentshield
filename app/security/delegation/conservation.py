"""Authority Conservation Engine (ACE).

The core invariant is intentionally explicit:

    A_child <= A_parent

unless an independently authorized escalation exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone

from app.security.delegation.model import AuthorityState, DelegationViolation


@dataclass(frozen=True)
class ConservationResult:
    allowed: bool
    violations: tuple[DelegationViolation, ...]

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "violations": [
                {"field": v.field, "reason": v.reason} for v in self.violations
            ],
        }


class AuthorityConservationEngine:
    """Compare child authority against a parent authority state."""

    def compare(
        self,
        parent: AuthorityState,
        child: AuthorityState,
        *,
        authorized_escalation: bool = False,
    ) -> ConservationResult:
        violations: list[DelegationViolation] = []

        if not child.capabilities.issubset(parent.capabilities):
            violations.append(DelegationViolation("capabilities", "child contains capabilities absent from parent"))
        if not child.operations.issubset(parent.operations):
            violations.append(DelegationViolation("operations", "child contains operations absent from parent"))
        if not child.resources.is_subset_of(parent.resources):
            violations.append(DelegationViolation("resources", "child resource scope exceeds parent"))
        if not child.data_scopes.is_subset_of(parent.data_scopes):
            violations.append(DelegationViolation("data_scopes", "child data scope exceeds parent"))
        if not child.network_scopes.is_subset_of(parent.network_scopes):
            violations.append(DelegationViolation("network_scopes", "child network scope exceeds parent"))

        if parent.valid_from and child.valid_from and child.valid_from < parent.valid_from:
            violations.append(DelegationViolation("valid_from", "child begins before parent authority"))
        if parent.valid_until:
            if child.valid_until is None or child.valid_until > parent.valid_until:
                violations.append(DelegationViolation("valid_until", "child outlives parent authority"))

        if parent.budget_cents is not None:
            if child.budget_cents is None or child.budget_cents > parent.budget_cents:
                violations.append(DelegationViolation("budget_cents", "child budget exceeds parent budget"))

        if child.delegation_depth > parent.delegation_depth:
            violations.append(DelegationViolation("delegation_depth", "child delegation depth exceeds parent allowance"))
        if child.risk_ceiling > parent.risk_ceiling:
            violations.append(DelegationViolation("risk_ceiling", "child risk ceiling is less restrictive than parent"))

        if violations and not authorized_escalation:
            return ConservationResult(False, tuple(violations))
        return ConservationResult(True, tuple(violations))
