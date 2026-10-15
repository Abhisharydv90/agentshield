"""Enterprise organization-wide policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import EnterprisePolicy


class EnterprisePolicyDenied(PermissionError):
    pass


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


def evaluate_region(
    policy: EnterprisePolicy,
    region: str,
) -> PolicyDecision:
    if policy.denied_regions and region in policy.denied_regions:
        return PolicyDecision(False, "region is explicitly denied")

    if policy.allowed_regions and region not in policy.allowed_regions:
        return PolicyDecision(False, "region is outside organization allowlist")

    return PolicyDecision(True, "region permitted")


def require_evidence_for_action(
    policy: EnterprisePolicy,
    *,
    has_evidence: bool,
) -> None:
    if policy.require_evidence_for_actions and not has_evidence:
        raise EnterprisePolicyDenied(
            "organization policy requires evidence for the action"
        )


def require_sso(
    policy: EnterprisePolicy,
    *,
    sso_authenticated: bool,
) -> None:
    if policy.enforce_sso and not sso_authenticated:
        raise EnterprisePolicyDenied(
            "organization policy requires SSO authentication"
        )


def require_high_risk_approval(
    policy: EnterprisePolicy,
    *,
    risk_score: int,
    has_human_approval: bool,
) -> None:
    if (
        policy.require_human_approval_for_high_risk
        and risk_score >= 65
        and not has_human_approval
    ):
        raise EnterprisePolicyDenied(
            "high-risk action requires human approval"
        )
