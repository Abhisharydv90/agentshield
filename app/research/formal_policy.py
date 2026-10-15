"""Bounded formal-policy verification reference implementation.

This is a transparent finite-state checker. It does not claim to prove every
possible execution of a production system; Phase 4 remains the runtime
authorization boundary.
"""

from __future__ import annotations

import hashlib
import json
from itertools import product

from .contracts import (
    FormalPolicy,
    PolicyDecision,
    PolicyModel,
    PolicyVerificationResult,
    TrustGrade,
)


def evaluate_policy_model(
    policy: FormalPolicy,
    model: PolicyModel,
) -> PolicyDecision:
    reasons: list[str] = []

    if model.capability not in policy.allowed_capabilities:
        reasons.append("capability outside allowlist")

    if model.operation not in policy.allowed_operations:
        reasons.append("operation outside allowlist")

    if (
        policy.required_provenance_grades
        and model.provenance_grade not in policy.required_provenance_grades
    ):
        reasons.append("provenance grade insufficient")

    if (
        policy.deny_high_risk_without_approval
        and model.risk_score > policy.max_risk_without_approval
        and not model.human_approved
    ):
        reasons.append("high-risk approval required")

    if model.delegation_depth > policy.max_delegation_depth:
        reasons.append("delegation depth exceeded")

    if f"{model.capability}:{model.operation}" in policy.forbidden_transitions:
        reasons.append("forbidden transition")

    return PolicyDecision(
        allowed=not reasons,
        reasons=reasons,
    )


def default_model_space(policy: FormalPolicy) -> list[PolicyModel]:
    capabilities = sorted(policy.allowed_capabilities) or ["none"]
    operations = sorted(policy.allowed_operations) or ["none"]
    grades = sorted(
        policy.required_provenance_grades or frozenset(TrustGrade),
        key=lambda item: item.value,
    )
    risk_values = sorted(
        {
            0,
            max(0, policy.max_risk_without_approval - 1),
            policy.max_risk_without_approval,
            min(100, policy.max_risk_without_approval + 1),
            100,
        }
    )
    approvals = [False, True]
    depths = sorted(
        {
            0,
            policy.max_delegation_depth,
            min(64, policy.max_delegation_depth + 1),
        }
    )

    models: list[PolicyModel] = []
    for values in product(
        capabilities,
        operations,
        grades,
        risk_values,
        approvals,
        depths,
    ):
        capability, operation, grade, risk, approved, depth = values
        models.append(
            PolicyModel(
                subject="formal-enumeration",
                capability=capability,
                operation=operation,
                provenance_grade=grade,
                risk_score=risk,
                human_approved=approved,
                delegation_depth=depth,
            )
        )
        if len(models) >= 5000:
            break

    return models


def _canonical(
    policy: FormalPolicy,
    models: list[PolicyModel],
) -> bytes:
    payload = {
        "policy": policy.model_dump(mode="json"),
        "models": [model.model_dump(mode="json") for model in models],
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def verify_policy(
    policy: FormalPolicy,
    models: list[PolicyModel] | None = None,
) -> PolicyVerificationResult:
    selected = models if models is not None else default_model_space(policy)
    violations: list[str] = []

    # Structural contradictions are verification failures; correctly denied
    # states are expected and therefore are not failures.
    if policy.max_risk_without_approval < 0:
        violations.append("negative risk threshold")
    if policy.max_risk_without_approval > 100:
        violations.append("risk threshold exceeds 100")
    if policy.max_delegation_depth < 0:
        violations.append("negative delegation depth")

    for model in selected:
        decision = evaluate_policy_model(policy, model)
        if model.capability in policy.allowed_capabilities and (
            model.operation in policy.allowed_operations
        ):
            transition = f"{model.capability}:{model.operation}"
            if (
                policy.deny_high_risk_without_approval
                and model.risk_score > policy.max_risk_without_approval
                and not model.human_approved
                and decision.allowed
            ):
                violations.append(
                    f"{transition}: high-risk bypass invariant"
                )

    violations = sorted(set(violations))
    verification_hash = hashlib.sha256(
        _canonical(policy, selected)
        + b"|"
        + "|".join(violations).encode("utf-8")
    ).hexdigest()

    return PolicyVerificationResult(
        policy_id=policy.policy_id,
        policy_version=policy.version,
        valid=not violations,
        violations=violations,
        checked_models=len(selected),
        verification_hash=verification_hash,
    )
