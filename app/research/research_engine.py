"""Phase 15 evaluator composing ACA, provenance and policy invariants."""

from __future__ import annotations

from uuid import UUID

from .aca import conservation_check
from .containment import build_containment_plan
from .contracts import (
    AuthorityVector,
    FormalPolicy,
    PolicyModel,
    ProvenanceCondition,
    ResearchEvaluation,
    TrustGrade,
)
from .decision_proof import build_decision_proof
from .formal_policy import evaluate_policy_model, verify_policy
from .provenance_guard import provenance_allows


class ResearchEngine:
    """Reference evaluator; Phase 4 remains the production authority boundary."""

    @staticmethod
    def policy_hash(policy: FormalPolicy) -> str:
        import hashlib
        import json

        return hashlib.sha256(
            json.dumps(
                policy.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()

    @classmethod
    def evaluate_authority_transition(
        cls,
        *,
        tenant_id: UUID,
        trace_id: str,
        subject_id: str,
        parent: AuthorityVector,
        child: AuthorityVector,
        policy: FormalPolicy,
        provenance_grade: TrustGrade,
        provenance_sources: set[str],
        evidence_integrity_valid: bool,
        evidence_tenant_match: bool,
        human_approved: bool = False,
        risk_score: int = 0,
        severity: str = "low",
    ) -> ResearchEvaluation:
        conservation = conservation_check(parent, child)

        provenance_ok = provenance_allows(
            condition=ProvenanceCondition(
                min_trust_grade=TrustGrade.VERIFIED,
                require_integrity=True,
                require_tenant_match=True,
            ),
            trust_grade=provenance_grade,
            sources=provenance_sources,
            integrity_valid=evidence_integrity_valid,
            tenant_match=evidence_tenant_match,
        )

        model = PolicyModel(
            subject=subject_id,
            capability=next(iter(sorted(child.capabilities)), "none"),
            operation=next(iter(sorted(child.operations)), "none"),
            provenance_grade=provenance_grade,
            risk_score=risk_score,
            human_approved=human_approved,
            delegation_depth=child.delegation_depth,
        )

        policy_result = verify_policy(policy, [model])
        policy_decision = evaluate_policy_model(policy, model)

        allowed = (
            conservation.conserved
            and provenance_ok
            and policy_result.valid
            and policy_decision.allowed
        )

        containment = None
        if allowed:
            decision = "allow"
            reason = "ACA, provenance and formal policy checks passed"
        else:
            decision = "deny"
            reasons: list[str] = []
            if not conservation.conserved:
                reasons.extend(conservation.violations)
            if not provenance_ok:
                reasons.append("provenance conditions failed")
            if not policy_result.valid:
                reasons.extend(policy_result.violations)
            if not policy_decision.allowed:
                reasons.extend(policy_decision.reasons)

            reason = "; ".join(sorted(set(reasons)))
            containment = build_containment_plan(
                tenant_id=tenant_id,
                trace_id=trace_id,
                subject_id=subject_id,
                reason=reason,
                severity=severity,
                evidence_present=evidence_integrity_valid,
                authority_violation=not conservation.conserved,
                approval_bypass=(
                    risk_score > policy.max_risk_without_approval
                    and not human_approved
                ),
            )

        proof = build_decision_proof(
            tenant_id=tenant_id,
            trace_id=trace_id,
            subject_id=subject_id,
            policy_hash=cls.policy_hash(policy),
            authority_before=parent.model_dump(mode="json"),
            authority_after=child.model_dump(mode="json"),
            provenance={
                "grade": provenance_grade.value,
                "sources": sorted(provenance_sources),
                "integrity": evidence_integrity_valid,
                "tenant_match": evidence_tenant_match,
            },
            decision=decision,
            reason=reason,
            containment_mode=(
                containment.actions[0].mode
                if containment and containment.actions
                else None
            ),
        )

        return ResearchEvaluation(
            tenant_id=tenant_id,
            trace_id=trace_id,
            subject_id=subject_id,
            authority_conserved=conservation.conserved,
            provenance_satisfied=provenance_ok,
            policy_valid=policy_result.valid and policy_decision.allowed,
            containment=containment,
            decision_proof=proof,
            research_invariant=(
                "A_child <= A_parent unless explicitly authorized"
            ),
        )
