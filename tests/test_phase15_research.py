"""Phase 15 Research / Invention deterministic boundary tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from app.research.aca import authority_distance, conservation_check
from app.research.containment import build_containment_plan
from app.research.contracts import (
    AuthorityVector,
    FormalPolicy,
    PolicyModel,
    ProvenanceCondition,
    TrustGrade,
)
from app.research.decision_proof import build_decision_proof
from app.research.formal_policy import (
    evaluate_policy_model,
    verify_policy,
)
from app.research.memory_trust import assess_memory_trust
from app.research.provenance_guard import provenance_allows
from app.research.research_engine import ResearchEngine


TENANT = UUID("11111111-1111-1111-1111-111111111111")


def parent() -> AuthorityVector:
    return AuthorityVector(
        capabilities=frozenset({"tool:read", "memory:read"}),
        operations=frozenset({"inspect", "search"}),
        resources=frozenset({"repo"}),
        data_scopes=frozenset({"public"}),
        network_scopes=frozenset({"api.example.com"}),
        delegation_depth=3,
        risk_ceiling=60,
    )


def reduced_child() -> AuthorityVector:
    return AuthorityVector(
        capabilities=frozenset({"tool:read"}),
        operations=frozenset({"inspect"}),
        resources=frozenset({"repo"}),
        data_scopes=frozenset({"public"}),
        network_scopes=frozenset({"api.example.com"}),
        delegation_depth=2,
        risk_ceiling=50,
    )


def policy() -> FormalPolicy:
    return FormalPolicy(
        policy_id="research-test",
        allowed_capabilities=frozenset({"tool:read"}),
        allowed_operations=frozenset({"inspect"}),
        required_provenance_grades=frozenset(
            {TrustGrade.VERIFIED, TrustGrade.ATTESTED}
        ),
        deny_high_risk_without_approval=True,
        max_risk_without_approval=65,
        max_delegation_depth=3,
    )


def test_authority_is_conserved_for_reduced_child():
    result = conservation_check(parent(), reduced_child())
    assert result.conserved
    assert authority_distance(parent(), reduced_child()) > 0


def test_authority_escalation_is_rejected():
    child = parent().model_copy(
        update={
            "capabilities": frozenset(
                {"tool:read", "tool:write"}
            ),
            "risk_ceiling": 90,
        }
    )
    result = conservation_check(parent(), child)
    assert not result.conserved
    assert "capabilities increased" in result.violations
    assert "risk ceiling increased" in result.violations


def test_provenance_condition_requires_integrity_and_source():
    condition = ProvenanceCondition(
        min_trust_grade=TrustGrade.VERIFIED,
        required_sources=frozenset({"signed-source"}),
        require_integrity=True,
        require_tenant_match=True,
    )
    assert provenance_allows(
        condition=condition,
        trust_grade=TrustGrade.ATTESTED,
        sources={"signed-source"},
        integrity_valid=True,
        tenant_match=True,
    )
    assert not provenance_allows(
        condition=condition,
        trust_grade=TrustGrade.OBSERVED,
        sources={"signed-source"},
        integrity_valid=True,
        tenant_match=True,
    )


def test_memory_never_grants_authority():
    memory = assess_memory_trust(
        memory_id=UUID("22222222-2222-2222-2222-222222222222"),
        tenant_id=TENANT,
        content_sha256="a" * 64,
        expected_sha256="a" * 64,
        provenance_grade=TrustGrade.VERIFIED,
        provenance_sources={"source"},
        integrity_valid=True,
        poisoning_suspected=False,
        source_tenant_id=TENANT,
    )
    assert memory.integrity_valid
    assert memory.provenance_valid
    assert memory.authority_effect == "none"


def test_formal_policy_verification_is_stable():
    first = verify_policy(policy())
    second = verify_policy(policy())
    assert first.valid
    assert first.verification_hash == second.verification_hash
    assert first.checked_models > 0


def test_high_risk_without_approval_is_denied_not_misclassified():
    model = PolicyModel(
        subject="agent",
        capability="tool:read",
        operation="inspect",
        provenance_grade=TrustGrade.VERIFIED,
        risk_score=90,
        human_approved=False,
    )
    decision = evaluate_policy_model(policy(), model)
    assert not decision.allowed
    assert "high-risk approval required" in decision.reasons


def test_containment_is_non_executable():
    plan = build_containment_plan(
        tenant_id=TENANT,
        trace_id="trace-1",
        subject_id="agent-1",
        reason="authority violation",
        severity="critical",
        evidence_present=True,
        authority_violation=True,
    )
    assert plan is not None
    assert plan.autonomous_execution_allowed is False
    assert any(
        action.mode.value == "revoke-delegation"
        for action in plan.actions
    )


def test_decision_proof_is_non_executable():
    proof = build_decision_proof(
        tenant_id=TENANT,
        trace_id="trace-1",
        subject_id="agent-1",
        policy_hash="b" * 64,
        authority_before=parent().model_dump(mode="json"),
        authority_after=reduced_child().model_dump(mode="json"),
        provenance={"grade": "verified"},
        decision="allow",
        reason="test",
    )
    assert proof.executable is False
    assert len(proof.proof_hash) == 64


def test_research_engine_allows_conserved_verified_case():
    result = ResearchEngine.evaluate_authority_transition(
        tenant_id=TENANT,
        trace_id="trace-1",
        subject_id="agent-1",
        parent=parent(),
        child=reduced_child(),
        policy=policy(),
        provenance_grade=TrustGrade.VERIFIED,
        provenance_sources={"source"},
        evidence_integrity_valid=True,
        evidence_tenant_match=True,
        risk_score=20,
        severity="low",
    )
    assert result.authority_conserved
    assert result.provenance_satisfied
    assert result.policy_valid
    assert result.decision_proof.decision == "allow"


def test_research_engine_denies_authority_escalation():
    child = parent().model_copy(
        update={
            "capabilities": frozenset(
                {"tool:read", "tool:write"}
            ),
            "operations": frozenset(
                {"inspect", "write"}
            ),
            "risk_ceiling": 90,
        }
    )
    result = ResearchEngine.evaluate_authority_transition(
        tenant_id=TENANT,
        trace_id="trace-2",
        subject_id="agent-2",
        parent=parent(),
        child=child,
        policy=policy(),
        provenance_grade=TrustGrade.OBSERVED,
        provenance_sources=set(),
        evidence_integrity_valid=True,
        evidence_tenant_match=True,
        risk_score=90,
        severity="critical",
    )
    assert not result.authority_conserved
    assert not result.provenance_satisfied
    assert result.containment is not None
    assert result.decision_proof.decision == "deny"
    assert result.decision_proof.executable is False


def test_policy_rejects_unauthorized_operation_model():
    model = PolicyModel(
        subject="agent",
        capability="tool:read",
        operation="write",
        provenance_grade=TrustGrade.VERIFIED,
        risk_score=1,
    )
    decision = evaluate_policy_model(policy(), model)
    assert not decision.allowed
    assert "operation outside allowlist" in decision.reasons


def test_provenance_age_can_expire():
    old = datetime.now(timezone.utc) - timedelta(seconds=120)
    assert not provenance_allows(
        condition=ProvenanceCondition(
            min_trust_grade=TrustGrade.VERIFIED,
            max_age_seconds=60,
        ),
        trust_grade=TrustGrade.VERIFIED,
        sources=set(),
        integrity_valid=True,
        tenant_match=True,
        created_at=old,
    )


@pytest.mark.parametrize(
    "grade",
    [TrustGrade.UNTRUSTED, TrustGrade.OBSERVED],
)
def test_low_provenance_never_satisfies_verified_requirement(grade):
    assert not provenance_allows(
        condition=ProvenanceCondition(
            min_trust_grade=TrustGrade.VERIFIED,
        ),
        trust_grade=grade,
        sources=set(),
        integrity_valid=True,
        tenant_match=True,
    )
