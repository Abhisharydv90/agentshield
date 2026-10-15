"""AURAGENT Phase 15 — Research / Invention Fabric."""

from .aca import AuthorityVector, ConservationResult, authority_distance, conservation_check
from .containment import ContainmentPlan, build_containment_plan
from .contracts import (
    ContainmentAction,
    ContainmentMode,
    FormalPolicy,
    MemoryTrustAssessment,
    PolicyModel,
    PolicyVerificationResult,
    ProvenanceCondition,
    ResearchDecisionProof,
    ResearchEvaluation,
    TrustGrade,
)
from .decision_proof import build_decision_proof
from .formal_policy import evaluate_policy_model, verify_policy
from .memory_trust import assess_memory_trust
from .provenance_guard import provenance_allows
from .research_engine import ResearchEngine

__all__ = [
    "AuthorityVector",
    "ConservationResult",
    "authority_distance",
    "conservation_check",
    "ContainmentPlan",
    "build_containment_plan",
    "ContainmentAction",
    "ContainmentMode",
    "FormalPolicy",
    "MemoryTrustAssessment",
    "PolicyModel",
    "PolicyVerificationResult",
    "ProvenanceCondition",
    "ResearchDecisionProof",
    "ResearchEvaluation",
    "TrustGrade",
    "build_decision_proof",
    "evaluate_policy_model",
    "verify_policy",
    "assess_memory_trust",
    "provenance_allows",
    "ResearchEngine",
]
