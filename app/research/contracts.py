"""Research-layer contracts that never mint runtime authority."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TrustGrade(StrEnum):
    UNTRUSTED = "untrusted"
    OBSERVED = "observed"
    VERIFIED = "verified"
    ATTESTED = "attested"


class ContainmentMode(StrEnum):
    OBSERVE = "observe"
    QUARANTINE = "quarantine"
    REVOKE_DELEGATION = "revoke-delegation"
    DISABLE_TOOL = "disable-tool"
    ISOLATE_WORKLOAD = "isolate-workload"
    REQUIRE_HUMAN = "require-human"


class AuthorityVector(BaseModel):
    """Research representation of authority as a partially ordered vector."""

    model_config = ConfigDict(extra="forbid")

    capabilities: frozenset[str] = frozenset()
    operations: frozenset[str] = frozenset()
    resources: frozenset[str] = frozenset()
    data_scopes: frozenset[str] = frozenset()
    network_scopes: frozenset[str] = frozenset()
    delegation_depth: int = Field(default=0, ge=0, le=64)
    risk_ceiling: int = Field(default=100, ge=0, le=100)


class ProvenanceCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_trust_grade: TrustGrade = TrustGrade.OBSERVED
    required_sources: frozenset[str] = frozenset()
    max_age_seconds: int | None = Field(default=None, ge=1, le=31536000)
    require_integrity: bool = True
    require_tenant_match: bool = True


class MemoryTrustAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    memory_id: UUID
    tenant_id: UUID
    content_sha256: str = Field(min_length=64, max_length=64)
    integrity_valid: bool
    provenance_valid: bool
    poisoning_suspected: bool
    trust_grade: TrustGrade
    authority_effect: str = "none"
    reasons: list[str] = Field(default_factory=list)


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str
    capability: str
    operation: str
    provenance_grade: TrustGrade
    risk_score: int = Field(ge=0, le=100)
    human_approved: bool = False
    delegation_depth: int = Field(default=0, ge=0, le=64)


class FormalPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=128)
    version: int = Field(default=1, ge=1)
    allowed_capabilities: frozenset[str] = frozenset()
    allowed_operations: frozenset[str] = frozenset()
    required_provenance_grades: frozenset[TrustGrade] = frozenset()
    deny_high_risk_without_approval: bool = True
    max_risk_without_approval: int = Field(default=65, ge=0, le=100)
    max_delegation_depth: int = Field(default=4, ge=0, le=64)
    forbidden_transitions: frozenset[str] = frozenset()


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reasons: list[str] = Field(default_factory=list)


class PolicyVerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str
    policy_version: int
    valid: bool
    violations: list[str] = Field(default_factory=list)
    checked_models: int = Field(ge=0)
    verification_hash: str = Field(min_length=64, max_length=64)


class ContainmentAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: ContainmentMode
    subject_id: str
    reason: str
    requires_human_approval: bool
    reversible: bool
    evidence_required: bool = True


class ContainmentPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: UUID
    tenant_id: UUID
    trace_id: str
    actions: list[ContainmentAction]
    trigger: str
    autonomous_execution_allowed: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    plan_hash: str = Field(min_length=64, max_length=64)


class ResearchDecisionProof(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proof_id: UUID
    tenant_id: UUID
    trace_id: str = Field(min_length=1, max_length=128)
    subject_id: str = Field(min_length=1, max_length=256)
    policy_hash: str = Field(min_length=64, max_length=64)
    authority_before_hash: str = Field(min_length=64, max_length=64)
    authority_after_hash: str = Field(min_length=64, max_length=64)
    provenance_hash: str = Field(min_length=64, max_length=64)
    decision: str
    reason: str
    containment_mode: ContainmentMode | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    proof_hash: str = Field(min_length=64, max_length=64)
    executable: bool = False


class ResearchEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: UUID
    trace_id: str
    subject_id: str
    authority_conserved: bool
    provenance_satisfied: bool
    policy_valid: bool
    containment: ContainmentPlan | None
    decision_proof: ResearchDecisionProof
    research_invariant: str
