"""AURAGENT Phase 15 Research / Invention API."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app.research.contracts import (
    AuthorityVector,
    FormalPolicy,
    PolicyVerificationResult,
    ResearchEvaluation,
    TrustGrade,
)
from app.research.formal_policy import verify_policy
from app.research.research_engine import ResearchEngine


router = APIRouter(
    prefix="/v1/research",
    tags=["research"],
)


def _tenant_id(request: Request) -> UUID:
    tenant = getattr(request.state, "tenant", None)
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )

    value = getattr(tenant, "tenant_id", tenant)
    try:
        return UUID(str(value))
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid tenant context",
        ) from exc


def _require_admin(request: Request) -> UUID:
    tenant_id = _tenant_id(request)
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authenticated user required",
        )

    role = getattr(user, "role", None)
    normalized = str(getattr(role, "value", role) or "").casefold()
    if normalized not in {"owner", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="research controls require owner/admin",
        )

    return tenant_id


class EvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str = Field(min_length=1, max_length=128)
    subject_id: str = Field(min_length=1, max_length=256)
    parent_authority: AuthorityVector
    child_authority: AuthorityVector
    policy: FormalPolicy
    provenance_grade: TrustGrade
    provenance_sources: set[str] = Field(default_factory=set)
    evidence_integrity_valid: bool
    evidence_tenant_match: bool
    human_approved: bool = False
    risk_score: int = Field(default=0, ge=0, le=100)
    severity: str = Field(default="low", min_length=1, max_length=16)


class PolicyVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy: FormalPolicy


@router.post("/evaluate", response_model=ResearchEvaluation)
async def evaluate(
    body: EvaluationRequest,
    request: Request,
) -> ResearchEvaluation:
    tenant_id = _require_admin(request)

    return ResearchEngine.evaluate_authority_transition(
        tenant_id=tenant_id,
        trace_id=body.trace_id,
        subject_id=body.subject_id,
        parent=body.parent_authority,
        child=body.child_authority,
        policy=body.policy,
        provenance_grade=body.provenance_grade,
        provenance_sources=set(body.provenance_sources),
        evidence_integrity_valid=body.evidence_integrity_valid,
        evidence_tenant_match=body.evidence_tenant_match,
        human_approved=body.human_approved,
        risk_score=body.risk_score,
        severity=body.severity,
    )


@router.post(
    "/verify-policy",
    response_model=PolicyVerificationResult,
)
async def verify_policy_endpoint(
    body: PolicyVerificationRequest,
    request: Request,
) -> PolicyVerificationResult:
    _require_admin(request)
    return verify_policy(body.policy)


@router.get("/invariants")
async def invariants(request: Request) -> dict[str, object]:
    _require_admin(request)
    return {
        "authority_conservation": (
            "A_child <= A_parent unless explicitly authorized"
        ),
        "identity_authority_separation": True,
        "authority_influence_separation": True,
        "influence_evidence_separation": True,
        "memory_never_grants_authority": True,
        "provenance_conditioned_authorization": True,
        "decision_proofs_are_evidence": True,
        "containment_default": "non-executable plan",
        "production_authority_owner": "Phase 4 Trust Kernel",
    }
