"""AURAGENT Phase 14 — Enterprise API."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app.enterprise.contracts import (
    ComplianceFramework,
    CompliancePackageManifest,
    EnterprisePolicy,
    KeyPurpose,
    KeyDescriptor,
    RetentionPolicy,
    SIEMDestination,
    SSOConfiguration,
    TenantSecurityPosture,
)
from app.enterprise.service import EnterpriseService


router = APIRouter(
    prefix="/v1/enterprise",
    tags=["enterprise"],
)

_service = EnterpriseService()


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


def _role(request: Request) -> str:
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authenticated user required",
        )
    role = getattr(user, "role", None)
    return str(getattr(role, "value", role) or "").casefold()


def _require_admin(request: Request) -> UUID:
    tenant_id = _tenant_id(request)
    if _role(request) not in {"owner", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="enterprise administration requires owner/admin",
        )
    return tenant_id


class SSORequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    config: SSOConfiguration


class RetentionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy: RetentionPolicy


class SIEMRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destination: SIEMDestination


class RegionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy: EnterprisePolicy
    region: str = Field(min_length=1, max_length=64)


class RiskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy: EnterprisePolicy
    risk_score: int = Field(ge=0, le=100)
    human_approved: bool = False


@router.post("/sso/validate")
async def validate_sso(
    body: SSORequest,
    request: Request,
) -> dict[str, object]:
    tenant_id = _require_admin(request)
    if body.config.organization_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cross-tenant SSO configuration rejected",
        )
    try:
        binding = _service.validate_sso(body.config)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return {
        "valid": True,
        "organization_id": tenant_id,
        "trust_binding_sha256": binding,
    }


@router.post("/retention/validate")
async def validate_retention(
    body: RetentionRequest,
    request: Request,
) -> dict[str, object]:
    tenant_id = _require_admin(request)
    if body.policy.organization_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cross-tenant retention policy rejected",
        )
    try:
        policy = _service.validate_retention(body.policy)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return {
        "valid": True,
        "organization_id": tenant_id,
        "policy": policy.model_dump(mode="json"),
    }


@router.post("/siem/validate")
async def validate_siem(
    body: SIEMRequest,
    request: Request,
) -> dict[str, object]:
    tenant_id = _require_admin(request)
    if body.destination.organization_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cross-tenant SIEM destination rejected",
        )
    try:
        destination = _service.validate_siem(body.destination)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return {
        "valid": True,
        "organization_id": tenant_id,
        "destination_id": destination.destination_id,
    }


@router.post("/policy/region")
async def check_region(
    body: RegionRequest,
    request: Request,
) -> dict[str, object]:
    tenant_id = _require_admin(request)
    if body.policy.organization_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cross-tenant policy rejected",
        )
    decision = _service.region_policy(
        body.policy,
        body.region,
    )
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "organization_id": tenant_id,
    }


@router.post("/policy/high-risk")
async def check_high_risk(
    body: RiskRequest,
    request: Request,
) -> dict[str, object]:
    tenant_id = _require_admin(request)
    if body.policy.organization_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cross-tenant policy rejected",
        )
    try:
        _service.check_high_risk(
            body.policy,
            risk_score=body.risk_score,
            human_approved=body.human_approved,
        )
    except PermissionError as exc:
        return {
            "allowed": False,
            "reason": str(exc),
            "organization_id": tenant_id,
        }
    return {
        "allowed": True,
        "reason": "enterprise policy permits the action",
        "organization_id": tenant_id,
    }


@router.post("/keys/provision", response_model=KeyDescriptor)
async def provision_key(
    request: Request,
    purpose: KeyPurpose = Query(default=KeyPurpose.SIGNING),
) -> KeyDescriptor:
    tenant_id = _require_admin(request)
    return _service.provision_key_descriptor(
        organization_id=tenant_id,
        purpose=purpose,
    )


@router.get("/keys/digest")
async def keys_digest(request: Request) -> dict[str, object]:
    tenant_id = _require_admin(request)
    return {
        "organization_id": tenant_id,
        "inventory_sha256": _service.key_digest(tenant_id),
    }


@router.post(
    "/compliance/package",
    response_model=CompliancePackageManifest,
)
async def compliance_package(
    request: Request,
    framework: ComplianceFramework = Query(
        default=ComplianceFramework.SOC2
    ),
    evidence_count: int = Query(default=0, ge=0, le=1000000),
    evidence_types: list[str] | None = Query(default=None),
) -> CompliancePackageManifest:
    tenant_id = _require_admin(request)

    available_evidence = set(evidence_types or [])
    return _service.compliance_package(
        organization_id=tenant_id,
        framework=framework,
        available_evidence=available_evidence,
        evidence_count=evidence_count,
    )


@router.post("/posture", response_model=TenantSecurityPosture)
async def posture(
    request: Request,
    policy: EnterprisePolicy,
    retention: RetentionPolicy,
    sso_enabled: bool = Query(default=False),
    siem_enabled: bool = Query(default=False),
) -> TenantSecurityPosture:
    tenant_id = _require_admin(request)

    if policy.organization_id != tenant_id or retention.organization_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cross-tenant enterprise state rejected",
        )

    keys = _service.key_provider.list_keys(str(tenant_id))
    return _service.posture(
        organization_id=tenant_id,
        sso_enabled=sso_enabled,
        policy=policy,
        retention=retention,
        siem_enabled=siem_enabled,
        active_keys=keys,
    )
