"""Phase 14 Enterprise service facade."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from .compliance import default_controls, package_manifest
from .contracts import (
    ComplianceFramework,
    CompliancePackageManifest,
    EnterprisePolicy,
    KeyDescriptor,
    RetentionPolicy,
    SSOConfiguration,
    SIEMDestination,
    TenantSecurityPosture,
)
from .keys import InMemoryKeyProvider, key_inventory_digest
from .policies import evaluate_region, require_high_risk_approval, require_sso
from .retention import validate_retention_policy
from .siem import validate_destination
from .sso import trust_binding_digest, validate_sso_configuration


class EnterpriseService:
    """Enterprise boundary that composes security controls without minting authority."""

    def __init__(
        self,
        *,
        key_provider: InMemoryKeyProvider | None = None,
    ) -> None:
        self.key_provider = key_provider or InMemoryKeyProvider()

    @staticmethod
    def validate_sso(config: SSOConfiguration) -> str:
        return trust_binding_digest(validate_sso_configuration(config))

    @staticmethod
    def validate_retention(policy: RetentionPolicy) -> RetentionPolicy:
        validate_retention_policy(policy)
        return policy

    @staticmethod
    def validate_siem(destination: SIEMDestination) -> SIEMDestination:
        return validate_destination(destination)

    @staticmethod
    def region_policy(
        policy: EnterprisePolicy,
        region: str,
    ):
        return evaluate_region(policy, region)

    @staticmethod
    def check_sso(
        policy: EnterprisePolicy,
        *,
        authenticated_by_sso: bool,
    ) -> None:
        require_sso(
            policy,
            sso_authenticated=authenticated_by_sso,
        )

    @staticmethod
    def check_high_risk(
        policy: EnterprisePolicy,
        *,
        risk_score: int,
        human_approved: bool,
    ) -> None:
        require_high_risk_approval(
            policy,
            risk_score=risk_score,
            has_human_approval=human_approved,
        )

    def provision_key_descriptor(
        self,
        *,
        organization_id: UUID,
        purpose,
    ) -> KeyDescriptor:
        return self.key_provider.create_key(
            organization_id=str(organization_id),
            purpose=purpose,
        )

    def key_digest(self, organization_id: UUID) -> str:
        return key_inventory_digest(
            self.key_provider.list_keys(str(organization_id))
        )

    @staticmethod
    def compliance_package(
        *,
        organization_id: UUID,
        framework: ComplianceFramework,
        available_evidence: set[str],
        evidence_count: int,
    ) -> CompliancePackageManifest:
        controls = default_controls(framework)
        return package_manifest(
            organization_id=organization_id,
            framework=framework,
            controls=controls,
            available_evidence=available_evidence,
            evidence_count=evidence_count,
        )

    @staticmethod
    def posture(
        *,
        organization_id: UUID,
        sso_enabled: bool,
        policy: EnterprisePolicy,
        retention: RetentionPolicy,
        siem_enabled: bool,
        active_keys: list[KeyDescriptor],
    ) -> TenantSecurityPosture:
        return TenantSecurityPosture(
            organization_id=organization_id,
            sso_enabled=sso_enabled,
            enforce_sso=policy.enforce_sso,
            evidence_retention_days=retention.evidence_days,
            audit_retention_days=retention.audit_days,
            siem_enabled=siem_enabled,
            active_signing_keys=sum(
                1
                for key in active_keys
                if key.active and key.purpose.value == "signing"
            ),
            active_encryption_keys=sum(
                1
                for key in active_keys
                if key.active and key.purpose.value == "data-encryption"
            ),
            legal_hold=retention.legal_hold,
        )
