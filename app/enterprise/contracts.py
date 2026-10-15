"""Stable enterprise contracts for AURAGENT."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class SSOProtocol(StrEnum):
    SAML2 = "saml2"


class KeyPurpose(StrEnum):
    DATA_ENCRYPTION = "data-encryption"
    SIGNING = "signing"
    WEBHOOK = "webhook"


class SIEMFormat(StrEnum):
    JSON = "json"
    CEF = "cef"


class ComplianceFramework(StrEnum):
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci-dss"
    CUSTOM = "custom"


class SSOConfiguration(BaseModel):
    """Configuration metadata for an enterprise SSO trust."""

    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    protocol: SSOProtocol = SSOProtocol.SAML2
    issuer: str = Field(min_length=1, max_length=512)
    audience: str = Field(min_length=1, max_length=512)
    metadata_url: HttpUrl
    certificate_fingerprint_sha256: str = Field(
        min_length=64,
        max_length=64,
    )
    enabled: bool = False
    require_signed_assertions: bool = True
    require_encrypted_assertions: bool = False
    allowed_email_domains: list[str] = Field(default_factory=list)


class RetentionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    evidence_days: int = Field(default=365, ge=1, le=3650)
    audit_days: int = Field(default=365, ge=1, le=3650)
    security_event_days: int = Field(default=365, ge=1, le=3650)
    memory_days: int = Field(default=365, ge=1, le=3650)
    legal_hold: bool = False
    version: int = Field(default=1, ge=1)


class SIEMDestination(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destination_id: str = Field(min_length=1, max_length=128)
    organization_id: UUID
    endpoint: HttpUrl
    format: SIEMFormat = SIEMFormat.JSON
    enabled: bool = False
    certificate_fingerprint_sha256: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
    )
    include_payload: bool = False
    include_redacted_metadata: bool = True
    batch_size: int = Field(default=50, ge=1, le=500)
    timeout_seconds: int = Field(default=10, ge=1, le=30)


class KeyDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str = Field(min_length=1, max_length=128)
    organization_id: UUID
    purpose: KeyPurpose
    algorithm: str = Field(min_length=1, max_length=64)
    version: int = Field(default=1, ge=1)
    active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    external_key_reference: str | None = Field(default=None, max_length=512)
    public_material_fingerprint: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
    )


class ComplianceControl(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str = Field(min_length=1, max_length=128)
    framework: ComplianceFramework
    title: str
    description: str
    evidence_requirements: list[str] = Field(default_factory=list)
    enabled: bool = True


class EnterprisePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    enforce_sso: bool = False
    deny_public_integrations: bool = True
    require_human_approval_for_high_risk: bool = True
    max_session_minutes: int = Field(default=480, ge=5, le=1440)
    allowed_regions: list[str] = Field(default_factory=list)
    denied_regions: list[str] = Field(default_factory=list)
    minimum_tls_version: str = "1.2"
    require_evidence_for_actions: bool = True
    require_signed_ecosystem_manifests: bool = False
    version: int = Field(default=1, ge=1)


class TenantSecurityPosture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    sso_enabled: bool
    enforce_sso: bool
    evidence_retention_days: int
    audit_retention_days: int
    siem_enabled: bool
    active_signing_keys: int
    active_encryption_keys: int
    legal_hold: bool
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CompliancePackageManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    framework: ComplianceFramework
    generated_at: datetime
    control_count: int = Field(ge=0)
    satisfied_count: int = Field(ge=0)
    evidence_count: int = Field(ge=0)
    package_sha256: str = Field(min_length=64, max_length=64)


class SIEMEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    organization_id: UUID
    timestamp: datetime
    event_type: str
    severity: str
    trace_id: str | None = None
    actor_id: str | None = None
    outcome: str | None = None
    redacted_metadata: dict[str, Any] = Field(default_factory=dict)
    schema_version: str = "1"
