"""Phase 14 Enterprise Fabric deterministic boundary tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import HttpUrl

from app.enterprise.compliance import (
    ComplianceFramework,
    control_satisfaction,
    default_controls,
    package_manifest,
)
from app.enterprise.contracts import (
    EnterprisePolicy,
    KeyPurpose,
    RetentionPolicy,
    SIEMDestination,
    SIEMFormat,
    SSOConfiguration,
)
from app.enterprise.keys import InMemoryKeyProvider, key_inventory_digest, rotation_due
from app.enterprise.policies import (
    EnterprisePolicyDenied,
    evaluate_region,
    require_high_risk_approval,
    require_sso,
)
from app.enterprise.retention import (
    expiry_for,
    should_expire,
    validate_retention_policy,
)
from app.enterprise.siem import (
    SIEMPolicyError,
    build_batch,
    export_contains_only_redacted_keys,
    validate_destination,
)
from app.enterprise.sso import (
    SSOConfigurationError,
    trust_binding_digest,
    validate_sso_configuration,
)


TENANT = UUID("11111111-1111-1111-1111-111111111111")


def sso() -> SSOConfiguration:
    return SSOConfiguration(
        organization_id=TENANT,
        issuer="https://idp.example/issuer",
        audience="auragent",
        metadata_url=HttpUrl("https://idp.example/metadata"),
        certificate_fingerprint_sha256="a" * 64,
    )


def retention() -> RetentionPolicy:
    return RetentionPolicy(
        organization_id=TENANT,
        evidence_days=365,
        audit_days=365,
        security_event_days=365,
        memory_days=180,
    )


def test_sso_validation_requires_https():
    validated = validate_sso_configuration(sso())
    assert validated.certificate_fingerprint_sha256 == "a" * 64
    assert len(trust_binding_digest(validated)) == 64


def test_sso_rejects_embedded_url_credentials():
    config = sso().model_copy(
        update={"metadata_url": HttpUrl("https://u:p@idp.example/metadata")}
    )
    with pytest.raises(SSOConfigurationError):
        validate_sso_configuration(config)


def test_retention_legal_hold_prevents_expiry():
    now = datetime.now(timezone.utc)
    created = now - timedelta(days=1000)
    assert not should_expire(
        created,
        now=now,
        retention_days=1,
        legal_hold=True,
    )


def test_retention_expires_after_window():
    now = datetime.now(timezone.utc)
    created = now - timedelta(days=366)
    assert should_expire(
        created,
        now=now,
        retention_days=365,
        legal_hold=False,
    )


def test_retention_policy_validates():
    policy = retention()
    validate_retention_policy(policy)
    assert expiry_for(
        datetime.now(timezone.utc),
        retention_days=365,
        legal_hold=False,
    ) is not None


def test_siem_rejects_cross_tenant_events():
    destination = SIEMDestination(
        destination_id="siem-1",
        organization_id=TENANT,
        endpoint=HttpUrl("https://siem.example/ingest"),
    )

    from app.enterprise.contracts import SIEMEvent

    event = SIEMEvent(
        event_id=UUID("22222222-2222-2222-2222-222222222222"),
        organization_id=UUID("33333333-3333-3333-3333-333333333333"),
        timestamp=datetime.now(timezone.utc),
        event_type="test",
        severity="low",
    )
    with pytest.raises(SIEMPolicyError):
        build_batch(destination, [event])


def test_siem_batch_is_redacted_and_bounded():
    destination = SIEMDestination(
        destination_id="siem-1",
        organization_id=TENANT,
        endpoint=HttpUrl("https://siem.example/ingest"),
        format=SIEMFormat.JSON,
    )
    from app.enterprise.contracts import SIEMEvent

    event = SIEMEvent(
        event_id=UUID("22222222-2222-2222-2222-222222222222"),
        organization_id=TENANT,
        timestamp=datetime.now(timezone.utc),
        event_type="blocked",
        severity="high",
        redacted_metadata={"reason": "policy"},
    )
    batch = build_batch(destination, [event])
    assert batch.content_type == "application/json"
    assert export_contains_only_redacted_keys(event)


def test_siem_rejects_http_destination():
    destination = SIEMDestination(
        destination_id="siem-1",
        organization_id=TENANT,
        endpoint=HttpUrl("http://siem.example/ingest"),
    )
    with pytest.raises(SIEMPolicyError):
        validate_destination(destination)


def test_key_provider_never_exposes_raw_key_bytes():
    provider = InMemoryKeyProvider()
    key = provider.create_key(
        organization_id=str(TENANT),
        purpose=KeyPurpose.SIGNING,
    )
    assert key.external_key_reference is None
    assert key.public_material_fingerprint
    assert "secret" not in repr(key).casefold()


def test_key_inventory_digest_is_deterministic():
    provider = InMemoryKeyProvider()
    provider.create_key(
        organization_id=str(TENANT),
        purpose=KeyPurpose.SIGNING,
    )
    keys = provider.list_keys(str(TENANT))
    assert key_inventory_digest(keys) == key_inventory_digest(keys)
    assert len(key_inventory_digest(keys)) == 64


def test_rotation_due_is_deterministic():
    provider = InMemoryKeyProvider()
    key = provider.create_key(
        organization_id=str(TENANT),
        purpose=KeyPurpose.SIGNING,
    )
    future = key.created_at + timedelta(days=366)
    assert rotation_due(key, now=future, max_age_days=365)


def test_region_policy_fails_for_denied_region():
    policy = EnterprisePolicy(
        organization_id=TENANT,
        denied_regions=["restricted"],
    )
    decision = evaluate_region(policy, "restricted")
    assert decision.allowed is False


def test_high_risk_policy_requires_approval():
    policy = EnterprisePolicy(
        organization_id=TENANT,
        require_human_approval_for_high_risk=True,
    )
    with pytest.raises(EnterprisePolicyDenied):
        require_high_risk_approval(
            policy,
            risk_score=90,
            has_human_approval=False,
        )


def test_sso_policy_requires_sso():
    policy = EnterprisePolicy(
        organization_id=TENANT,
        enforce_sso=True,
    )
    with pytest.raises(EnterprisePolicyDenied):
        require_sso(policy, sso_authenticated=False)


def test_compliance_controls_are_explicit():
    controls = default_controls(ComplianceFramework.SOC2)
    satisfied = control_satisfaction(
        controls,
        {
            "audit_chain",
            "evidence_graph",
            "rbac",
            "policy_decisions",
            "tenant_scope",
            "retention_policy",
            "key_inventory",
        },
    )
    assert controls
    assert all(satisfied.values())


def test_compliance_manifest_hash_is_stable():
    controls = default_controls(ComplianceFramework.SOC2)
    first = package_manifest(
        organization_id=TENANT,
        framework=ComplianceFramework.SOC2,
        controls=controls,
        available_evidence={"audit_chain"},
        evidence_count=1,
    )
    second = package_manifest(
        organization_id=TENANT,
        framework=ComplianceFramework.SOC2,
        controls=controls,
        available_evidence={"audit_chain"},
        evidence_count=1,
    )
    assert first.package_sha256 == second.package_sha256
