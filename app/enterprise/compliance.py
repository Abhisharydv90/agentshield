"""Framework-neutral compliance control evaluation."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Iterable
from uuid import UUID

from .contracts import (
    ComplianceControl,
    ComplianceFramework,
    CompliancePackageManifest,
)


def default_controls(
    framework: ComplianceFramework,
) -> list[ComplianceControl]:
    common = [
        ComplianceControl(
            control_id="AUDIT-001",
            framework=framework,
            title="Tamper-evident audit",
            description="Security-sensitive activity is recorded through the evidence/audit fabric.",
            evidence_requirements=["audit_chain", "evidence_graph"],
        ),
        ComplianceControl(
            control_id="AUTH-001",
            framework=framework,
            title="Access control",
            description="Administrative access is restricted through authenticated roles and policy.",
            evidence_requirements=["rbac", "policy_decisions"],
        ),
        ComplianceControl(
            control_id="TENANT-001",
            framework=framework,
            title="Tenant isolation",
            description="Enterprise data access is tenant scoped.",
            evidence_requirements=["tenant_scope"],
        ),
        ComplianceControl(
            control_id="RET-001",
            framework=framework,
            title="Retention policy",
            description="Retention and legal hold controls are explicit.",
            evidence_requirements=["retention_policy"],
        ),
        ComplianceControl(
            control_id="KEY-001",
            framework=framework,
            title="Key management",
            description="Cryptographic keys are represented by external references or descriptors, not raw key material.",
            evidence_requirements=["key_inventory"],
        ),
    ]
    return common


def control_satisfaction(
    controls: Iterable[ComplianceControl],
    available_evidence: set[str],
) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for control in controls:
        result[control.control_id] = all(
            requirement in available_evidence
            for requirement in control.evidence_requirements
        )
    return result


def package_manifest(
    *,
    organization_id: UUID,
    framework: ComplianceFramework,
    controls: list[ComplianceControl],
    available_evidence: set[str],
    evidence_count: int,
) -> CompliancePackageManifest:
    satisfaction = control_satisfaction(
        controls,
        available_evidence,
    )
    satisfied = sum(1 for value in satisfaction.values() if value)

    canonical = json.dumps(
        {
            "organization_id": str(organization_id),
            "framework": framework.value,
            "controls": [
                control.model_dump(mode="json")
                for control in controls
            ],
            "available_evidence": sorted(available_evidence),
            "evidence_count": evidence_count,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

    return CompliancePackageManifest(
        organization_id=organization_id,
        framework=framework,
        generated_at=datetime.now(timezone.utc),
        control_count=len(controls),
        satisfied_count=satisfied,
        evidence_count=evidence_count,
        package_sha256=hashlib.sha256(canonical).hexdigest(),
    )
