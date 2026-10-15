"""Trusted-memory assessment over the existing Phase 6 memory boundary."""

from __future__ import annotations

from uuid import UUID

from .contracts import MemoryTrustAssessment, ProvenanceCondition, TrustGrade
from .provenance_guard import provenance_allows


_RANK = {
    TrustGrade.UNTRUSTED: 0,
    TrustGrade.OBSERVED: 1,
    TrustGrade.VERIFIED: 2,
    TrustGrade.ATTESTED: 3,
}


def assess_memory_trust(
    *,
    memory_id: UUID,
    tenant_id: UUID,
    content_sha256: str,
    expected_sha256: str,
    provenance_grade: TrustGrade,
    provenance_sources: set[str],
    integrity_valid: bool,
    poisoning_suspected: bool,
    source_tenant_id: UUID | None,
    required_sources: set[str] | None = None,
    max_age_valid: bool = True,
) -> MemoryTrustAssessment:
    integrity = (
        integrity_valid
        and len(content_sha256) == 64
        and content_sha256 == expected_sha256
    )
    tenant_match = source_tenant_id is None or source_tenant_id == tenant_id

    condition = ProvenanceCondition(
        min_trust_grade=TrustGrade.VERIFIED,
        required_sources=frozenset(required_sources or set()),
        require_integrity=True,
        require_tenant_match=True,
    )

    provenance_valid = provenance_allows(
        condition=condition,
        trust_grade=provenance_grade,
        sources=provenance_sources,
        integrity_valid=integrity,
        tenant_match=tenant_match,
    ) and max_age_valid

    reasons: list[str] = []
    if not integrity:
        reasons.append("content integrity check failed")
    if not provenance_valid:
        reasons.append("provenance conditions were not satisfied")
    if poisoning_suspected:
        reasons.append("poisoning was suspected")
    if not tenant_match:
        reasons.append("tenant provenance mismatch")
    if not reasons:
        reasons.append("memory passed configured trust checks")

    if poisoning_suspected or not integrity:
        final_grade = TrustGrade.UNTRUSTED
    else:
        final_grade = min(
            provenance_grade,
            TrustGrade.VERIFIED,
            key=lambda item: _RANK[item],
        )

    return MemoryTrustAssessment(
        memory_id=memory_id,
        tenant_id=tenant_id,
        content_sha256=content_sha256,
        integrity_valid=integrity,
        provenance_valid=provenance_valid,
        poisoning_suspected=poisoning_suspected,
        trust_grade=final_grade,
        authority_effect="none",
        reasons=reasons,
    )
