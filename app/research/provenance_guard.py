"""Provenance-conditioned authorization research primitive."""

from __future__ import annotations

from datetime import datetime, timezone

from .contracts import ProvenanceCondition, TrustGrade


_RANK = {
    TrustGrade.UNTRUSTED: 0,
    TrustGrade.OBSERVED: 1,
    TrustGrade.VERIFIED: 2,
    TrustGrade.ATTESTED: 3,
}


def provenance_allows(
    *,
    condition: ProvenanceCondition,
    trust_grade: TrustGrade,
    sources: set[str],
    integrity_valid: bool,
    tenant_match: bool,
    created_at: datetime | None = None,
    now: datetime | None = None,
) -> bool:
    if _RANK[trust_grade] < _RANK[condition.min_trust_grade]:
        return False

    if not condition.required_sources.issubset(sources):
        return False

    if condition.require_integrity and not integrity_valid:
        return False

    if condition.require_tenant_match and not tenant_match:
        return False

    if condition.max_age_seconds is not None:
        if created_at is None:
            return False
        current = now or datetime.now(timezone.utc)
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        age = (current - created_at).total_seconds()
        if age < 0 or age > condition.max_age_seconds:
            return False

    return True
