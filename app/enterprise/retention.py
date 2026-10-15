"""Enterprise retention and legal-hold decisions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .contracts import RetentionPolicy


class RetentionPolicyError(ValueError):
    pass


def validate_retention_policy(policy: RetentionPolicy) -> None:
    if policy.evidence_days < policy.audit_days // 10:
        # Prevent obviously inconsistent configurations that would retain only
        # a tiny evidence window while preserving a much longer audit window.
        raise RetentionPolicyError(
            "evidence retention is unexpectedly shorter than audit retention"
        )


def expiry_for(
    created_at: datetime,
    *,
    retention_days: int,
    legal_hold: bool,
) -> datetime | None:
    if legal_hold:
        return None
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return created_at + timedelta(days=retention_days)


def should_expire(
    created_at: datetime,
    *,
    now: datetime,
    retention_days: int,
    legal_hold: bool,
) -> bool:
    expiry = expiry_for(
        created_at,
        retention_days=retention_days,
        legal_hold=legal_hold,
    )
    if expiry is None:
        return False
    return now >= expiry
