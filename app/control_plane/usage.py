"""Provider-neutral usage aggregation over RequestLog."""
from __future__ import annotations
from datetime import datetime
from typing import Iterable
from uuid import UUID
from .contracts import UsageSummary


def summarize_request_logs(
    *, organization_id: UUID, rows: Iterable[object], since: datetime | None
) -> UsageSummary:
    request_count = blocked = approved = denied = 0
    for row in rows:
        request_count += 1
        decision = str(
            getattr(row, "decision", getattr(row, "outcome", "")) or ""
        ).casefold()
        if decision in {"blocked", "block"}:
            blocked += 1
        elif decision in {"approved", "allow", "allowed"}:
            approved += 1
        elif decision in {"denied", "deny"}:
            denied += 1
    return UsageSummary(
        organization_id=organization_id,
        since=since,
        request_count=request_count,
        blocked_count=blocked,
        approved_count=approved,
        denied_count=denied,
        estimated_usage_units=request_count,
    )
