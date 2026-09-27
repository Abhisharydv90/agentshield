"""
Tamper-evident audit log with per-tenant hash chaining.

Every event's record_hash is:
    SHA-256(prev_hash || canonical_json(payload))

Timestamps are always normalized to UTC before hashing so that reading
the row back from Postgres (which returns tz-aware datetimes) produces
the same ISO string that was hashed at write time.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import SecurityEvent


# ============================================================
# Canonicalization helpers
# ============================================================

def canonical_timestamp(ts: datetime) -> str:
    """
    Return a UTC ISO-8601 string with explicit +00:00 offset.

    Naive datetimes are assumed to be UTC. Aware datetimes are converted
    to UTC. Output is always identical for the same instant, regardless
    of whether it was written naive or read back tz-aware from Postgres.
    """
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    else:
        ts = ts.astimezone(timezone.utc)
    return ts.isoformat()


def compute_hash(prev_hash: str | None, payload: dict) -> str:
    """SHA-256 of prev_hash || canonical JSON payload."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if prev_hash:
        body = prev_hash.encode("utf-8") + body
    return hashlib.sha256(body).hexdigest()


# ============================================================
# Write
# ============================================================

async def write_event(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    request_id: str | None,
    threat_category: str,
    action_taken: str,
    evaluator_reasoning: str = "",
) -> SecurityEvent:
    """
    Append a new event to the tenant's hash chain.

    The chain is scoped per tenant — different tenants' events never
    interleave. Chain integrity is verified by `verify_chain()`.
    """
    # 1. Get the previous record_hash FOR THIS TENANT
    stmt = (
        select(SecurityEvent.record_hash)
        .where(SecurityEvent.tenant_id == tenant_id)
        .order_by(desc(SecurityEvent.timestamp))
        .limit(1)
    )
    prev_hash = (await session.execute(stmt)).scalar_one_or_none()

    # 2. Build the canonical payload — tz-aware UTC timestamp
    timestamp = datetime.now(timezone.utc)
    payload = {
        "tenant_id": str(tenant_id),
        "request_id": request_id,
        "timestamp": canonical_timestamp(timestamp),
        "threat_category": threat_category,
        "action_taken": action_taken,
        "evaluator_reasoning": evaluator_reasoning or "",
    }

    # 3. Compute hash
    new_hash = compute_hash(prev_hash, payload)

    # 4. Persist
    event = SecurityEvent(
        tenant_id=tenant_id,
        request_id=request_id,
        timestamp=timestamp,
        threat_category=threat_category,
        action_taken=action_taken,
        evaluator_reasoning=evaluator_reasoning,
        prev_hash=prev_hash,
        record_hash=new_hash,
    )
    session.add(event)
    await session.commit()
    await session.refresh(event)
    return event


# ============================================================
# Verify
# ============================================================

async def verify_chain(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    limit: int = 10000,
) -> dict:
    """
    Walk the tenant's chain oldest-to-newest and recompute every hash.

    Returns:
        { "valid": bool, "length": int, "broken_at": str | None }
    """
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.tenant_id == tenant_id)
        .order_by(SecurityEvent.timestamp.asc())
        .limit(limit)
    )
    events = (await session.execute(stmt)).scalars().all()

    if not events:
        return {"valid": True, "length": 0, "broken_at": None}

    previous_hash: str | None = None

    for e in events:
        # Link check
        if e.prev_hash != previous_hash:
            return {"valid": False, "length": len(events), "broken_at": str(e.event_id)}

        # Hash check
        payload = {
            "tenant_id": str(e.tenant_id),
            "request_id": e.request_id,
            "timestamp": canonical_timestamp(e.timestamp),
            "threat_category": e.threat_category,
            "action_taken": e.action_taken,
            "evaluator_reasoning": e.evaluator_reasoning or "",
        }
        expected_hash = compute_hash(previous_hash, payload)
        if e.record_hash != expected_hash:
            return {"valid": False, "length": len(events), "broken_at": str(e.event_id)}

        previous_hash = e.record_hash

    return {"valid": True, "length": len(events), "broken_at": None}