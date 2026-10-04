"""
Tamper-evident audit log with per-tenant hash chaining.

Security properties:

- Each tenant has an independent chain.
- PostgreSQL transaction advisory locks serialize appends for the same tenant.
- Concurrent writes therefore cannot fork the chain.
- Canonical hashing is preserved for compatibility with existing records.
- Verification recomputes both links and record hashes.
- 7F-3 creates a corresponding EvidenceNode in the same transaction as each
  SecurityEvent, so audit persistence and evidence persistence are atomic.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import SecurityEvent
from app.security.evidence.runtime import record_runtime_evidence


# ============================================================
# Canonical timestamp
# ============================================================


def canonical_timestamp(
    ts: datetime,
) -> str:
    """
    Convert a timestamp to one canonical UTC representation.
    """

    if ts.tzinfo is None:

        ts = ts.replace(
            tzinfo=timezone.utc
        )

    else:

        ts = ts.astimezone(
            timezone.utc
        )

    return ts.isoformat()


# ============================================================
# Hashing
# ============================================================


def compute_hash(
    prev_hash: str | None,
    payload: dict,
) -> str:
    """
    SHA-256(prev_hash || canonical_json(payload)).
    """

    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    ).encode(
        "utf-8"
    )

    if prev_hash:

        body = (
            prev_hash.encode(
                "utf-8"
            )
            + body
        )

    return hashlib.sha256(
        body
    ).hexdigest()


# ============================================================
# Tenant serialization lock
# ============================================================


def _tenant_lock_key(
    tenant_id: uuid.UUID,
) -> int:
    """
    Convert a UUID into a signed PostgreSQL advisory-lock key.

    The same tenant UUID always produces the same lock key.
    Different tenants may proceed independently.
    """

    raw = tenant_id.bytes[:8]

    return int.from_bytes(
        raw,
        byteorder="big",
        signed=True,
    )


async def _acquire_tenant_append_lock(
    session: AsyncSession,
    tenant_id: uuid.UUID,
) -> None:
    """
    Acquire a transaction-scoped PostgreSQL advisory lock.

    PostgreSQL releases this automatically when the current
    transaction commits/rolls back.
    """

    key = _tenant_lock_key(
        tenant_id
    )

    await session.execute(
        text(
            "SELECT pg_advisory_xact_lock(:lock_key)"
        ),
        {
            "lock_key": key
        },
    )


# ============================================================
# Payload builder
# ============================================================


def _build_payload(
    tenant_id: uuid.UUID,
    request_id: str | None,
    timestamp: datetime,
    threat_category: str,
    action_taken: str,
    evaluator_reasoning: str,
) -> dict:

    return {
        "tenant_id":
            str(tenant_id),
        "request_id":
            request_id,
        "timestamp":
            canonical_timestamp(
                timestamp
            ),
        "threat_category":
            threat_category,
        "action_taken":
            action_taken,
        "evaluator_reasoning":
            evaluator_reasoning or "",
    }


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
    Append one event to a tenant's audit chain.

    A transaction-scoped advisory lock prevents two concurrent
    writers from reading the same previous hash.

    The SecurityEvent and its EvidenceNode are committed together. If
    evidence creation fails, neither record is committed.
    """

    # --------------------------------------------------------
    # Serialize append operations for THIS tenant.
    # --------------------------------------------------------

    await _acquire_tenant_append_lock(
        session,
        tenant_id,
    )

    # --------------------------------------------------------
    # Find the current chain tip.
    # --------------------------------------------------------

    stmt = (
        select(
            SecurityEvent
        )
        .where(
            SecurityEvent.tenant_id
            == tenant_id
        )
        .order_by(
            desc(
                SecurityEvent.timestamp
            ),
            desc(
                SecurityEvent.event_id
            ),
        )
        .limit(1)
    )

    previous_event = (
        await session.execute(
            stmt
        )
    ).scalar_one_or_none()

    prev_hash = (
        previous_event.record_hash
        if previous_event
        else None
    )

    # --------------------------------------------------------
    # Canonical timestamp
    # --------------------------------------------------------

    timestamp = datetime.now(
        timezone.utc
    )

    payload = _build_payload(
        tenant_id=tenant_id,
        request_id=request_id,
        timestamp=timestamp,
        threat_category=
            threat_category,
        action_taken=
            action_taken,
        evaluator_reasoning=
            evaluator_reasoning,
    )

    # --------------------------------------------------------
    # Hash
    # --------------------------------------------------------

    record_hash = compute_hash(
        prev_hash,
        payload,
    )

    # --------------------------------------------------------
    # Persist audit event
    # --------------------------------------------------------

    event = SecurityEvent(
        event_id=uuid.uuid4(),
        tenant_id=tenant_id,
        request_id=request_id,
        timestamp=timestamp,
        threat_category=
            threat_category,
        action_taken=
            action_taken,
        evaluator_reasoning=
            evaluator_reasoning,
        prev_hash=prev_hash,
        record_hash=record_hash,
    )

    session.add(
        event
    )

    # Flush first so the explicit event_id and FK target are materialized
    # before the EvidenceNode is added.
    await session.flush()

    # --------------------------------------------------------
    # 7F-3 runtime evidence
    # --------------------------------------------------------

    record_runtime_evidence(
        session=session,
        event=event,
        payload=payload,
    )

    # --------------------------------------------------------
    # Atomic commit
    # --------------------------------------------------------

    try:
        await session.commit()
    except Exception:
        await session.rollback()
        raise

    await session.refresh(
        event
    )

    return event


# ============================================================
# Verify
# ============================================================


async def verify_chain(
    session: AsyncSession,
    tenant_id: uuid.UUID,
) -> dict:

    stmt = (
        select(
            SecurityEvent
        )
        .where(
            SecurityEvent.tenant_id
            == tenant_id
        )
        .order_by(
            SecurityEvent.timestamp.asc(),
            SecurityEvent.event_id.asc(),
        )
    )

    events = (
        await session.execute(
            stmt
        )
    ).scalars().all()

    if not events:

        return {
            "valid":
                True,
            "length":
                0,
            "broken_at":
                None,
        }

    previous_hash: str | None = None

    for event in events:

        # ----------------------------------------------------
        # Chain-link verification
        # ----------------------------------------------------

        if (
            event.prev_hash
            != previous_hash
        ):

            return {
                "valid":
                    False,
                "length":
                    len(events),
                "broken_at":
                    str(
                        event.event_id
                    ),
            }

        # ----------------------------------------------------
        # Record-hash verification
        # ----------------------------------------------------

        payload = _build_payload(
            tenant_id=
                event.tenant_id,
            request_id=
                event.request_id,
            timestamp=
                event.timestamp,
            threat_category=
                event.threat_category,
            action_taken=
                event.action_taken,
            evaluator_reasoning=
                event.evaluator_reasoning
                or "",
        )

        expected_hash = compute_hash(
            previous_hash,
            payload,
        )

        if (
            event.record_hash
            != expected_hash
        ):

            return {
                "valid":
                    False,
                "length":
                    len(events),
                "broken_at":
                    str(
                        event.event_id
                    ),
            }

        previous_hash = (
            event.record_hash
        )

    return {
        "valid":
            True,
        "length":
            len(events),
        "broken_at":
            None,
    }
