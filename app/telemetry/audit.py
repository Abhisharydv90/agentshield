"""
Tamper-evident audit log with per-tenant hash chaining.

Security properties:

- Each tenant has an independent chain.
- PostgreSQL transaction advisory locks serialize appends for the same tenant.
- Concurrent writes therefore cannot fork the chain.
- Canonical hashing is preserved for compatibility with existing records.
- Verification recomputes both links and record hashes.
- 7F-3 creates a corresponding EvidenceNode in the same transaction as each
  SecurityEvent.
- 7F-4 creates an EvidenceEdge linking successive runtime evidence nodes.
- Evidence nodes are flushed before edges reference them.
- Historical audit events without EvidenceNodes are treated as a safe
  lineage boundary.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    desc,
    select,
    text,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    EvidenceNode,
    SecurityEvent,
)
from app.security.evidence.runtime import (
    link_runtime_evidence,
    record_runtime_evidence,
)


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
    transaction commits or rolls back.
    """

    key = _tenant_lock_key(
        tenant_id
    )

    await session.execute(
        text(
            "SELECT pg_advisory_xact_lock(:lock_key)"
        ),
        {
            "lock_key":
                key
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
            evaluator_reasoning
            or "",
    }


# ============================================================
# Previous evidence lookup
# ============================================================


async def _find_previous_evidence(
    *,
    session: AsyncSession,
    tenant_id: uuid.UUID,
    previous_event: SecurityEvent | None,
) -> EvidenceNode | None:
    """
    Find the EvidenceNode corresponding to the previous audit event.

    Returning None is intentional for historical events that predate
    runtime evidence creation. Such events form a safe lineage boundary
    rather than causing the runtime to invent an edge.
    """

    if previous_event is None:
        return None

    if previous_event.event_id is None:
        raise RuntimeError(
            "previous_audit_event_id_unavailable"
        )

    stmt = (
        select(
            EvidenceNode
        )
        .where(
            EvidenceNode.tenant_id
            == tenant_id
        )
        .where(
            EvidenceNode.security_event_id
            == previous_event.event_id
        )
    )

    result = await session.execute(
        stmt
    )

    return result.scalar_one_or_none()


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

    The SecurityEvent, EvidenceNode, and optional EvidenceEdge are
    committed together. If any part fails, the whole transaction rolls back.
    """

    # --------------------------------------------------------
    # Serialize append operations for THIS tenant.
    # --------------------------------------------------------

    await _acquire_tenant_append_lock(
        session,
        tenant_id,
    )

    # --------------------------------------------------------
    # Find the current audit-chain tip.
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
    # Find the evidence predecessor, if one exists.
    # --------------------------------------------------------

    previous_evidence = (
        await _find_previous_evidence(
            session=session,
            tenant_id=tenant_id,
            previous_event=previous_event,
        )
    )

    # --------------------------------------------------------
    # Canonical timestamp.
    # --------------------------------------------------------

    timestamp = datetime.now(
        timezone.utc
    )

    payload = _build_payload(
        tenant_id=tenant_id,
        request_id=request_id,
        timestamp=timestamp,
        threat_category=threat_category,
        action_taken=action_taken,
        evaluator_reasoning=evaluator_reasoning,
    )

    # --------------------------------------------------------
    # Compute audit hash.
    # --------------------------------------------------------

    record_hash = compute_hash(
        prev_hash,
        payload,
    )

    # --------------------------------------------------------
    # Build audit event.
    # --------------------------------------------------------

    event = SecurityEvent(
        event_id=
            uuid.uuid4(),

        tenant_id=
            tenant_id,

        request_id=
            request_id,

        timestamp=
            timestamp,

        threat_category=
            threat_category,

        action_taken=
            action_taken,

        evaluator_reasoning=
            evaluator_reasoning,

        prev_hash=
            prev_hash,

        record_hash=
            record_hash,
    )

    try:

        # ----------------------------------------------------
        # Persist the audit event.
        # ----------------------------------------------------

        session.add(
            event
        )

        # Flush the audit row first.
        await session.flush()

        # ----------------------------------------------------
        # 7F-3 — create evidence node
        # ----------------------------------------------------

        current_evidence = (
            record_runtime_evidence(
                session=session,
                event=event,
                payload=payload,
            )
        )

        # ----------------------------------------------------
        # IMPORTANT:
        # Flush the new EvidenceNode BEFORE creating an
        # EvidenceEdge that references it.
        # ----------------------------------------------------

        await session.flush()

        # ----------------------------------------------------
        # 7F-4 — create causal edge
        # ----------------------------------------------------

        if previous_evidence is not None:

            link_runtime_evidence(
                session=session,
                previous_evidence=
                    previous_evidence,
                current_evidence=
                    current_evidence,
            )

        # ----------------------------------------------------
        # Atomic commit
        # ----------------------------------------------------

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