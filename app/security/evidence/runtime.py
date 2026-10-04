"""
Runtime evidence recording primitives for AgentShield.

7F-3 introduces the first live runtime producer for the Evidence Graph:
every persisted SecurityEvent gets a corresponding EvidenceNode in the
same database transaction.

Security properties:

- The evidence artifact is content-addressed with SHA-256.
- Raw evaluator reasoning is never duplicated into evidence metadata.
- The evidence node is tenant-scoped through the SecurityEvent foreign key.
- Evidence creation is atomic with audit-event creation: if evidence cannot
  be recorded, the surrounding transaction can fail closed.
- The evidence hash is independent from database identifiers and timestamps
  except where those values are actually part of the audit artifact payload.
"""

from __future__ import annotations

from typing import Any
import uuid

from app.db.models import EvidenceNode, SecurityEvent
from app.security.evidence.hashing import fingerprint_evidence


RUNTIME_EVIDENCE_SCHEMA_VERSION = "1"
RUNTIME_EVIDENCE_NODE_TYPE = "security_event"
RUNTIME_EVIDENCE_SOURCE = "audit"


def build_runtime_evidence_metadata(
    event: SecurityEvent,
) -> dict[str, Any]:
    """
    Build the redacted metadata persisted alongside the evidence hash.

    The full evaluator reasoning is deliberately excluded. A separate hash
    commits the evidence to the exact reasoning without duplicating sensitive
    text in the Evidence Graph.
    """

    if event.event_id is None:
        raise RuntimeError("runtime_evidence_event_id_unavailable")

    reasoning = event.evaluator_reasoning or ""

    return {
        "event_id": str(event.event_id),
        "request_id": event.request_id,
        "threat_category": event.threat_category,
        "action_taken": event.action_taken,
        "prev_hash": event.prev_hash,
        "record_hash": event.record_hash,
        "reason_hash": fingerprint_evidence(
            {"reason": reasoning}
        ),
    }


def build_runtime_evidence_artifact(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Return the canonical audit artifact used for content addressing."""

    return dict(payload)


def runtime_evidence_hash(
    payload: dict[str, Any],
) -> str:
    """Return the SHA-256 content hash for a runtime audit artifact."""

    return fingerprint_evidence(
        build_runtime_evidence_artifact(payload)
    )


def record_runtime_evidence(
    *,
    session,
    event: SecurityEvent,
    payload: dict[str, Any],
) -> EvidenceNode:
    """
    Add one runtime evidence node to the current transaction.

    The caller is responsible for transaction commit/rollback. This helper
    intentionally performs no commit itself so the audit event and evidence
    node are persisted atomically.
    """

    if event.event_id is None:
        raise RuntimeError("runtime_evidence_event_id_unavailable")

    trace_id = event.request_id or ""
    if len(trace_id) > 128:
        raise ValueError("runtime_evidence_trace_id_too_long")

    node = EvidenceNode(
        evidence_id=uuid.uuid4(),
        tenant_id=event.tenant_id,
        trace_id=trace_id,
        node_type=RUNTIME_EVIDENCE_NODE_TYPE,
        schema_version=RUNTIME_EVIDENCE_SCHEMA_VERSION,
        artifact_hash=runtime_evidence_hash(payload),
        source=RUNTIME_EVIDENCE_SOURCE,
        metadata_redacted=build_runtime_evidence_metadata(event),
        security_event_id=event.event_id,
        created_at=event.timestamp,
    )

    session.add(node)
    return node
