"""
Runtime evidence recording primitives for AgentShield.

7F-4 extends the 7F-3 runtime producer with explicit causal linkage between
successive runtime evidence artifacts.

Security properties:

- The evidence artifact is content-addressed with SHA-256.
- Raw evaluator reasoning is never duplicated into evidence metadata.
- Evidence is tenant-scoped.
- Evidence nodes are flushed before edges referencing them are inserted.
- Causal edges are created inside the same transaction as the audit event
  and evidence node.
- Historical audit events without EvidenceNodes are treated as a safe
  lineage boundary rather than receiving a fabricated predecessor.
"""

from __future__ import annotations

from typing import Any
import uuid

from app.db.models import (
    EvidenceEdge,
    EvidenceNode,
    SecurityEvent,
)
from app.security.evidence.hashing import (
    fingerprint_evidence,
)


RUNTIME_EVIDENCE_SCHEMA_VERSION = "1"
RUNTIME_EVIDENCE_NODE_TYPE = "security_event"
RUNTIME_EVIDENCE_SOURCE = "audit"

RUNTIME_EVIDENCE_EDGE_RELATION = (
    "audit_chain_continuation"
)


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
        raise RuntimeError(
            "runtime_evidence_event_id_unavailable"
        )

    reasoning = event.evaluator_reasoning or ""

    return {
        "event_id":
            str(event.event_id),

        "request_id":
            event.request_id,

        "threat_category":
            event.threat_category,

        "action_taken":
            event.action_taken,

        "prev_hash":
            event.prev_hash,

        "record_hash":
            event.record_hash,

        "reason_hash":
            fingerprint_evidence(
                {
                    "reason":
                        reasoning,
                }
            ),
    }


def build_runtime_evidence_artifact(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """
    Return the canonical audit artifact used for content addressing.
    """

    return dict(
        payload
    )


def runtime_evidence_hash(
    payload: dict[str, Any],
) -> str:
    """
    Return the SHA-256 content hash for a runtime audit artifact.
    """

    return fingerprint_evidence(
        build_runtime_evidence_artifact(
            payload
        )
    )


def record_runtime_evidence(
    *,
    session,
    event: SecurityEvent,
    payload: dict[str, Any],
) -> EvidenceNode:
    """
    Add one runtime EvidenceNode to the current transaction.

    This function intentionally creates ONLY the node.

    The caller must flush the node before creating an EvidenceEdge that
    references it. PostgreSQL enforces the composite tenant-scoped foreign
    keys on EvidenceEdge, so the node must already exist in the transaction's
    database state.

    No commit is performed here.
    """

    if event.event_id is None:
        raise RuntimeError(
            "runtime_evidence_event_id_unavailable"
        )

    trace_id = event.request_id or ""

    if len(trace_id) > 128:
        raise ValueError(
            "runtime_evidence_trace_id_too_long"
        )

    node = EvidenceNode(
        evidence_id=
            uuid.uuid4(),

        tenant_id=
            event.tenant_id,

        trace_id=
            trace_id,

        node_type=
            RUNTIME_EVIDENCE_NODE_TYPE,

        schema_version=
            RUNTIME_EVIDENCE_SCHEMA_VERSION,

        artifact_hash=
            runtime_evidence_hash(
                payload
            ),

        source=
            RUNTIME_EVIDENCE_SOURCE,

        metadata_redacted=
            build_runtime_evidence_metadata(
                event
            ),

        security_event_id=
            event.event_id,

        created_at=
            event.timestamp,
    )

    session.add(
        node
    )

    return node


def link_runtime_evidence(
    *,
    session,
    previous_evidence: EvidenceNode,
    current_evidence: EvidenceNode,
) -> EvidenceEdge:
    """
    Create one causal EvidenceEdge between two already-created nodes.

    The caller must flush `current_evidence` before invoking this function.

    The edge remains in the same database transaction and is therefore
    committed or rolled back together with the audit event and evidence node.
    """

    if (
        previous_evidence.tenant_id
        != current_evidence.tenant_id
    ):
        raise ValueError(
            "runtime_evidence_cross_tenant_link"
        )

    if (
        previous_evidence.evidence_id
        == current_evidence.evidence_id
    ):
        raise ValueError(
            "runtime_evidence_self_link"
        )

    edge = EvidenceEdge(
        edge_id=
            uuid.uuid4(),

        tenant_id=
            current_evidence.tenant_id,

        trace_id=
            current_evidence.trace_id,

        from_evidence_id=
            previous_evidence.evidence_id,

        to_evidence_id=
            current_evidence.evidence_id,

        relation=
            RUNTIME_EVIDENCE_EDGE_RELATION,

        created_at=
            current_evidence.created_at,
    )

    session.add(
        edge
    )

    return edge