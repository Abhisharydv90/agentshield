"""
Evidence Fabric forensic services.

Phase 8 responsibilities:

8.10  investigation data reconstruction
8.11  read-only forensic replay
8.12  trace reconstruction
8.13  compliance package fingerprinting

Important security boundary:

    forensic replay NEVER executes an agent action.

It reconstructs historical evidence only.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    EvidenceEdge,
    EvidenceNode,
    SecurityEvent,
)
from app.security.evidence.hashing import (
    fingerprint_evidence,
)
from app.security.evidence.limits import (
    DEFAULT_REPLAY_EVENTS,
    DEFAULT_TRACE_EVENTS,
    EVIDENCE_PACKAGE_SCHEMA_VERSION,
    MAX_GRAPH_EDGES,
    MAX_REPLAY_EVENTS,
    MAX_TRACE_EVENTS,
)
from app.security.evidence.runtime import (
    runtime_evidence_hash,
)
from app.telemetry.audit import (
    _build_payload,
    compute_hash,
)


# ============================================================
# Data contracts
# ============================================================


@dataclass(frozen=True)
class TraceRecord:
    sequence: int

    event_id: uuid.UUID

    evidence_id: uuid.UUID | None

    timestamp: datetime

    request_id: str | None

    threat_category: str

    action_taken: str

    record_hash: str

    prev_hash: str | None

    artifact_hash: str | None

    node_type: str | None

    source: str | None

    metadata_redacted: dict

    record_hash_valid: bool

    evidence_hash_valid: bool

    predecessor_evidence_id: uuid.UUID | None

    predecessor_relation: str | None


@dataclass(frozen=True)
class TraceIntegrity:
    status: str

    events_checked: int

    evidence_checked: int

    missing_evidence: int


@dataclass(frozen=True)
class TraceReconstruction:
    trace_id: str

    event_count: int

    node_count: int

    edge_count: int

    start_time: datetime | None

    end_time: datetime | None

    truncated: bool

    integrity: TraceIntegrity

    records: list[TraceRecord]


# ============================================================
# Internal helpers
# ============================================================


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(
        timezone.utc
    )


def _event_payload(
    event: SecurityEvent,
) -> dict:
    return _build_payload(
        tenant_id=event.tenant_id,
        request_id=event.request_id,
        timestamp=event.timestamp,
        threat_category=event.threat_category,
        action_taken=event.action_taken,
        evaluator_reasoning=(
            event.evaluator_reasoning
            or ""
        ),
    )


def _serialize_package_node(
    node: EvidenceNode,
) -> dict:
    return {
        "evidence_id":
            str(node.evidence_id),

        "tenant_id":
            str(node.tenant_id),

        "trace_id":
            node.trace_id,

        "node_type":
            node.node_type,

        "schema_version":
            node.schema_version,

        "artifact_hash":
            node.artifact_hash,

        "source":
            node.source,

        "metadata_redacted":
            dict(
                node.metadata_redacted
                or {}
            ),

        "security_event_id":
            (
                str(
                    node.security_event_id
                )
                if node.security_event_id
                else None
            ),

        "created_at":
            _utc(
                node.created_at
            ).isoformat(),
    }


def _serialize_package_edge(
    edge: EvidenceEdge,
) -> dict:
    return {
        "edge_id":
            str(edge.edge_id),

        "tenant_id":
            str(edge.tenant_id),

        "trace_id":
            edge.trace_id,

        "from_evidence_id":
            str(
                edge.from_evidence_id
            ),

        "to_evidence_id":
            str(
                edge.to_evidence_id
            ),

        "relation":
            edge.relation,

        "created_at":
            _utc(
                edge.created_at
            ).isoformat(),
    }


# ============================================================
# Trace reconstruction
# ============================================================


async def reconstruct_trace(
    *,
    session: AsyncSession,
    tenant_id: uuid.UUID,
    trace_id: str,
    max_events: int = DEFAULT_TRACE_EVENTS,
) -> TraceReconstruction | None:
    """
    Reconstruct one tenant-scoped trace.

    The operation is read-only.

    No agent action is executed.
    """

    trace_id = trace_id.strip()

    if not trace_id:
        raise ValueError(
            "trace_id_empty"
        )

    if len(trace_id) > 128:
        raise ValueError(
            "trace_id_too_long"
        )

    max_events = min(
        max(
            int(max_events),
            1,
        ),
        MAX_TRACE_EVENTS,
    )

    # --------------------------------------------------------
    # Security events
    # --------------------------------------------------------

    event_rows = (
        await session.execute(
            select(
                SecurityEvent
            )
            .where(
                SecurityEvent.tenant_id
                == tenant_id
            )
            .where(
                SecurityEvent.request_id
                == trace_id
            )
            .order_by(
                SecurityEvent.timestamp.asc(),
                SecurityEvent.event_id.asc(),
            )
            .limit(
                max_events + 1
            )
        )
    ).scalars().all()

    truncated = (
        len(event_rows)
        > max_events
    )

    events = event_rows[
        :max_events
    ]

    # --------------------------------------------------------
    # Evidence nodes
    # --------------------------------------------------------

    node_rows = (
        await session.execute(
            select(
                EvidenceNode
            )
            .where(
                EvidenceNode.tenant_id
                == tenant_id
            )
            .where(
                EvidenceNode.trace_id
                == trace_id
            )
            .order_by(
                EvidenceNode.created_at.asc(),
                EvidenceNode.evidence_id.asc(),
            )
            .limit(
                max_events + 1
            )
        )
    ).scalars().all()

    if len(node_rows) > max_events:
        truncated = True
        node_rows = node_rows[:max_events]

    nodes = node_rows

    # --------------------------------------------------------
    # Evidence edges
    # --------------------------------------------------------

    edge_rows = (
        await session.execute(
            select(
                EvidenceEdge
            )
            .where(
                EvidenceEdge.tenant_id
                == tenant_id
            )
            .where(
                EvidenceEdge.trace_id
                == trace_id
            )
            .order_by(
                EvidenceEdge.created_at.asc(),
                EvidenceEdge.edge_id.asc(),
            )
            .limit(
                MAX_GRAPH_EDGES + 1
            )
        )
    ).scalars().all()

    if (
        len(edge_rows)
        > MAX_GRAPH_EDGES
    ):
        truncated = True

    edges = edge_rows[
        :MAX_GRAPH_EDGES
    ]

    # --------------------------------------------------------
    # If there is no event OR evidence, the trace does not exist.
    # --------------------------------------------------------

    if not events and not nodes:
        return None

    # --------------------------------------------------------
    # Lookup maps
    # --------------------------------------------------------

    node_by_event = {
        node.security_event_id:
            node
        for node in nodes
        if node.security_event_id
        is not None
    }

    edge_by_to: dict[
        uuid.UUID,
        EvidenceEdge,
    ] = {}

    for edge in edges:
        edge_by_to.setdefault(
            edge.to_evidence_id,
            edge,
        )

    # --------------------------------------------------------
    # Reconstruct records
    # --------------------------------------------------------

    records: list[
        TraceRecord
    ] = []

    missing_evidence = 0
    evidence_checked = 0

    for index, event in enumerate(
        events,
        start=1,
    ):

        node = node_by_event.get(
            event.event_id
        )

        payload = _event_payload(
            event
        )

        expected_record_hash = (
            compute_hash(
                event.prev_hash,
                payload,
            )
        )

        record_hash_valid = (
            event.record_hash
            == expected_record_hash
        )

        evidence_hash_valid = False

        if node is None:
            missing_evidence += 1

        else:
            evidence_checked += 1

            expected_artifact_hash = (
                runtime_evidence_hash(
                    payload
                )
            )

            evidence_hash_valid = (
                node.artifact_hash
                == expected_artifact_hash
            )

        predecessor_evidence_id = None
        predecessor_relation = None

        if node is not None:
            predecessor = edge_by_to.get(
                node.evidence_id
            )

            if predecessor is not None:
                predecessor_evidence_id = (
                    predecessor.from_evidence_id
                )

                predecessor_relation = (
                    predecessor.relation
                )

        records.append(
            TraceRecord(
                sequence=index,
                event_id=event.event_id,
                evidence_id=(
                    node.evidence_id
                    if node is not None
                    else None
                ),
                timestamp=_utc(
                    event.timestamp
                ),
                request_id=(
                    event.request_id
                ),
                threat_category=(
                    event.threat_category
                ),
                action_taken=(
                    event.action_taken
                ),
                record_hash=(
                    event.record_hash
                ),
                prev_hash=(
                    event.prev_hash
                ),
                artifact_hash=(
                    node.artifact_hash
                    if node is not None
                    else None
                ),
                node_type=(
                    node.node_type
                    if node is not None
                    else None
                ),
                source=(
                    node.source
                    if node is not None
                    else None
                ),
                metadata_redacted=(
                    dict(
                        node.metadata_redacted
                        or {}
                    )
                    if node is not None
                    else {}
                ),
                record_hash_valid=(
                    record_hash_valid
                ),
                evidence_hash_valid=(
                    evidence_hash_valid
                ),
                predecessor_evidence_id=(
                    predecessor_evidence_id
                ),
                predecessor_relation=(
                    predecessor_relation
                ),
            )
        )

    # --------------------------------------------------------
    # Integrity state
    # --------------------------------------------------------

    invalid_record = any(
        not record.record_hash_valid
        for record in records
    )

    invalid_evidence = any(
        record.evidence_id is not None
        and not record.evidence_hash_valid
        for record in records
    )

    if invalid_record or invalid_evidence:
        integrity_status = "invalid"

    elif (
        truncated
        or missing_evidence > 0
    ):
        integrity_status = "partial"

    else:
        integrity_status = "verified"

    start_time = (
        _utc(events[0].timestamp)
        if events
        else (
            _utc(nodes[0].created_at)
            if nodes
            else None
        )
    )

    end_time = (
        _utc(events[-1].timestamp)
        if events
        else (
            _utc(nodes[-1].created_at)
            if nodes
            else None
        )
    )

    return TraceReconstruction(
        trace_id=trace_id,
        event_count=len(events),
        node_count=len(nodes),
        edge_count=len(edges),
        start_time=start_time,
        end_time=end_time,
        truncated=truncated,
        integrity=TraceIntegrity(
            status=integrity_status,
            events_checked=len(events),
            evidence_checked=evidence_checked,
            missing_evidence=missing_evidence,
        ),
        records=records,
    )


# ============================================================
# Forensic replay
# ============================================================


async def reconstruct_replay(
    *,
    session: AsyncSession,
    tenant_id: uuid.UUID,
    trace_id: str,
    max_events: int = DEFAULT_REPLAY_EVENTS,
) -> TraceReconstruction | None:
    """
    Build the read-only forensic replay representation.

    This function does not execute tools, mutate state, or invoke agents.
    """

    max_events = min(
        max(
            int(max_events),
            1,
        ),
        MAX_REPLAY_EVENTS,
    )

    return await reconstruct_trace(
        session=session,
        tenant_id=tenant_id,
        trace_id=trace_id,
        max_events=max_events,
    )


# ============================================================
# Compliance package fingerprint
# ============================================================


def compute_compliance_package_hash(
    *,
    tenant_id: uuid.UUID,
    nodes: list[EvidenceNode],
    edges: list[EvidenceEdge],
    verification: dict,
) -> str:
    """
    Generate a deterministic fingerprint for the logical evidence package.

    The generated_at timestamp is intentionally excluded so the same
    underlying package produces the same package hash.
    """

    payload = {
        "schema_version":
            EVIDENCE_PACKAGE_SCHEMA_VERSION,

        "tenant_id":
            str(tenant_id),

        "nodes": [
            _serialize_package_node(
                node
            )
            for node in nodes
        ],

        "edges": [
            _serialize_package_edge(
                edge
            )
            for edge in edges
        ],

        "verification": {
            "valid":
                bool(
                    verification.get(
                        "valid",
                        False,
                    )
                ),

            "chain_valid":
                bool(
                    verification.get(
                        "chain_valid",
                        False,
                    )
                ),

            "chain_length":
                int(
                    verification.get(
                        "chain_length",
                        0,
                    )
                ),

            "nodes_checked":
                int(
                    verification.get(
                        "nodes_checked",
                        0,
                    )
                ),

            "edges_checked":
                int(
                    verification.get(
                        "edges_checked",
                        0,
                    )
                ),

            "truncated":
                bool(
                    verification.get(
                        "truncated",
                        False,
                    )
                ),

            "issues":
                verification.get(
                    "issues",
                    [],
                ),
        },
    }

    return fingerprint_evidence(
        payload
    )
