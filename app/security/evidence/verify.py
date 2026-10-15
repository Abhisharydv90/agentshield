"""
Evidence Graph integrity verification.

Verification layers:

1. SecurityEvent hash-chain verification.
2. EvidenceNode -> SecurityEvent tenant binding.
3. EvidenceNode metadata binding.
4. Runtime evidence artifact hash verification.
5. Redacted reasoning fingerprint verification.
6. EvidenceEdge tenant/scoped relationship verification.
7. Audit-chain continuation edge verification.
8. Edge chronology validation.
9. Expected-edge completeness validation.
10. Bounding / truncation detection.

Raw evaluator reasoning is NEVER returned.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select

from app.db.models import (
    EvidenceEdge,
    EvidenceNode,
    SecurityEvent,
)
from app.security.evidence.runtime import (
    RUNTIME_EVIDENCE_EDGE_RELATION,
    runtime_evidence_hash,
)
from app.security.evidence.hashing import fingerprint_evidence
from app.security.evidence.limits import (
    MAX_VERIFY_EDGES,
    MAX_VERIFY_EVENTS,
    MAX_VERIFY_NODES,
)
from app.telemetry.audit import (
    _build_payload,
    verify_chain,
)


_SHA256_RE = re.compile(
    r"^[0-9a-f]{64}$"
)


@dataclass(frozen=True)
class VerificationIssue:
    code: str
    detail: str


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    chain_valid: bool
    chain_length: int
    broken_at: str | None
    nodes_checked: int
    edges_checked: int
    truncated: bool
    issues: list[VerificationIssue]

    def to_dict(
        self,
    ) -> dict:
        return {
            "valid": self.valid,
            "chain_valid": self.chain_valid,
            "chain_length": self.chain_length,
            "broken_at": self.broken_at,
            "nodes_checked": self.nodes_checked,
            "edges_checked": self.edges_checked,
            "truncated": self.truncated,
            "issues": [
                {
                    "code": issue.code,
                    "detail": issue.detail,
                }
                for issue in self.issues
            ],
        }


def _issue(
    issues: list[VerificationIssue],
    code: str,
    detail: str,
) -> None:
    issues.append(
        VerificationIssue(
            code=code,
            detail=detail,
        )
    )


async def verify_evidence_graph(
    *,
    session,
    tenant_id: uuid.UUID,
    max_events: int = MAX_VERIFY_EVENTS,
    max_nodes: int = MAX_VERIFY_NODES,
    max_edges: int = MAX_VERIFY_EDGES,
) -> VerificationResult:

    max_events = min(
        max(
            int(max_events),
            1,
        ),
        MAX_VERIFY_EVENTS,
    )

    max_nodes = min(
        max(
            int(max_nodes),
            1,
        ),
        MAX_VERIFY_NODES,
    )

    max_edges = min(
        max(
            int(max_edges),
            1,
        ),
        MAX_VERIFY_EDGES,
    )

    issues: list[
        VerificationIssue
    ] = []

    # ========================================================
    # 1. Existing SecurityEvent chain
    # ========================================================

    chain = await verify_chain(
        session,
        tenant_id,
    )

    # ========================================================
    # 2. Fetch bounded SecurityEvents
    # ========================================================

    event_rows = (
        await session.execute(
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

    event_by_id = {
        event.event_id:
            event
        for event in events
    }

    # ========================================================
    # 3. Runtime evidence nodes
    # ========================================================

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
                EvidenceNode.node_type
                == "security_event"
            )
            .order_by(
                EvidenceNode.created_at.asc(),
                EvidenceNode.evidence_id.asc(),
            )
            .limit(
                max_nodes + 1
            )
        )
    ).scalars().all()

    if len(node_rows) > max_nodes:
        truncated = True

    nodes = node_rows[
        :max_nodes
    ]

    node_by_event = {
        node.security_event_id:
            node
        for node in nodes
        if node.security_event_id is not None
    }

    node_by_id = {
        node.evidence_id:
            node
        for node in nodes
    }

    # ========================================================
    # 4. Node verification
    # ========================================================

    for node in nodes:

        if node.security_event_id is None:

            _issue(
                issues,
                "runtime_node_missing_security_event",
                str(node.evidence_id),
            )

            continue

        event = event_by_id.get(
            node.security_event_id
        )

        if event is None:

            _issue(
                issues,
                "node_security_event_not_in_verification_scope",
                str(node.evidence_id),
            )

            continue

        metadata = (
            node.metadata_redacted
            or {}
        )

        expected_event_id = str(
            event.event_id
        )

        if (
            metadata.get("event_id")
            != expected_event_id
        ):
            _issue(
                issues,
                "metadata_event_id_mismatch",
                expected_event_id,
            )

        if (
            metadata.get("request_id")
            != event.request_id
        ):
            _issue(
                issues,
                "metadata_request_id_mismatch",
                expected_event_id,
            )

        if (
            metadata.get("threat_category")
            != event.threat_category
        ):
            _issue(
                issues,
                "metadata_threat_category_mismatch",
                expected_event_id,
            )

        if (
            metadata.get("action_taken")
            != event.action_taken
        ):
            _issue(
                issues,
                "metadata_action_mismatch",
                expected_event_id,
            )

        if (
            metadata.get("prev_hash")
            != event.prev_hash
        ):
            _issue(
                issues,
                "metadata_prev_hash_mismatch",
                expected_event_id,
            )

        if (
            metadata.get("record_hash")
            != event.record_hash
        ):
            _issue(
                issues,
                "metadata_record_hash_mismatch",
                expected_event_id,
            )

        expected_reason_hash = (
            fingerprint_evidence(
                {
                    "reason":
                        event.evaluator_reasoning
                        or "",
                }
            )
        )

        if (
            metadata.get("reason_hash")
            != expected_reason_hash
        ):
            _issue(
                issues,
                "reason_hash_mismatch",
                expected_event_id,
            )

        if not _SHA256_RE.match(
            node.artifact_hash or ""
        ):
            _issue(
                issues,
                "artifact_hash_format_invalid",
                expected_event_id,
            )
        else:

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

            expected_artifact_hash = (
                runtime_evidence_hash(
                    payload
                )
            )

            if (
                node.artifact_hash
                != expected_artifact_hash
            ):
                _issue(
                    issues,
                    "artifact_hash_mismatch",
                    expected_event_id,
                )

        if (
            node.tenant_id
            != event.tenant_id
        ):
            _issue(
                issues,
                "node_event_tenant_mismatch",
                expected_event_id,
            )

        if (
            node.trace_id
            != (event.request_id or "")
        ):
            _issue(
                issues,
                "node_trace_id_mismatch",
                expected_event_id,
            )

        if (
            node.created_at
            != event.timestamp
        ):
            _issue(
                issues,
                "node_timestamp_mismatch",
                expected_event_id,
            )

    # ========================================================
    # 5. Fetch edges
    # ========================================================

    edge_rows = (
        await session.execute(
            select(
                EvidenceEdge
            )
            .where(
                EvidenceEdge.tenant_id
                == tenant_id
            )
            .order_by(
                EvidenceEdge.created_at.asc(),
                EvidenceEdge.edge_id.asc(),
            )
            .limit(
                max_edges + 1
            )
        )
    ).scalars().all()

    if len(edge_rows) > max_edges:
        truncated = True

    edges = edge_rows[
        :max_edges
    ]

    # ========================================================
    # 6. Edge verification
    # ========================================================

    actual_pairs: set[
        tuple[
            uuid.UUID,
            uuid.UUID,
        ]
    ] = set()

    for edge in edges:

        if (
            edge.tenant_id
            != tenant_id
        ):
            _issue(
                issues,
                "edge_tenant_mismatch",
                str(edge.edge_id),
            )
            continue

        from_node = node_by_id.get(
            edge.from_evidence_id
        )

        to_node = node_by_id.get(
            edge.to_evidence_id
        )

        if (
            from_node is None
            or to_node is None
        ):
            # The verifier may be bounded. Do not turn a bounded
            # out-of-scope edge into a false positive.
            if not truncated:
                _issue(
                    issues,
                    "edge_endpoint_missing",
                    str(edge.edge_id),
                )
            continue

        if (
            edge.from_evidence_id
            == edge.to_evidence_id
        ):
            _issue(
                issues,
                "edge_self_link",
                str(edge.edge_id),
            )

        if (
            edge.relation
            != RUNTIME_EVIDENCE_EDGE_RELATION
        ):
            _issue(
                issues,
                "edge_relation_invalid",
                str(edge.edge_id),
            )

        if (
            from_node.created_at
            >= to_node.created_at
        ):
            _issue(
                issues,
                "edge_time_order_invalid",
                str(edge.edge_id),
            )

        if (
            edge.trace_id
            != to_node.trace_id
        ):
            _issue(
                issues,
                "edge_trace_id_mismatch",
                str(edge.edge_id),
            )

        from_event = (
            event_by_id.get(
                from_node.security_event_id
            )
            if from_node.security_event_id
            else None
        )

        to_event = (
            event_by_id.get(
                to_node.security_event_id
            )
            if to_node.security_event_id
            else None
        )

        if (
            from_event is None
            or to_event is None
        ):
            if not truncated:
                _issue(
                    issues,
                    "edge_security_event_missing",
                    str(edge.edge_id),
                )
        else:
            if (
                to_event.prev_hash
                != from_event.record_hash
            ):
                _issue(
                    issues,
                    "edge_hash_continuity_invalid",
                    str(edge.edge_id),
                )

        actual_pairs.add(
            (
                edge.from_evidence_id,
                edge.to_evidence_id,
            )
        )

    # ========================================================
    # 7. Expected continuation edges
    # ========================================================

    expected_pairs: set[
        tuple[
            uuid.UUID,
            uuid.UUID,
        ]
    ] = set()

    for index in range(
        1,
        len(events),
    ):

        previous_event = events[
            index - 1
        ]

        current_event = events[
            index
        ]

        previous_node = node_by_event.get(
            previous_event.event_id
        )

        current_node = node_by_event.get(
            current_event.event_id
        )

        # Historical events without evidence intentionally form
        # lineage boundaries.
        if (
            previous_node is None
            or current_node is None
        ):
            continue

        expected_pairs.add(
            (
                previous_node.evidence_id,
                current_node.evidence_id,
            )
        )

    for pair in expected_pairs:

        if pair not in actual_pairs:

            _issue(
                issues,
                "expected_edge_missing",
                (
                    f"{pair[0]}->{pair[1]}"
                ),
            )

    # ========================================================
    # 8. Chain consistency
    # ========================================================

    if not chain["valid"]:
        _issue(
            issues,
            "security_event_chain_invalid",
            str(
                chain.get(
                    "broken_at"
                )
            ),
        )

    # ========================================================
    # 9. Final verdict
    # ========================================================

    valid = (
        chain["valid"]
        and not issues
        and not truncated
    )

    return VerificationResult(
        valid=valid,
        chain_valid=bool(
            chain["valid"]
        ),
        chain_length=int(
            chain["length"]
        ),
        broken_at=(
            str(chain["broken_at"])
            if chain["broken_at"]
            else None
        ),
        nodes_checked=len(
            nodes
        ),
        edges_checked=len(
            edges
        ),
        truncated=truncated,
        issues=issues,
    )