"""Explainability assembled from redacted, machine-verifiable facts only."""

from __future__ import annotations

from typing import Iterable

from .contracts import EvidenceEdgeView, EvidenceNodeView, ExplainabilityView


def build_explainability(
    *,
    subject: EvidenceNodeView,
    nodes: Iterable[EvidenceNodeView],
    edges: Iterable[EvidenceEdgeView],
) -> ExplainabilityView:
    node_map = {node.evidence_id: node for node in nodes}
    incoming = [
        edge for edge in edges if edge.to_evidence_id == subject.evidence_id
    ]
    outgoing = [
        edge for edge in edges if edge.from_evidence_id == subject.evidence_id
    ]

    chain: list[str] = []
    influence_sources: list[str] = []

    for edge in sorted(
        incoming,
        key=lambda item: (item.created_at, str(item.edge_id)),
    ):
        source = node_map.get(edge.from_evidence_id)
        if source is not None:
            relation = edge.relation.replace("_", " ")
            chain.append(
                f"{source.node_type} ({source.evidence_id}) -> "
                f"{relation} -> {subject.node_type} ({subject.evidence_id})"
            )
            influence_sources.append(source.source)

    for edge in sorted(
        outgoing,
        key=lambda item: (item.created_at, str(item.edge_id)),
    ):
        target = node_map.get(edge.to_evidence_id)
        if target is not None:
            chain.append(
                f"{subject.node_type} ({subject.evidence_id}) -> "
                f"{edge.relation.replace('_', ' ')} -> "
                f"{target.node_type} ({target.evidence_id})"
            )

    summary = (
        f"Evidence {subject.evidence_id} is a {subject.node_type} artifact "
        f"from {subject.source}, created at {subject.created_at.isoformat()}."
    )

    return ExplainabilityView(
        subject_evidence_id=subject.evidence_id,
        summary=summary,
        chain=chain,
        influence_sources=sorted(set(influence_sources)),
        authority_statement=(
            "This explanation does not confer, increase, or infer authority. "
            "Influence and authority remain separate."
        ),
        evidence_statement=(
            "The explanation is derived from redacted evidence metadata and "
            "graph relationships; evaluator reasoning is intentionally excluded."
        ),
    )
