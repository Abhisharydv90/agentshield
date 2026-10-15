"""Forensic replay reconstruction — deliberately non-executable."""

from __future__ import annotations

from typing import Iterable

from .contracts import EvidenceEdgeView, EvidenceNodeView, ReplayStep
from .timeline import TimelineItem


def build_forensic_replay(
    *,
    timeline: Iterable[TimelineItem],
    nodes: Iterable[EvidenceNodeView],
    edges: Iterable[EvidenceEdgeView],
    max_steps: int = 500,
) -> list[ReplayStep]:
    node_map = {node.evidence_id: node for node in nodes}
    relation_map: dict = {}
    for edge in edges:
        relation_map.setdefault(edge.to_evidence_id, []).append(edge.relation)

    steps: list[ReplayStep] = []
    for item in list(timeline)[:max_steps]:
        node = node_map.get(item.evidence_id)
        relations = relation_map.get(item.evidence_id, [])
        relation_text = ", ".join(sorted(set(relations))) if relations else "none"

        detail = f"Observed evidence {item.evidence_id} ({item.node_type})"
        if item.action:
            detail += f"; observed action={item.action}"
        if item.threat_category:
            detail += f"; threat={item.threat_category}"
        detail += f"; incoming relations={relation_text}"

        steps.append(
            ReplayStep(
                sequence=item.sequence,
                timestamp=item.timestamp,
                evidence_id=item.evidence_id,
                event_type=item.node_type,
                description=detail,
                authority_context="forensic-observation-only",
                executable=False,
            )
        )

    return steps


def assert_non_executable(steps: Iterable[ReplayStep]) -> None:
    if any(step.executable for step in steps):
        raise RuntimeError("investigation replay must never be executable")
