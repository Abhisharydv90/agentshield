"""Deterministic causal candidate reconstruction."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Iterable
from uuid import UUID

from .contracts import CauseCandidate, EvidenceEdgeView, EvidenceNodeView


_RELATION_WEIGHT = {
    "causes": 1.0,
    "derived_from": 0.95,
    "triggered": 0.9,
    "influenced": 0.75,
    "references": 0.55,
    "associated": 0.4,
}


def _score(distance: int, relation: str | None) -> float:
    base = 1.0 / (1.0 + max(distance, 0))
    weight = _RELATION_WEIGHT.get((relation or "").lower(), 0.5)
    return round(min(1.0, base * weight), 6)


def build_cause_candidates(
    *,
    target_evidence_id: UUID,
    nodes: Iterable[EvidenceNodeView],
    edges: Iterable[EvidenceEdgeView],
    max_candidates: int = 20,
    max_depth: int = 6,
) -> list[CauseCandidate]:
    node_map = {node.evidence_id: node for node in nodes}
    if target_evidence_id not in node_map:
        return []

    incoming: dict[UUID, list[EvidenceEdgeView]] = defaultdict(list)
    for edge in edges:
        incoming[edge.to_evidence_id].append(edge)

    queue: deque[tuple[UUID, int, EvidenceEdgeView | None]] = deque(
        [(target_evidence_id, 0, None)]
    )
    seen = {target_evidence_id}
    candidates: list[CauseCandidate] = []

    while queue and len(candidates) < max_candidates:
        current, distance, via_edge = queue.popleft()
        if distance >= max_depth:
            continue

        for edge in sorted(
            incoming.get(current, []),
            key=lambda item: (item.created_at, str(item.edge_id)),
            reverse=True,
        ):
            parent_id = edge.from_evidence_id
            if parent_id in seen:
                continue
            seen.add(parent_id)
            parent = node_map.get(parent_id)
            if parent is None:
                continue

            relation = edge.relation
            relation_text = relation.replace("_", " ")
            score = _score(distance + 1, relation)
            candidates.append(
                CauseCandidate(
                    evidence_id=parent.evidence_id,
                    node_type=parent.node_type,
                    relation=relation,
                    distance=distance + 1,
                    score=score,
                    explanation=(
                        f"{parent.node_type} is {relation_text} the "
                        f"target evidence at graph distance {distance + 1}."
                    ),
                )
            )
            queue.append((parent_id, distance + 1, edge))

    candidates.sort(
        key=lambda item: (-item.score, item.distance, str(item.evidence_id))
    )
    return candidates[:max_candidates]


def choose_trace_target(
    nodes: Iterable[EvidenceNodeView],
    edges: Iterable[EvidenceEdgeView],
) -> UUID | None:
    node_list = list(nodes)
    if not node_list:
        return None

    outgoing = {edge.from_evidence_id for edge in edges}
    terminal = [node for node in node_list if node.evidence_id not in outgoing]
    pool = terminal or node_list

    return max(
        pool,
        key=lambda node: (node.created_at, str(node.evidence_id)),
    ).evidence_id
