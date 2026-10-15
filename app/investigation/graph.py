"""Bounded graph traversal primitives for Phase 10."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterable
from uuid import UUID

from .contracts import EvidenceEdgeView, EvidenceNodeView


class InvestigationGraphError(ValueError):
    """Raised when an investigation graph violates a hard bound."""


@dataclass(frozen=True)
class BoundedGraph:
    root_evidence_id: UUID
    nodes: list[EvidenceNodeView]
    edges: list[EvidenceEdgeView]
    depth: int
    truncated: bool


def bounded_bfs(
    *,
    root_evidence_id: UUID,
    nodes: Iterable[EvidenceNodeView],
    edges: Iterable[EvidenceEdgeView],
    max_depth: int,
    max_nodes: int,
    max_edges: int,
) -> BoundedGraph | None:
    if max_depth < 0 or max_nodes < 1 or max_edges < 1:
        raise InvestigationGraphError("invalid investigation graph bounds")

    node_map = {node.evidence_id: node for node in nodes}
    root = node_map.get(root_evidence_id)
    if root is None:
        return None

    edge_list = sorted(
        edges,
        key=lambda edge: (edge.created_at, str(edge.edge_id)),
    )
    adjacency: dict[UUID, list[UUID]] = defaultdict(list)
    edge_lookup: dict[tuple[UUID, UUID], list[EvidenceEdgeView]] = defaultdict(list)

    for edge in edge_list:
        adjacency[edge.from_evidence_id].append(edge.to_evidence_id)
        adjacency[edge.to_evidence_id].append(edge.from_evidence_id)
        edge_lookup[(edge.from_evidence_id, edge.to_evidence_id)].append(edge)
        edge_lookup[(edge.to_evidence_id, edge.from_evidence_id)].append(edge)

    visited = {root_evidence_id}
    queue: deque[tuple[UUID, int]] = deque([(root_evidence_id, 0)])
    selected_edges: dict[UUID, EvidenceEdgeView] = {}
    truncated = False
    reached_depth = 0

    while queue:
        current, depth = queue.popleft()
        reached_depth = max(reached_depth, depth)
        if depth >= max_depth:
            continue

        for neighbor in adjacency.get(current, []):
            if len(visited) >= max_nodes:
                truncated = True
                break

            pair_edges = edge_lookup.get((current, neighbor), [])
            for edge in pair_edges:
                if len(selected_edges) >= max_edges:
                    truncated = True
                    break
                selected_edges[edge.edge_id] = edge

            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, depth + 1))

        if truncated and len(visited) >= max_nodes:
            break

    nodes_out = sorted(
        (node_map[node_id] for node_id in visited if node_id in node_map),
        key=lambda node: (node.created_at, str(node.evidence_id)),
    )
    edges_out = sorted(
        selected_edges.values(),
        key=lambda edge: (edge.created_at, str(edge.edge_id)),
    )

    if len(nodes_out) > max_nodes:
        nodes_out = nodes_out[:max_nodes]
        truncated = True
    if len(edges_out) > max_edges:
        edges_out = edges_out[:max_edges]
        truncated = True

    return BoundedGraph(
        root_evidence_id=root_evidence_id,
        nodes=nodes_out,
        edges=edges_out,
        depth=min(reached_depth, max_depth),
        truncated=truncated,
    )
