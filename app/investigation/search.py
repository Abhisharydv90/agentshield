"""Tenant-scoped bounded evidence search."""

from __future__ import annotations

from typing import Iterable

from .contracts import EvidenceNodeView, SearchHit


def local_search(
    *,
    nodes: Iterable[EvidenceNodeView],
    query: str,
    limit: int = 100,
    trace_id: str | None = None,
    node_type: str | None = None,
    source: str | None = None,
) -> list[SearchHit]:
    needle = query.strip().casefold()
    if not needle:
        return []

    results: list[SearchHit] = []
    for node in sorted(
        nodes,
        key=lambda item: (item.created_at, str(item.evidence_id)),
        reverse=True,
    ):
        if trace_id is not None and node.trace_id != trace_id:
            continue
        if node_type is not None and node.node_type != node_type:
            continue
        if source is not None and node.source != source:
            continue

        haystacks = {
            "trace_id": node.trace_id,
            "node_type": node.node_type,
            "artifact_hash": node.artifact_hash,
            "source": node.source,
            "metadata_redacted": _stable_json(node.metadata_redacted),
        }
        matched = [
            field_name
            for field_name, value in haystacks.items()
            if needle in value.casefold()
        ]

        if matched:
            results.append(
                SearchHit(
                    evidence_id=node.evidence_id,
                    trace_id=node.trace_id,
                    node_type=node.node_type,
                    source=node.source,
                    artifact_hash=node.artifact_hash,
                    created_at=node.created_at,
                    matched_fields=matched,
                )
            )
        if len(results) >= limit:
            break

    return results


def _stable_json(value: object) -> str:
    import json

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
