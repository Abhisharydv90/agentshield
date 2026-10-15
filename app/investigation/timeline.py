"""Chronological reconstruction of evidence-bound security activity."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable
from uuid import UUID

from app.db.models import SecurityEvent

from .contracts import EvidenceNodeView, TimelineItem


def build_timeline(
    *,
    nodes: Iterable[EvidenceNodeView],
    events: Iterable[SecurityEvent],
    limit: int,
) -> list[TimelineItem]:
    event_map = {event.event_id: event for event in events}
    ordered = sorted(
        nodes,
        key=lambda node: (node.created_at, str(node.evidence_id)),
    )[:limit]

    out: list[TimelineItem] = []
    for index, node in enumerate(ordered, start=1):
        event = event_map.get(node.security_event_id)
        out.append(
            TimelineItem(
                sequence=index,
                timestamp=node.created_at,
                evidence_id=node.evidence_id,
                node_type=node.node_type,
                source=node.source,
                action=event.action_taken if event else None,
                threat_category=event.threat_category if event else None,
                request_id=event.request_id if event else None,
            )
        )
    return out


def event_ids(nodes: Iterable[EvidenceNodeView]) -> set[UUID]:
    return {
        node.security_event_id
        for node in nodes
        if node.security_event_id is not None
    }


def timeline_summary(timeline: Iterable[TimelineItem]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for item in timeline:
        counts[item.node_type] += 1
    return dict(sorted(counts.items()))
