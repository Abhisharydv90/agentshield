"""Phase 10 Investigation Platform deterministic and safety tests."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from app.investigation.causality import build_cause_candidates, choose_trace_target
from app.investigation.contracts import (
    EvidenceEdgeView,
    EvidenceNodeView,
)
from app.investigation.graph import bounded_bfs
from app.investigation.replay import assert_non_executable, build_forensic_replay
from app.investigation.search import local_search
from app.investigation.service import build_incident_id


def node(node_type: str, *, trace_id: str = "trace-1") -> EvidenceNodeView:
    return EvidenceNodeView(
        evidence_id=uuid4(),
        trace_id=trace_id,
        node_type=node_type,
        schema_version="1",
        artifact_hash="a" * 64,
        source="test",
        metadata_redacted={"label": node_type},
        security_event_id=None,
        created_at=datetime.now(timezone.utc),
    )


def edge(a: EvidenceNodeView, b: EvidenceNodeView, relation: str) -> EvidenceEdgeView:
    return EvidenceEdgeView(
        edge_id=uuid4(),
        trace_id=a.trace_id,
        from_evidence_id=a.evidence_id,
        to_evidence_id=b.evidence_id,
        relation=relation,
        created_at=datetime.now(timezone.utc),
    )


def test_incident_id_is_deterministic_and_tenant_bound():
    tenant = UUID("11111111-1111-1111-1111-111111111111")
    first = build_incident_id(tenant_id=tenant, trace_id="abc")
    second = build_incident_id(tenant_id=tenant, trace_id="abc")
    third = build_incident_id(
        tenant_id=UUID("22222222-2222-2222-2222-222222222222"),
        trace_id="abc",
    )
    assert first == second
    assert first != third
    assert first.startswith("inc_")


def test_bounded_graph_respects_node_and_edge_caps():
    a = node("root")
    b = node("child")
    c = node("child-2")
    edges = [edge(a, b, "causes"), edge(b, c, "derived_from")]

    result = bounded_bfs(
        root_evidence_id=a.evidence_id,
        nodes=[a, b, c],
        edges=edges,
        max_depth=4,
        max_nodes=2,
        max_edges=10,
    )
    assert result is not None
    assert len(result.nodes) <= 2
    assert result.truncated is True


def test_causal_candidates_walk_backward():
    a = node("cause")
    b = node("middle")
    c = node("impact")
    edges = [edge(a, b, "causes"), edge(b, c, "derived_from")]

    target = choose_trace_target([a, b, c], edges)
    assert target == c.evidence_id

    causes = build_cause_candidates(
        target_evidence_id=c.evidence_id,
        nodes=[a, b, c],
        edges=edges,
        max_candidates=10,
        max_depth=5,
    )
    assert causes
    assert causes[0].evidence_id == b.evidence_id


def test_search_only_uses_indexed_redacted_fields():
    a = node("prompt_injection")
    b = node("normal")
    assert local_search(
        nodes=[a, b],
        query="prompt_injection",
        limit=10,
    )[0].evidence_id == a.evidence_id


def test_replay_is_never_executable():
    a = node("observed")
    replay = build_forensic_replay(
        timeline=[],
        nodes=[a],
        edges=[],
        max_steps=10,
    )
    assert replay == []
    assert_non_executable(replay)


def test_contract_artifact_hash_shape_is_not_silently_changed():
    a = node("observed")
    assert len(a.artifact_hash) == 64
    assert a.artifact_hash == "a" * 64


@pytest.mark.parametrize("bad_query", ["", "   "])
def test_empty_search_is_bounded_to_empty_result(bad_query: str):
    a = node("observed")
    assert local_search(nodes=[a], query=bad_query, limit=10) == []
