"""Stable, redacted contracts for the AURAGENT Investigation Platform."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class InvestigationLimits(BaseModel):
    """Hard bounds applied before database access."""

    model_config = ConfigDict(extra="forbid")

    max_nodes: int = Field(default=250, ge=1, le=1000)
    max_edges: int = Field(default=500, ge=1, le=2000)
    max_depth: int = Field(default=6, ge=0, le=12)
    max_timeline: int = Field(default=500, ge=1, le=1000)
    max_search: int = Field(default=100, ge=1, le=250)


class EvidenceNodeView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: UUID
    trace_id: str
    node_type: str
    schema_version: str
    artifact_hash: str
    source: str
    metadata_redacted: dict[str, Any]
    security_event_id: UUID | None
    created_at: datetime


class EvidenceEdgeView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    edge_id: UUID
    trace_id: str
    from_evidence_id: UUID
    to_evidence_id: UUID
    relation: str
    created_at: datetime


class GraphView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root_evidence_id: UUID
    nodes: list[EvidenceNodeView]
    edges: list[EvidenceEdgeView]
    depth: int
    truncated: bool


class TimelineItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sequence: int
    timestamp: datetime
    evidence_id: UUID
    node_type: str
    source: str
    action: str | None = None
    threat_category: str | None = None
    request_id: str | None = None


class CauseCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: UUID
    node_type: str
    relation: str | None
    distance: int
    score: float = Field(ge=0.0, le=1.0)
    explanation: str


class ReplayStep(BaseModel):
    """Forensic reconstruction step. Never executable."""

    model_config = ConfigDict(extra="forbid")

    sequence: int
    timestamp: datetime
    evidence_id: UUID
    event_type: str
    description: str
    authority_context: str = "not-executable"
    executable: bool = False


class ExplainabilityView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject_evidence_id: UUID
    summary: str
    chain: list[str]
    influence_sources: list[str]
    authority_statement: str
    evidence_statement: str


class SearchHit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: UUID
    trace_id: str
    node_type: str
    source: str
    artifact_hash: str
    created_at: datetime
    matched_fields: list[str]


class IncidentView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    tenant_id: UUID
    trace_id: str
    status: str
    first_seen: datetime | None
    last_seen: datetime | None
    node_count: int
    edge_count: int
    event_count: int
    root_evidence_id: UUID | None
    timeline: list[TimelineItem]
    causes: list[CauseCandidate]
    graph: GraphView | None
    explainability: ExplainabilityView | None
    forensic_replay: list[ReplayStep]
    bounded: bool
    replay_is_executable: bool = False
