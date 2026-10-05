"""
Stable Evidence Graph contracts.

These Pydantic models define the externally visible evidence API shape.

Privacy rule:
    evaluator_reasoning is NEVER part of EvidenceNodeResponse.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class EvidenceNodeResponse(BaseModel):
    evidence_id: UUID
    tenant_id: UUID
    trace_id: str
    node_type: str
    schema_version: str
    artifact_hash: str
    source: str
    metadata_redacted: dict[str, Any]
    security_event_id: UUID | None
    created_at: str


class EvidenceEdgeResponse(BaseModel):
    edge_id: UUID
    tenant_id: UUID
    trace_id: str
    from_evidence_id: UUID
    to_evidence_id: UUID
    relation: str
    created_at: str


class EvidencePageResponse(BaseModel):
    nodes: list[EvidenceNodeResponse]
    next_cursor: str | None
    has_more: bool


class EvidenceGraphResponse(BaseModel):
    root_evidence_id: UUID
    nodes: list[EvidenceNodeResponse]
    edges: list[EvidenceEdgeResponse]
    truncated: bool


class EvidenceIssueResponse(BaseModel):
    code: str
    detail: str


class EvidenceVerificationResponse(BaseModel):
    valid: bool
    chain_valid: bool
    chain_length: int
    broken_at: str | None
    nodes_checked: int
    edges_checked: int
    truncated: bool
    issues: list[EvidenceIssueResponse]
    verified_at: str


class EvidenceSummaryResponse(BaseModel):
    tenant: str
    node_count: int
    edge_count: int


class EvidenceExportResponse(BaseModel):
    schema_version: str = Field(default="7.0")
    exported_at: str
    tenant: str
    truncated: bool
    verification: EvidenceVerificationResponse
    nodes: list[EvidenceNodeResponse]
    edges: list[EvidenceEdgeResponse]
    privacy: dict[str, str]