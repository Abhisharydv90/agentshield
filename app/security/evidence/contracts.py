"""
Stable Evidence Fabric API contracts.

Privacy rule:
    evaluator_reasoning is never exposed by Evidence Fabric APIs.

Phase 8 additions:
    trace reconstruction
    forensic replay
    compliance evidence reporting
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


# ============================================================
# Core evidence
# ============================================================


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


# ============================================================
# Verification
# ============================================================


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


# ============================================================
# Summary
# ============================================================


class EvidenceSummaryResponse(BaseModel):
    tenant: str
    node_count: int
    edge_count: int


# ============================================================
# Trace reconstruction
# ============================================================


class EvidenceTraceRecordResponse(BaseModel):
    sequence: int

    event_id: UUID

    evidence_id: UUID | None

    timestamp: str

    request_id: str | None

    threat_category: str

    action_taken: str

    record_hash: str

    prev_hash: str | None

    artifact_hash: str | None

    node_type: str | None

    source: str | None

    metadata_redacted: dict[str, Any]

    record_hash_valid: bool

    evidence_hash_valid: bool

    predecessor_evidence_id: UUID | None

    predecessor_relation: str | None


class EvidenceTraceIntegrityResponse(BaseModel):
    status: str

    events_checked: int

    evidence_checked: int

    missing_evidence: int


class EvidenceTraceResponse(BaseModel):
    trace_id: str

    event_count: int

    node_count: int

    edge_count: int

    start_time: str | None

    end_time: str | None

    truncated: bool

    integrity: EvidenceTraceIntegrityResponse

    records: list[EvidenceTraceRecordResponse]


# ============================================================
# Forensic replay
# ============================================================


class EvidenceReplayResponse(BaseModel):
    trace_id: str

    mode: str = Field(
        default="forensic"
    )

    executed: bool = Field(
        default=False
    )

    mutations_performed: bool = Field(
        default=False
    )

    generated_at: str

    truncated: bool

    records: list[EvidenceTraceRecordResponse]


# ============================================================
# Compliance evidence package
# ============================================================


class EvidenceExportResponse(BaseModel):
    schema_version: str = Field(
        default="8.0"
    )

    package_hash: str

    exported_at: str

    tenant: str

    truncated: bool

    verification: EvidenceVerificationResponse

    nodes: list[EvidenceNodeResponse]

    edges: list[EvidenceEdgeResponse]

    privacy: dict[str, str]


class EvidenceComplianceReportResponse(BaseModel):
    schema_version: str = Field(
        default="8.0"
    )

    report_id: UUID

    generated_at: str

    tenant: str

    package_hash: str

    node_count: int

    edge_count: int

    truncated: bool

    verification: EvidenceVerificationResponse

    controls: dict[str, str]