"""
Database models.

Multi-tenancy: every security-relevant record carries a tenant_id. The hash
chain in security_events is scoped per tenant, so chains from different
customers never interleave.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    String,
    Integer,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    UniqueConstraint,
    CheckConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB


class Base(DeclarativeBase):
    pass


# ============================================================
# Tenant & API keys
# ============================================================

class Tenant(Base):
    """An isolated customer account. Every other record points to one."""

    __tablename__ = "tenants"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    slug: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default="active", nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class APIKey(Base):
    """An API key belonging to a tenant. Only the hash is stored."""

    __tablename__ = "api_keys"

    key_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    key_hash: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )


# ============================================================
# Users
# ============================================================

class User(Base):
    """
    A human user belonging to a tenant.
    One tenant can have multiple users.
    """

    __tablename__ = "users"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        default="",
    )
    role: Mapped[str] = mapped_column(
        String(20),
        default="owner",
        nullable=False,
    )
    email_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        default="active",
        nullable=False,
    )

    failed_login_attempts: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default="0",
        nullable=False,
    )

    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    session_version: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default="0",
        nullable=False,
    )


class TOTPCredential(Base):
    """
    TOTP secret + recovery codes for a user.
    """

    __tablename__ = "totp_credentials"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        primary_key=True,
    )
    secret: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    recovery_codes_hash: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class TenantSettings(Base):
    """
    Gateway-level settings for a tenant.
    """

    __tablename__ = "tenant_settings"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        primary_key=True,
    )
    inbound_scanner_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    pii_redaction_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    judge_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    alert_sounds: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    email_alerts: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


# ============================================================
# Agent identities
# ============================================================

class Agent(Base):
    """
    An AI agent identity belonging to a tenant.

    Distinct from APIKey — an agent is a *who*, an API key is a *how*.
    """

    __tablename__ = "agents"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        String(500),
        default="",
        nullable=False,
    )
    scopes: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        default="active",
        nullable=False,
    )
    api_key_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("api_keys.key_id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


# ============================================================
# Persisted human approval state
# ============================================================

class ApprovalRequest(Base):
    """
    Durable one-time authorization request for a high-risk agent action.

    The complete action payload and its SHA-256 fingerprint are stored
    together so an approval cannot be detached from the exact action
    that was originally presented to the human.

    state:
        pending
        approved
        denied
        expired
        consumed
    """

    __tablename__ = "approval_requests"

    approval_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.agent_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    trace_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )

    action_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    action_payload: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
    )

    policy_version: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    policy_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    capability_snapshot_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    decision_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    state: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        index=True,
    )

    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    decided_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    decision_reason: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )


# ============================================================
# Policies
# ============================================================

class Policy(Base):
    """
    A tenant's rule set evaluated by the deterministic policy engine.
    """

    __tablename__ = "policies"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        String(500),
        default="",
        nullable=False,
    )
    version: Mapped[str] = mapped_column(
        String(20),
        default="1.0.0",
        nullable=False,
    )
    active: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    rules: Mapped[list[dict]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


# ============================================================
# Webhooks
# ============================================================

class Webhook(Base):
    """
    An outbound HTTP webhook.
    """

    __tablename__ = "webhooks"

    webhook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    url: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        String(200),
        default="",
        nullable=False,
    )
    events: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    secret: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


# ============================================================
# Auth tokens
# ============================================================

class AuthToken(Base):
    """
    One-time tokens for password reset and email verification.
    """

    __tablename__ = "auth_tokens"

    token_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    request_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


# ============================================================
# Requests & security events
# ============================================================

class RequestLog(Base):
    """
    One row per inbound request handled by the gateway.
    """

    __tablename__ = "requests_log"

    request_id: Mapped[str] = mapped_column(
        String,
        primary_key=True,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    agent_identity: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )
    provider_model: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )
    total_tokens: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )
    latency_ms: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )
    outcome: Mapped[str] = mapped_column(
        String,
        default="allowed",
    )

class EvidenceNode(Base):
    """
    Cryptographically identifiable security evidence artifact.

    The payload itself is represented by artifact_hash. The optional
    metadata_redacted field is intended only for already-redacted,
    non-secret metadata.
    """

    __tablename__ = "evidence_nodes"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    trace_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )

    node_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    schema_version: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="1",
    )

    artifact_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    metadata_redacted: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    security_event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "security_events.event_id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "evidence_id",
            name="uq_evidence_nodes_tenant_evidence",
        ),
    )

class EvidenceEdge(Base):
    """
    Directed causal relationship between two evidence nodes.

    Composite tenant-scoped foreign keys ensure that an edge cannot
    connect evidence belonging to different tenants.
    """

    __tablename__ = "evidence_edges"

    edge_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    trace_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )

    from_evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    to_evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    relation: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        ForeignKeyConstraint(
            [
                "tenant_id",
                "from_evidence_id",
            ],
            [
                "evidence_nodes.tenant_id",
                "evidence_nodes.evidence_id",
            ],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            [
                "tenant_id",
                "to_evidence_id",
            ],
            [
                "evidence_nodes.tenant_id",
                "evidence_nodes.evidence_id",
            ],
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "tenant_id",
            "from_evidence_id",
            "to_evidence_id",
            "relation",
            name="uq_evidence_edge_relationship",
        ),
        CheckConstraint(
            "from_evidence_id <> to_evidence_id",
            name="ck_evidence_edge_not_self",
        ),
    )

class SecurityEvent(Base):
    """
    Tamper-evident audit log.
    """

    __tablename__ = "security_events"

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    request_id: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    threat_category: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    action_taken: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    evaluator_reasoning: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    prev_hash: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    record_hash: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )


# ============================================================
# Indexes
# ============================================================

Index(
    "ix_security_events_tenant_time",
    SecurityEvent.tenant_id,
    SecurityEvent.timestamp.desc(),
)

Index(
    "ix_security_events_tenant_threat",
    SecurityEvent.tenant_id,
    SecurityEvent.threat_category,
)

Index(
    "ix_requests_log_tenant_time",
    RequestLog.tenant_id,
    RequestLog.timestamp.desc(),
)

Index(
    "ix_api_keys_tenant_active",
    APIKey.tenant_id,
    APIKey.revoked,
)

Index(
    "ix_webhooks_tenant_active",
    Webhook.tenant_id,
    Webhook.active,
)

Index(
    "ix_auth_tokens_user_kind_active",
    AuthToken.user_id,
    AuthToken.kind,
    AuthToken.used_at,
)

Index(
    "ix_approval_requests_tenant_state",
    ApprovalRequest.tenant_id,
    ApprovalRequest.state,
    ApprovalRequest.expires_at,
)

Index(
    "ix_approval_requests_agent_time",
    ApprovalRequest.agent_id,
    ApprovalRequest.requested_at.desc(),
)

Index(
    "ix_evidence_nodes_tenant_trace",
    EvidenceNode.tenant_id,
    EvidenceNode.trace_id,
)

Index(
    "ix_evidence_nodes_tenant_type_time",
    EvidenceNode.tenant_id,
    EvidenceNode.node_type,
    EvidenceNode.created_at.desc(),
)

Index(
    "ix_evidence_edges_tenant_trace",
    EvidenceEdge.tenant_id,
    EvidenceEdge.trace_id,
)

Index(
    "ix_evidence_edges_from",
    EvidenceEdge.tenant_id,
    EvidenceEdge.from_evidence_id,
)

Index(
    "ix_evidence_edges_to",
    EvidenceEdge.tenant_id,
    EvidenceEdge.to_evidence_id,
)

Index(
    "uq_agents_api_key_id",
    Agent.api_key_id,
    unique=True,
    postgresql_where=Agent.api_key_id.is_not(None),
)