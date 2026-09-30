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
    Index,
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
    )  # active | suspended | deleted
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
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


# ============================================================
# Users
# ============================================================

class User(Base):
    """
    A human user belonging to a tenant.
    One tenant can have multiple users (future: teams).
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
        String(255), unique=True, nullable=False, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    role: Mapped[str] = mapped_column(
        String(20), default="owner", nullable=False
    )  # owner | admin | member
    email_verified: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(20), default="active", nullable=False
    )

    # --- Brute-force lockout (added for auth hardening) ---
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class TOTPCredential(Base):
    """
    TOTP secret + recovery codes for a user.

    A row exists as soon as setup begins. The row is only "active" once
    verified_at is populated. Recovery codes are stored as SHA-256 hashes —
    never in plaintext. Each is consumed on use.
    """

    __tablename__ = "totp_credentials"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        primary_key=True,
    )
    secret: Mapped[str] = mapped_column(String(64), nullable=False)
    recovery_codes_hash: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class TenantSettings(Base):
    """
    Gateway-level settings for a tenant.
    One row per tenant. Created lazily on first read.
    """

    __tablename__ = "tenant_settings"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        primary_key=True,
    )
    inbound_scanner_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    pii_redaction_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    judge_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    alert_sounds: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    email_alerts: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class Agent(Base):
    """
    An AI agent identity belonging to a tenant.

    Distinct from APIKey — an agent is a *who* (identity with scopes),
    an API key is a *how* (credential). One agent typically uses one key.
    """

    __tablename__ = "agents"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    status: Mapped[str] = mapped_column(
        String(20), default="active", nullable=False
    )  # active | suspended | revoked
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
        DateTime(timezone=True), nullable=True
    )


class Policy(Base):
    """
    A tenant's rule set evaluated by the deterministic policy engine
    before the LLM Judge is invoked.

    Rules are stored as JSONB — the shape is:
        [
          {
            "tool_pattern": "db.*",
            "op": "read" | "write" | "delete" | "execute" | null,
            "target_allowlist": ["billing_*"],
            "target_denylist": ["users"],
            "decision": "allow" | "deny" | "step_up"
          }
        ]
    """

    __tablename__ = "policies"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    version: Mapped[str] = mapped_column(String(20), default="1.0.0", nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rules: Mapped[list[dict]] = mapped_column(JSONB, nullable=False, default=list)
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


class Webhook(Base):
    """
    An outbound HTTP webhook. AgentShield POSTs a signed JSON payload
    to `url` when any event in `events` fires for this tenant.

    The `secret` is used to compute an HMAC-SHA256 signature sent as
    `X-AgentShield-Signature`. Receivers verify it to authenticate
    the payload.
    """

    __tablename__ = "webhooks"

    webhook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    events: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    secret: Mapped[str] = mapped_column(String(64), nullable=False)
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
# Auth tokens (password reset + email verification)
# ============================================================

class AuthToken(Base):
    """
    One-time tokens for password reset and email verification.

    Only the SHA-256 of the raw token is stored — the plaintext is shown
    once, in the email link, and never persisted. A row is marked `used_at`
    on consumption and a fresh one is issued on resend, so tokens are
    single-use with an absolute expiry.
    """

    __tablename__ = "auth_tokens"

    token_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    # kind: "password_reset" | "email_verification"

    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    request_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


# ============================================================
# Requests & security events
# ============================================================

class RequestLog(Base):
    """One row per inbound request handled by the gateway."""

    __tablename__ = "requests_log"

    request_id: Mapped[str] = mapped_column(String, primary_key=True)
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
    agent_identity: Mapped[str] = mapped_column(String, nullable=False)
    provider_model: Mapped[str] = mapped_column(String, nullable=False)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    outcome: Mapped[str] = mapped_column(String, default="allowed")


class SecurityEvent(Base):
    """
    Tamper-evident audit log. The hash chain is scoped per tenant,
    so each tenant's chain is independent.
    """

    __tablename__ = "security_events"

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    request_id: Mapped[str | None] = mapped_column(String, nullable=True)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    threat_category: Mapped[str] = mapped_column(String, nullable=False)
    action_taken: Mapped[str] = mapped_column(String, nullable=False)
    evaluator_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Hash chain — prev_hash links to the previous event for THIS tenant
    prev_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    record_hash: Mapped[str] = mapped_column(String, nullable=False)


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