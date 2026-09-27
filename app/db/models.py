"""
Database models.

Multi-tenancy: every security-relevant record carries a tenant_id. The hash
chain in security_events is scoped per tenant, so chains from different
customers never interleave.
"""

from __future__ import annotations

from datetime import datetime, timezone

import uuid
from datetime import datetime

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
from sqlalchemy.dialects.postgresql import UUID


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
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)  # active | suspended | deleted
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class APIKey(Base):
    """An API key belonging to a tenant. Only the hash is stored."""

    __tablename__ = "api_keys"

    key_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)  # first 12 chars, for display
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)  # sha256 hex
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
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
        UUID(as_uuid=True), ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    role: Mapped[str] = mapped_column(String(20), default="owner", nullable=False)  # owner | admin | member
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)

# ============================================================
# Requests & security events
# ============================================================

class RequestLog(Base):
    """One row per inbound request handled by the gateway."""

    __tablename__ = "requests_log"

    request_id: Mapped[str] = mapped_column(String, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False, index=True,
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
        UUID(as_uuid=True), ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    request_id: Mapped[str | None] = mapped_column(String, nullable=True)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
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

Index("ix_security_events_tenant_time", SecurityEvent.tenant_id, SecurityEvent.timestamp.desc())
Index("ix_security_events_tenant_threat", SecurityEvent.tenant_id, SecurityEvent.threat_category)
Index("ix_requests_log_tenant_time", RequestLog.tenant_id, RequestLog.timestamp.desc())
Index("ix_api_keys_tenant_active", APIKey.tenant_id, APIKey.revoked)