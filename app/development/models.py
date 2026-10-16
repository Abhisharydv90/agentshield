"""Persistent Phase 1 agent-development records.

The existing Agent table remains the runtime identity. Phase 1 adds immutable
version records, deployment declarations, reusable templates, and human
membership bindings around that identity.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AgentVersion(Base):
    __tablename__ = "agent_versions"

    version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
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
    version: Mapped[str] = mapped_column(
        String(32), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="draft",
        server_default="draft",
        index=True,
    )
    description: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        default="",
        server_default="",
    )
    capabilities: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    manifest: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    content_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        server_default="now()",
        nullable=False,
    )
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "agent_id",
            "version",
            name="uq_agent_versions_tenant_agent_version",
        ),
        CheckConstraint(
            "status IN ('draft', 'published', 'revoked')",
            name="ck_agent_versions_status",
        ),
    )


class AgentDeployment(Base):
    """Control-plane declaration for deploying one immutable agent version.

    Phase 1 records the desired deployment; actual workload execution remains
    owned by the runtime/isolation layers.
    """

    __tablename__ = "agent_deployments"

    deployment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
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
    version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agent_versions.version_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    environment: Mapped[str] = mapped_column(
        String(32), nullable=False
    )
    region: Mapped[str] = mapped_column(
        String(64), nullable=False, default="local", server_default="local"
    )
    desired_replicas: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active", server_default="active", index=True
    )
    config: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        server_default="now()",
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
        nullable=False,
    )

    __table_args__ = (
        CheckConstraint(
            "environment <> '' AND length(environment) <= 32",
            name="ck_agent_deployments_environment",
        ),
        CheckConstraint(
            "region <> '' AND length(region) <= 64",
            name="ck_agent_deployments_region",
        ),
        CheckConstraint(
            "desired_replicas BETWEEN 1 AND 100",
            name="ck_agent_deployments_replicas",
        ),
        CheckConstraint(
            "status IN ('active', 'stopped', 'failed', 'retired')",
            name="ck_agent_deployments_status",
        ),
    )


class AgentTemplate(Base):
    __tablename__ = "agent_templates"

    template_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(120), nullable=False
    )
    description: Mapped[str] = mapped_column(
        String(500), nullable=False, default="", server_default=""
    )
    version: Mapped[str] = mapped_column(
        String(32), nullable=False
    )
    capabilities: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    manifest: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true", index=True
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        server_default="now()",
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "name", "version",
            name="uq_agent_templates_tenant_name_version",
        ),
    )


class AgentMember(Base):
    __tablename__ = "agent_members"

    membership_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
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
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(
        String(20), nullable=False, default="viewer", server_default="viewer"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        server_default="now()",
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "agent_id", "user_id",
            name="uq_agent_members_tenant_agent_user",
        ),
        CheckConstraint(
            "role IN ('viewer', 'operator', 'manager')",
            name="ck_agent_members_role",
        ),
    )


Index(
    "ix_agent_versions_agent_status",
    AgentVersion.agent_id,
    AgentVersion.status,
)
Index(
    "ix_agent_deployments_tenant_agent_status",
    AgentDeployment.tenant_id,
    AgentDeployment.agent_id,
    AgentDeployment.status,
)
Index(
    "ix_agent_members_agent_role",
    AgentMember.agent_id,
    AgentMember.role,
)
