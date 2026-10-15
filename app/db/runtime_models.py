"""
AURAGENT persistent runtime models.

These models implement the durable persistence boundary for:

- Agent lifecycle
- Sessions
- Tasks
- Task dependencies
- Checkpoints
- Workflow definitions
- Workflow steps
- Workflow runs
- Runtime events

Security principles:

1. All runtime records are tenant-scoped.
2. Raw task/result payloads are not required to live in the runtime DB.
3. Payload hashes provide integrity references.
4. Redacted metadata is explicitly separated from opaque artifacts.
5. Runtime events are operational events, not immutable audit records.
6. Security evidence remains owned by app.security.evidence.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models import Base


# ============================================================
# Timestamp helper
# ============================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================
# Runtime sessions
# ============================================================

class RuntimeSession(Base):
    """
    Durable execution session.

    A RuntimeSession is the runtime-plane concept of a conversation/
    execution context and must not be confused with an authentication
    browser session.
    """

    __tablename__ = "runtime_sessions"

    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "tenants.tenant_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "agents.agent_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    trace_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="active",
    )

    state_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    metadata_redacted: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    last_active_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index(
            "ix_runtime_sessions_tenant_agent",
            "tenant_id",
            "agent_id",
        ),
        Index(
            "ix_runtime_sessions_tenant_trace",
            "tenant_id",
            "trace_id",
        ),
        Index(
            "ix_runtime_sessions_tenant_activity",
            "tenant_id",
            "last_active_at",
        ),
    )


# ============================================================
# Workflow definitions
# ============================================================

class WorkflowDefinition(Base):
    """
    Immutable-versioned logical workflow definition.

    Multiple versions may exist for one tenant/workflow name.
    Exactly one version can be active according to service logic.
    """

    __tablename__ = "workflow_definitions"

    workflow_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "tenants.tenant_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
    )

    version: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    definition_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    definition_redacted: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "name",
            "version",
            name="uq_workflow_definitions_tenant_name_version",
        ),
        Index(
            "ix_workflow_definitions_tenant_active",
            "tenant_id",
            "active",
        ),
    )


# ============================================================
# Workflow steps
# ============================================================

class WorkflowStep(Base):
    """
    One logical step in a workflow definition.

    Dependency references are stored by stable step key rather than
    database row ordering.
    """

    __tablename__ = "workflow_steps"

    step_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    workflow_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "workflow_definitions.workflow_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    step_key: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
    )

    ordinal: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    task_kind: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )

    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "agents.agent_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    config_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    config_redacted: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    depends_on_step_keys: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )

    __table_args__ = (
        UniqueConstraint(
            "workflow_id",
            "step_key",
            name="uq_workflow_steps_workflow_key",
        ),
        Index(
            "ix_workflow_steps_workflow_ordinal",
            "workflow_id",
            "ordinal",
        ),
    )


# ============================================================
# Workflow runs
# ============================================================

class WorkflowRun(Base):
    """
    One execution instance of a workflow definition.
    """

    __tablename__ = "workflow_runs"

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "tenants.tenant_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    workflow_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "workflow_definitions.workflow_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "runtime_sessions.session_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    trace_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="created",
    )

    input_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    output_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    metadata_redacted: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index(
            "ix_workflow_runs_tenant_status",
            "tenant_id",
            "status",
        ),
        Index(
            "ix_workflow_runs_tenant_trace",
            "tenant_id",
            "trace_id",
        ),
    )


# ============================================================
# Runtime tasks
# ============================================================

class RuntimeTask(Base):
    """
    Durable executable task.

    Payloads remain opaque to the persistence layer.
    The database stores integrity hashes and redacted operational
    metadata rather than requiring raw sensitive task arguments.
    """

    __tablename__ = "runtime_tasks"

    task_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "tenants.tenant_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "agents.agent_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "runtime_sessions.session_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    workflow_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "workflow_runs.run_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    workflow_step_key: Mapped[str | None] = mapped_column(
        String(160),
        nullable=True,
    )

    trace_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    kind: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="created",
    )

    priority: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    payload_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    result_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    metadata_redacted: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    idempotency_key: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )

    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    max_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3,
        server_default="3",
    )

    timeout_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=300,
        server_default="300",
    )

    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_error_code: Mapped[str | None] = mapped_column(
        String(160),
        nullable=True,
    )

    latest_checkpoint_sequence: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "task_id",
            name="uq_runtime_tasks_tenant_task",
        ),
        UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_runtime_tasks_tenant_idempotency",
        ),
        CheckConstraint(
            "priority >= -100000 AND priority <= 100000",
            name="ck_runtime_tasks_priority_bounds",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_runtime_tasks_attempt_count",
        ),
        CheckConstraint(
            "max_attempts >= 1 AND max_attempts <= 100",
            name="ck_runtime_tasks_max_attempts",
        ),
        CheckConstraint(
            "timeout_seconds >= 1 AND timeout_seconds <= 86400",
            name="ck_runtime_tasks_timeout_bounds",
        ),
        Index(
            "ix_runtime_tasks_tenant_status_available",
            "tenant_id",
            "status",
            "available_at",
        ),
        Index(
            "ix_runtime_tasks_tenant_agent",
            "tenant_id",
            "agent_id",
        ),
        Index(
            "ix_runtime_tasks_tenant_trace",
            "tenant_id",
            "trace_id",
        ),
        Index(
            "ix_runtime_tasks_workflow",
            "tenant_id",
            "workflow_run_id",
        ),
    )


# ============================================================
# Runtime task dependencies
# ============================================================

class RuntimeTaskDependency(Base):
    """
    Directed dependency:

        task_id depends on depends_on_task_id
    """

    __tablename__ = "runtime_task_dependencies"

    dependency_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "tenants.tenant_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    task_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    depends_on_task_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "task_id"],
            [
                "runtime_tasks.tenant_id",
                "runtime_tasks.task_id",
            ],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "depends_on_task_id"],
            [
                "runtime_tasks.tenant_id",
                "runtime_tasks.task_id",
            ],
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "tenant_id",
            "task_id",
            "depends_on_task_id",
            name="uq_runtime_task_dependency",
        ),
        CheckConstraint(
            "task_id <> depends_on_task_id",
            name="ck_runtime_task_dependency_no_self",
        ),
        Index(
            "ix_runtime_task_dependencies_task",
            "tenant_id",
            "task_id",
        ),
        Index(
            "ix_runtime_task_dependencies_parent",
            "tenant_id",
            "depends_on_task_id",
        ),
    )


# ============================================================
# Runtime checkpoints
# ============================================================

class RuntimeCheckpoint(Base):
    """
    Durable checkpoint for recovery and workflow continuation.

    State is represented primarily by a digest. Raw state may live in
    object storage or another controlled persistence backend.
    """

    __tablename__ = "runtime_checkpoints"

    checkpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "tenants.tenant_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    task_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "runtime_tasks.task_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    sequence: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    state_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    metadata_redacted: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "task_id",
            "sequence",
            name="uq_runtime_checkpoint_task_sequence",
        ),
        CheckConstraint(
            "sequence >= 0",
            name="ck_runtime_checkpoint_sequence",
        ),
        Index(
            "ix_runtime_checkpoints_task",
            "tenant_id",
            "task_id",
            "sequence",
        ),
    )


# ============================================================
# Runtime operational events
# ============================================================

class RuntimeEvent(Base):
    """
    Operational event emitted by the runtime.

    This is intentionally separate from SecurityEvent.

    Security/audit records belong to the immutable evidence/audit
    subsystem. RuntimeEvent is for scheduler/state/workflow telemetry
    and lifecycle reconstruction.
    """

    __tablename__ = "runtime_events"

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "tenants.tenant_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    task_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "runtime_tasks.task_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "runtime_sessions.session_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    workflow_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "workflow_runs.run_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    trace_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    event_type: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )

    event_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="1",
    )

    correlation_id: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )

    payload_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    metadata_redacted: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    idempotency_key: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_runtime_events_tenant_idempotency",
        ),
        Index(
            "ix_runtime_events_tenant_trace_time",
            "tenant_id",
            "trace_id",
            "occurred_at",
        ),
        Index(
            "ix_runtime_events_task_time",
            "tenant_id",
            "task_id",
            "occurred_at",
        ),
        Index(
            "ix_runtime_events_workflow_time",
            "tenant_id",
            "workflow_run_id",
            "occurred_at",
        ),
    )