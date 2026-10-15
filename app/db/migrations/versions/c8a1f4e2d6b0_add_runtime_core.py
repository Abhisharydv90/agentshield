"""
Create AURAGENT durable runtime core.

Revision ID: c8a1f4e2d6b0
Revises: 6d0c4e7a91b2
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "c8a1f4e2d6b0"
down_revision: Union[str, None] = "6d0c4e7a91b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ========================================================
    # Runtime sessions
    # ========================================================

    op.create_table(
        "runtime_sessions",
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "trace_id",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "state_version",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "metadata_redacted",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "last_active_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "ended_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.agent_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("session_id"),
    )

    op.create_index(
        "ix_runtime_sessions_tenant_agent",
        "runtime_sessions",
        ["tenant_id", "agent_id"],
        unique=False,
    )

    op.create_index(
        "ix_runtime_sessions_tenant_trace",
        "runtime_sessions",
        ["tenant_id", "trace_id"],
        unique=False,
    )

    op.create_index(
        "ix_runtime_sessions_tenant_activity",
        "runtime_sessions",
        ["tenant_id", "last_active_at"],
        unique=False,
    )

    # ========================================================
    # Workflow definitions
    # ========================================================

    op.create_table(
        "workflow_definitions",
        sa.Column(
            "workflow_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "name",
            sa.String(length=160),
            nullable=False,
        ),
        sa.Column(
            "version",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "active",
            sa.Boolean(),
            nullable=False,
        ),
        sa.Column(
            "definition_hash",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "definition_redacted",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("workflow_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "name",
            "version",
            name="uq_workflow_definitions_tenant_name_version",
        ),
    )

    op.create_index(
        "ix_workflow_definitions_tenant_active",
        "workflow_definitions",
        ["tenant_id", "active"],
        unique=False,
    )

    # ========================================================
    # Workflow steps
    # ========================================================

    op.create_table(
        "workflow_steps",
        sa.Column(
            "step_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "workflow_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "step_key",
            sa.String(length=160),
            nullable=False,
        ),
        sa.Column(
            "ordinal",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "task_kind",
            sa.String(length=120),
            nullable=False,
        ),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "config_hash",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "config_redacted",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "depends_on_step_keys",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["workflow_id"],
            ["workflow_definitions.workflow_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.agent_id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("step_id"),
        sa.UniqueConstraint(
            "workflow_id",
            "step_key",
            name="uq_workflow_steps_workflow_key",
        ),
    )

    op.create_index(
        "ix_workflow_steps_workflow_ordinal",
        "workflow_steps",
        ["workflow_id", "ordinal"],
        unique=False,
    )

    # ========================================================
    # Workflow runs
    # ========================================================

    op.create_table(
        "workflow_runs",
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "workflow_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "trace_id",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "input_hash",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "output_hash",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "metadata_redacted",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workflow_id"],
            ["workflow_definitions.workflow_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["runtime_sessions.session_id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("run_id"),
    )

    op.create_index(
        "ix_workflow_runs_tenant_status",
        "workflow_runs",
        ["tenant_id", "status"],
        unique=False,
    )

    op.create_index(
        "ix_workflow_runs_tenant_trace",
        "workflow_runs",
        ["tenant_id", "trace_id"],
        unique=False,
    )

    # ========================================================
    # Runtime tasks
    # ========================================================

    op.create_table(
        "runtime_tasks",
        sa.Column(
            "task_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "workflow_run_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "workflow_step_key",
            sa.String(length=160),
            nullable=True,
        ),
        sa.Column(
            "trace_id",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "kind",
            sa.String(length=160),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "priority",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "payload_hash",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "result_hash",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "metadata_redacted",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "idempotency_key",
            sa.String(length=200),
            nullable=True,
        ),
        sa.Column(
            "attempt_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "max_attempts",
            sa.Integer(),
            server_default="3",
            nullable=False,
        ),
        sa.Column(
            "timeout_seconds",
            sa.Integer(),
            server_default="300",
            nullable=False,
        ),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "last_error_code",
            sa.String(length=160),
            nullable=True,
        ),
        sa.Column(
            "latest_checkpoint_sequence",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.CheckConstraint(
            "priority >= -100000 AND priority <= 100000",
            name="ck_runtime_tasks_priority_bounds",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0",
            name="ck_runtime_tasks_attempt_count",
        ),
        sa.CheckConstraint(
            "max_attempts >= 1 AND max_attempts <= 100",
            name="ck_runtime_tasks_max_attempts",
        ),
        sa.CheckConstraint(
            "timeout_seconds >= 1 AND timeout_seconds <= 86400",
            name="ck_runtime_tasks_timeout_bounds",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.agent_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["runtime_sessions.session_id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["workflow_run_id"],
            ["workflow_runs.run_id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("task_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "task_id",
            name="uq_runtime_tasks_tenant_task",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_runtime_tasks_tenant_idempotency",
        ),
    )

    op.create_index(
        "ix_runtime_tasks_tenant_status_available",
        "runtime_tasks",
        ["tenant_id", "status", "available_at"],
        unique=False,
    )

    op.create_index(
        "ix_runtime_tasks_tenant_agent",
        "runtime_tasks",
        ["tenant_id", "agent_id"],
        unique=False,
    )

    op.create_index(
        "ix_runtime_tasks_tenant_trace",
        "runtime_tasks",
        ["tenant_id", "trace_id"],
        unique=False,
    )

    op.create_index(
        "ix_runtime_tasks_workflow",
        "runtime_tasks",
        ["tenant_id", "workflow_run_id"],
        unique=False,
    )

    # ========================================================
    # Task dependencies
    # ========================================================

    op.create_table(
        "runtime_task_dependencies",
        sa.Column(
            "dependency_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "task_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "depends_on_task_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.CheckConstraint(
            "task_id <> depends_on_task_id",
            name="ck_runtime_task_dependency_no_self",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "task_id"],
            [
                "runtime_tasks.tenant_id",
                "runtime_tasks.task_id",
            ],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "depends_on_task_id"],
            [
                "runtime_tasks.tenant_id",
                "runtime_tasks.task_id",
            ],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("dependency_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "task_id",
            "depends_on_task_id",
            name="uq_runtime_task_dependency",
        ),
    )

    op.create_index(
        "ix_runtime_task_dependencies_task",
        "runtime_task_dependencies",
        ["tenant_id", "task_id"],
        unique=False,
    )

    op.create_index(
        "ix_runtime_task_dependencies_parent",
        "runtime_task_dependencies",
        ["tenant_id", "depends_on_task_id"],
        unique=False,
    )

    # ========================================================
    # Checkpoints
    # ========================================================

    op.create_table(
        "runtime_checkpoints",
        sa.Column(
            "checkpoint_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "task_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "sequence",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "state_hash",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "metadata_redacted",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.CheckConstraint(
            "sequence >= 0",
            name="ck_runtime_checkpoint_sequence",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["runtime_tasks.task_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("checkpoint_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "task_id",
            "sequence",
            name="uq_runtime_checkpoint_task_sequence",
        ),
    )

    op.create_index(
        "ix_runtime_checkpoints_task",
        "runtime_checkpoints",
        ["tenant_id", "task_id", "sequence"],
        unique=False,
    )

    # ========================================================
    # Runtime events
    # ========================================================

    op.create_table(
        "runtime_events",
        sa.Column(
            "event_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "task_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "workflow_run_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "trace_id",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "event_type",
            sa.String(length=120),
            nullable=False,
        ),
        sa.Column(
            "event_version",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "correlation_id",
            sa.String(length=200),
            nullable=True,
        ),
        sa.Column(
            "payload_hash",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "metadata_redacted",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "idempotency_key",
            sa.String(length=200),
            nullable=True,
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["runtime_tasks.task_id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["runtime_sessions.session_id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["workflow_run_id"],
            ["workflow_runs.run_id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("event_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_runtime_events_tenant_idempotency",
        ),
    )

    op.create_index(
        "ix_runtime_events_tenant_trace_time",
        "runtime_events",
        ["tenant_id", "trace_id", "occurred_at"],
        unique=False,
    )

    op.create_index(
        "ix_runtime_events_task_time",
        "runtime_events",
        ["tenant_id", "task_id", "occurred_at"],
        unique=False,
    )

    op.create_index(
        "ix_runtime_events_workflow_time",
        "runtime_events",
        ["tenant_id", "workflow_run_id", "occurred_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_runtime_events_workflow_time",
        table_name="runtime_events",
    )
    op.drop_index(
        "ix_runtime_events_task_time",
        table_name="runtime_events",
    )
    op.drop_index(
        "ix_runtime_events_tenant_trace_time",
        table_name="runtime_events",
    )
    op.drop_table("runtime_events")

    op.drop_index(
        "ix_runtime_checkpoints_task",
        table_name="runtime_checkpoints",
    )
    op.drop_table("runtime_checkpoints")

    op.drop_index(
        "ix_runtime_task_dependencies_parent",
        table_name="runtime_task_dependencies",
    )
    op.drop_index(
        "ix_runtime_task_dependencies_task",
        table_name="runtime_task_dependencies",
    )
    op.drop_table("runtime_task_dependencies")

    op.drop_index(
        "ix_runtime_tasks_workflow",
        table_name="runtime_tasks",
    )
    op.drop_index(
        "ix_runtime_tasks_tenant_trace",
        table_name="runtime_tasks",
    )
    op.drop_index(
        "ix_runtime_tasks_tenant_agent",
        table_name="runtime_tasks",
    )
    op.drop_index(
        "ix_runtime_tasks_tenant_status_available",
        table_name="runtime_tasks",
    )
    op.drop_table("runtime_tasks")

    op.drop_index(
        "ix_workflow_runs_tenant_trace",
        table_name="workflow_runs",
    )
    op.drop_index(
        "ix_workflow_runs_tenant_status",
        table_name="workflow_runs",
    )
    op.drop_table("workflow_runs")

    op.drop_index(
        "ix_workflow_steps_workflow_ordinal",
        table_name="workflow_steps",
    )
    op.drop_table("workflow_steps")

    op.drop_index(
        "ix_workflow_definitions_tenant_active",
        table_name="workflow_definitions",
    )
    op.drop_table("workflow_definitions")

    op.drop_index(
        "ix_runtime_sessions_tenant_activity",
        table_name="runtime_sessions",
    )
    op.drop_index(
        "ix_runtime_sessions_tenant_trace",
        table_name="runtime_sessions",
    )
    op.drop_index(
        "ix_runtime_sessions_tenant_agent",
        table_name="runtime_sessions",
    )
    op.drop_table("runtime_sessions")