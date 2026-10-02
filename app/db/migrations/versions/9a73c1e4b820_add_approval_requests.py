"""
Add persisted security approval requests.

Revision ID: 9a73c1e4b820
Revises: 8c2f1a7d4b11
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "9a73c1e4b820"

down_revision: Union[
    str,
    None,
] = "8c2f1a7d4b11"

branch_labels: Union[
    str,
    Sequence[str],
    None,
] = None

depends_on: Union[
    str,
    Sequence[str],
    None,
] = None


def upgrade() -> None:

    op.create_table(
        "approval_requests",

        sa.Column(
            "approval_id",
            sa.UUID(),
            nullable=False,
        ),

        sa.Column(
            "tenant_id",
            sa.UUID(),
            nullable=False,
        ),

        sa.Column(
            "agent_id",
            sa.UUID(),
            nullable=False,
        ),

        sa.Column(
            "trace_id",
            sa.String(length=128),
            nullable=False,
        ),

        sa.Column(
            "action_fingerprint",
            sa.String(length=64),
            nullable=False,
        ),

        sa.Column(
            "action_payload",
            sa.JSON(),
            nullable=False,
        ),

        sa.Column(
            "policy_version",
            sa.String(length=64),
            nullable=False,
        ),

        sa.Column(
            "state",
            sa.String(length=20),
            nullable=False,
        ),

        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),

        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),

        sa.Column(
            "decided_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),

        sa.Column(
            "decided_by_user_id",
            sa.UUID(),
            nullable=True,
        ),

        sa.Column(
            "decision_reason",
            sa.String(length=500),
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

        sa.ForeignKeyConstraint(
            ["decided_by_user_id"],
            ["users.user_id"],
            ondelete="SET NULL",
        ),

        sa.PrimaryKeyConstraint(
            "approval_id"
        ),
    )

    op.create_index(
        "ix_approval_requests_tenant_id",
        "approval_requests",
        ["tenant_id"],
        unique=False,
    )

    op.create_index(
        "ix_approval_requests_agent_id",
        "approval_requests",
        ["agent_id"],
        unique=False,
    )

    op.create_index(
        "ix_approval_requests_trace_id",
        "approval_requests",
        ["trace_id"],
        unique=False,
    )

    op.create_index(
        "ix_approval_requests_action_fingerprint",
        "approval_requests",
        ["action_fingerprint"],
        unique=False,
    )

    op.create_index(
        "ix_approval_requests_state",
        "approval_requests",
        ["state"],
        unique=False,
    )

    op.create_index(
        "ix_approval_requests_expires_at",
        "approval_requests",
        ["expires_at"],
        unique=False,
    )

    op.create_index(
        "ix_approval_requests_decided_by_user_id",
        "approval_requests",
        ["decided_by_user_id"],
        unique=False,
    )

    op.create_index(
        "ix_approval_requests_tenant_state",
        "approval_requests",
        [
            "tenant_id",
            "state",
            "expires_at",
        ],
        unique=False,
    )

    op.create_index(
        "ix_approval_requests_agent_time",
        "approval_requests",
        [
            "agent_id",
            "requested_at",
        ],
        unique=False,
    )


def downgrade() -> None:

    op.drop_index(
        "ix_approval_requests_agent_time",
        table_name="approval_requests",
    )

    op.drop_index(
        "ix_approval_requests_tenant_state",
        table_name="approval_requests",
    )

    op.drop_index(
        "ix_approval_requests_decided_by_user_id",
        table_name="approval_requests",
    )

    op.drop_index(
        "ix_approval_requests_expires_at",
        table_name="approval_requests",
    )

    op.drop_index(
        "ix_approval_requests_state",
        table_name="approval_requests",
    )

    op.drop_index(
        "ix_approval_requests_action_fingerprint",
        table_name="approval_requests",
    )

    op.drop_index(
        "ix_approval_requests_trace_id",
        table_name="approval_requests",
    )

    op.drop_index(
        "ix_approval_requests_agent_id",
        table_name="approval_requests",
    )

    op.drop_index(
        "ix_approval_requests_tenant_id",
        table_name="approval_requests",
    )

    op.drop_table(
        "approval_requests"
    )