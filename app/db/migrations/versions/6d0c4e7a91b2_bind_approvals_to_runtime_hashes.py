"""Bind approvals to cryptographic runtime state.

Revision ID: 6d0c4e7a91b2
Revises: 3147fb0ad8df
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "6d0c4e7a91b2"
down_revision: Union[str, None] = "3147fb0ad8df"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_ZERO_HASH = "0" * 64


def upgrade() -> None:
    op.add_column(
        "approval_requests",
        sa.Column("policy_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "approval_requests",
        sa.Column(
            "capability_snapshot_hash",
            sa.String(length=64),
            nullable=True,
        ),
    )
    op.add_column(
        "approval_requests",
        sa.Column("decision_hash", sa.String(length=64), nullable=True),
    )

    # Historical approvals predate runtime cryptographic binding. Preserve
    # audit history but invalidate any still-live authorization.
    op.execute(
        sa.text(
            """
            UPDATE approval_requests
            SET
                policy_hash = :zero,
                capability_snapshot_hash = :zero,
                decision_hash = :zero,
                state = CASE
                    WHEN state IN ('pending', 'approved')
                    THEN 'expired'
                    ELSE state
                END,
                decision_reason = CASE
                    WHEN state IN ('pending', 'approved')
                    THEN 'approval_invalidated_by_7f2'
                    ELSE decision_reason
                END
            """
        ).bindparams(zero=_ZERO_HASH)
    )

    op.alter_column(
        "approval_requests",
        "policy_hash",
        existing_type=sa.String(length=64),
        nullable=False,
    )
    op.alter_column(
        "approval_requests",
        "capability_snapshot_hash",
        existing_type=sa.String(length=64),
        nullable=False,
    )
    op.alter_column(
        "approval_requests",
        "decision_hash",
        existing_type=sa.String(length=64),
        nullable=False,
    )

    op.create_index(
        "ix_approval_requests_policy_hash",
        "approval_requests",
        ["policy_hash"],
        unique=False,
    )
    op.create_index(
        "ix_approval_requests_capability_snapshot_hash",
        "approval_requests",
        ["capability_snapshot_hash"],
        unique=False,
    )
    op.create_index(
        "ix_approval_requests_decision_hash",
        "approval_requests",
        ["decision_hash"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_approval_requests_decision_hash",
        table_name="approval_requests",
    )
    op.drop_index(
        "ix_approval_requests_capability_snapshot_hash",
        table_name="approval_requests",
    )
    op.drop_index(
        "ix_approval_requests_policy_hash",
        table_name="approval_requests",
    )
    op.drop_column("approval_requests", "decision_hash")
    op.drop_column("approval_requests", "capability_snapshot_hash")
    op.drop_column("approval_requests", "policy_hash")
