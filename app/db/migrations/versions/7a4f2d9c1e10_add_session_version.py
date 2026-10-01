"""
add session version for server-side session revocation

Revision ID: 7a4f2d9c1e10
Revises: dce8d7e9aa30
Create Date: 2026-10-01

Adds a monotonically increasing session_version to users.

Incrementing this value invalidates previously issued JWT sessions.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "7a4f2d9c1e10"

down_revision: Union[str, None] = "69ea0e49bf56"

branch_labels: Union[str, Sequence[str], None] = None

depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "session_version",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    op.drop_column(
        "users",
        "session_version",
    )