"""Enforce one active policy per tenant.

Revision ID: e1b7c8d9e0f1
Revises: 766ad2d4675e
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e1b7c8d9e0f1"
down_revision: Union[str, None] = "766ad2d4675e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Keep the newest active policy for each tenant and deactivate older
    # duplicates before creating the uniqueness constraint.
    op.execute(
        sa.text(
            """
            WITH ranked AS (
                SELECT
                    policy_id,
                    ROW_NUMBER() OVER (
                        PARTITION BY tenant_id
                        ORDER BY updated_at DESC, policy_id DESC
                    ) AS rn
                FROM policies
                WHERE active IS TRUE
            )
            UPDATE policies AS p
            SET active = FALSE
            FROM ranked AS r
            WHERE p.policy_id = r.policy_id
              AND r.rn > 1
            """
        )
    )

    op.create_index(
        "uq_policies_tenant_active",
        "policies",
        ["tenant_id"],
        unique=True,
        postgresql_where=sa.text("active IS TRUE"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_policies_tenant_active",
        table_name="policies",
    )
