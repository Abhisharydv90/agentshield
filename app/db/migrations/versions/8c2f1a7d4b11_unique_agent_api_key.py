"""
Enforce one-to-one Agent <-> API key binding.

An API key must map to at most one Agent.

This prevents ambiguous agent identity at runtime.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "8c2f1a7d4b11"

down_revision: Union[
    str,
    None,
] = "7a4f2d9c1e10"

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


INDEX_NAME = "uq_agents_api_key_id"


def upgrade() -> None:

    bind = op.get_bind()

    duplicates = bind.execute(
        sa.text(
            """
            SELECT api_key_id, COUNT(*) AS agent_count
            FROM agents
            WHERE api_key_id IS NOT NULL
            GROUP BY api_key_id
            HAVING COUNT(*) > 1
            """
        )
    ).fetchall()

    if duplicates:

        formatted = ", ".join(
            str(row[0])
            for row in duplicates
        )

        raise RuntimeError(
            "Cannot enforce unique Agent/API-key binding. "
            "Duplicate api_key_id values exist for: "
            f"{formatted}"
        )

    op.create_index(
        INDEX_NAME,
        "agents",
        ["api_key_id"],
        unique=True,
        postgresql_where=sa.text(
            "api_key_id IS NOT NULL"
        ),
    )


def downgrade() -> None:

    op.drop_index(
        INDEX_NAME,
        table_name="agents",
    )