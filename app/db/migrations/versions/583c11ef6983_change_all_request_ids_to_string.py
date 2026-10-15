"""
Change request_id columns from UUID to String.

Revision ID: 583c11ef6983
Revises: 2e8bfd41ea46
Create Date: 2026-09-26 15:42:34.900576

This migration must explicitly remove the existing foreign key before
changing the PostgreSQL column types.

PostgreSQL cannot reliably perform the UUID -> VARCHAR conversion while
the FK relationship is still attached.

Upgrade:
    requests_log.request_id
        UUID -> VARCHAR

    security_events.request_id
        UUID -> VARCHAR

Downgrade:
    requests_log.request_id
        VARCHAR -> UUID

    security_events.request_id
        VARCHAR -> UUID
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# ---------------------------------------------------------------------------
# Revision identifiers
# ---------------------------------------------------------------------------

revision: str = "583c11ef6983"
down_revision: Union[str, None] = "2e8bfd41ea46"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ---------------------------------------------------------------------------
# Constraint name created by PostgreSQL for the FK in the initial migration
# ---------------------------------------------------------------------------

_SECURITY_EVENTS_REQUEST_ID_FK = (
    "security_events_request_id_fkey"
)


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------

def upgrade() -> None:
    """
    Convert both request_id columns from UUID to String.

    The FK must be dropped first because the referenced and referencing
    columns are changing type.
    """

    # 1. Remove the UUID foreign key relationship.
    op.drop_constraint(
        _SECURITY_EVENTS_REQUEST_ID_FK,
        "security_events",
        type_="foreignkey",
    )

    # 2. Convert the parent primary-key column.
    #
    # PostgreSQL performs the conversion explicitly through ::text so the
    # migration does not depend on an implicit cast.
    op.alter_column(
        "requests_log",
        "request_id",
        existing_type=sa.UUID(),
        type_=sa.String(),
        existing_nullable=False,
        postgresql_using="request_id::text",
    )

    # 3. Convert the child foreign-key column.
    op.alter_column(
        "security_events",
        "request_id",
        existing_type=sa.UUID(),
        type_=sa.String(),
        existing_nullable=True,
        postgresql_using="request_id::text",
    )

    # 4. Restore the FK using the new String columns.
    op.create_foreign_key(
        _SECURITY_EVENTS_REQUEST_ID_FK,
        "security_events",
        "requests_log",
        ["request_id"],
        ["request_id"],
        ondelete=None,
        onupdate=None,
    )


# ---------------------------------------------------------------------------
# Downgrade
# ---------------------------------------------------------------------------

def downgrade() -> None:
    """
    Convert both request_id columns from String back to UUID.
    """

    # 1. Remove the String foreign key relationship.
    op.drop_constraint(
        _SECURITY_EVENTS_REQUEST_ID_FK,
        "security_events",
        type_="foreignkey",
    )

    # 2. Convert the child column back to UUID.
    #
    # Existing values must contain valid UUID strings for downgrade to
    # succeed. NULL values remain NULL.
    op.alter_column(
        "security_events",
        "request_id",
        existing_type=sa.String(),
        type_=sa.UUID(),
        existing_nullable=True,
        postgresql_using="request_id::uuid",
    )

    # 3. Convert the parent primary-key column back to UUID.
    op.alter_column(
        "requests_log",
        "request_id",
        existing_type=sa.String(),
        type_=sa.UUID(),
        existing_nullable=False,
        postgresql_using="request_id::uuid",
    )

    # 4. Restore the original FK relationship.
    op.create_foreign_key(
        _SECURITY_EVENTS_REQUEST_ID_FK,
        "security_events",
        "requests_log",
        ["request_id"],
        ["request_id"],
        ondelete=None,
        onupdate=None,
    )