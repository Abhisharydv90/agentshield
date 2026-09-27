"""add multi-tenancy

Revision ID: dce8d7e9aa30
Revises: 583c11ef6983
Create Date: 2026-09-27 15:17:17.768198

Multi-tenancy migration.

Strategy:
  1. Create `tenants` and `api_keys` tables (empty).
  2. Insert a "default" tenant — everything existing will belong to it.
  3. Add `tenant_id` to `security_events` and `requests_log` as NULLABLE.
  4. Backfill all existing rows with the default tenant's UUID.
  5. Tighten `tenant_id` to NOT NULL.
  6. Add named foreign key constraints and indexes.

This is a "data-preserving" migration — no rows are lost. On rollback, the
tenant_id columns are dropped but the tenants themselves remain (this is
intentional — downgrading a multi-tenant DB is destructive by nature).
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "dce8d7e9aa30"
down_revision: Union[str, None] = "583c11ef6983"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------
    # 1. tenants
    # ------------------------------------------------------------
    op.create_table(
        "tenants",
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("tenant_id"),
    )
    op.create_index(op.f("ix_tenants_slug"), "tenants", ["slug"], unique=True)

    # ------------------------------------------------------------
    # 2. api_keys
    # ------------------------------------------------------------
    op.create_table(
        "api_keys",
        sa.Column("key_id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("key_prefix", sa.String(length=16), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("key_id"),
    )
    op.create_index(op.f("ix_api_keys_key_hash"), "api_keys", ["key_hash"], unique=True)
    op.create_index(op.f("ix_api_keys_tenant_id"), "api_keys", ["tenant_id"])
    op.create_index("ix_api_keys_tenant_active", "api_keys", ["tenant_id", "revoked"])

    # ------------------------------------------------------------
    # 3. Insert the default tenant
    # ------------------------------------------------------------
    # gen_random_uuid() is built into Postgres 13+. Neon runs 15+.
    op.execute(
        """
        INSERT INTO tenants (tenant_id, slug, name, status)
        VALUES (gen_random_uuid(), 'default', 'Default Tenant', 'active')
        ON CONFLICT (slug) DO NOTHING
        """
    )

    # ------------------------------------------------------------
    # 4. Add tenant_id to security_events (NULLABLE first)
    # ------------------------------------------------------------
    op.add_column(
        "security_events",
        sa.Column("tenant_id", sa.UUID(), nullable=True),
    )

    # Backfill from default tenant
    op.execute(
        """
        UPDATE security_events
        SET tenant_id = (SELECT tenant_id FROM tenants WHERE slug = 'default')
        WHERE tenant_id IS NULL
        """
    )

    # Tighten to NOT NULL
    op.alter_column("security_events", "tenant_id", nullable=False)

    # Add FK with an explicit name (required for clean rollback)
    op.create_foreign_key(
        "security_events_tenant_id_fkey",
        "security_events",
        "tenants",
        ["tenant_id"],
        ["tenant_id"],
        ondelete="CASCADE",
    )
    op.create_index(op.f("ix_security_events_tenant_id"), "security_events", ["tenant_id"])
    op.create_index("ix_security_events_tenant_threat", "security_events", ["tenant_id", "threat_category"])
    op.create_index(
        "ix_security_events_tenant_time",
        "security_events",
        ["tenant_id", sa.text("timestamp DESC")],
    )

    # ------------------------------------------------------------
    # 5. Add tenant_id to requests_log (NULLABLE first)
    # ------------------------------------------------------------
    op.add_column(
        "requests_log",
        sa.Column("tenant_id", sa.UUID(), nullable=True),
    )

    op.execute(
        """
        UPDATE requests_log
        SET tenant_id = (SELECT tenant_id FROM tenants WHERE slug = 'default')
        WHERE tenant_id IS NULL
        """
    )

    op.alter_column("requests_log", "tenant_id", nullable=False)

    op.create_foreign_key(
        "requests_log_tenant_id_fkey",
        "requests_log",
        "tenants",
        ["tenant_id"],
        ["tenant_id"],
        ondelete="CASCADE",
    )
    op.create_index(op.f("ix_requests_log_tenant_id"), "requests_log", ["tenant_id"])
    op.create_index(
        "ix_requests_log_tenant_time",
        "requests_log",
        ["tenant_id", sa.text("timestamp DESC")],
    )


def downgrade() -> None:
    # requests_log
    op.drop_index("ix_requests_log_tenant_time", table_name="requests_log")
    op.drop_index(op.f("ix_requests_log_tenant_id"), table_name="requests_log")
    op.drop_constraint("requests_log_tenant_id_fkey", "requests_log", type_="foreignkey")
    op.drop_column("requests_log", "tenant_id")

    # security_events
    op.drop_index("ix_security_events_tenant_time", table_name="security_events")
    op.drop_index("ix_security_events_tenant_threat", table_name="security_events")
    op.drop_index(op.f("ix_security_events_tenant_id"), table_name="security_events")
    op.drop_constraint("security_events_tenant_id_fkey", "security_events", type_="foreignkey")
    op.drop_column("security_events", "tenant_id")

    # api_keys
    op.drop_index("ix_api_keys_tenant_active", table_name="api_keys")
    op.drop_index(op.f("ix_api_keys_tenant_id"), table_name="api_keys")
    op.drop_index(op.f("ix_api_keys_key_hash"), table_name="api_keys")
    op.drop_table("api_keys")

    # tenants
    op.drop_index(op.f("ix_tenants_slug"), table_name="tenants")
    op.drop_table("tenants")