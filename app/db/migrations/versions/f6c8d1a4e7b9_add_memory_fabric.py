"""add AURAGENT phase 6 memory fabric

Revision ID: f6c8d1a4e7b9
Revises: f4a7b9c1d2e3
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "f6c8d1a4e7b9"
down_revision = "f4a7b9c1d2e3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "memory_sources",
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_type", sa.String(length=40), nullable=False),
        sa.Column("uri", sa.String(length=2000), nullable=True),
        sa.Column("title", sa.String(length=500), nullable=True),
        sa.Column("expected_content_hash", sa.String(length=64), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("trust_class", sa.String(length=20), nullable=False),
        sa.Column("verification_method", sa.String(length=80), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("source_id"),
    )
    op.create_index("ix_memory_sources_tenant_created", "memory_sources", ["tenant_id", "created_at"])
    op.create_index("ix_memory_sources_tenant_hash", "memory_sources", ["tenant_id", "content_hash"])

    op.create_table(
        "memory_records",
        sa.Column("memory_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("namespace", sa.String(length=200), nullable=False),
        sa.Column("memory_key", sa.String(length=500), nullable=False),
        sa.Column("kind", sa.String(length=30), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("current_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("trust_class", sa.String(length=20), nullable=False),
        sa.Column("influence_class", sa.String(length=20), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("retention_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.agent_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("memory_id"),
        sa.UniqueConstraint("tenant_id", "namespace", "memory_key", name="uq_memory_records_tenant_namespace_key"),
    )
    op.create_index("ix_memory_records_tenant_agent", "memory_records", ["tenant_id", "agent_id"])
    op.create_index("ix_memory_records_tenant_namespace_status", "memory_records", ["tenant_id", "namespace", "status"])
    op.create_index("ix_memory_records_retention", "memory_records", ["tenant_id", "retention_until"])

    op.create_table(
        "memory_versions",
        sa.Column("version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("memory_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("version_hash", sa.String(length=64), nullable=False),
        sa.Column("previous_version_hash", sa.String(length=64), nullable=True),
        sa.Column("embedding", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("writer_agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["memory_id"], ["memory_records.memory_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("version_id"),
        sa.UniqueConstraint("tenant_id", "memory_id", "version_number", name="uq_memory_versions_memory_version"),
    )
    op.create_index("ix_memory_versions_tenant_memory", "memory_versions", ["tenant_id", "memory_id", "version_number"])
    op.create_index("ix_memory_versions_tenant_hash", "memory_versions", ["tenant_id", "version_hash"])

    op.create_table(
        "memory_lineage",
        sa.Column("lineage_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("memory_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation", sa.String(length=30), nullable=False),
        sa.Column("influence_class", sa.String(length=20), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("previous_lineage_hash", sa.String(length=64), nullable=True),
        sa.Column("record_hash", sa.String(length=64), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["memory_id"], ["memory_records.memory_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["version_id"], ["memory_versions.version_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("lineage_id"),
    )
    op.create_index("ix_memory_lineage_tenant_memory", "memory_lineage", ["tenant_id", "memory_id", "created_at"])
    op.create_index("ix_memory_lineage_tenant_hash", "memory_lineage", ["tenant_id", "record_hash"])


def downgrade() -> None:
    op.drop_index("ix_memory_lineage_tenant_hash", table_name="memory_lineage")
    op.drop_index("ix_memory_lineage_tenant_memory", table_name="memory_lineage")
    op.drop_table("memory_lineage")

    op.drop_index("ix_memory_versions_tenant_hash", table_name="memory_versions")
    op.drop_index("ix_memory_versions_tenant_memory", table_name="memory_versions")
    op.drop_table("memory_versions")

    op.drop_index("ix_memory_records_retention", table_name="memory_records")
    op.drop_index("ix_memory_records_tenant_namespace_status", table_name="memory_records")
    op.drop_index("ix_memory_records_tenant_agent", table_name="memory_records")
    op.drop_table("memory_records")

    op.drop_index("ix_memory_sources_tenant_hash", table_name="memory_sources")
    op.drop_index("ix_memory_sources_tenant_created", table_name="memory_sources")
    op.drop_table("memory_sources")
