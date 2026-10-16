"""add phase 1 agent development tables

Revision ID: p1a2b3c4d5e6
Revises: 6d0c4e7a91b2
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "p1a2b3c4d5e6"
down_revision: Union[str, None] = "6d0c4e7a91b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_versions",
        sa.Column("version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="draft", nullable=False),
        sa.Column("description", sa.String(length=500), server_default="", nullable=False),
        sa.Column("capabilities", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('draft', 'published', 'revoked')", name="ck_agent_versions_status"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.agent_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.user_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("version_id"),
        sa.UniqueConstraint("tenant_id", "agent_id", "version", name="uq_agent_versions_tenant_agent_version"),
    )
    op.create_index("ix_agent_versions_tenant_id", "agent_versions", ["tenant_id"], unique=False)
    op.create_index("ix_agent_versions_agent_id", "agent_versions", ["agent_id"], unique=False)
    op.create_index("ix_agent_versions_status", "agent_versions", ["status"], unique=False)
    op.create_index("ix_agent_versions_content_hash", "agent_versions", ["content_hash"], unique=False)
    op.create_index("ix_agent_versions_created_by_user_id", "agent_versions", ["created_by_user_id"], unique=False)
    op.create_index("ix_agent_versions_agent_status", "agent_versions", ["agent_id", "status"], unique=False)

    op.create_table(
        "agent_templates",
        sa.Column("template_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.String(length=500), server_default="", nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("capabilities", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.user_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("template_id"),
        sa.UniqueConstraint("tenant_id", "name", "version", name="uq_agent_templates_tenant_name_version"),
    )
    op.create_index("ix_agent_templates_tenant_id", "agent_templates", ["tenant_id"], unique=False)
    op.create_index("ix_agent_templates_active", "agent_templates", ["active"], unique=False)

    op.create_table(
        "agent_deployments",
        sa.Column("deployment_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("environment", sa.String(length=32), nullable=False),
        sa.Column("region", sa.String(length=64), server_default="local", nullable=False),
        sa.Column("desired_replicas", sa.Integer(), server_default="1", nullable=False),
        sa.Column("status", sa.String(length=20), server_default="active", nullable=False),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("environment <> '' AND length(environment) <= 32", name="ck_agent_deployments_environment"),
        sa.CheckConstraint("region <> '' AND length(region) <= 64", name="ck_agent_deployments_region"),
        sa.CheckConstraint("desired_replicas BETWEEN 1 AND 100", name="ck_agent_deployments_replicas"),
        sa.CheckConstraint("status IN ('active', 'stopped', 'failed', 'retired')", name="ck_agent_deployments_status"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.agent_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["version_id"], ["agent_versions.version_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.user_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("deployment_id"),
    )
    op.create_index("ix_agent_deployments_tenant_id", "agent_deployments", ["tenant_id"], unique=False)
    op.create_index("ix_agent_deployments_agent_id", "agent_deployments", ["agent_id"], unique=False)
    op.create_index("ix_agent_deployments_version_id", "agent_deployments", ["version_id"], unique=False)
    op.create_index("ix_agent_deployments_status", "agent_deployments", ["status"], unique=False)
    op.create_index(
        "ix_agent_deployments_tenant_agent_status",
        "agent_deployments",
        ["tenant_id", "agent_id", "status"],
        unique=False,
    )

    op.create_table(
        "agent_members",
        sa.Column("membership_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(length=20), server_default="viewer", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("role IN ('viewer', 'operator', 'manager')", name="ck_agent_members_role"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.agent_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.user_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("membership_id"),
        sa.UniqueConstraint("tenant_id", "agent_id", "user_id", name="uq_agent_members_tenant_agent_user"),
    )
    op.create_index("ix_agent_members_tenant_id", "agent_members", ["tenant_id"], unique=False)
    op.create_index("ix_agent_members_agent_id", "agent_members", ["agent_id"], unique=False)
    op.create_index("ix_agent_members_user_id", "agent_members", ["user_id"], unique=False)
    op.create_index("ix_agent_members_agent_role", "agent_members", ["agent_id", "role"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_agent_members_agent_role", table_name="agent_members")
    op.drop_index("ix_agent_members_user_id", table_name="agent_members")
    op.drop_index("ix_agent_members_agent_id", table_name="agent_members")
    op.drop_index("ix_agent_members_tenant_id", table_name="agent_members")
    op.drop_table("agent_members")

    op.drop_index("ix_agent_deployments_tenant_agent_status", table_name="agent_deployments")
    op.drop_index("ix_agent_deployments_status", table_name="agent_deployments")
    op.drop_index("ix_agent_deployments_version_id", table_name="agent_deployments")
    op.drop_index("ix_agent_deployments_agent_id", table_name="agent_deployments")
    op.drop_index("ix_agent_deployments_tenant_id", table_name="agent_deployments")
    op.drop_table("agent_deployments")

    op.drop_index("ix_agent_templates_active", table_name="agent_templates")
    op.drop_index("ix_agent_templates_tenant_id", table_name="agent_templates")
    op.drop_table("agent_templates")

    op.drop_index("ix_agent_versions_agent_status", table_name="agent_versions")
    op.drop_index("ix_agent_versions_created_by_user_id", table_name="agent_versions")
    op.drop_index("ix_agent_versions_content_hash", table_name="agent_versions")
    op.drop_index("ix_agent_versions_status", table_name="agent_versions")
    op.drop_index("ix_agent_versions_agent_id", table_name="agent_versions")
    op.drop_index("ix_agent_versions_tenant_id", table_name="agent_versions")
    op.drop_table("agent_versions")
