"""
Add evidence graph foundation.

Revision ID: acdee238fb9a
Revises: 9a73c1e4b820
Create Date: 2026-10-02

This migration contains ONLY the Evidence Graph changes.
Unrelated Alembic autogeneration differences are intentionally excluded.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# Revision identifiers, used by Alembic.
revision: str = "acdee238fb9a"
down_revision: Union[str, None] = "9a73c1e4b820"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ========================================================
    # Evidence nodes
    # ========================================================

    op.create_table(
        "evidence_nodes",
        sa.Column(
            "evidence_id",
            sa.UUID(),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            sa.UUID(),
            nullable=False,
        ),
        sa.Column(
            "trace_id",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "node_type",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "schema_version",
            sa.String(length=20),
            nullable=False,
        ),
        sa.Column(
            "artifact_hash",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "source",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "metadata_redacted",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "security_event_id",
            sa.UUID(),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),

        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            ondelete="CASCADE",
        ),

        sa.ForeignKeyConstraint(
            ["security_event_id"],
            ["security_events.event_id"],
            ondelete="SET NULL",
        ),

        # Required so EvidenceEdge can safely use:
        # (tenant_id, evidence_id) as a composite FK target.
        sa.UniqueConstraint(
            "tenant_id",
            "evidence_id",
            name="uq_evidence_nodes_tenant_evidence",
        ),

        sa.PrimaryKeyConstraint(
            "evidence_id",
        ),
    )

    # EvidenceNode indexes generated from the model.
    op.create_index(
        op.f("ix_evidence_nodes_artifact_hash"),
        "evidence_nodes",
        ["artifact_hash"],
        unique=False,
    )

    op.create_index(
        op.f("ix_evidence_nodes_security_event_id"),
        "evidence_nodes",
        ["security_event_id"],
        unique=False,
    )

    op.create_index(
        op.f("ix_evidence_nodes_tenant_id"),
        "evidence_nodes",
        ["tenant_id"],
        unique=False,
    )

    op.create_index(
        "ix_evidence_nodes_tenant_trace",
        "evidence_nodes",
        ["tenant_id", "trace_id"],
        unique=False,
    )

    op.create_index(
        "ix_evidence_nodes_tenant_type_time",
        "evidence_nodes",
        [
            "tenant_id",
            "node_type",
            sa.text("created_at DESC"),
        ],
        unique=False,
    )

    op.create_index(
        op.f("ix_evidence_nodes_trace_id"),
        "evidence_nodes",
        ["trace_id"],
        unique=False,
    )

    # ========================================================
    # Evidence edges
    # ========================================================

    op.create_table(
        "evidence_edges",
        sa.Column(
            "edge_id",
            sa.UUID(),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            sa.UUID(),
            nullable=False,
        ),
        sa.Column(
            "trace_id",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "from_evidence_id",
            sa.UUID(),
            nullable=False,
        ),
        sa.Column(
            "to_evidence_id",
            sa.UUID(),
            nullable=False,
        ),
        sa.Column(
            "relation",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),

        # Prevent meaningless self-referential edges.
        sa.CheckConstraint(
            "from_evidence_id <> to_evidence_id",
            name="ck_evidence_edge_not_self",
        ),

        # Every edge belongs to a tenant.
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            ondelete="CASCADE",
        ),

        # Tenant-scoped source node.
        sa.ForeignKeyConstraint(
            [
                "tenant_id",
                "from_evidence_id",
            ],
            [
                "evidence_nodes.tenant_id",
                "evidence_nodes.evidence_id",
            ],
            ondelete="CASCADE",
        ),

        # Tenant-scoped destination node.
        sa.ForeignKeyConstraint(
            [
                "tenant_id",
                "to_evidence_id",
            ],
            [
                "evidence_nodes.tenant_id",
                "evidence_nodes.evidence_id",
            ],
            ondelete="CASCADE",
        ),

        sa.UniqueConstraint(
            "tenant_id",
            "from_evidence_id",
            "to_evidence_id",
            "relation",
            name="uq_evidence_edge_relationship",
        ),

        sa.PrimaryKeyConstraint(
            "edge_id",
        ),
    )

    # EvidenceEdge indexes generated from the model.
    op.create_index(
        "ix_evidence_edges_from",
        "evidence_edges",
        ["tenant_id", "from_evidence_id"],
        unique=False,
    )

    op.create_index(
        op.f("ix_evidence_edges_tenant_id"),
        "evidence_edges",
        ["tenant_id"],
        unique=False,
    )

    op.create_index(
        "ix_evidence_edges_tenant_trace",
        "evidence_edges",
        ["tenant_id", "trace_id"],
        unique=False,
    )

    op.create_index(
        "ix_evidence_edges_to",
        "evidence_edges",
        ["tenant_id", "to_evidence_id"],
        unique=False,
    )

    op.create_index(
        op.f("ix_evidence_edges_trace_id"),
        "evidence_edges",
        ["trace_id"],
        unique=False,
    )


def downgrade() -> None:
    # ========================================================
    # Evidence edges
    # ========================================================

    op.drop_index(
        op.f("ix_evidence_edges_trace_id"),
        table_name="evidence_edges",
    )

    op.drop_index(
        "ix_evidence_edges_to",
        table_name="evidence_edges",
    )

    op.drop_index(
        "ix_evidence_edges_tenant_trace",
        table_name="evidence_edges",
    )

    op.drop_index(
        op.f("ix_evidence_edges_tenant_id"),
        table_name="evidence_edges",
    )

    op.drop_index(
        "ix_evidence_edges_from",
        table_name="evidence_edges",
    )

    op.drop_table(
        "evidence_edges",
    )

    # ========================================================
    # Evidence nodes
    # ========================================================

    op.drop_index(
        op.f("ix_evidence_nodes_trace_id"),
        table_name="evidence_nodes",
    )

    op.drop_index(
        "ix_evidence_nodes_tenant_type_time",
        table_name="evidence_nodes",
    )

    op.drop_index(
        "ix_evidence_nodes_tenant_trace",
        table_name="evidence_nodes",
    )

    op.drop_index(
        op.f("ix_evidence_nodes_tenant_id"),
        table_name="evidence_nodes",
    )

    op.drop_index(
        op.f("ix_evidence_nodes_security_event_id"),
        table_name="evidence_nodes",
    )

    op.drop_index(
        op.f("ix_evidence_nodes_artifact_hash"),
        table_name="evidence_nodes",
    )

    op.drop_table(
        "evidence_nodes",
    )