"""Phase 18 — Add follow-up system tables.

Creates:
  - follow_up_status enum (pending, in_progress, completed, cancelled)
  - follow_up_priority enum (low, medium, high, urgent)
  - follow_ups table with FKs to organizations, leads, users

Revision ID: 007_follow_up_system
Create Date: 2026-08-22
"""
from alembic import op
import sqlalchemy as sa

revision = "007_follow_up_system"
down_revision = "006_call_management_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create enum types
    follow_up_status_enum = sa.Enum(
        "pending", "in_progress", "completed", "cancelled",
        name="follow_up_status",
    )
    follow_up_status_enum.create(op.get_bind(), checkfirst=True)

    follow_up_priority_enum = sa.Enum(
        "low", "medium", "high", "urgent",
        name="follow_up_priority",
    )
    follow_up_priority_enum.create(op.get_bind(), checkfirst=True)

    # Create follow_ups table
    op.create_table(
        "follow_ups",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "lead_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("leads.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_by",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "assigned_to",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "priority",
            follow_up_priority_enum,
            nullable=False,
            server_default="medium",
        ),
        sa.Column(
            "status",
            follow_up_status_enum,
            nullable=False,
            server_default="pending",
        ),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "completed_by",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "cancelled_by",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # Indexes
    op.create_index("ix_follow_ups_organization_id", "follow_ups", ["organization_id"])
    op.create_index("ix_follow_ups_lead_id", "follow_ups", ["lead_id"])
    op.create_index(
        "ix_follow_ups_org_status", "follow_ups", ["organization_id", "status"]
    )
    op.create_index(
        "ix_follow_ups_org_due_at", "follow_ups", ["organization_id", "due_at"]
    )
    op.create_index(
        "ix_follow_ups_status_due_at", "follow_ups", ["status", "due_at"]
    )


def downgrade() -> None:
    op.drop_table("follow_ups")
    sa.Enum(name="follow_up_priority").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="follow_up_status").drop(op.get_bind(), checkfirst=True)
