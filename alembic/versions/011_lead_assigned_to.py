"""Phase 22 — Add assigned_to to leads for team assignment.

Adds an ``assigned_to`` column to the ``leads`` table, referencing
``users.id``.  This enables round-robin or manual lead assignment
so that follow-ups, reminders, and notifications route to the correct
team member.

Revision ID: 011_lead_assigned_to
Create Date: 2026-08-17
"""
from alembic import op
import sqlalchemy as sa

revision = "011_lead_assigned_to"
down_revision = "010_startup_ddl_values"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "leads",
        sa.Column(
            "assigned_to",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_leads_assigned_to",
        "leads",
        ["assigned_to"],
    )
    op.create_index(
        "ix_leads_org_assigned",
        "leads",
        ["organization_id", "assigned_to"],
    )


def downgrade() -> None:
    op.drop_index("ix_leads_org_assigned", table_name="leads")
    op.drop_index("ix_leads_assigned_to", table_name="leads")
    op.drop_column("leads", "assigned_to")
