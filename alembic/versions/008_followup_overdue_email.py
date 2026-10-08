"""Phase 19B — Add overdue_email_sent_at to follow_ups.

Adds a nullable timestamp column to track when the overdue email
notification was last sent for a follow-up task. This prevents
duplicate emails from being sent by the recurring check job.

Revision ID: 008_followup_overdue_email
Create Date: 2026-08-23
"""
from alembic import op
import sqlalchemy as sa

revision = "008_followup_overdue_email"
down_revision = "007_follow_up_system"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "follow_ups",
        sa.Column(
            "overdue_email_sent_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("follow_ups", "overdue_email_sent_at")
