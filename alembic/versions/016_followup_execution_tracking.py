"""Phase 7 Part 1 — Add email execution tracking columns to follow_ups.

Adds:
  - email_sent_at: timestamp of successful email send
  - email_retry_count: number of failed send attempts
  - last_error: most recent error message

Revision ID: 016_followup_execution_tracking
Create Date: 2026-08-20
"""
from alembic import op
import sqlalchemy as sa

revision = "016_followup_execution_tracking"
down_revision = "015_zoom_oauth_states"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "follow_ups",
        sa.Column(
            "email_sent_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "follow_ups",
        sa.Column(
            "email_retry_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "follow_ups",
        sa.Column(
            "last_error",
            sa.Text(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("follow_ups", "last_error")
    op.drop_column("follow_ups", "email_retry_count")
    op.drop_column("follow_ups", "email_sent_at")
