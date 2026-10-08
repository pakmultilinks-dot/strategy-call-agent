"""Phase 2 — Add Zoom meeting fields to leads table.

Adds nullable zoom_meeting_id and zoom_join_url columns to the leads
table. These fields store the Zoom meeting reference and join URL for
each lead, enabling the pipeline to persist Zoom meeting information
for reminder emails, cancellation, and rescheduling.

Both columns are nullable — existing leads (pre-Zoom migration) and
leads on organizations without Zoom integration will have NULL values.

Revision ID: 014_zoom_lead_fields
Create Date: 2026-08-19
"""
from alembic import op
import sqlalchemy as sa

revision = "014_zoom_lead_fields"
down_revision = "013_token_blocklist"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "leads",
        sa.Column(
            "zoom_meeting_id",
            sa.String(),
            nullable=True,
        ),
    )
    op.add_column(
        "leads",
        sa.Column(
            "zoom_join_url",
            sa.String(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("leads", "zoom_join_url")
    op.drop_column("leads", "zoom_meeting_id")
