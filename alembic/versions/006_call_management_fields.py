"""Phase 12 — Add call management fields to leads table.

Adds columns needed for the call management feature:
  - call_outcome (enum: connected, completed, no_answer, voicemail, etc.)
  - call_notes (text)
  - call_duration_minutes (integer)
  - cancelled_at (timestamp)
  - reschedule_count (integer, default 0)

Revision ID: 006_call_management_fields
Create Date: 2026-08-21
"""
from alembic import op
import sqlalchemy as sa

revision = "006_call_management_fields"
down_revision = "005_eventlog_lead_nullable"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create the call_outcome enum type
    call_outcome_enum = sa.Enum(
        "connected", "completed", "no_answer", "voicemail", "busy",
        "wrong_number", "rescheduled", "cancelled", "no_show", "not_interested",
        name="call_outcome",
    )
    call_outcome_enum.create(op.get_bind(), checkfirst=True)

    # Add new columns to leads table
    op.add_column("leads", sa.Column("call_outcome", call_outcome_enum, nullable=True))
    op.add_column("leads", sa.Column("call_notes", sa.Text(), nullable=True))
    op.add_column("leads", sa.Column("call_duration_minutes", sa.Integer(), nullable=True))
    op.add_column("leads", sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("leads", sa.Column("reschedule_count", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    op.drop_column("leads", "reschedule_count")
    op.drop_column("leads", "cancelled_at")
    op.drop_column("leads", "call_duration_minutes")
    op.drop_column("leads", "call_notes")
    op.drop_column("leads", "call_outcome")
    # Drop the enum type
    sa.Enum(name="call_outcome").drop(op.get_bind(), checkfirst=True)
