"""Phase 6D — Add organization branding fields and meeting duration.

Adds branding columns (sender_name, brand_color, tagline) to the
organizations table and meeting_duration_minutes to org_schedule_config.

All new columns are nullable for zero-downtime deployment.  Existing
rows will use platform defaults until the admin configures
organization-specific branding via the dashboard or API.

Revision ID: 004_org_branding_meeting (truncated to fit 32-char limit)
Create Date: 2026-08-15
"""
import sqlalchemy as sa
from alembic import op

revision = "004_org_branding_meeting"
down_revision = "003_org_webhook_secret"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Organization branding fields ──────────────────────────────────
    op.add_column(
        "organizations",
        sa.Column("sender_name", sa.String(), nullable=True),
    )
    op.add_column(
        "organizations",
        sa.Column("brand_color", sa.String(), nullable=True),
    )
    op.add_column(
        "organizations",
        sa.Column("tagline", sa.String(), nullable=True),
    )

    # ── OrgScheduleConfig meeting duration ─────────────────────────────
    op.add_column(
        "org_schedule_config",
        sa.Column("meeting_duration_minutes", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("org_schedule_config", "meeting_duration_minutes")
    op.drop_column("organizations", "tagline")
    op.drop_column("organizations", "brand_color")
    op.drop_column("organizations", "sender_name")
