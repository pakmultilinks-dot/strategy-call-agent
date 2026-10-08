"""Add customer_timezone column to leads table.

Stores the resolved IANA timezone name (e.g. "America/New_York") at parse
time so downstream consumers (calendar, email, reminders) can format
appointment times in the customer's local timezone.

Both the Google Form webhook handler and the dashboard CRUD handlers
populate this column when a lead is created or its appointment is
re-parsed.

Revision ID: 019_customer_timezone
Create Date: 2026-09-11
"""
from alembic import op
import sqlalchemy as sa

revision = "019_customer_timezone"
down_revision = "018_org_subscription_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "leads",
        sa.Column(
            "customer_timezone",
            sa.String(64),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("leads", "customer_timezone")
