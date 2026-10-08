"""P1-A — Add subscription tracking fields to organizations.

Adds ``subscription_id`` and ``subscription_status`` columns to the
``organizations`` table for tracking payment provider state.

Revision ID: 018_org_subscription_fields
Create Date: 2026-08-30
"""
from alembic import op
import sqlalchemy as sa

revision = "018_org_subscription_fields"
down_revision = "017_org_form_field_mappings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column(
            "subscription_id",
            sa.String(),
            nullable=True,
            comment="Payment provider subscription ID (e.g. Stripe sub_xxx)",
        ),
    )
    op.add_column(
        "organizations",
        sa.Column(
            "subscription_status",
            sa.String(),
            nullable=True,
            comment="active | canceled | past_due | trialing",
        ),
    )


def downgrade() -> None:
    op.drop_column("organizations", "subscription_status")
    op.drop_column("organizations", "subscription_id")
