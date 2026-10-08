"""Phase 23 — Add subscription plan fields to organizations.

Adds ``plan``, ``plan_started_at``, and ``trial_ends_at`` columns to the
``organizations`` table.  Existing rows default to ``plan='free'``.

Revision ID: 012_subscription_plan
Create Date: 2026-08-17
"""
from alembic import op
import sqlalchemy as sa

revision = "012_subscription_plan"
down_revision = "011_lead_assigned_to"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column(
            "plan",
            sa.String(),
            nullable=False,
            server_default="free",
        ),
    )
    op.add_column(
        "organizations",
        sa.Column("plan_started_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "organizations",
        sa.Column("trial_ends_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Backfill plan_started_at to created_at for existing orgs
    op.execute(
        "UPDATE organizations SET plan_started_at = created_at WHERE plan_started_at IS NULL"
    )


def downgrade() -> None:
    op.drop_column("organizations", "trial_ends_at")
    op.drop_column("organizations", "plan_started_at")
    op.drop_column("organizations", "plan")
