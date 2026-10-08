"""Phase 6B.5 — Add webhook_secret to organizations for per-org webhook auth.

Adds a nullable webhook_secret column to the organizations table.
This allows each organization to have its own webhook secret for
validating inbound Google Form webhook submissions.

Revision ID: 003_org_webhook_secret
Create Date: 2026-08-15
"""
import sqlalchemy as sa
from alembic import op

revision = "003_org_webhook_secret"
down_revision = "002_auth_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("webhook_secret", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("organizations", "webhook_secret")
