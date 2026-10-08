"""events_log.organization_id NOT NULL

Revision ID: 021_events_log_org_not_null
Revises: 020_rsvp_tokens
Create Date: 2026-09-24

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "021_events_log_org_not_null"
down_revision = "020_rsvp_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # events_log.organization_id is currently nullable in the DB but the
    # application model declares nullable=False.  NULL rows ARE reachable:
    # _log_webhook_auth_failure() inserts EventLog(organization_id=None)
    # when the org slug doesn't resolve (e.g. attacker probing random
    # slugs), so clean them before the ALTER or the migration fails on
    # real databases and entrypoint.sh (set -e) crash-loops the deploy.
    op.execute(
        sa.text("DELETE FROM events_log WHERE organization_id IS NULL")
    )
    op.alter_column(
        "events_log",
        "organization_id",
        existing_type=sa.Uuid(),
        nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "events_log",
        "organization_id",
        existing_type=sa.Uuid(),
        nullable=True,
    )
