"""failed_jobs.resolved: String -> Boolean

Revision ID: 022_failed_jobs_resolved_boolean
Revises: 021_events_log_org_not_null
Create Date: 2026-10-08

C4 fix: the FailedJob.resolved column was declared as VARCHAR in the DB
while the Python model and queries treat it as a boolean
(.is_(False) renders "IS false", which Postgres rejects on varchar with
"argument of IS FALSE must be type boolean"). This migration normalizes
the stored string values ('true'/'false' in any case) and alters the
column to a real BOOLEAN.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "022_failed_jobs_resolved_boolean"
down_revision = "021_events_log_org_not_null"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Normalize legacy string values to canonical 'true'/'false' first,
    # so the USING cast below never fails on unexpected content.
    op.execute(
        sa.text(
            "UPDATE failed_jobs "
            "SET resolved = CASE "
            "WHEN lower(resolved) IN ('true', 't', '1', 'yes') THEN 'true' "
            "ELSE 'false' END "
            "WHERE lower(resolved) NOT IN ('true', 'false')"
        )
    )
    op.alter_column(
        "failed_jobs",
        "resolved",
        existing_type=sa.String(),
        type_=sa.Boolean(),
        existing_nullable=False,
        postgresql_using="resolved::boolean",
    )


def downgrade() -> None:
    op.alter_column(
        "failed_jobs",
        "resolved",
        existing_type=sa.Boolean(),
        type_=sa.String(),
        existing_nullable=False,
        postgresql_using="resolved::text",
    )
