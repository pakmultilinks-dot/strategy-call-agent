"""Phase 6E — Make events_log.lead_id and organization_id nullable.

Webhook auth failures and configuration changes don't involve a Lead
or may not have org context, so both columns must be nullable to
support these audit event types:
  - webhook_auth_failed
  - webhook_secret_updated
  - webhook_secret_rotated

Revision ID: 005_eventlog_lead_nullable
Create Date: 2026-08-16
"""
from alembic import op

revision = "005_eventlog_lead_nullable"
down_revision = "004_org_branding_meeting"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop the NOT NULL constraints.  The FKs remain —
    # non-null values still must reference valid rows.
    op.execute("ALTER TABLE events_log ALTER COLUMN lead_id DROP NOT NULL")
    op.execute("ALTER TABLE events_log ALTER COLUMN organization_id DROP NOT NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE events_log ALTER COLUMN organization_id SET NOT NULL")
    op.execute("ALTER TABLE events_log ALTER COLUMN lead_id SET NOT NULL")
