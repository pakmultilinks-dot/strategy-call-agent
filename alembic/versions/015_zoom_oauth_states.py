"""Phase 6B.5 — Create zoom_oauth_states table (Step 3).

Creates the ``zoom_oauth_states`` table for storing CSRF state tokens
during the Zoom OAuth2 Web Application flow.  Mirrors the existing
``google_oauth_states`` table exactly in structure and indexing.

Columns:
  - id:             UUID primary key
  - organization_id: FK → organizations.id (CASCADE)
  - user_id:        FK → users.id (CASCADE)
  - state_token:    unique, indexed — the CSRF token
  - redirect_uri:   where Zoom redirects after consent
  - scopes:         JSON — granted OAuth scopes (audit)
  - expires_at:     indexed — TTL enforcement
  - used:           bool — single-use enforcement
  - created_at:     auto-set on insert

Revision ID: 015_zoom_oauth_states
Create Date: 2026-08-19
"""
from alembic import op
import sqlalchemy as sa

revision = "015_zoom_oauth_states"
down_revision = "014_zoom_lead_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "zoom_oauth_states",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", sa.dialects.postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.dialects.postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("state_token", sa.String(128), nullable=False, unique=True),
        sa.Column("redirect_uri", sa.String(512), nullable=False),
        sa.Column("scopes", sa.JSON, nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_zoom_oauth_states_org_id", "zoom_oauth_states", ["organization_id"])
    op.create_index("ix_zoom_oauth_states_state_token", "zoom_oauth_states", ["state_token"])
    op.create_index("ix_zoom_oauth_states_expires_at", "zoom_oauth_states", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_zoom_oauth_states_expires_at", table_name="zoom_oauth_states")
    op.drop_index("ix_zoom_oauth_states_state_token", table_name="zoom_oauth_states")
    op.drop_index("ix_zoom_oauth_states_org_id", table_name="zoom_oauth_states")
    op.drop_table("zoom_oauth_states")
