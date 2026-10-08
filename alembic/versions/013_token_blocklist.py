"""Phase 28 P1-D — Add token_blocklist table.

Creates the table for revoked JWT tokens used by the logout and password
change flows.  Each row stores the JWT's jti claim, user_id, and expiry.
``get_current_user()`` checks this table on every authenticated request.

Revision ID: 013_token_blocklist
Create Date: 2026-09-01
"""
from alembic import op
import sqlalchemy as sa

revision = "013_token_blocklist"
down_revision = "012_subscription_plan"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "token_blocklist",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "jti",
            sa.String(36),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "user_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "reason",
            sa.String(50),
            nullable=False,
            server_default="logout",
        ),
        sa.Column(
            "revoked_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
    )
    op.create_index("ix_token_blocklist_user_id", "token_blocklist", ["user_id"])
    op.create_index("ix_token_blocklist_expires_at", "token_blocklist", ["expires_at"])
    op.create_index("ix_token_blocklist_jti", "token_blocklist", ["jti"])


def downgrade() -> None:
    op.drop_index("ix_token_blocklist_jti", table_name="token_blocklist")
    op.drop_index("ix_token_blocklist_expires_at", table_name="token_blocklist")
    op.drop_index("ix_token_blocklist_user_id", table_name="token_blocklist")
    op.drop_table("token_blocklist")
