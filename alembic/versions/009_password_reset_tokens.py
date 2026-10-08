"""Phase 20 P1-A — Add password_reset_tokens table.

Creates the table for password reset tokens used by the forgot-password /
reset-password flow. Tokens are stored as bcrypt hashes (never plaintext)
with a configurable expiry and a one-time-use flag.

Revision ID: 009_password_reset_tokens
Create Date: 2026-08-25
"""
from alembic import op
import sqlalchemy as sa

revision = "009_password_reset_tokens"
down_revision = "008_followup_overdue_email"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "password_reset_tokens",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "user_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "token_hash",
            sa.String(255),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "used",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_password_reset_tokens_user_id",
        "password_reset_tokens",
        ["user_id"],
    )
    op.create_index(
        "ix_password_reset_tokens_token_hash",
        "password_reset_tokens",
        ["token_hash"],
    )
    op.create_index(
        "ix_password_reset_tokens_expires_at",
        "password_reset_tokens",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_password_reset_tokens_expires_at")
    op.drop_index("ix_password_reset_tokens_token_hash")
    op.drop_index("ix_password_reset_tokens_user_id")
    op.drop_table("password_reset_tokens")
