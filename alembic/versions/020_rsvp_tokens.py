"""Phase 4 — Add rsvp_tokens table for customer Accept/Decline RSVP workflow.

Creates the table for one-time RSVP tokens embedded in confirmation emails.
Each token is bcrypt-hashed, single-use, time-limited, and scoped to a lead.

Revision ID: 020_rsvp_tokens
Create Date: 2026-09-12
"""
from alembic import op
import sqlalchemy as sa

revision = "020_rsvp_tokens"
down_revision = "019_customer_timezone"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rsvp_tokens",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "lead_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("leads.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "token_hash",
            sa.String(255),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "choice",
            sa.String(16),
            nullable=False,
        ),
        sa.Column(
            "consumed",
            sa.Boolean,
            nullable=False,
            server_default="false",
        ),
        sa.Column(
            "consumed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_rsvp_tokens_lead_id", "rsvp_tokens", ["lead_id"])
    op.create_index("ix_rsvp_tokens_organization_id", "rsvp_tokens", ["organization_id"])
    op.create_index("ix_rsvp_tokens_token_hash", "rsvp_tokens", ["token_hash"], unique=True)
    op.create_index("ix_rsvp_tokens_expires_at", "rsvp_tokens", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_rsvp_tokens_expires_at", table_name="rsvp_tokens")
    op.drop_index("ix_rsvp_tokens_token_hash", table_name="rsvp_tokens")
    op.drop_index("ix_rsvp_tokens_organization_id", table_name="rsvp_tokens")
    op.drop_index("ix_rsvp_tokens_lead_id", table_name="rsvp_tokens")
    op.drop_table("rsvp_tokens")
