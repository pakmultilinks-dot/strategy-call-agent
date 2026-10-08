"""Phase 20 P1-B — Replace startup DDL with Alembic migration.

Migrates the two startup-time DDL operations (from ``app/main.py``) into a
proper Alembic migration so they run once at upgrade time instead of on
every boot:

1. **LeadStatus enum values** — ``ALTER TYPE lead_status ADD VALUE IF NOT
   EXISTS`` for every value in the ``LeadStatus`` enum.  SQLAlchemy's
   ``create_all()`` does NOT alter existing enum types to add new values.

2. **processing_started_at column** — ``ALTER TABLE leads ADD COLUMN IF NOT
   EXISTS processing_started_at`` (Phase 8 optimistic pipeline lock).

Both operations are idempotent and safe to run on databases that already
have them (``IF NOT EXISTS`` / ``IF EXISTS`` guards).

Revision ID: 010_startup_ddl_values
Create Date: 2026-08-25
"""
from alembic import op
import sqlalchemy as sa

revision = "010_startup_ddl_values"
down_revision = "009_password_reset_tokens"
branch_labels = None
depends_on = None

# All values that should exist in the lead_status PostgreSQL enum.
_LEAD_STATUS_VALUES = [
    "pending",
    "scheduled",
    "accepted",
    "tentative",
    "declined",
    "not_interested",
    "reminded",
    "error",
    "completed",
]


def upgrade() -> None:
    # 1. Ensure every LeadStatus enum value exists in PostgreSQL.
    for val in _LEAD_STATUS_VALUES:
        op.execute(
            f"ALTER TYPE lead_status ADD VALUE IF NOT EXISTS '{val}'"
        )

    # 2. Add processing_started_at column if missing (Phase 8).
    op.execute(
        "ALTER TABLE leads ADD COLUMN IF NOT EXISTS "
        "processing_started_at TIMESTAMP WITH TIME ZONE NULL"
    )


def downgrade() -> None:
    # Enum values cannot be removed in PostgreSQL.
    # processing_started_at can be dropped.
    op.drop_column("leads", "processing_started_at")
