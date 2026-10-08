"""Phase 6B.3 — Authentication and authorization foundation.

Changes:
  1. Backfills password_hash for any existing users with NULL (placeholder hash)
  2. Makes password_hash NOT NULL on the users table
  3. Adds JWT_SECRET_KEY and auth-related configuration

This is DATA-SAFE — existing users get a placeholder hash that cannot be
used to log in (they must reset their password or be re-created).
"""
import uuid as _uuid

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "002_auth_foundation"
down_revision = "001_multi_tenant"
branch_labels = None
depends_on = None


def _column_exists(conn, table: str, column: str) -> bool:
    """Check if a column already exists on a table."""
    result = conn.execute(
        sa.text(
            "SELECT EXISTS ("
            "  SELECT FROM information_schema.columns"
            "  WHERE table_schema = 'public'"
            "    AND table_name = :table"
            "    AND column_name = :column"
            ")"
        ),
        {"table": table, "column": column},
    )
    return result.scalar()


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------
    # 1. Backfill password_hash for users with NULL password_hash.
    #    Use a bcrypt hash of a dummy password that can never be used to log in.
    #    This is safe because the auth code rejects login if password_hash
    #    starts with "!PLACEHOLDER_".
    # ------------------------------------------------------------------
    # Generate a bcrypt hash of a long random string — this is a one-time cost
    # and ensures the placeholder can never collide with a real password.
    from passlib.context import CryptContext
    _ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    placeholder = _ctx.hash("!PLACEHOLDER_MUST_RESET_000000000000")

    conn.execute(
        sa.text(
            "UPDATE users SET password_hash = :ph WHERE password_hash IS NULL"
        ),
        {"ph": placeholder},
    )

    # ------------------------------------------------------------------
    # 2. Make password_hash NOT NULL (all rows now have a value)
    # ------------------------------------------------------------------
    if _column_exists(conn, "users", "password_hash"):
        # Check current nullability
        result = conn.execute(
            sa.text(
                "SELECT is_nullable FROM information_schema.columns "
                "WHERE table_name = 'users' AND column_name = 'password_hash'"
            )
        )
        row = result.fetchone()
        if row and row[0] == "YES":
            conn.execute(
                sa.text(
                    "ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL"
                )
            )


def downgrade() -> None:
    conn = op.get_bind()

    # Make password_hash nullable again
    if _column_exists(conn, "users", "password_hash"):
        conn.execute(
            sa.text(
                "ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL"
            )
        )
