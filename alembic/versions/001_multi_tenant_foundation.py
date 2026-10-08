"""Phase 6B.1 - Multi-tenant foundation migration.

Creates the tenant boundary infrastructure and backfills existing data:

  1. Creates enum types: organization_status, user_role, user_status,
     integration_status
  2. Creates tables: organizations, users, org_integrations, org_schedule_config
  3. Adds organization_id (nullable) to: leads, events_log, failed_jobs
  4. Creates a default Organization representing the current single-tenant install
  5. Backfills all existing leads/events/failed_jobs with that default org_id
  6. Enforces NOT NULL on organization_id

This is a DATA-SAFE migration - all existing rows are preserved and assigned
to the default organization before the NOT NULL constraint is applied.

Revision ID: 001_multi_tenant
Create Date: 2026-08-14
"""
import uuid as _uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

# revision identifiers, used by Alembic.
revision = "001_multi_tenant"
down_revision = None
branch_labels = None
depends_on = None

# The default org UUID that represents the current single-tenant installation.
# This is deterministic so the migration is idempotent.
_DEFAULT_ORG_ID = _uuid.UUID("00000000-0000-0000-0000-000000000001")


def _table_exists(conn, name: str) -> bool:
    """Check if a table already exists in the database."""
    result = conn.execute(
        sa.text(
            "SELECT EXISTS ("
            "  SELECT FROM information_schema.tables"
            "  WHERE table_schema = 'public' AND table_name = :name"
            ")"
        ),
        {"name": name},
    )
    return result.scalar()


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


def _index_exists(conn, name: str) -> bool:
    """Check if a named index already exists."""
    result = conn.execute(
        sa.text(
            "SELECT EXISTS ("
            "  SELECT FROM pg_indexes"
            "  WHERE schemaname = 'public' AND indexname = :name"
            ")"
        ),
        {"name": name},
    )
    return result.scalar()


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------
    # 0. C2 FIX: bootstrap pre-multi-tenant tables on fresh databases.
    #    Migration 001 was written assuming leads/events_log/failed_jobs/
    #    schedule_config already exist (upgrade path).  On a FRESH database
    #    they don't, so op.add_column would raise "relation does not exist"
    #    and entrypoint.sh (set -e) would crash-loop every fresh deploy.
    #    Create them from the current model definitions when missing.
    #    This is idempotent (checkfirst) and safe for existing DBs.
    # ------------------------------------------------------------------
    try:
        from app.models import Base as _AppBase

        for _tname in ("leads", "events_log", "failed_jobs", "schedule_config"):
            _table = _AppBase.metadata.tables.get(_tname)
            if _table is not None:
                _table.create(bind=conn, checkfirst=True)
    except Exception as exc:
        # If model import fails (unexpected), log and continue - the
        # subsequent steps will raise informatively.
        print(f"[001] WARNING: could not bootstrap base tables: {exc}")

    # ------------------------------------------------------------------
    # 1. Create enum types (truly idempotent via DO blocks)
    # ------------------------------------------------------------------
    for enum_name, values in [
        ("organization_status", ["active", "suspended", "disabled"]),
        ("user_role", ["owner", "admin", "member"]),
        ("user_status", ["active", "disabled"]),
        ("integration_status", ["connected", "disconnected", "error", "pending"]),
    ]:
        values_sql = ", ".join(f"'{v}'" for v in values)
        conn.execute(
            sa.text(
                "DO $$ BEGIN"
                f"  CREATE TYPE {enum_name} AS ENUM ({values_sql});"
                " EXCEPTION WHEN duplicate_object THEN NULL;"
                " END $$"
            )
        )

    # ------------------------------------------------------------------
    # 2. organizations table (raw DDL to avoid SQLAlchemy enum auto-creation)
    # ------------------------------------------------------------------
    if not _table_exists(conn, "organizations"):
        conn.execute(sa.text(
            "CREATE TABLE organizations ("
            "  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),"
            "  name VARCHAR NOT NULL,"
            "  slug VARCHAR NOT NULL UNIQUE,"
            "  display_name VARCHAR,"
            "  status organization_status NOT NULL DEFAULT 'active',"
            "  timezone VARCHAR NOT NULL DEFAULT 'America/Chicago',"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        ))
        conn.execute(sa.text(
            "CREATE UNIQUE INDEX ix_organizations_slug ON organizations (slug)"
        ))

    # ------------------------------------------------------------------
    # 3. users table
    # ------------------------------------------------------------------
    if not _table_exists(conn, "users"):
        conn.execute(sa.text(
            "CREATE TABLE users ("
            "  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),"
            "  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,"
            "  email VARCHAR NOT NULL,"
            "  password_hash VARCHAR,"
            "  full_name VARCHAR,"
            "  role user_role NOT NULL DEFAULT 'member',"
            "  status user_status NOT NULL DEFAULT 'active',"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  UNIQUE (organization_id, email)"
            ")"
        ))
        conn.execute(sa.text(
            "CREATE INDEX ix_users_organization_id ON users (organization_id)"
        ))

    # ------------------------------------------------------------------
    # 4. org_integrations table
    # ------------------------------------------------------------------
    if not _table_exists(conn, "org_integrations"):
        conn.execute(sa.text(
            "CREATE TABLE org_integrations ("
            "  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),"
            "  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,"
            "  provider VARCHAR NOT NULL,"
            "  integration_type VARCHAR NOT NULL,"
            "  status integration_status NOT NULL DEFAULT 'pending',"
            "  credentials_encrypted TEXT,"
            "  metadata_json JSONB,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        ))
        conn.execute(sa.text(
            "CREATE INDEX ix_org_integrations_org_id ON org_integrations (organization_id)"
        ))
        conn.execute(sa.text(
            "CREATE INDEX ix_org_integrations_org_provider ON org_integrations (organization_id, provider)"
        ))

    # ------------------------------------------------------------------
    # 5. org_schedule_config table
    # ------------------------------------------------------------------
    if not _table_exists(conn, "org_schedule_config"):
        conn.execute(sa.text(
            "CREATE TABLE org_schedule_config ("
            "  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),"
            "  organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,"
            "  timezone VARCHAR NOT NULL DEFAULT 'America/Chicago',"
            "  reminder_enabled BOOLEAN NOT NULL DEFAULT true,"
            "  reminder_hour INTEGER NOT NULL DEFAULT 8,"
            "  reminder_minute INTEGER NOT NULL DEFAULT 0,"
            "  reminder_window_minutes INTEGER,"
            "  rsvp_poll_interval_minutes INTEGER NOT NULL DEFAULT 10,"
            "  scheduler_enabled BOOLEAN NOT NULL DEFAULT true,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        ))
        conn.execute(sa.text(
            "CREATE INDEX ix_org_schedule_config_org_id ON org_schedule_config (organization_id)"
        ))

    # ------------------------------------------------------------------
    # 6. Add organization_id to existing tables (nullable first)
    # ------------------------------------------------------------------
    for table_name in ["leads", "events_log", "failed_jobs"]:
        if not _column_exists(conn, table_name, "organization_id"):
            op.add_column(
                table_name,
                sa.Column("organization_id", PG_UUID(as_uuid=True), nullable=True),
            )

    # ------------------------------------------------------------------
    # 7. Seed the default organization
    # ------------------------------------------------------------------
    org_exists = conn.execute(
        sa.text("SELECT EXISTS (SELECT 1 FROM organizations WHERE id = :id)"),
        {"id": _DEFAULT_ORG_ID},
    ).scalar()

    if not org_exists:
        conn.execute(
            sa.text(
                "INSERT INTO organizations (id, name, slug, status, timezone)"
                " VALUES (:id, :name, :slug, 'active', 'America/Chicago')"
            ),
            {
                "id": _DEFAULT_ORG_ID,
                "name": "Integrated IT Trainings",
                "slug": "integrated-it-trainings",
            },
        )

    # ------------------------------------------------------------------
    # 8. Seed default org_schedule_config from existing schedule_config
    # ------------------------------------------------------------------
    schedule_exists = conn.execute(
        sa.text(
            "SELECT EXISTS ("
            "  SELECT 1 FROM org_schedule_config WHERE organization_id = :org_id"
            ")"
        ),
        {"org_id": _DEFAULT_ORG_ID},
    ).scalar()

    if not schedule_exists:
        # Read existing schedule_config if the table exists (it may not
        # on fresh databases - step 0 creates an empty one, so the
        # SELECT below is safe, but guard anyway).
        old_config = None
        if _table_exists(conn, "schedule_config"):
            old_config = conn.execute(
                sa.text("SELECT reminder_time, rsvp_poll_interval_minutes FROM schedule_config LIMIT 1")
            ).fetchone()

        if old_config:
            reminder_time = old_config[0]  # "HH:MM"
            hour, minute = reminder_time.split(":")
            poll_interval = old_config[1]
        else:
            hour, minute = "8", "0"
            poll_interval = 10

        conn.execute(
            sa.text(
                "INSERT INTO org_schedule_config"
                " (id, organization_id, timezone, reminder_enabled, reminder_hour,"
                "  reminder_minute, rsvp_poll_interval_minutes, scheduler_enabled)"
                " VALUES (:id, :org_id, 'America/Chicago', true, :hour, :minute,"
                "  :poll, true)"
            ),
            {
                "id": str(_uuid.uuid4()),
                "org_id": _DEFAULT_ORG_ID,
                "hour": int(hour),
                "minute": int(minute),
                "poll": poll_interval,
            },
        )

    # ------------------------------------------------------------------
    # 9. Backfill organization_id on existing rows
    # ------------------------------------------------------------------
    for table_name in ["leads", "events_log", "failed_jobs"]:
        conn.execute(
            sa.text(
                f"UPDATE {table_name}"
                " SET organization_id = :org_id"
                " WHERE organization_id IS NULL"
            ),
            {"org_id": _DEFAULT_ORG_ID},
        )

    # ------------------------------------------------------------------
    # 10. Add indexes on organization_id (before NOT NULL constraint)
    # ------------------------------------------------------------------
    for table_name, indexes in [
        ("leads", [
            ("ix_leads_organization_id", ["organization_id"]),
            ("ix_leads_org_status", ["organization_id", "status"]),
            ("ix_leads_org_email", ["organization_id", "email"]),
        ]),
        ("events_log", [
            ("ix_events_log_organization_id", ["organization_id"]),
            ("ix_events_log_org_created", ["organization_id", "created_at"]),
        ]),
        ("failed_jobs", [
            ("ix_failed_jobs_organization_id", ["organization_id"]),
            ("ix_failed_jobs_org_created", ["organization_id", "created_at"]),
        ]),
    ]:
        for idx_name, idx_cols in indexes:
            if not _index_exists(conn, idx_name):
                op.create_index(idx_name, table_name, idx_cols)

    # ------------------------------------------------------------------
    # 11. Enforce NOT NULL on organization_id (data is backfilled)
    # ------------------------------------------------------------------
    for table_name in ["leads", "events_log", "failed_jobs"]:
        # Check if any NULLs remain (safety guard).
        null_count = conn.execute(
            sa.text(
                f"SELECT COUNT(*) FROM {table_name} WHERE organization_id IS NULL"
            )
        ).scalar()
        if null_count == 0:
            conn.execute(
                sa.text(
                    f"ALTER TABLE {table_name}"
                    " ALTER COLUMN organization_id SET NOT NULL"
                )
            )
        else:
            # Should never happen after the backfill above, but guard.
            raise RuntimeError(
                f"Cannot enforce NOT NULL on {table_name}.organization_id:"
                f" {null_count} NULL rows remain."
            )

    # ------------------------------------------------------------------
    # 12. Add foreign key constraints (deferred to after backfill)
    # ------------------------------------------------------------------
    for table_name in ["leads", "events_log", "failed_jobs"]:
        fk_name = f"fk_{table_name}_organization_id"
        # Check if FK already exists.
        fk_exists = conn.execute(
            sa.text(
                "SELECT EXISTS ("
                "  SELECT 1 FROM information_schema.table_constraints"
                "  WHERE constraint_schema = 'public'"
                "    AND constraint_name = :name"
                ")"
            ),
            {"name": fk_name},
        ).scalar()
        if not fk_exists:
            conn.execute(
                sa.text(
                    f"ALTER TABLE {table_name}"
                    f" ADD CONSTRAINT {fk_name}"
                    f" FOREIGN KEY (organization_id)"
                    " REFERENCES organizations(id) ON DELETE RESTRICT"
                )
            )

    # ------------------------------------------------------------------
    # 13. Seed a default admin user for the default organization
    # ------------------------------------------------------------------
    user_exists = conn.execute(
        sa.text(
            "SELECT EXISTS ("
            "  SELECT 1 FROM users WHERE organization_id = :org_id"
            ")"
        ),
        {"org_id": _DEFAULT_ORG_ID},
    ).scalar()

    if not user_exists:
        conn.execute(
            sa.text(
                "INSERT INTO users (id, organization_id, email, full_name, role, status)"
                " VALUES (:id, :org_id, 'admin@integrated-it-trainings.local',"
                " 'Admin', 'owner', 'active')"
            ),
            {
                "id": str(_uuid.uuid4()),
                "org_id": _DEFAULT_ORG_ID,
            },
        )


def downgrade() -> None:
    """Revert the multi-tenant foundation.

    WARNING: This removes organization_id from existing tables and drops
    the new tables. Data in org-specific tables will be LOST.
    """
    conn = op.get_bind()

    # Drop new tables in reverse dependency order.
    for table_name in [
        "org_schedule_config",
        "org_integrations",
        "users",
    ]:
        if _table_exists(conn, table_name):
            op.drop_table(table_name)

    # Remove organization_id and FK from existing tables.
    for table_name in ["leads", "events_log", "failed_jobs"]:
        fk_name = f"fk_{table_name}_organization_id"
        # Drop indexes (use the actual names from the upgrade path).
        idx_names = {
            "leads": [
                "ix_leads_organization_id",
                "ix_leads_org_status",
                "ix_leads_org_email",
            ],
            "events_log": [
                "ix_events_log_organization_id",
                "ix_events_log_org_created",
            ],
            "failed_jobs": [
                "ix_failed_jobs_organization_id",
                "ix_failed_jobs_org_created",
            ],
        }
        for idx_name in idx_names.get(table_name, []):
            if _index_exists(conn, idx_name):
                op.drop_index(idx_name, table_name)

        # Drop FK constraint.
        fk_exists = conn.execute(
            sa.text(
                "SELECT EXISTS ("
                "  SELECT 1 FROM information_schema.table_constraints"
                "  WHERE constraint_schema = 'public'"
                "    AND constraint_name = :name"
                ")"
            ),
            {"name": fk_name},
        ).scalar()
        if fk_exists:
            op.drop_constraint(fk_name, table_name, type_="foreignkey")

        # Drop the column.
        if _column_exists(conn, table_name, "organization_id"):
            op.drop_column(table_name, "organization_id")

    # Drop organizations last.
    if _table_exists(conn, "organizations"):
        op.drop_table("organizations")

    # Drop enum types.
    for enum_name in ["integration_status", "user_status", "user_role", "organization_status"]:
        enum_exists = conn.execute(
            sa.text("SELECT EXISTS (SELECT 1 FROM pg_type WHERE typname = :name)"),
            {"name": enum_name},
        ).scalar()
        if enum_exists:
            sa.Enum(name=enum_name).drop(conn, checkfirst=True)
