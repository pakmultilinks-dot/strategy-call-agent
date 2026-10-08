"""Alembic env.py — configured for strategy-call-agent multi-tenant migrations.

Reads DATABASE_URL from app.config.settings (same as the application).
Imports all ORM models so autogenerate and revision can inspect the schema.
"""
import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# ---------------------------------------------------------------------------
# Alembic Config
# ---------------------------------------------------------------------------
config = context.config

# Override sqlalchemy.url from app settings if not set in alembic.ini.
# This ensures the migration always uses the same DB as the running app.
from app.config import settings  # noqa: E402
config.set_main_option("sqlalchemy.url", settings.database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ---------------------------------------------------------------------------
# Target metadata — import ALL models so Alembic sees every table.
# ---------------------------------------------------------------------------
from app.models import Base  # noqa: E402  — leads, events_log, failed_jobs, schedule_config
import app.models_multi_tenant  # noqa: E402  — organizations, users, org_integrations, org_schedule_config

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — emits SQL without connecting."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode — connects and applies DDL."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
