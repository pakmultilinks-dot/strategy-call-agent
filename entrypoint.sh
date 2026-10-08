#!/usr/bin/env bash
# Docker entrypoint for strategy-call-agent (Phase 25).
# Runs Alembic migrations before starting the application server.
# Prevents "relation does not exist" errors in fresh deployments.
set -euo pipefail

echo "[entrypoint] Starting strategy-call-agent container..."
# SECURITY: never log the raw DATABASE_URL - it contains the DB password.
# Redact the userinfo section before printing.
_redacted_url="$(printf '%s' "${DATABASE_URL:-(not set)}" | sed -E 's#(://[^/:]+:)[^@]+@#\1***@#')"
echo "[entrypoint] Database URL: ${_redacted_url}"

# Run migrations - safe to run repeatedly (idempotent)
echo "[entrypoint] Running Alembic migrations..."
alembic upgrade head

echo "[entrypoint] Migrations complete. Starting application server..."

# Pass all arguments to CMD (e.g. gunicorn, uvicorn)
exec "$@"
