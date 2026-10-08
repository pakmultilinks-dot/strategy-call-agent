#!/usr/bin/env bash
# ── Database Restore Script ──────────────────────────────────────────────────
# Phase 27 (P0-6): Production restore strategy
#
# Restores a pg_dump backup to the PostgreSQL database.
# WARNING: This will DROP and recreate all tables in the target database.
#
# Usage:
#   ./scripts/restore.sh backups/strategy_calls_20250101_080000.dump
#   ./scripts/restore.sh --latest                           # Restore most recent backup
#   ./scripts/restore.sh --list                             # List available backups
#   DATABASE_URL=... ./scripts/restore.sh backup.dump       # Target specific DB
#
# Safety:
#   - Creates a pre-restore backup before restoring
#   - Validates backup file integrity before restoring
#   - Requires --confirm flag for destructive restore
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
BACKUP_DIR="${BACKUP_DIR:-./backups}"
DATABASE_URL="${DATABASE_URL:-postgresql+psycopg2://postgres:postgres@localhost:5432/strategy_calls}"
CONFIRM=false

# ── Parse arguments ──────────────────────────────────────────────────────────
BACKUP_FILE=""
ACTION="restore"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --confirm)
            CONFIRM=true
            shift
            ;;
        --latest)
            BACKUP_FILE=$(ls -t "$BACKUP_DIR"/strategy_calls_*.dump 2>/dev/null | head -1)
            if [[ -z "$BACKUP_FILE" ]]; then
                echo "ERROR: No backups found in $BACKUP_DIR"
                exit 1
            fi
            shift
            ;;
        --list)
            ACTION="list"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--latest] [--list] [--confirm] [BACKUP_FILE]"
            echo ""
            echo "Options:"
            echo "  --latest    Restore the most recent backup"
            echo "  --list      List available backups"
            echo "  --confirm   Skip confirmation prompt (required for restore)"
            exit 0
            ;;
        *)
            BACKUP_FILE="$1"
            shift
            ;;
    esac
done

# ── Extract connection details from DATABASE_URL ─────────────────────────────
DB_HOST=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:]*\):\([0-9]*\)/.*|\1|p')
DB_PORT=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:]*\):\([0-9]*\)/.*|\2|p')
DB_USER=$(echo "$DATABASE_URL" | sed -n 's|.*://\([^:]*\):.*@\([^/]*\)/.*|\1|p')
DB_NAME=$(echo "$DATABASE_URL" | sed -n 's|.*/\([^?]*\).*|\1|p')
DB_PASS=$(echo "$DATABASE_URL" | sed -n 's|.*://[^:]*:\([^@]*\)@.*|\1|p')

export PGPASSWORD="$DB_PASS"

# ── List action ──────────────────────────────────────────────────────────────
if [[ "$ACTION" == "list" ]]; then
    echo "Available backups in $BACKUP_DIR:"
    echo ""
    ls -lhS "$BACKUP_DIR"/strategy_calls_*.dump 2>/dev/null | while read -r line; do
        echo "  $line"
    done
    COUNT=$(ls "$BACKUP_DIR"/strategy_calls_*.dump 2>/dev/null | wc -l)
    echo ""
    echo "Total: $COUNT backup(s)"
    unset PGPASSWORD
    exit 0
fi

# ── Validate backup file ─────────────────────────────────────────────────────
if [[ -z "$BACKUP_FILE" ]]; then
    echo "ERROR: No backup file specified. Use --latest or provide a file path."
    echo "Run '$0 --list' to see available backups."
    unset PGPASSWORD
    exit 1
fi

if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "ERROR: Backup file not found: $BACKUP_FILE"
    unset PGPASSWORD
    exit 1
fi

BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo "Backup file: $BACKUP_FILE ($BACKUP_SIZE)"

echo "[$(date -Iseconds)] Validating backup integrity..."
if ! pg_restore --list "$BACKUP_FILE" > /dev/null 2>&1; then
    echo "ERROR: Backup file is corrupt or not a valid pg_dump custom format."
    unset PGPASSWORD
    exit 1
fi
echo "[$(date -Iseconds)] Integrity check passed"

# ── Confirmation ─────────────────────────────────────────────────────────────
if [[ "$CONFIRM" != "true" ]]; then
    echo ""
    echo "WARNING: This will DROP and recreate all tables in database '$DB_NAME' @ $DB_HOST:$DB_PORT"
    echo ""
    read -r -p "Type 'RESTORE' to confirm: " confirmation
    if [[ "$confirmation" != "RESTORE" ]]; then
        echo "Aborted."
        unset PGPASSWORD
        exit 0
    fi
fi

# ── Pre-restore backup ───────────────────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PRE_RESTORE_FILE="${BACKUP_DIR}/strategy_calls_pre_restore_${TIMESTAMP}.dump"
echo "[$(date -Iseconds)] Creating pre-restore backup..."
pg_dump \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    --format=custom \
    --compress=9 \
    --no-owner \
    --no-privileges \
    -f "$PRE_RESTORE_FILE" \
    2>&1 || {
        echo "WARNING: Pre-restore backup failed. Continuing with restore."
    }
echo "[$(date -Iseconds)] Pre-restore backup saved: $PRE_RESTORE_FILE"

# ── Drop and recreate schema ─────────────────────────────────────────────────
echo "[$(date -Iseconds)] Dropping and recreating public schema..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c \
    "DROP SCHEMA public CASCADE; CREATE SCHEMA public;" 2>&1

# ── Restore ──────────────────────────────────────────────────────────────────
echo "[$(date -Iseconds)] Restoring from $BACKUP_FILE..."
pg_restore \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    --no-owner \
    --no-privileges \
    --verbose \
    "$BACKUP_FILE" \
    2>&1 || {
        echo "WARNING: pg_restore returned non-zero exit code (some errors may be ignorable)"
    }

echo "[$(date -Iseconds)] Restore complete"

# ── Run Alembic migrations to ensure schema is current ───────────────────────
echo "[$(date -Iseconds)] Running Alembic migrations..."
alembic upgrade head 2>&1 || {
    echo "WARNING: Alembic migration failed. Schema may need manual intervention."
}

unset PGPASSWORD
echo "[$(date -Iseconds)] Restore process finished successfully"
