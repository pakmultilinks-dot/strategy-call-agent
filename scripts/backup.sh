#!/usr/bin/env bash
# ── Database Backup Script ────────────────────────────────────────────────────
# Phase 27 (P0-6): Production backup strategy
#
# Creates timestamped pg_dump backups of the PostgreSQL database.
# Designed for use in Docker (exec into the app container) or standalone.
#
# Usage:
#   ./scripts/backup.sh                    # Uses DATABASE_URL from environment
#   DATABASE_URL=... ./scripts/backup.sh   # Explicit connection string
#   ./scripts/backup.sh --retention 7      # Keep only last 7 backups
#
# Backups are saved to: ./backups/
# Each backup file is named: strategy_calls_YYYYMMDD_HHMMSS.dump
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
DATABASE_URL="${DATABASE_URL:-postgresql+psycopg2://postgres:postgres@localhost:5432/strategy_calls}"

# Parse --retention flag
while [[ $# -gt 0 ]]; do
    case "$1" in
        --retention)
            RETENTION_DAYS="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--retention DAYS]"
            echo ""
            echo "Options:"
            echo "  --retention DAYS  Number of days to keep backups (default: 30)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Ensure backup directory exists ───────────────────────────────────────────
mkdir -p "$BACKUP_DIR"

# ── Build timestamp ──────────────────────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/strategy_calls_${TIMESTAMP}.dump"

# ── Extract connection details from DATABASE_URL ─────────────────────────────
# Parse: postgresql+psycopg2://USER:PASS@HOST:PORT/DBNAME
DB_HOST=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:]*\):\([0-9]*\)/.*|\1|p')
DB_PORT=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:]*\):\([0-9]*\)/.*|\2|p')
DB_USER=$(echo "$DATABASE_URL" | sed -n 's|.*://\([^:]*\):.*@\([^/]*\)/.*|\1|p')
DB_NAME=$(echo "$DATABASE_URL" | sed -n 's|.*/\([^?]*\).*|\1|p')

# Handle URL-encoded passwords (e.g., %40 for @)
DB_PASS=$(echo "$DATABASE_URL" | sed -n 's|.*://[^:]*:\([^@]*\)@.*|\1|p')

if [[ -z "$DB_HOST" || -z "$DB_PORT" || -z "$DB_USER" || -z "$DB_NAME" ]]; then
    echo "ERROR: Could not parse DATABASE_URL"
    echo "Expected format: postgresql+psycopg2://USER:PASS@HOST:PORT/DBNAME"
    exit 1
fi

# ── Create backup ────────────────────────────────────────────────────────────
echo "[$(date -Iseconds)] Starting backup: $DB_NAME @ $DB_HOST:$DB_PORT"
echo "[$(date -Iseconds)] Output: $BACKUP_FILE"

export PGPASSWORD="$DB_PASS"
pg_dump \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    --format=custom \
    --compress=9 \
    --verbose \
    --no-owner \
    --no-privileges \
    -f "$BACKUP_FILE" \
    2>&1

unset PGPASSWORD

BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo "[$(date -Iseconds)] Backup complete: $BACKUP_FILE ($BACKUP_SIZE)"

# ── Retention: remove backups older than RETENTION_DAYS ──────────────────────
echo "[$(date -Iseconds)] Cleaning backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -name "strategy_calls_*.dump" -type f -mtime +"$RETENTION_DAYS" -delete -print | while read -r f; do
    echo "[$(date -Iseconds)] Removed old backup: $f"
done

REMAINING=$(find "$BACKUP_DIR" -name "strategy_calls_*.dump" -type f | wc -l)
echo "[$(date -Iseconds)] Retention complete: $REMAINING backup(s) remaining"

# ── Integrity check ──────────────────────────────────────────────────────────
# Verify the backup file is a valid custom-format archive
if pg_restore --list "$BACKUP_FILE" > /dev/null 2>&1; then
    echo "[$(date -Iseconds)] Integrity check passed: backup is valid"
else
    echo "[$(date -Iseconds)] WARNING: Integrity check failed! Backup may be corrupt."
    exit 1
fi

echo "[$(date -Iseconds)] Backup process finished successfully"
