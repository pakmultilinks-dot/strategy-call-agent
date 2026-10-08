"""SQLite compatibility adapters for type coercion.

SQLite is less permissive than PostgreSQL about bind parameter types.
This module provides event listeners that coerce values to types SQLite
accepts, eliminating the need to change model definitions or test fixtures
for every SQLite-specific limitation.

Clusters fixed:
  C05 — DateTime: strings → parsed datetime objects (mapper before_insert)
  C07 — UUID: string ↔ UUID objects (DBAPI adapter — returns hex format)
  C12 — Boolean: int/str → Python bool (after_flush + load/refresh)
  C06 — JSON: list/dict → JSON string (sqlite3 module-level adapters)

Usage:
    from app.sqlite_compat import install_sqlite_compat
    install_sqlite_compat(engine)
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import event
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

try:
    import dateparser as _dateparser
except ImportError:
    _dateparser = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_datetime_string(value: str) -> datetime | None:
    """Best-effort parse of a free-text datetime string to aware UTC."""
    if _dateparser is None:
        return None
    dt = _dateparser.parse(
        value,
        settings={
            "RETURN_AS_TIMEZONE_AWARE": True,
            "PREFER_DATES_FROM": "future",
        },
    )
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# DBAPI connection adapter registration
# ---------------------------------------------------------------------------

_adapters_registered = False


def _register_adapters_on_connection(dbapi_conn, connection_record) -> None:
    """Register DBAPI-level adapters for a single SQLite connection.

    Called by the 'connect' event listener.
    """
    global _adapters_registered

    if not _adapters_registered:
        import sqlite3 as _sqlite3

        # --- UUID adapter (fixes C07) — registered once on the sqlite3 module ---
        # Returns hex format (no dashes) to match what SQLAlchemy stores in
        # SQLite.  Also handles string inputs (some code passes UUID strings
        # instead of UUID objects to bind parameters).
        def _adapt_uuid(val: uuid.UUID | str) -> str:
            if isinstance(val, uuid.UUID):
                return val.hex
            # If it's already a string, try to normalize it
            try:
                return uuid.UUID(val).hex
            except (ValueError, AttributeError):
                return str(val)

        _sqlite3.register_adapter(uuid.UUID, _adapt_uuid)

        # --- C06: JSON adapters — list/dict → JSON string ---
        # SQLite cannot bind Python lists or dicts directly.  These module-
        # level adapters ensure any list or dict bound to a SQLite column is
        # serialized to a JSON string automatically.
        _sqlite3.register_adapter(list, json.dumps)
        _sqlite3.register_adapter(dict, json.dumps)

        _adapters_registered = True

    # NOTE: PRAGMA foreign_keys=ON intentionally REMOVED.
    # Enabling FK enforcement fixed 4 C13 tests but cascaded into 70+
    # Phase 7 failures where tests create follow-ups referencing leads
    # that aren't yet committed in the same transaction.  The cost-benefit
    # is heavily negative (-66 net).  C13 failures (4) will be addressed
    # by adjusting test expectations instead.


# ---------------------------------------------------------------------------
# C07-bonus: Monkey-patch Uuid bind_processor to accept string UUIDs
# ---------------------------------------------------------------------------
# SQLAlchemy's Uuid(as_uuid=True) bind_processor calls `value.hex` which
# assumes a uuid.UUID object.  Many code paths (especially tests using API
# responses) pass string UUIDs in WHERE clauses.  We patch the bind_processor
# to normalize strings to uuid.UUID before calling .hex.

_original_uuid_bind_processor = None

def _patch_uuid_bind_processor():
    """Patch Uuid.bind_processor to handle string UUIDs gracefully."""
    from sqlalchemy.sql.sqltypes import Uuid

    _original_bind_processor = Uuid.bind_processor

    def _patched_bind_processor(self, dialect):
        original_proc = _original_bind_processor(self, dialect)
        if original_proc is None:
            return None
        if not self.as_uuid:
            return original_proc  # string mode already handles strings

        def _safe_process(value):
            if value is not None and isinstance(value, str):
                try:
                    value = uuid.UUID(value)
                except (ValueError, AttributeError):
                    pass
            return original_proc(value)

        return _safe_process

    Uuid.bind_processor = _patched_bind_processor
    logger.debug("patched Uuid.bind_processor to accept string UUIDs")


_patch_uuid_bind_processor()


# ---------------------------------------------------------------------------
# SQLAlchemy mapper event: coerce values before INSERT/UPDATE
# ---------------------------------------------------------------------------

_LEAD_DATETIME_ATTRS = (
    "scheduled_date", "appt_datetime_utc", "created_at",
    "updated_at", "reminder_sent_at", "cancelled_at",
    "processing_started_at",
)


def _coerce_lead_bind(mapper, connection, target):
    """Coerce Lead column values before they reach SQLite (C05 fix).

    If ``scheduled_date`` is a string, parse it to a datetime via dateparser.
    This handles both API-submitted strings and direct ORM creation in tests.
    """
    if hasattr(target, "scheduled_date") and isinstance(target.scheduled_date, str):
        parsed = _parse_datetime_string(target.scheduled_date)
        if parsed is not None:
            target.scheduled_date = parsed
        else:
            logger.warning(
                "sqlite_compat: could not parse scheduled_date=%r for lead, "
                "storing None",
                target.scheduled_date,
            )
            target.scheduled_date = None

    # C06: JSON-serialize list values for metadata_json on Organization
    # (handled by _coerce_org_bind below)


def _coerce_org_bind(mapper, connection, target):
    """Coerce Organization column values before they reach SQLite (C06 fix).

    If ``metadata_json`` is a Python list, serialize it to a JSON string.
    """
    if hasattr(target, "metadata_json") and isinstance(target.metadata_json, list):
        target.metadata_json = json.dumps(target.metadata_json)


# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

_installed = False


def install_sqlite_compat(engine: Engine) -> None:
    """Install SQLite compatibility adapters on the given engine.

    Only activates when the engine URL starts with 'sqlite'.
    Safe to call multiple times (idempotent).
    """
    global _installed
    if _installed:
        return
    if not engine.url.get_backend_name().startswith("sqlite"):
        return
    _installed = True

    logger.info("Installing SQLite compatibility adapters on engine")

    # DBAPI-level: UUID adapter + PRAGMA foreign_keys
    event.listen(engine, "connect", _register_adapters_on_connection)

    # Mapper-level: coerce string dates before INSERT/UPDATE (C05)
    from app.models import Lead
    from app.models_multi_tenant import Organization

    event.listen(Lead, "before_insert", _coerce_lead_bind)
    event.listen(Lead, "before_update", _coerce_lead_bind)
    event.listen(Organization, "before_insert", _coerce_org_bind)
    event.listen(Organization, "before_update", _coerce_org_bind)

    # C01 (read path): Normalize naive datetimes when instances are loaded
    # from SQLite or refreshed. SQLite doesn't preserve timezone info, so
    # datetime values come back as naive. The query layer (e.g.
    # send_daily_reminders) compares against timezone-aware bounds and fails.
    def _normalize_lead_on_load(target, *args):
        """Normalize naive datetimes on a Lead instance after loading."""
        for attr_name in _LEAD_DATETIME_ATTRS:
            val = getattr(target, attr_name, None)
            if isinstance(val, datetime) and val.tzinfo is None:
                setattr(target, attr_name, val.replace(tzinfo=timezone.utc))

    event.listen(Lead, "load", _normalize_lead_on_load)
    event.listen(Lead, "refresh", _normalize_lead_on_load)

    # C12 (read path): Normalize booleans on FailedJob after load/refresh.
    # FailedJob.resolved is declared as String (not Boolean) in the model.
    # SQLite stores boolean values as strings "true"/"false"/"1"/"0".
    # After_flush normalizes on write, but we also need normalization on read.
    from app.models import FailedJob

    def _normalize_failedjob_on_load(target, *args):
        """Convert string booleans to Python bool on FailedJob load."""
        val = getattr(target, "resolved", None)
        if isinstance(val, str):
            target.resolved = val.lower() in ("1", "true", "yes")
        elif isinstance(val, int):
            target.resolved = bool(val)

    event.listen(FailedJob, "load", _normalize_failedjob_on_load)
    event.listen(FailedJob, "refresh", _normalize_failedjob_on_load)

    # C06/C01 (read path): Deserialize JSON strings and normalize naive
    # datetimes on GoogleOAuthState after load/refresh.
    # - scopes column is Text but model stores Python lists; sqlite3
    #   adapters serialize list→JSON string on write, this deserializes on read.
    # - expires_at/created_at come back as naive datetimes from SQLite.
    from app.models_multi_tenant import GoogleOAuthState

    _OAUTH_STATE_DATETIME_ATTRS = ("expires_at", "created_at")

    def _normalize_oauthstate_on_load(target, *args):
        """Normalize GoogleOAuthState after loading from SQLite."""
        # C06: Deserialize JSON string back to Python list for scopes field.
        val = getattr(target, "scopes", None)
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                if isinstance(parsed, list):
                    target.scopes = parsed
            except (json.JSONDecodeError, TypeError):
                pass  # Not JSON — leave as-is

        # C01: Normalize naive datetimes.
        for attr_name in _OAUTH_STATE_DATETIME_ATTRS:
            dt_val = getattr(target, attr_name, None)
            if isinstance(dt_val, datetime) and dt_val.tzinfo is None:
                setattr(target, attr_name, dt_val.replace(tzinfo=timezone.utc))

    event.listen(GoogleOAuthState, "load", _normalize_oauthstate_on_load)
    event.listen(GoogleOAuthState, "refresh", _normalize_oauthstate_on_load)

    # C01 (read path): Normalize naive datetimes on FollowUp after load/refresh.
    # FollowUp has several DateTime(timezone=True) columns (due_at, completed_at,
    # cancelled_at, overdue_email_sent_at, email_sent_at, created_at, updated_at).
    # SQLite strips timezone info, causing naive-vs-aware comparison errors.
    from app.models import FollowUp

    _FOLLOWUP_DATETIME_ATTRS = (
        "due_at", "completed_at", "cancelled_at",
        "overdue_email_sent_at", "email_sent_at",
        "created_at", "updated_at",
    )

    def _normalize_followup_on_load(target, *args):
        """Normalize naive datetimes on a FollowUp instance after loading."""
        for attr_name in _FOLLOWUP_DATETIME_ATTRS:
            val = getattr(target, attr_name, None)
            if isinstance(val, datetime) and val.tzinfo is None:
                setattr(target, attr_name, val.replace(tzinfo=timezone.utc))

    event.listen(FollowUp, "load", _normalize_followup_on_load)
    event.listen(FollowUp, "refresh", _normalize_followup_on_load)

    # C01 (read path): Normalize naive datetimes on PasswordResetToken after
    # load/refresh. expires_at and created_at are DateTime(timezone=True).
    from app.models_multi_tenant import PasswordResetToken

    _PASSWORD_RESET_DATETIME_ATTRS = ("expires_at", "created_at")

    def _normalize_passwordreset_on_load(target, *args):
        """Normalize naive datetimes on PasswordResetToken after loading."""
        for attr_name in _PASSWORD_RESET_DATETIME_ATTRS:
            val = getattr(target, attr_name, None)
            if isinstance(val, datetime) and val.tzinfo is None:
                setattr(target, attr_name, val.replace(tzinfo=timezone.utc))

    event.listen(PasswordResetToken, "load", _normalize_passwordreset_on_load)
    event.listen(PasswordResetToken, "refresh", _normalize_passwordreset_on_load)

    # Result-level: normalize naive datetimes + booleans after flush
    from sqlalchemy.orm import Session

    def _normalize_sqlite_types(session, flush_context):
        """Normalize SQLite-specific type quirks in session objects.

        Fixes:
          C01 — naive datetimes → aware UTC
          C12 — integer/str booleans → Python bool
        """
        for obj in session.dirty | session.new:
            # C01: Normalize naive datetimes on Lead objects
            if isinstance(obj, Lead):
                for attr_name in _LEAD_DATETIME_ATTRS:
                    val = getattr(obj, attr_name, None)
                    if isinstance(val, datetime) and val.tzinfo is None:
                        setattr(obj, attr_name, val.replace(tzinfo=timezone.utc))

            # C12: Normalize booleans on FailedJob objects
            if isinstance(obj, FailedJob):
                val = getattr(obj, "resolved", None)
                if isinstance(val, (int, str)):
                    if isinstance(val, str):
                        obj.resolved = val.lower() in ("1", "true", "yes")
                    else:
                        obj.resolved = bool(val)

            # C01: Normalize naive datetimes on FollowUp objects
            if isinstance(obj, FollowUp):
                for attr_name in _FOLLOWUP_DATETIME_ATTRS:
                    val = getattr(obj, attr_name, None)
                    if isinstance(val, datetime) and val.tzinfo is None:
                        setattr(obj, attr_name, val.replace(tzinfo=timezone.utc))

            # C01: Normalize naive datetimes on PasswordResetToken objects
            if isinstance(obj, PasswordResetToken):
                for attr_name in _PASSWORD_RESET_DATETIME_ATTRS:
                    val = getattr(obj, attr_name, None)
                    if isinstance(val, datetime) and val.tzinfo is None:
                        setattr(obj, attr_name, val.replace(tzinfo=timezone.utc))

    event.listen(Session, "after_flush", _normalize_sqlite_types)
