"""Audit logging service (Phase 28 — P1-E).

Provides structured audit event recording for security-sensitive operations.
Events are written to the ``events_log`` table (EventLog model) with a
dedicated ``event_type`` prefix ``audit.`` for easy filtering.

SECURITY:
  - Audit events are append-only (never deleted or modified).
  - All events include organization_id for tenant scoping.
  - Payload is JSON-serialized with sanitized metadata (no passwords/tokens).

PHASE 1 (Hardening): organization_id is now REQUIRED for all audit events.
Events that cannot be attributed to a specific organization (e.g. login
failure for a non-existent email) should be logged via the logger instead.
"""
from __future__ import annotations

import json
import logging
import uuid

from sqlalchemy.orm import Session

from app.models import EventLog

logger = logging.getLogger(__name__)


def log_audit_event(
    db: Session,
    *,
    event_type: str,
    organization_id: uuid.UUID | None = None,
    lead_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    detail: dict | None = None,
) -> None:
    """Write an audit event to the events_log table.

    All audit event types are prefixed with ``audit.`` for easy filtering.

    Args:
        db: The database session.
        event_type: The audit event type (e.g. "audit.login_success").
        organization_id: The tenant/org ID (for tenant scoping). REQUIRED.
        lead_id: Optional lead reference (usually None for auth events).
        user_id: The user who performed the action (stored in payload).
        detail: Additional metadata (JSON-serializable). Keys like
            ``password``, ``token``, ``secret`` are stripped automatically.

    Raises:
        RuntimeError: If organization_id is None.
    """
    if organization_id is None:
        raise RuntimeError(
            f"log_audit_event() requires explicit organization_id. "
            f"event_type={event_type!r}"
        )

    safe_detail = {}
    if detail:
        _SENSITIVE_KEYS = frozenset({
            "password", "current_password", "new_password",
            "token", "secret", "api_key", "access_token",
            "credentials", "credentials_encrypted", "authorization",
        })
        for k, v in detail.items():
            if k.lower() in _SENSITIVE_KEYS:
                safe_detail[k] = "***REDACTED***"
            else:
                safe_detail[k] = str(v) if not isinstance(v, (str, int, float, bool, list, dict, type(None))) else v

    # Add user_id to payload
    if user_id:
        safe_detail["user_id"] = str(user_id)

    payload = json.dumps(safe_detail) if safe_detail else None

    event = EventLog(
        lead_id=lead_id,
        event_type=event_type,
        payload=payload,
        organization_id=organization_id,
    )
    db.add(event)
    # Don't commit here — let the caller control the transaction boundary.
    # Flush to ensure the event is assigned an ID before the caller commits.
    db.flush()

    logger.info(
        "audit_event: type=%s org=%s user=%s",
        event_type, organization_id, user_id,
    )
