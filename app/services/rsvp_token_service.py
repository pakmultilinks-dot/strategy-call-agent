"""RSVP token generation, validation, and processing (Phase 4).

Handles the customer-facing Accept/Decline RSVP workflow:
  1. Generate tokens during pipeline completion (confirmation email).
  2. Validate tokens when customer clicks Accept/Decline link.
  3. Process RSVP: status change, calendar release, follow-up cancellation.

Security:
  - Tokens are SHA-256 hashed (not bcrypt) for exact-match DB lookup.
  - Each token is single-use (consumed=True after use).
  - Tokens expire after RSVP_TOKEN_EXPIRY_DAYS (30 days default).
  - Only leads in pollable states can receive tokens.
  - Tokens are scoped to a specific lead + organization.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import EventLog, Lead, LeadStatus, RSVPToken

logger = logging.getLogger("strategy-call-agent.rsvp-tokens")

# Token configuration
RSVP_TOKEN_BYTE_LENGTH = 32  # 256 bits of entropy
RSVP_TOKEN_EXPIRY_DAYS = 30


def _hash_token(token: str) -> str:
    """Hash an RSVP token with SHA-256 for storage.

    We use SHA-256 (not bcrypt) for the token hash because:
    1. We need exact-match lookup (bcrypt is designed for slow comparison).
    2. The token itself already has high entropy (256 bits).
    3. This is a one-time-use token, not a user-chosen password.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_rsvp_tokens(
    db: Session,
    lead: Lead,
) -> tuple[str, str]:
    """Generate accept and decline RSVP tokens for a lead.

    Called during pipeline completion after confirmation email is built.
    Generates two tokens: one for accept, one for decline.

    Args:
        db: Database session.
        lead: The lead to generate tokens for.

    Returns:
        (accept_token, decline_token) - plaintext tokens to embed in URLs.

    Raises:
        ValueError: If lead is not in a pollable state.
    """
    _pollable = {LeadStatus.SCHEDULED, LeadStatus.ACCEPTED, LeadStatus.TENTATIVE}
    if lead.status not in _pollable:
        raise ValueError(
            f"Cannot generate RSVP tokens for lead {lead.id}: "
            f"status is {lead.status.value}, must be one of "
            f"{', '.join(s.value for s in _pollable)}"
        )

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=RSVP_TOKEN_EXPIRY_DAYS)

    # Invalidate any existing unconsumed tokens for this lead
    _invalidate_old_tokens(db, lead.id)

    # Generate accept token
    accept_plaintext = secrets.token_urlsafe(RSVP_TOKEN_BYTE_LENGTH)
    accept_hash = _hash_token(accept_plaintext)
    db.add(RSVPToken(
        lead_id=lead.id,
        organization_id=lead.organization_id,
        token_hash=accept_hash,
        choice="accept",
        expires_at=expires_at,
    ))

    # Generate decline token
    decline_plaintext = secrets.token_urlsafe(RSVP_TOKEN_BYTE_LENGTH)
    decline_hash = _hash_token(decline_plaintext)
    db.add(RSVPToken(
        lead_id=lead.id,
        organization_id=lead.organization_id,
        token_hash=decline_hash,
        choice="decline",
        expires_at=expires_at,
    ))

    db.commit()
    logger.info(
        "RSVP tokens generated for lead %s (org=%s)",
        lead.id, lead.organization_id,
    )
    return accept_plaintext, decline_plaintext


def _invalidate_old_tokens(db: Session, lead_id: uuid.UUID) -> None:
    """Mark all unconsumed tokens for a lead as consumed (invalidate)."""
    from sqlalchemy import update

    db.execute(
        update(RSVPToken)
        .where(
            RSVPToken.lead_id == lead_id,
            RSVPToken.consumed == False,
        )
        .values(consumed=True, consumed_at=datetime.now(timezone.utc))
    )


# ---------------------------------------------------------------------------
# Token Validation Result
# ---------------------------------------------------------------------------

@dataclass
class RSVPResult:
    """Result of processing an RSVP token."""
    success: bool
    choice: str  # "accept" or "decline"
    lead_name: str
    company_address: str | None
    appt_datetime_utc: datetime | None
    already_used: bool = False
    expired: bool = False
    not_found: bool = False
    error: str | None = None


def validate_and_process_rsvp(
    db: Session,
    token_plaintext: str,
) -> RSVPResult:
    """Validate an RSVP token and process the RSVP action.

    Args:
        db: Database session.
        token_plaintext: The plaintext token from the URL.

    Returns:
        RSVPResult with the outcome of the RSVP processing.
    """
    token_hash = _hash_token(token_plaintext)
    now = datetime.now(timezone.utc)

    # Look up the token
    rsvp_token = db.query(RSVPToken).filter(
        RSVPToken.token_hash == token_hash,
    ).first()

    if rsvp_token is None:
        return RSVPResult(
            success=False,
            choice="",
            lead_name="",
            company_address=None,
            appt_datetime_utc=None,
            not_found=True,
            error="Invalid RSVP link.",
        )

    # Check if already used
    if rsvp_token.consumed:
        lead = db.get(Lead, rsvp_token.lead_id)
        return RSVPResult(
            success=False,
            choice=rsvp_token.choice,
            lead_name=lead.name if lead else "",
            company_address=lead.company_address if lead else None,
            appt_datetime_utc=lead.appt_datetime_utc if lead else None,
            already_used=True,
            error="This RSVP link has already been used.",
        )

    # Check if expired (M15 fix: SQLite returns naive datetimes from
    # DateTime(timezone=True) columns - attach UTC before comparing).
    _expires_at = rsvp_token.expires_at
    if _expires_at is not None and _expires_at.tzinfo is None:
        _expires_at = _expires_at.replace(tzinfo=timezone.utc)
    if _expires_at is not None and _expires_at < now:
        lead = db.get(Lead, rsvp_token.lead_id)
        return RSVPResult(
            success=False,
            choice=rsvp_token.choice,
            lead_name=lead.name if lead else "",
            company_address=lead.company_address if lead else None,
            appt_datetime_utc=lead.appt_datetime_utc if lead else None,
            expired=True,
            error="This RSVP link has expired.",
        )

    # Load the lead
    lead = db.get(Lead, rsvp_token.lead_id)
    if lead is None:
        rsvp_token.consumed = True
        rsvp_token.consumed_at = now
        db.commit()
        return RSVPResult(
            success=False,
            choice=rsvp_token.choice,
            lead_name="",
            company_address=None,
            appt_datetime_utc=None,
            not_found=True,
            error="Lead not found.",
        )

    # Check lead is in a pollable state
    _pollable = {LeadStatus.SCHEDULED, LeadStatus.ACCEPTED, LeadStatus.TENTATIVE}
    if lead.status not in _pollable:
        # Mark token as consumed even though lead is not in pollable state
        # to prevent repeated attempts
        rsvp_token.consumed = True
        rsvp_token.consumed_at = now
        db.commit()
        return RSVPResult(
            success=False,
            choice=rsvp_token.choice,
            lead_name=lead.name,
            company_address=lead.company_address,
            appt_datetime_utc=lead.appt_datetime_utc,
            error=f"Cannot process RSVP: lead is in '{lead.status.value}' status.",
        )

    # Process the RSVP
    choice = rsvp_token.choice
    old_status = lead.status.value

    if choice == "accept":
        lead.status = LeadStatus.ACCEPTED
        _log_rsvp_event(
            db, lead.id, "rsvp_accepted",
            {"old_status": old_status, "via": "customer_link"},
            organization_id=lead.organization_id,
        )
    elif choice == "decline":
        lead.status = LeadStatus.DECLINED

        # Phase 7 Part 3: Auto-cancellation cascade - lead is entering DECLINED (terminal).
        from app.services.followup_cancellation import cancel_pending_followups_for_lead
        cancel_pending_followups_for_lead(db, lead.id, lead.organization_id)

        # Release calendar event (delete it, free the slot)
        if lead.calendar_event_id:
            try:
                from app.services.calendar_service import CalendarService
                from app.services.org_context import OrganizationContext
                org_ctx = OrganizationContext.from_id(lead.organization_id)
                cal = CalendarService(org_context=org_ctx, db=db)
                cal.release_calendar_event(
                    lead.calendar_event_id, lead.name, db,
                )
            except Exception as exc:
                logger.warning(
                    "calendar release failed for lead %s during RSVP decline: %s",
                    lead.id, exc,
                )
                _log_rsvp_event(
                    db, lead.id, "calendar_release_error",
                    {"error": str(exc)[:500]},
                    organization_id=lead.organization_id,
                )

        # Cancel Zoom meeting if one exists
        if lead.zoom_meeting_id:
            try:
                from app.services.meeting_provider import (
                    ZoomMeetingProvider,
                    resolve_meeting_provider,
                )
                from app.services.org_context import OrganizationContext
                org_ctx = OrganizationContext.from_id(lead.organization_id)
                provider = resolve_meeting_provider(org_context=org_ctx, db=db)
                if isinstance(provider, ZoomMeetingProvider):
                    provider.cancel_meeting(lead.zoom_meeting_id)
            except Exception as exc:
                logger.warning(
                    "Zoom cancel failed for lead %s during RSVP decline: %s",
                    lead.id, exc,
                )

        _log_rsvp_event(
            db, lead.id, "rsvp_declined",
            {"old_status": old_status, "via": "customer_link"},
            organization_id=lead.organization_id,
        )

        # Send org notification (best-effort, never blocks RSVP)
        try:
            from app.services.decline_notification import send_decline_notification
            send_decline_notification(db, lead)
        except Exception as exc:
            logger.warning(
                "decline notification failed for lead %s: %s", lead.id, exc,
            )
    else:
        rsvp_token.consumed = True
        rsvp_token.consumed_at = now
        db.commit()
        return RSVPResult(
            success=False,
            choice=choice,
            lead_name=lead.name,
            company_address=lead.company_address,
            appt_datetime_utc=lead.appt_datetime_utc,
            error=f"Unknown RSVP choice: {choice}",
        )

    # Mark token as consumed
    rsvp_token.consumed = True
    rsvp_token.consumed_at = now
    db.commit()

    logger.info(
        "RSVP processed: lead=%s choice=%s old_status=%s new_status=%s",
        lead.id, choice, old_status, lead.status.value,
    )

    return RSVPResult(
        success=True,
        choice=choice,
        lead_name=lead.name,
        company_address=lead.company_address,
        appt_datetime_utc=lead.appt_datetime_utc,
    )


def _log_rsvp_event(
    db: Session,
    lead_id: uuid.UUID,
    event_type: str,
    payload: dict | None = None,
    organization_id: uuid.UUID | None = None,
) -> None:
    """Log an RSVP event for a lead."""
    if organization_id is None:
        raise RuntimeError(
            f"_log_rsvp_event requires explicit organization_id. "
            f"event_type={event_type!r} lead_id={lead_id}"
        )
    db.add(
        EventLog(
            lead_id=lead_id,
            event_type=event_type,
            payload=json.dumps(payload) if payload is not None else None,
            organization_id=organization_id,
        )
    )
    db.flush()  # flush to catch constraint errors before commit
