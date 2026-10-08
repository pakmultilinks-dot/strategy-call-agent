"""RSVP decline detection via polling (Phase 2 + 6B.4).

Polls live Calendar events for leads that are scheduled/accepted/tentative
and applies RSVP state transitions. Polling (not push notifications) is the
correct choice for local/dev — push requires a public HTTPS endpoint.

Scheduling (cron) is wired up in a later phase; for now this is triggered
manually via POST /internal/poll-rsvps.

Phase 6B.4: Each lead's Calendar is queried using credentials resolved
for the lead's owning organization.
"""
import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.events import publish_event
from app.models import EventLog, Lead, LeadStatus
from app.services.calendar_service import CalendarService
from app.services.org_context import OrganizationContext

logger = logging.getLogger("strategy-call-agent.rsvp")

# Leads in these states are checked against their live Calendar event.
_POLLABLE = (LeadStatus.SCHEDULED, LeadStatus.ACCEPTED, LeadStatus.TENTATIVE)

# Map a live RSVP responseStatus to a LeadStatus (None -> handled separately).
_RSVP_TO_STATUS = {
    "accepted": LeadStatus.ACCEPTED,
    "tentative": LeadStatus.TENTATIVE,
}


def _log_event(db: Session, lead_id, event_type: str, payload: dict | None = None,
               organization_id: uuid.UUID | None = None) -> None:
    """Log an event for a lead.

    Phase 6B.4: Accepts explicit organization_id to avoid relying on the
    global tenant context which may not be set in background tasks.

    Phase 1 (Hardening): organization_id is now REQUIRED.  The default-org
    fallback has been removed.
    """
    if organization_id is None:
        raise RuntimeError(
            f"_log_event() in rsvp_poller requires explicit organization_id. "
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
    db.commit()


def _process_lead(db: Session, cal: CalendarService, lead: Lead, summary: dict) -> None:
    """Apply the RSVP state transition for one lead. Never raises out."""
    event_id = lead.calendar_event_id
    try:
        status = cal.get_attendee_status(event_id, lead.email)

        # Re-fetch to guard against a race with the Phase 1 pipeline (status
        # may have changed since the poll query ran).
        fresh = db.get(Lead, lead.id)
        if fresh is None or fresh.status not in _POLLABLE or not fresh.calendar_event_id:
            return

        now = datetime.now(timezone.utc).isoformat()

        if status is None or status == "declined":
            # Declined (or event manually deleted in the Calendar UI).
            if status == "declined":
                # Update the event to mark it as declined: prefix title with
                # [DECLINED], set color to red (11), set transparent.
                # The event is PRESERVED as historical evidence.
                try:
                    event_data = cal._get_event(event_id)
                    original_summary = event_data.get("summary", "Strategy Call")
                except Exception:
                    original_summary = "Strategy Call"
                cal.update_event_declined(event_id, original_summary, db)
            # Mark declined; PRESERVE the calendar_event_id (historical record).
            # NEVER delete the Lead row.
            fresh.status = LeadStatus.DECLINED
            # calendar_event_id is intentionally PRESERVED — the event still
            # exists in Calendar with [DECLINED] prefix.
            # Phase 7 Part 3: Auto-cancellation cascade — lead is entering DECLINED
            # (terminal).  Cancel pending follow-ups to prevent the scheduler from
            # contacting a lead that is no longer eligible for outreach.
            from app.services.followup_cancellation import (
                cancel_pending_followups_for_lead,
            )
            cancel_pending_followups_for_lead(db, fresh.id, lead.organization_id)
            db.commit()
            _log_event(
                db,
                fresh.id,
                "declined",
                {"detected_at": now, "event_id": event_id, "via": "rsvp" if status == "declined" else "event_missing"},
                organization_id=lead.organization_id,
            )
            summary["declined"] += 1
            # Silent on the prospect's end: no email/notification is sent.
            return

        # accepted / tentative -> sync DB to live RSVP state if it changed.
        new_status = _RSVP_TO_STATUS.get(status)
        if new_status is not None and fresh.status != new_status:
            old = fresh.status
            fresh.status = new_status
            db.commit()
            _log_event(
                db,
                fresh.id,
                "rsvp_changed",
                {"from": old.value, "to": new_status.value, "event_id": event_id},
                organization_id=lead.organization_id,
            )
            summary["updated"] += 1
        # needsAction or unchanged -> nothing to do.
    except Exception as exc:
        db.rollback()
        logger.exception("rsvp poll failed for lead %s", lead.id)
        summary["errors"] += 1
        try:
            _log_event(db, lead.id, "error", {"error": str(exc)[:2000], "event_id": event_id},
                       organization_id=lead.organization_id)
        except Exception:
            db.rollback()


def poll_rsvp_updates(organization_id: uuid.UUID | None = None) -> dict:
    """Check every pollable lead's live RSVP status and apply transitions.

    Phase 6B.6: Accepts optional organization_id to scope the RSVP poll
    to a single organization (customer-triggered).  When None (platform
    admin trigger), processes ALL organizations.

    Processes leads one at a time with error isolation — one bad lead never
    stops the cycle. Returns a summary dict for observability.

    Phase 6B.4: Each lead's Calendar is queried using credentials resolved
    for the lead's owning organization via IntegrationConfigResolver.
    """
    summary = {"checked": 0, "declined": 0, "updated": 0, "errors": 0}
    db = SessionLocal()
    try:
        q = db.query(Lead).filter(
            Lead.status.in_(_POLLABLE), Lead.calendar_event_id.isnot(None)
        )
        if organization_id is not None:
            q = q.filter(Lead.organization_id == organization_id)
        leads = q.yield_per(100)
        for lead in leads:
            summary["checked"] += 1
            # Build org context from the lead's organization
            org_ctx = None
            if lead.organization_id:
                org_ctx = OrganizationContext.from_id(lead.organization_id)
            # Build per-lead CalendarService with org-specific credentials
            try:
                cal = CalendarService(org_context=org_ctx, db=db)
            except Exception:
                # Google credentials not configured for this org — skip
                summary["errors"] += 1
                try:
                    _log_event(
                        db, lead.id, "error",
                        {"reason": "google_credentials_not_configured", "org_id": str(lead.organization_id)},
                        organization_id=lead.organization_id,
                    )
                except Exception:
                    db.rollback()
                continue
            _process_lead(db, cal, lead, summary)
    except Exception:
        # A failure not tied to a specific lead (e.g. auth).
        # rsvp_poll is an unrecoverable batch job type; log only.
        logger.exception("rsvp poll cycle failed")
        summary["errors"] += 1
    finally:
        db.close()
    logger.info("rsvp poll summary: %s", summary)
    publish_event("rsvp.completed", summary, organization_id=organization_id)
    return summary
