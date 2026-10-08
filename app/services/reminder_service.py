"""Daily reminder emails (Phase 3 + 6B.4 + 6D + Phase 27).

Sends a fixed-template reminder to every lead still "on" for a call TODAY
(in the business timezone). Fixed template on purpose — no AI call, so the
time-sensitive daily job doesn't depend on an AI provider.

Phase 6B.4: Supports organization-specific credential resolution.
Each lead's reminder is sent using credentials resolved for the lead's
owning organization.

Phase 6D: Email templates use per-organization branding (company name,
sender name, brand color, tagline) via BrandingConfig.  Timezone is
resolved per-organization via IntegrationConfigResolver.
"""
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.events import publish_event
from app.models import EventLog, Lead, LeadStatus
from app.services.calendar_service import CalendarService
from app.services.email_service import EmailService
from app.services.email_templates import (
    build_reminder_html,
    build_reminder_subject,
    build_reminder_text,
)
from app.services.org_context import OrganizationContext

logger = logging.getLogger("strategy-call-agent.reminder")

# Leads still considered "on" for their call (NOT declined).
_REMINDABLE = (LeadStatus.SCHEDULED, LeadStatus.ACCEPTED, LeadStatus.TENTATIVE)


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
            f"_log_event() in reminder_service requires explicit organization_id. "
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


def _today_bounds_utc(tz: ZoneInfo) -> tuple[datetime, datetime]:
    """Return [start, end) of TODAY in the business timezone, as aware UTC.

    Computed at query time so DST transitions are always handled correctly.
    """
    now_local = datetime.now(tz)
    start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    end_local = start_local + timedelta(days=1)
    return start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)


def _fmt_local(dt_utc: datetime, tz: ZoneInfo) -> str:
    """Human-readable local time, e.g. '2:00 PM CDT'. Portable across
    Windows/POSIX (avoids the Unix-only %-I strftime flag)."""
    local = dt_utc.astimezone(tz)
    hour = local.hour % 12 or 12
    ampm = "AM" if local.hour < 12 else "PM"
    return f"{hour}:{local.minute:02d} {ampm} {local.tzname()}"


def _process_lead(
    db: Session,
    cal: CalendarService,
    mail: EmailService,
    lead: Lead,
    tz: ZoneInfo,
    summary: dict,
    org_ctx: OrganizationContext | None = None,
) -> None:
    """Send a reminder for one lead. Never raises out.

    Phase 6D: Resolves branding for the lead's organization and passes
    it to email template functions for org-specific branding.

    Phase 8: Timezone is resolved per-lead from the organization's
    configured timezone, falling back to the platform default.
    """
    try:
        # Phase 8: Resolve per-lead timezone from org config
        lead_tz = tz  # default to passed-in timezone
        if org_ctx is not None and db is not None:
            try:
                from app.services.integration_config_resolver import (
                    IntegrationConfigResolver,
                )
                resolved_tz = IntegrationConfigResolver.resolve_timezone(db, org_ctx.organization_id)
                lead_tz = ZoneInfo(resolved_tz)
            except Exception:
                pass  # fallback to the default tz

        # Resolve branding for this lead's organization
        branding = None
        if org_ctx is not None and db is not None:
            from app.services.integration_config_resolver import (
                IntegrationConfigResolver,
            )
            try:
                branding = IntegrationConfigResolver.resolve_branding(db, org_ctx.organization_id)
            except Exception:
                branding = None

        # Phase 10B: Atomically claim this lead for reminder processing
        # using SELECT FOR UPDATE (PostgreSQL) or plain SELECT (SQLite).
        # This prevents the double-send race condition where two concurrent
        # reminder runs both see reminder_sent_at IS NULL before either commits.
        from sqlalchemy import text as sa_text

        is_postgres = str(db.bind.url).startswith("postgresql")
        lock_clause = " FOR UPDATE" if is_postgres else ""

        # Note: SQLAlchemy stores UUIDs in SQLite as 32-char hex without
        # dashes, so we must use lead.id.hex for the raw SQL parameter
        # instead of str(lead.id) which includes dashes.
        lead_id_hex = lead.id.hex if not is_postgres else str(lead.id)

        result = db.execute(
            sa_text(
                f"SELECT id FROM leads WHERE id = :lead_id AND reminder_sent_at IS NULL{lock_clause}"
            ),
            {"lead_id": lead_id_hex},
        )
        if result.fetchone() is None:
            # Already reminded by another process, or race lost — skip.
            summary["skipped"] = summary.get("skipped", 0) + 1
            return

        # Fetch the meeting link for the reminder email.
        # Zoom-backed leads store the join URL directly on the lead;
        # Google Meet leads fetch it live from the Calendar event.
        meet_link = None
        if getattr(lead, "zoom_join_url", None):
            meet_link = lead.zoom_join_url
        elif lead.calendar_event_id:
            meet_link = cal.get_meet_link(lead.calendar_event_id)
        meeting_provider = "zoom" if getattr(lead, "zoom_join_url", None) else None
        if not meet_link:
            _log_event(db, lead.id, "error", {"reason": "meet link unavailable", "event_id": lead.calendar_event_id},
                       organization_id=lead.organization_id)
            summary["errors"] += 1
            # Release the lock by committing (the row is still locked but
            # reminder_sent_at remains NULL so it can be retried).
            db.commit()
            return

        local_time = _fmt_local(lead.appt_datetime_utc, lead_tz)
        subject = build_reminder_subject(lead, local_time, branding=branding)
        text_body = build_reminder_text(lead, meet_link, lead_tz, branding=branding, meeting_provider=meeting_provider)
        html_body = build_reminder_html(lead, meet_link, lead_tz, branding=branding, meeting_provider=meeting_provider)

        mail.send_email(lead.email, subject, text_body, db, html_body=html_body)

        # Mark sent (guard against double-sends) and audit-log it.
        # The FOR UPDATE lock is still held, so no concurrent process can
        # pass the guard above until we commit.
        db.execute(
            sa_text(
                "UPDATE leads SET reminder_sent_at = :now WHERE id = :lead_id"
            ),
            {"now": datetime.now(timezone.utc), "lead_id": lead_id_hex},
        )
        db.commit()
        _log_event(db, lead.id, "reminder_sent", {"local_time": local_time, "meet_link": meet_link},
                   organization_id=lead.organization_id)
        summary["sent"] += 1
    except Exception as exc:
        db.rollback()
        logger.exception("reminder failed for lead %s", lead.id)
        summary["errors"] += 1
        # Do NOT set reminder_sent_at so it can be retried later.
        try:
            _log_event(db, lead.id, "error", {"error": str(exc)[:2000]},
                       organization_id=lead.organization_id)
        except Exception:
            db.rollback()


def send_daily_reminders(organization_id: uuid.UUID | None = None) -> dict:
    """Send reminders to all of today's still-on leads. Returns a summary.

    Phase 6B.6: Accepts optional organization_id to scope the reminder run
    to a single organization (customer-triggered).  When None (platform
    admin trigger), processes ALL organizations.

    Eligibility rules (all must pass):
    1. lead exists in the database
    2. lead status is SCHEDULED, ACCEPTED, or TENTATIVE
    3. appointment is scheduled for TODAY in BUSINESS_TIMEZONE
    4. appointment has NOT already received today's reminder (reminder_sent_at guard)
    5. calendar_event_id exists (Meet link can be fetched)
    6. lead has a valid email
    7. the appointment time is still in the future (not already passed)
    8. (if organization_id is set) lead belongs to that organization
    """
    summary = {"checked": 0, "sent": 0, "errors": 0}
    now_utc = datetime.now(timezone.utc)

    db = SessionLocal()
    try:
        # Phase 5 fix: resolve per-org timezone when organization_id is provided,
        # so "today" bounds are computed in the org's own timezone, not the
        # global business_timezone.
        if organization_id is not None:
            from app.models_multi_tenant import Organization as OrgModel
            _org = db.query(OrgModel).filter(OrgModel.id == organization_id).first()
            org_tz_name = (_org.timezone if _org and _org.timezone else settings.business_timezone)
            tz = ZoneInfo(org_tz_name)
        else:
            tz = ZoneInfo(settings.business_timezone)
        start_utc, end_utc = _today_bounds_utc(tz)

        q = db.query(Lead).filter(
            Lead.status.in_(_REMINDABLE),
            Lead.reminder_sent_at.is_(None),
            Lead.appt_datetime_utc.isnot(None),
            Lead.appt_datetime_utc >= start_utc,
            Lead.appt_datetime_utc < end_utc,
            # Skip meetings whose appointment time has already passed.
            Lead.appt_datetime_utc > now_utc,
            # Must have a calendar event so we can fetch the Meet link.
            Lead.calendar_event_id.isnot(None),
            # Must have an email address to send the reminder.
            Lead.email.isnot(None),
            Lead.email != "",
        )
        if organization_id is not None:
            q = q.filter(Lead.organization_id == organization_id)
        leads = q.all()

        for lead in leads:
            summary["checked"] += 1

            # Build org context from the lead's organization for credential resolution
            org_ctx = None
            if lead.organization_id:
                org_ctx = OrganizationContext.from_id(lead.organization_id)
            # Build per-lead services with org-specific credentials
            try:
                cal = CalendarService(org_context=org_ctx, db=db)
                mail = EmailService(org_context=org_ctx, db=db)
            except Exception:
                # If Google credentials are not configured, skip this lead
                # rather than failing the entire reminder run.
                cal = None
                mail = None
            if cal is None or mail is None:
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
            _process_lead(db, cal, mail, lead, tz, summary, org_ctx)
    except Exception:
        logger.exception("daily reminder run failed")
        # daily_reminder is an unrecoverable batch job type; log only.
        summary["errors"] += 1
    finally:
        db.close()
    logger.info("daily reminder summary: %s", summary)
    publish_event("reminder.completed", summary, organization_id=organization_id)
    return summary
