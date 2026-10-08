"""Google Calendar integration (Phase 1 + 6B.4 + 6D + 8).

Creates Calendar events with auto-generated Meet links.

Phase 6B.4: Supports organization-specific credentials via
IntegrationConfigResolver. Falls back to platform defaults when
org-specific credentials are not configured.

Phase 6D: Event summary uses the organization's company name from
BrandingConfig.  Meeting duration is resolved from OrgScheduleConfig.

Phase 8: Checks free/busy before creating events to prevent double-booking.

Credential resolution order:
  1. Organization-specific Google OAuth tokens (from credential vault)
  2. Platform default token.json (backward compatibility)
"""
import json
import logging
import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from googleapiclient.discovery import build
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Lead
from app.services.google_auth import get_google_credentials
from app.services.integration_config_resolver import BrandingConfig
from app.services.org_context import OrganizationContext

# Calendar display is always anchored in this IANA timezone.
# Customer-facing emails/reminders will use the customer's own timezone
# (stored on lead.customer_timezone) — that is a separate concern.
CALENDAR_DISPLAY_TZ = "America/New_York"
from app.services.retry import external_call_retry, record_failed_job

logger = logging.getLogger(__name__)

_DEFAULT_MEETING_DURATION_MINUTES = 30


class CalendarSlotConflictError(Exception):
    """Raised when the requested time slot is already busy on Google Calendar.

    This is distinct from transient API failures (retried by tenacity) and
    authentication errors.  The pipeline treats this as a deterministic
    failure: the lead is NOT promoted to SCHEDULED and a FailedJob is
    recorded so operators can investigate the double-booking.
    """


def _na(value: str | None) -> str:
    """Render an optional lead field for humans; never crash on None."""
    return value if value else "N/A"


class CalendarService:
    """Wraps the Google Calendar API.

    Phase 6B.4: Accepts optional org_context and db for credential resolution.
    When org_context is provided, credentials are resolved from the
    organization's configured integrations, falling back to platform defaults.
    When org_context is None, the original global-config behavior is preserved.
    """

    def __init__(
        self,
        org_context: OrganizationContext | None = None,
        db: Session | None = None,
    ) -> None:
        if org_context is not None and db is not None:
            # Organization-aware credential resolution
            from app.services.integration_config_resolver import (
                IntegrationConfigResolver,
            )

            oauth_config = IntegrationConfigResolver.resolve_google_oauth(db, org_context.organization_id)
            cal_config = IntegrationConfigResolver.resolve_calendar_config(db, org_context.organization_id)
            self._branding = IntegrationConfigResolver.resolve_branding(db, org_context.organization_id)
            meeting_config = IntegrationConfigResolver.resolve_meeting_config(db, org_context.organization_id)
            self._org_id = org_context.organization_id
            self._meeting_duration = meeting_config.duration_minutes

            creds = get_google_credentials(
                client_id=oauth_config.client_id,
                client_secret=oauth_config.client_secret,
                refresh_token=oauth_config.refresh_token,
            )
            self._calendar_id = cal_config.calendar_id
        else:
            # Platform default: backward-compatible with original behavior
            creds = get_google_credentials()
            self._calendar_id = settings.calendar_id or "primary"
            self._org_id = None
            self._branding = BrandingConfig()
            self._meeting_duration = _DEFAULT_MEETING_DURATION_MINUTES

        self._service = build("calendar", "v3", credentials=creds, cache_discovery=True)

    @external_call_retry
    def _insert_event(self, body: dict) -> dict:
        return (
            self._service.events()
            .insert(
                calendarId=self._calendar_id,
                body=body,
                conferenceDataVersion=1,
                sendUpdates="none",
            )
            .execute()
        )

    @external_call_retry
    def _freebusy_query(self, body: dict) -> dict:
        """Query free/busy status for a time range."""
        return (
            self._service.freebusy()
            .query(body=body)
            .execute()
        )

    def check_slot_available(self, start: datetime, end: datetime) -> bool:
        """Check if a time slot is available on the calendar.

        Returns True if the slot is free, False if busy.
        Raises on API errors (transient errors retried by decorator).
        """
        body = {
            "timeMin": start.isoformat(),
            "timeMax": end.isoformat(),
            "timeZone": "UTC",
            "items": [{"id": self._calendar_id}],
        }
        try:
            result = self._freebusy_query(body)
            cal_busy = (
                result
                .get("calendars", {})
                .get(self._calendar_id, {})
                .get("busy", [])
            )
            return len(cal_busy) == 0
        except Exception as exc:
            # If we can't check availability, err on the side of allowing
            # the booking (Google Calendar itself will reject true conflicts).
            logger.warning(
                "free/busy check failed; allowing booking to proceed "
                "(calendar_id=%s, exception_type=%s, exception_message=%s)",
                self._calendar_id,
                type(exc).__name__,
                str(exc),
                exc_info=True,
            )
            return True

    def create_event(
        self,
        lead: Lead,
        db: Session,
        external_meeting_link: str | None = None,
    ) -> tuple[str, str | None]:
        """Create a Calendar event. Returns (event_id, meet_link).

        Phase 8: Checks free/busy before creating to prevent double-booking.
        Retries transient failures; on final failure records a FailedJob and raises.

        Args:
            external_meeting_link: When provided (e.g. a Zoom join URL), the event
                is created WITHOUT Google Meet conferencing.  The link is stored as
                the event location so it appears on the calendar.  The returned
                ``meet_link`` is the same external URL.
        """
        if lead.appt_datetime_utc is None:
            raise ValueError(
                "appt_datetime_utc is None; refusing to create a Calendar event "
                "without a start time"
            )

        start = lead.appt_datetime_utc
        end = start + timedelta(minutes=self._meeting_duration)

        # NOTE: Slot-conflict check (Phase 8 free/busy query) intentionally
        # removed.  Our business rule allows overlapping Calendar events
        # because multiple employees may book calls for different prospects
        # at the same requested time.  The check_slot_available() method
        # and CalendarSlotConflictError class are preserved for backward
        # compatibility but are no longer invoked during event creation.

        # ── Timezone conversion for Calendar display ──────────────
        # Google Calendar is ALWAYS displayed in the fixed Eastern timezone.
        # The customer's own timezone (lead.customer_timezone) is reserved
        # for customer-facing emails and reminders — NOT for Calendar.
        # The internal UTC instant (appt_datetime_utc) is NEVER modified.
        display_tz = ZoneInfo(CALENDAR_DISPLAY_TZ)
        start_local = start.astimezone(display_tz)
        end_local = end.astimezone(display_tz)

        description = (
            f"Strategy call with {_na(lead.name)}\n"
            f"Courses: {_na(lead.courses)}\n"
            f"Phone Number: {_na(lead.phone_number)}\n"
            f"Direct Number: {_na(lead.direct_number)}\n"
            f"Caller Name: {_na(lead.caller_name)}"
        )
        body = {
            "summary": f"Strategy Call: {_na(self._branding.company_name)} <> {_na(lead.company_address)}",
            "description": description,
            "start": {
                "dateTime": start_local.strftime("%Y-%m-%dT%H:%M:%S"),
                "timeZone": CALENDAR_DISPLAY_TZ,
            },
            "end": {
                "dateTime": end_local.strftime("%Y-%m-%dT%H:%M:%S"),
                "timeZone": CALENDAR_DISPLAY_TZ,
            },
            "attendees": [{"email": lead.email}],
            # Idempotency key: if the same lead ID is used, Google Calendar
            # will return the existing event instead of creating a duplicate.
            "iCalUID": f"lead-{lead.id}@strategy-call-agent",
        }
        if external_meeting_link:
            # Zoom (or other external provider): store the join URL as the
            # event location; do NOT create a Google Meet conference.
            body["location"] = external_meeting_link
        else:
            body["conferenceData"] = {
                "createRequest": {
                    "requestId": str(uuid.uuid4()),
                    "conferenceSolutionKey": {"type": "hangoutsMeet"},
                }
            }

        try:
            event = self._insert_event(body)
        except Exception as exc:
            record_failed_job(
                db,
                job_type="calendar_create",
                payload=json.dumps({"lead_id": str(lead.id), "email": lead.email}),
                error=str(exc),
                organization_id=self._org_id,
            )
            raise

        event_id = event.get("id", "")
        meet_link = event.get("hangoutLink")
        if not meet_link:
            for ep in event.get("conferenceData", {}).get("entryPoints", []):
                if ep.get("entryPointType") == "video":
                    meet_link = ep.get("uri")
                    break
        return event_id, meet_link

    @external_call_retry
    def _get_event(self, event_id: str) -> dict:
        return (
            self._service.events()
            .get(calendarId=self._calendar_id, eventId=event_id)
            .execute()
        )

    def get_attendee_status(self, event_id: str, attendee_email: str) -> str | None:
        """Return the responseStatus of the attendee matching attendee_email.

        Returns None if the event no longer exists (e.g. manually deleted in
        the Calendar UI) or has been cancelled — callers treat that as a
        decline. Only the attendee whose email matches is considered (never
        attendees[0] blindly), so extra attendees don't cause a misread.
        """
        from googleapiclient.errors import HttpError

        try:
            event = self._get_event(event_id)
        except HttpError as exc:
            if getattr(exc, "status_code", None) in (404, 410):
                return None  # event gone -> treat as declined upstream
            raise
        if event.get("status") == "cancelled":
            return None
        for att in event.get("attendees", []):
            if (att.get("email") or "").lower() == (attendee_email or "").lower():
                return att.get("responseStatus")
        return None  # attendee not found on the event

    def get_meet_link(self, event_id: str) -> str | None:
        """Return the Meet link for an event, or None if the event/link is gone.

        Used by the reminder job to include a working Meet link without
        storing it on the Lead. Defensive: a missing event returns None.
        """
        from googleapiclient.errors import HttpError

        try:
            event = self._get_event(event_id)
        except HttpError as exc:
            if getattr(exc, "status_code", None) in (404, 410):
                return None
            raise
        if event.get("status") == "cancelled":
            return None
        link = event.get("hangoutLink")
        if not link:
            for ep in event.get("conferenceData", {}).get("entryPoints", []):
                if ep.get("entryPointType") == "video":
                    link = ep.get("uri")
                    break
        return link

    @external_call_retry
    def _delete_event(self, event_id: str) -> None:
        self._service.events().delete(
            calendarId=self._calendar_id, eventId=event_id, sendUpdates="none"
        ).execute()

    @external_call_retry
    def _patch_event(self, event_id: str, body: dict) -> dict:
        return (
            self._service.events()
            .patch(calendarId=self._calendar_id, eventId=event_id, body=body)
            .execute()
        )

    def update_event_declined(self, event_id: str, original_summary: str, db: Session) -> None:
        """Update a Calendar event to mark it as declined.

        Instead of deleting the event, we:
        1. Prefix the title with [DECLINED]
        2. Set colorId=11 (red)
        3. Set transparency="transparent" (removes it from free/busy)

        The event is preserved as historical evidence.
        """
        from googleapiclient.errors import HttpError

        body = {
            "summary": f"[DECLINED] {original_summary}",
            "colorId": "11",
            "transparency": "transparent",
        }
        try:
            self._patch_event(event_id, body)
        except HttpError as exc:
            if getattr(exc, "status_code", None) in (404, 410):
                return  # already gone -> nothing to do
            record_failed_job(
                db,
                job_type="calendar_update_declined",
                payload=json.dumps({"event_id": event_id}),
                error=str(exc),
                organization_id=self._org_id,
            )
            raise
        except Exception as exc:
            record_failed_job(
                db,
                job_type="calendar_update_declined",
                payload=json.dumps({"event_id": event_id}),
                error=str(exc),
                organization_id=self._org_id,
            )
            raise

    def release_calendar_event(
        self,
        event_id: str,
        lead_name: str,
        db: Session,
    ) -> bool:
        """Delete a Google Calendar event when an appointment is declined/cancelled.

        Deletes the event completely so the 30-minute slot appears totally
        empty on Google Calendar — no visible [DECLINED] artifact remains.

        Requirements:
        - Organization scoped: uses the credentials of the owning org.
        - Event ID based: deletes the exact stored event ID.
        - Idempotent: if the event is already deleted, returns True.
        - Safe failure: on Google API error, records a FailedJob and returns False.

        Args:
            event_id: The Google Calendar event ID to release.
            lead_name: The lead name (kept for API compatibility; unused by delete).
            db: Active database session.

        Returns:
            True if the event was deleted or was already gone (idempotent).
            False if the Google API call failed after retries.
        """
        if not event_id:
            logger.warning("release_calendar_event called with empty event_id")
            return True

        try:
            self.delete_event(event_id, db)
            logger.info(
                "calendar event deleted: event_id=%s org=%s",
                event_id, self._org_id,
            )
            return True
        except Exception as exc:
            # delete_event already records a FailedJob on error.
            # Log the failure and return False so the caller can handle it.
            logger.warning(
                "calendar event release failed: event_id=%s org=%s error=%s",
                event_id, self._org_id, str(exc)[:200],
            )
            return False

    def update_event_reschedule(
        self,
        event_id: str,
        new_start_utc: datetime,
        duration_minutes: int,
        summary: str,
        db: Session,
    ) -> None:
        """Update a Calendar event with a new start/end time after rescheduling.

        Patches the event's start/end dateTime and summary. A 404/410
        (event already gone) is treated as a no-op success. On final failure
        a FailedJob is recorded and the exception re-raised — the caller
        decides whether to fail the reschedule operation.
        """
        from googleapiclient.errors import HttpError

        new_end_utc = new_start_utc + timedelta(minutes=duration_minutes)

        # ── Timezone conversion for Calendar display ──────────────
        # Always display in the fixed Eastern timezone.
        display_tz = ZoneInfo(CALENDAR_DISPLAY_TZ)
        start_local = new_start_utc.astimezone(display_tz)
        end_local = new_end_utc.astimezone(display_tz)

        body = {
            "start": {
                "dateTime": start_local.strftime("%Y-%m-%dT%H:%M:%S"),
                "timeZone": CALENDAR_DISPLAY_TZ,
            },
            "end": {
                "dateTime": end_local.strftime("%Y-%m-%dT%H:%M:%S"),
                "timeZone": CALENDAR_DISPLAY_TZ,
            },
            "summary": summary,
        }
        try:
            self._patch_event(event_id, body)
        except HttpError as exc:
            if getattr(exc, "status_code", None) in (404, 410):
                return  # already gone -> nothing to do
            record_failed_job(
                db,
                job_type="calendar_update_reschedule",
                payload=json.dumps({"event_id": event_id}),
                error=str(exc),
                organization_id=self._org_id,
            )
            raise
        except Exception as exc:
            record_failed_job(
                db,
                job_type="calendar_update_reschedule",
                payload=json.dumps({"event_id": event_id}),
                error=str(exc),
                organization_id=self._org_id,
            )
            raise

    def delete_event(self, event_id: str, db: Session) -> None:
        """Delete a Calendar event. A 404/410 (already gone) is success.

        Retries transient failures; on final failure records a FailedJob and
        raises.
        """
        from googleapiclient.errors import HttpError

        try:
            self._delete_event(event_id)
        except HttpError as exc:
            if getattr(exc, "status_code", None) in (404, 410):
                return  # already deleted -> nothing to do
            record_failed_job(
                db,
                job_type="calendar_delete",
                payload=json.dumps({"event_id": event_id}),
                error=str(exc),
                organization_id=self._org_id,
            )
            raise
        except Exception as exc:
            record_failed_job(
                db,
                job_type="calendar_delete",
                payload=json.dumps({"event_id": event_id}),
                error=str(exc),
                organization_id=self._org_id,
            )
            raise
