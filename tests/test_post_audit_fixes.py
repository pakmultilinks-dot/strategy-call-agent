"""Focused tests for the two post-audit fixes (Session 3).

Fix 1 — Calendar sends no duplicate invitation email
  - sendUpdates="none" in _insert_event()
  - Attendees still included in event body
  - Zoom join URL still stored in event
  - Event ID returned as before
  - Google Meet path unaffected

Fix 2 — Email templates show provider-appropriate button text
  - Zoom → "Join Zoom Meeting"
  - Google Meet → "Join Google Meet"
  - Unknown/None → "Join Meeting"
  - URL unchanged in all cases
  - Backward-compatible default (no meeting_provider param)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Lead, LeadStatus
from app.services.email_templates import (
    _meeting_button_label,
    build_confirmation_html,
    build_confirmation_text,
    build_reminder_html,
    build_reminder_text,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TZ = ZoneInfo("America/Chicago")

_DEFAULT_MEET_LINK = "https://meet.google.com/abc-defg-hij"
_ZOOM_MEET_LINK = "https://zoom.us/j/123456789"


def _future_appt() -> datetime:
    return (datetime.now(_TZ) + timedelta(hours=2)).astimezone(timezone.utc)


def _make_lead(**overrides) -> Lead:
    """Create a minimal Lead for template testing (no DB required)."""
    defaults = {
        "id": "00000000-0000-0000-0000-000000000001",
        "interested": "yes",
        "name": "Jane Doe",
        "company_address": "Acme Corp",
        "phone_number": "555-0100",
        "direct_number": None,
        "courses": "Python, Docker",
        "email": "jane@example.com",
        "scheduled_date": "tomorrow",
        "caller_name": "Agent Smith",
        "appt_datetime_raw": "tomorrow 2pm",
        "appt_datetime_utc": _future_appt(),
        "dedupe_key": "jane@example.com|tomorrow 2pm",
        "status": LeadStatus.SCHEDULED,
        "calendar_event_id": "cal-123",
        "reminder_sent_at": None,
    }
    defaults.update(overrides)
    return Lead(**defaults)


# ===========================================================================
# Fix 1 — sendUpdates="none"
# ===========================================================================


class TestFix1SendUpdatesNone:
    """Verify that CalendarService._insert_event uses sendUpdates='none'
    so Google no longer sends a duplicate invitation email."""

    def test_insert_event_uses_send_updates_none(self):
        """_insert_event must pass sendUpdates='none' to the Calendar API."""
        from app.services.calendar_service import CalendarService

        mock_service = MagicMock()
        cs = CalendarService.__new__(CalendarService)
        cs._service = mock_service
        cs._calendar_id = "primary"

        mock_service.events.return_value.insert.return_value.execute.return_value = {
            "id": "evt-123"
        }

        body = {
            "summary": "Test Event",
            "start": {"dateTime": "2026-08-20T14:00:00-05:00"},
            "end": {"dateTime": "2026-08-20T15:00:00-05:00"},
            "attendees": [{"email": "jane@example.com"}],
        }

        cs._insert_event(body)

        # Verify the Calendar API insert was called with sendUpdates="none"
        insert_call = mock_service.events.return_value.insert
        insert_call.assert_called_once()
        call_kwargs = insert_call.call_args
        assert call_kwargs.kwargs.get("sendUpdates") == "none" or \
               (len(call_kwargs.args) == 0 and call_kwargs[1].get("sendUpdates") == "none"), \
            f"Expected sendUpdates='none', got: {call_kwargs}"

    def test_insert_event_does_not_use_send_updates_all(self):
        """Regression guard: sendUpdates='all' must NOT appear."""
        from app.services.calendar_service import CalendarService

        mock_service = MagicMock()
        cs = CalendarService.__new__(CalendarService)
        cs._service = mock_service
        cs._calendar_id = "primary"

        mock_service.events.return_value.insert.return_value.execute.return_value = {
            "id": "evt-456"
        }

        body = {"summary": "Test"}
        cs._insert_event(body)

        call_kwargs = mock_service.events.return_value.insert.call_args
        send_value = call_kwargs.kwargs.get("sendUpdates")
        assert send_value != "all", "sendUpdates='all' would cause duplicate invitation emails"

    def test_attendees_still_included_in_event_body(self):
        """Attendees must remain in the body even with sendUpdates='none'."""
        from app.services.calendar_service import CalendarService

        mock_service = MagicMock()
        cs = CalendarService.__new__(CalendarService)
        cs._service = mock_service
        cs._calendar_id = "primary"

        mock_service.events.return_value.insert.return_value.execute.return_value = {
            "id": "evt-789"
        }

        body = {
            "summary": "Strategy Call",
            "attendees": [{"email": "jane@example.com"}],
            "location": "https://zoom.us/j/123456",
        }

        cs._insert_event(body)

        # Body is passed through unchanged
        actual_body = mock_service.events.return_value.insert.call_args[1]["body"]
        assert actual_body["attendees"] == [{"email": "jane@example.com"}]
        assert "zoom.us" in actual_body["location"]

    def test_insert_event_returns_event_id(self):
        """_insert_event still returns the event dict from Calendar API."""
        from app.services.calendar_service import CalendarService

        mock_service = MagicMock()
        cs = CalendarService.__new__(CalendarService)
        cs._service = mock_service
        cs._calendar_id = "primary"

        expected = {"id": "evt-returned", "htmlLink": "https://calendar.google.com/..."}
        mock_service.events.return_value.insert.return_value.execute.return_value = expected

        result = cs._insert_event({"summary": "Test"})
        assert result == expected
        assert result["id"] == "evt-returned"

    def test_rsvp_attendee_status_unaffected_by_send_updates(self):
        """RSVP poller reads responseStatus via _get_event(), not sendUpdates.
        Verify get_attendee_status still works (Google Meet path)."""
        from app.services.calendar_service import CalendarService

        mock_service = MagicMock()
        cs = CalendarService.__new__(CalendarService)
        cs._service = mock_service
        cs._calendar_id = "primary"

        mock_service.events.return_value.get.return_value.execute.return_value = {
            "attendees": [
                {"email": "jane@example.com", "responseStatus": "accepted"},
            ]
        }

        result = cs.get_attendee_status("evt-rsvp", "jane@example.com")
        assert result == "accepted"


# ===========================================================================
# Fix 3 — delete_event sends no cancellation notification to prospect
# ===========================================================================


class TestFix3DeleteEventNoNotification:
    """Verify that CalendarService._delete_event uses sendUpdates='none'
    so Google Calendar does NOT send a cancellation email to the prospect
    when an event is deleted."""

    def test_delete_event_uses_send_updates_none(self):
        """_delete_event must pass sendUpdates='none' to the Calendar API."""
        from app.services.calendar_service import CalendarService

        mock_service = MagicMock()
        cs = CalendarService.__new__(CalendarService)
        cs._service = mock_service
        cs._calendar_id = "primary"

        mock_service.events.return_value.delete.return_value.execute.return_value = {}

        cs._delete_event("evt-delete-123")

        # Verify the Calendar API delete was called with sendUpdates="none"
        delete_call = mock_service.events.return_value.delete
        delete_call.assert_called_once()
        call_kwargs = delete_call.call_args
        assert call_kwargs.kwargs.get("sendUpdates") == "none" or \
               (len(call_kwargs.args) == 0 and call_kwargs[1].get("sendUpdates") == "none"), \
            f"Expected sendUpdates='none', got: {call_kwargs}"

    def test_delete_event_does_not_use_send_updates_all(self):
        """Regression guard: sendUpdates='all' must NOT appear in delete."""
        from app.services.calendar_service import CalendarService

        mock_service = MagicMock()
        cs = CalendarService.__new__(CalendarService)
        cs._service = mock_service
        cs._calendar_id = "primary"

        mock_service.events.return_value.delete.return_value.execute.return_value = {}

        cs._delete_event("evt-delete-456")

        call_kwargs = mock_service.events.return_value.delete.call_args
        send_value = call_kwargs.kwargs.get("sendUpdates")
        assert send_value != "all", \
            "sendUpdates='all' in _delete_event would send cancellation email to prospect"

    def test_delete_event_passes_correct_calendar_and_event_ids(self):
        """_delete_event must still use the correct calendarId and eventId."""
        from app.services.calendar_service import CalendarService

        mock_service = MagicMock()
        cs = CalendarService.__new__(CalendarService)
        cs._service = mock_service
        cs._calendar_id = "org-cal-789"

        mock_service.events.return_value.delete.return_value.execute.return_value = {}

        cs._delete_event("evt-target-event")

        call_kwargs = mock_service.events.return_value.delete.call_args
        assert call_kwargs.kwargs.get("calendarId") == "org-cal-789"
        assert call_kwargs.kwargs.get("eventId") == "evt-target-event"
        assert call_kwargs.kwargs.get("sendUpdates") == "none"


# ===========================================================================
# Fix 2 — Email template provider-aware button text
# ===========================================================================


class TestMeetingButtonLabel:
    """Unit test the helper function that maps provider → button label."""

    def test_zoom_returns_zoom_label(self):
        assert _meeting_button_label("zoom") == "Join Zoom Meeting"

    def test_google_meet_returns_google_meet_label(self):
        assert _meeting_button_label("google_meet") == "Join Google Meet"

    def test_none_returns_generic_label(self):
        assert _meeting_button_label(None) == "Join Meeting"

    def test_unknown_returns_generic_label(self):
        assert _meeting_button_label("teams") == "Join Meeting"
        assert _meeting_button_label("webex") == "Join Meeting"
        assert _meeting_button_label("") == "Join Meeting"


class TestFix2ConfirmationHTMLButton:
    """Confirmation HTML email must show provider-specific button text."""

    def test_zoom_shows_zoom_button(self):
        lead = _make_lead()
        html = build_confirmation_html(
            lead, _ZOOM_MEET_LINK, "Great call coming up!",
            meeting_provider="zoom",
        )
        assert "Join Zoom Meeting" in html
        assert "Join Google Meet" not in html

    def test_google_meet_shows_google_meet_button(self):
        lead = _make_lead()
        html = build_confirmation_html(
            lead, _DEFAULT_MEET_LINK, "Great call coming up!",
            meeting_provider="google_meet",
        )
        assert "Join Google Meet" in html
        assert "Join Zoom Meeting" not in html

    def test_none_shows_generic_button(self):
        lead = _make_lead()
        html = build_confirmation_html(
            lead, _DEFAULT_MEET_LINK, "Great call coming up!",
            meeting_provider=None,
        )
        assert "Join Meeting" in html
        # "Join Google Meet" is the old default — must NOT appear
        assert "Join Google Meet" not in html

    def test_url_unchanged_for_zoom(self):
        lead = _make_lead()
        html = build_confirmation_html(
            lead, _ZOOM_MEET_LINK, "Great call!",
            meeting_provider="zoom",
        )
        assert _ZOOM_MEET_LINK in html

    def test_backward_compatible_no_param(self):
        """Calling without meeting_provider defaults to generic label."""
        lead = _make_lead()
        html = build_confirmation_html(
            lead, _DEFAULT_MEET_LINK, "Hello!"
        )
        # Default is None → "Join Meeting"
        assert "Join Meeting" in html


class TestFix2ConfirmationTextButton:
    """Confirmation plain-text email must show provider-specific button text."""

    def test_zoom_shows_zoom_button(self):
        lead = _make_lead()
        text = build_confirmation_text(
            lead, _ZOOM_MEET_LINK, "Great call coming up!",
            meeting_provider="zoom",
        )
        assert "Join Zoom Meeting" in text
        assert "Join Google Meet" not in text

    def test_google_meet_shows_google_meet_button(self):
        lead = _make_lead()
        text = build_confirmation_text(
            lead, _DEFAULT_MEET_LINK, "Great call coming up!",
            meeting_provider="google_meet",
        )
        assert "Join Google Meet" in text

    def test_none_shows_generic_button(self):
        lead = _make_lead()
        text = build_confirmation_text(
            lead, _DEFAULT_MEET_LINK, "Hello!",
            meeting_provider=None,
        )
        assert "Join Meeting" in text
        assert "Join Google Meet" not in text

    def test_url_unchanged_for_zoom(self):
        lead = _make_lead()
        text = build_confirmation_text(
            lead, _ZOOM_MEET_LINK, "Great call!",
            meeting_provider="zoom",
        )
        assert _ZOOM_MEET_LINK in text


class TestFix2ReminderHTMLButton:
    """Reminder HTML email must show provider-specific button text."""

    def test_zoom_shows_zoom_button(self):
        lead = _make_lead()
        html = build_reminder_html(
            lead, _ZOOM_MEET_LINK,
            meeting_provider="zoom",
        )
        assert "Join Zoom Meeting" in html
        assert "Join Google Meet" not in html

    def test_google_meet_shows_google_meet_button(self):
        lead = _make_lead()
        html = build_reminder_html(
            lead, _DEFAULT_MEET_LINK,
            meeting_provider="google_meet",
        )
        assert "Join Google Meet" in html

    def test_none_shows_generic_button(self):
        lead = _make_lead()
        html = build_reminder_html(
            lead, _DEFAULT_MEET_LINK,
            meeting_provider=None,
        )
        assert "Join Meeting" in html
        assert "Join Google Meet" not in html

    def test_url_unchanged_for_zoom(self):
        lead = _make_lead()
        html = build_reminder_html(
            lead, _ZOOM_MEET_LINK,
            meeting_provider="zoom",
        )
        assert _ZOOM_MEET_LINK in html

    def test_backward_compatible_no_param(self):
        """Calling without meeting_provider defaults to generic label."""
        lead = _make_lead()
        html = build_reminder_html(lead, _DEFAULT_MEET_LINK)
        assert "Join Meeting" in html


class TestFix2ReminderTextButton:
    """Reminder plain-text email must show provider-specific button text."""

    def test_zoom_shows_zoom_button(self):
        lead = _make_lead()
        text = build_reminder_text(
            lead, _ZOOM_MEET_LINK,
            meeting_provider="zoom",
        )
        assert "Join Zoom Meeting" in text
        assert "Join Google Meet" not in text

    def test_google_meet_shows_google_meet_button(self):
        lead = _make_lead()
        text = build_reminder_text(
            lead, _DEFAULT_MEET_LINK,
            meeting_provider="google_meet",
        )
        assert "Join Google Meet" in text

    def test_none_shows_generic_button(self):
        lead = _make_lead()
        text = build_reminder_text(
            lead, _DEFAULT_MEET_LINK,
            meeting_provider=None,
        )
        assert "Join Meeting" in text
        assert "Join Google Meet" not in text

    def test_url_unchanged_for_zoom(self):
        lead = _make_lead()
        text = build_reminder_text(
            lead, _ZOOM_MEET_LINK,
            meeting_provider="zoom",
        )
        assert _ZOOM_MEET_LINK in text

    def test_backward_compatible_no_param(self):
        """Calling without meeting_provider defaults to generic label."""
        lead = _make_lead()
        text = build_reminder_text(lead, _DEFAULT_MEET_LINK)
        assert "Join Meeting" in text


# ===========================================================================
# Cross-cutting: no visual regressions
# ===========================================================================


class TestNoVisualRegressions:
    """Ensure button styling (color, border-radius) is preserved."""

    def test_meeting_button_color_preserved_html(self):
        """The green meeting button color must remain unchanged."""
        lead = _make_lead()
        html = build_confirmation_html(
            lead, _ZOOM_MEET_LINK, "Test",
            meeting_provider="zoom",
        )
        assert "#0d652d" in html

    def test_meeting_button_color_preserved_reminder(self):
        lead = _make_lead()
        html = build_reminder_html(
            lead, _ZOOM_MEET_LINK,
            meeting_provider="zoom",
        )
        assert "#0d652d" in html
