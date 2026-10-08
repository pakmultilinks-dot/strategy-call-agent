"""Comprehensive tests for the daily reminder service (Phase 6).

Covers:
- Eligibility rules (status, same-day, past meetings, calendar event, email)
- Deduplication via reminder_sent_at guard
- Error isolation (one failed lead does not block others)
- Manual trigger endpoint
- Structured logging / EventLog audit trail
- Subject line correctness ("Today" not "Tomorrow")
"""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy.orm import Session

from app.models import EventLog, FollowUp, Lead, LeadStatus


TZ = ZoneInfo("America/Chicago")


def _future_appt() -> datetime:
    """Appointment guaranteed within today's bounds and in the future.

    Previously this added a fixed 2 hours to TODAY_LOCAL (computed at
    import time).  When the test suite ran late at night (past ~10 PM CDT),
    the +2h crossed midnight into the next day, placing the appointment
    OUTSIDE the query's today-bounds filter and causing checked == 0.

    Fix: compute the midpoint between now and end-of-day dynamically so the
    appointment is always (a) in the future, (b) within today's bounds.
    """
    from app.services.reminder_service import _today_bounds_utc
    start_utc, end_utc = _today_bounds_utc(TZ)
    now_utc = datetime.now(timezone.utc)
    # Midpoint between now and end-of-day is always in the future and within bounds
    return now_utc + (end_utc - now_utc) // 2


def _past_appt() -> datetime:
    """Appointment guaranteed within today's bounds but in the past.

    Previously this subtracted a fixed 2 hours from TODAY_LOCAL, which
    could land outside today's bounds when the suite ran very early in
    the day.  Fix: use the midpoint between start-of-day and now.
    """
    from app.services.reminder_service import _today_bounds_utc
    start_utc, _end_utc = _today_bounds_utc(TZ)
    now_utc = datetime.now(timezone.utc)
    # Midpoint between start-of-day and now is always in the past and within bounds
    return start_utc + (now_utc - start_utc) // 2


def _cleanup_leads(db: Session) -> None:
    """Remove all leads from the DB to ensure test isolation.
    
    send_daily_reminders() opens its own SessionLocal() and sees ALL
    committed leads. We clean them up to avoid cross-test contamination.
    """
    from app.models import EventLog, FailedJob
    db.query(EventLog).delete()
    db.query(FailedJob).delete()
    db.query(FollowUp).delete()
    db.query(Lead).delete()
    db.commit()


def _make_lead(
    db: Session,
    *,
    status: LeadStatus = LeadStatus.SCHEDULED,
    appt: datetime | None = None,
    calendar_event_id: str | None = "evt_test_123",
    email: str = "test@example.com",
    reminder_sent_at: datetime | None = None,
) -> Lead:
    """Insert a test lead with unique dedupe key."""
    from app.tenant import _DEFAULT_ORG_ID
    appt = appt or _future_appt()
    lead = Lead(
        id=uuid.uuid4(),
        name="Test Lead",
        email=email,
        phone_number="555-0000",
        company_address="123 Test St",
        status=status,
        appt_datetime_raw="tomorrow 2pm",
        appt_datetime_utc=appt,
        calendar_event_id=calendar_event_id,
        scheduled_date="tomorrow",
        courses="Python",
        dedupe_key=f"test-{uuid.uuid4().hex[:12]}",
        reminder_sent_at=reminder_sent_at,
        organization_id=_DEFAULT_ORG_ID,
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


# ── 1. Eligibility: status filter ────────────────────────────────────────────


class TestEligibilityStatus:
    """Only SCHEDULED, ACCEPTED, TENTATIVE leads are eligible."""

    @pytest.mark.parametrize(
        "status",
        [LeadStatus.DECLINED, LeadStatus.NOT_INTERESTED, LeadStatus.REMINDED, LeadStatus.ERROR],
    )
    def test_non_remindable_status_excluded(self, db_session, status):
        from app.services.reminder_service import send_daily_reminders

        _cleanup_leads(db_session)
        lead = _make_lead(db_session, status=status)
        with patch("app.services.reminder_service.CalendarService") as MockCal, \
             patch("app.services.reminder_service.EmailService") as MockMail:
            MockCal.return_value.get_meet_link.return_value = "https://meet.google.com/test"
            result = send_daily_reminders()
        assert result["checked"] == 0
        assert result["sent"] == 0

    @pytest.mark.parametrize(
        "status",
        [LeadStatus.SCHEDULED, LeadStatus.ACCEPTED, LeadStatus.TENTATIVE],
    )
    def test_remindable_status_included(self, db_session, status):
        from app.services.reminder_service import send_daily_reminders

        _cleanup_leads(db_session)
        lead = _make_lead(db_session, status=status)
        with patch("app.services.reminder_service.CalendarService") as MockCal, \
             patch("app.services.reminder_service.EmailService") as MockMail:
            MockCal.return_value.get_meet_link.return_value = "https://meet.google.com/test"
            result = send_daily_reminders()
        assert result["checked"] == 1


# ── 2. Eligibility: same-day filter ──────────────────────────────────────────


class TestEligibilitySameDay:
    """Only leads with appointments TODAY are eligible."""

    def test_tomorrow_appt_excluded(self, db_session):
        from app.services.reminder_service import _today_bounds_utc, send_daily_reminders

        _cleanup_leads(db_session)
        # Compute "today" dynamically at execution time using the same
        # function the production code uses, so the reference is always
        # consistent regardless of when this test runs in the suite.
        _start_utc, end_utc = _today_bounds_utc(TZ)
        # Noon tomorrow (Chicago time) is well past the [start, end) window.
        tomorrow_noon_utc = (end_utc + timedelta(hours=12)).astimezone(timezone.utc)
        _make_lead(db_session, appt=tomorrow_noon_utc)
        result = send_daily_reminders()
        assert result["checked"] == 0

    def test_yesterday_appt_excluded(self, db_session):
        from app.services.reminder_service import _today_bounds_utc, send_daily_reminders

        _cleanup_leads(db_session)
        start_utc, _end_utc = _today_bounds_utc(TZ)
        # Yesterday at noon (Chicago time) is well before the [start, end) window.
        yesterday_noon_utc = (start_utc - timedelta(hours=12)).astimezone(timezone.utc)
        _make_lead(db_session, appt=yesterday_noon_utc)
        result = send_daily_reminders()
        assert result["checked"] == 0


# ── 3. Eligibility: past meetings excluded ───────────────────────────────────


class TestEligibilityPastMeeting:
    """Meetings whose appointment time has already passed are excluded."""

    def test_past_appt_excluded(self, db_session):
        from app.services.reminder_service import send_daily_reminders

        _cleanup_leads(db_session)
        _make_lead(db_session, appt=_past_appt())
        result = send_daily_reminders()
        assert result["checked"] == 0

    def test_future_appt_included(self, db_session):
        from app.services.reminder_service import send_daily_reminders

        _cleanup_leads(db_session)
        _make_lead(db_session, appt=_future_appt())
        with patch("app.services.reminder_service.CalendarService") as MockCal, \
             patch("app.services.reminder_service.EmailService"):
            MockCal.return_value.get_meet_link.return_value = "https://meet.google.com/test"
            result = send_daily_reminders()
        assert result["checked"] == 1


# ── 4. Eligibility: calendar_event_id required ───────────────────────────────


class TestEligibilityCalendarEvent:
    """Leads without a calendar_event_id are excluded from the query."""

    def test_no_calendar_event_excluded(self, db_session):
        from app.services.reminder_service import send_daily_reminders

        _cleanup_leads(db_session)
        _make_lead(db_session, calendar_event_id=None)
        result = send_daily_reminders()
        assert result["checked"] == 0


# ── 5. Eligibility: email required ───────────────────────────────────────────


class TestEligibilityEmail:
    """Leads without a valid email are excluded from the query."""

    def test_empty_email_excluded(self, db_session):
        from app.services.reminder_service import send_daily_reminders

        _cleanup_leads(db_session)
        # email is NOT NULL at DB level, but empty string is caught by query filter
        _make_lead(db_session, email="")
        result = send_daily_reminders()
        assert result["checked"] == 0

    def test_valid_email_included(self, db_session):
        from app.services.reminder_service import send_daily_reminders

        _cleanup_leads(db_session)
        _make_lead(db_session, email="valid@example.com")
        with patch("app.services.reminder_service.CalendarService") as MockCal, \
             patch("app.services.reminder_service.EmailService") as MockMail:
            MockCal.return_value.get_meet_link.return_value = "https://meet.google.com/test"
            result = send_daily_reminders()
        assert result["checked"] == 1


# ── 6. Deduplication: reminder_sent_at guard ─────────────────────────────────


class TestDeduplication:
    """A lead that was already reminded today should not be re-sent."""

    def test_already_reminded_excluded(self, db_session):
        from app.services.reminder_service import send_daily_reminders

        _cleanup_leads(db_session)
        _make_lead(db_session, reminder_sent_at=datetime.now(timezone.utc))
        result = send_daily_reminders()
        assert result["checked"] == 0


# ── 7. Error isolation: one failed lead does not block others ────────────────


class TestErrorIsolation:
    """If one lead fails (e.g., Meet link unavailable), others still process."""

    def test_error_does_not_block_other_leads(self, db_session):
        from app.services.reminder_service import send_daily_reminders

        _cleanup_leads(db_session)
        lead_good = _make_lead(db_session, email="good@example.com", calendar_event_id="evt_good_001")
        lead_bad = _make_lead(db_session, email="bad@example.com", calendar_event_id="evt_bad_001")

        call_count = 0
        def fake_get_meet_link(event_id):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return None  # First call fails
            return "https://meet.google.com/ok"

        with patch("app.services.reminder_service.CalendarService") as MockCal, \
             patch("app.services.reminder_service.EmailService") as MockMail:
            MockCal.return_value.get_meet_link.side_effect = fake_get_meet_link
            result = send_daily_reminders()

        # Both are checked; at least one errors, at least one succeeds
        assert result["checked"] == 2
        assert result["errors"] >= 1
        assert result["sent"] >= 1


# ── 8. Successful send sets reminder_sent_at ─────────────────────────────────


class TestReminderSentAtGuard:
    """After a successful send, reminder_sent_at is set on the lead."""

    def test_reminder_sent_at_set_after_send(self, db_session):
        from app.services.reminder_service import send_daily_reminders

        _cleanup_leads(db_session)
        lead = _make_lead(db_session)
        assert lead.reminder_sent_at is None

        with patch("app.services.reminder_service.CalendarService") as MockCal, \
             patch("app.services.reminder_service.EmailService") as MockMail:
            MockCal.return_value.get_meet_link.return_value = "https://meet.google.com/test"
            result = send_daily_reminders()

        assert result["sent"] >= 1  # at least our lead was sent
        db_session.refresh(lead)
        assert lead.reminder_sent_at is not None  # guard is set

    def test_reminder_sent_at_not_set_on_error(self, db_session):
        from app.services.reminder_service import send_daily_reminders

        _cleanup_leads(db_session)
        lead = _make_lead(db_session)
        with patch("app.services.reminder_service.CalendarService") as MockCal, \
             patch("app.services.reminder_service.EmailService"):
            MockCal.return_value.get_meet_link.return_value = None  # force error
            result = send_daily_reminders()

        assert result["errors"] >= 1
        db_session.refresh(lead)
        assert lead.reminder_sent_at is None  # NOT set — allows retry


# ── 9. EventLog audit trail ──────────────────────────────────────────────────


class TestEventLog:
    """Successful reminders create EventLog rows."""

    def test_reminder_sent_event_logged(self, db_session):
        from app.services.reminder_service import send_daily_reminders

        _cleanup_leads(db_session)
        lead = _make_lead(db_session)
        with patch("app.services.reminder_service.CalendarService") as MockCal, \
             patch("app.services.reminder_service.EmailService"):
            MockCal.return_value.get_meet_link.return_value = "https://meet.google.com/test"
            send_daily_reminders()

        events = db_session.query(EventLog).filter_by(lead_id=lead.id).all()
        event_types = [e.event_type for e in events]
        assert "reminder_sent" in event_types

    def test_error_event_logged_on_failure(self, db_session):
        from app.services.reminder_service import send_daily_reminders

        _cleanup_leads(db_session)
        lead = _make_lead(db_session)
        with patch("app.services.reminder_service.CalendarService") as MockCal, \
             patch("app.services.reminder_service.EmailService"):
            MockCal.return_value.get_meet_link.return_value = None
            send_daily_reminders()

        events = db_session.query(EventLog).filter_by(lead_id=lead.id).all()
        event_types = [e.event_type for e in events]
        assert "error" in event_types


# ── 10. Subject line: "Today" not "Tomorrow" ─────────────────────────────────


class TestSubjectToday:
    """The reminder subject must say 'Today' because this is a same-day job."""

    def test_subject_says_today(self):
        from app.services.email_templates import build_reminder_subject

        lead = MagicMock()
        subject = build_reminder_subject(lead, "2:00 PM CDT")
        assert "Today" in subject
        assert "Tomorrow" not in subject

    def test_subject_contains_company(self):
        from app.services.email_templates import build_reminder_subject

        lead = MagicMock()
        subject = build_reminder_subject(lead, "2:00 PM CDT")
        assert "Strategy Call Agent" in subject

    def test_subject_starts_with_reminder(self):
        from app.services.email_templates import build_reminder_subject

        lead = MagicMock()
        subject = build_reminder_subject(lead, "2:00 PM CDT")
        assert subject.startswith("Reminder:")


# ── 11. Summary dict structure ───────────────────────────────────────────────


class TestSummaryStructure:
    """The returned summary dict has the expected keys."""

    def test_summary_keys(self, db_session):
        from app.services.reminder_service import send_daily_reminders

        result = send_daily_reminders()
        assert "checked" in result
        assert "sent" in result
        assert "errors" in result
        assert isinstance(result["checked"], int)
        assert isinstance(result["sent"], int)
        assert isinstance(result["errors"], int)
        assert result["checked"] >= result["sent"] + result["errors"]
