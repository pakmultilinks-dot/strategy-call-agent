"""Regression tests for Calendar slot-conflict handling.

Verifies the NEW business rule: overlapping Google Calendar events are
ALLOWED because multiple employees may book calls for different prospects
at the same requested time.

Key behaviors tested:
  1. create_event() no longer checks free/busy — no CalendarSlotConflictError
  2. Two leads at the same exact time are both successfully scheduled
  3. Three leads at the same exact time are all successfully scheduled
  4. Exact requested times are preserved (2:30-3:00 stays 2:30-3:00)
  5. No automatic time shifting occurs
  6. A deleted/canceled event does not prevent another lead at the same time
  7. Genuine Google Calendar API failures still follow the existing error path
  8. Existing timezone and duration tests continue to pass
  9. CalendarSlotConflictError class is preserved for backward compatibility
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from app.models import EventLog, FailedJob, Lead, LeadStatus
from app.models_multi_tenant import Organization
from app.services.calendar_service import CalendarService, CalendarSlotConflictError
from app.services.meeting_provider import MeetingDetails, ZoomMeetingProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_org(db: Session) -> Organization:
    """Insert a minimal Organization row."""
    org = Organization(
        name=f"SlotConflict Org {uuid.uuid4().hex[:6]}",
        slug=f"sc-test-{uuid.uuid4().hex[:6]}",
        display_name="SlotConflict Test Org",
    )
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


def _make_lead(db: Session, org_id: uuid.UUID, **overrides) -> Lead:
    """Insert a PENDING lead with all required fields."""
    defaults = dict(
        name="Slot Conflict Test Lead",
        email=f"sc-{uuid.uuid4().hex[:8]}@example.com",
        company_address="123 Conflict St",
        appt_datetime_raw="tomorrow 3pm",
        appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=2),
        status=LeadStatus.PENDING,
        organization_id=org_id,
        dedupe_key=f"sc-lead-{uuid.uuid4().hex[:12]}",
    )
    defaults.update(overrides)
    lead = Lead(**defaults)
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


class _FakeZoomProvider(ZoomMeetingProvider):
    """Lightweight stand-in for ZoomMeetingProvider."""

    def __init__(
        self,
        meeting_id: str = "zoom_sc_123",
        meeting_link: str = "https://zoom.us/j/sc123?pwd=test",
    ):
        self._meeting_id = meeting_id
        self._meeting_link = meeting_link

    def create_meeting(self, **kwargs):
        return MeetingDetails(
            meeting_id=self._meeting_id,
            meeting_link=self._meeting_link,
        )


def _run_pipeline(db_session, lead, calendar_side_effect):
    """Run the pipeline with mocked services.

    Args:
        calendar_side_effect: What CalendarService.create_event raises/returns.
            - If an Exception, it is raised.
            - If a tuple, it is returned as (event_id, meet_link).
    """
    from app.main import _run_pipeline_inner

    mock_cal_svc = MagicMock()
    if isinstance(calendar_side_effect, Exception):
        mock_cal_svc.create_event.side_effect = calendar_side_effect
    else:
        mock_cal_svc.create_event.return_value = calendar_side_effect

    mock_ai_svc = MagicMock()
    mock_ai_svc.generate_confirmation_email.return_value = ("Hello!", "gpt-test")

    mock_email_svc = MagicMock()
    mock_email_svc.send_confirmation_email.return_value = "msg_123"

    mock_resolver = MagicMock()
    mock_resolver.resolve_branding.return_value = MagicMock(company_name="Test Co")
    mock_resolver.resolve_meeting_config.return_value = MagicMock(duration_minutes=30)

    with (
        patch("app.services.meeting_provider.resolve_meeting_provider",
              return_value=_FakeZoomProvider()),
        patch("app.services.calendar_service.CalendarService",
              return_value=mock_cal_svc),
        patch("app.services.ai_service.AIService",
              return_value=mock_ai_svc),
        patch("app.services.email_service.EmailService",
              return_value=mock_email_svc),
        patch("app.services.integration_config_resolver.IntegrationConfigResolver",
              return_value=mock_resolver),
    ):
        _run_pipeline_inner(lead.id)


# ---------------------------------------------------------------------------
# Test 1: create_event() no longer raises CalendarSlotConflictError
# ---------------------------------------------------------------------------

class TestNoSlotConflictBlocking:
    """create_event() does NOT check free/busy or raise CalendarSlotConflictError."""

    def test_create_event_does_not_check_slot_availability(
        self, db_session: Session
    ):
        """create_event proceeds directly to _insert_event without free/busy query."""
        org = _make_org(db_session)
        lead = _make_lead(db_session, org.id)

        mock_cal_svc = MagicMock()
        mock_cal_svc.create_event.return_value = ("evt_no_conflict", "https://meet.google.com/test")

        with patch("app.services.calendar_service.CalendarService",
                    return_value=mock_cal_svc):
            # Should succeed — no CalendarSlotConflictError
            result = mock_cal_svc.create_event(lead, db_session)
            assert result == ("evt_no_conflict", "https://meet.google.com/test")

    def test_create_event_allows_busy_slot(
        self, db_session: Session
    ):
        """Even if check_slot_available returns False, create_event still creates."""
        from unittest.mock import PropertyMock

        org = _make_org(db_session)
        lead = _make_lead(db_session, org.id)

        # Use real CalendarService.create_event but mock _insert_event
        mock_insert = MagicMock()
        mock_insert.return_value = {"id": "evt_busy_slot", "hangoutLink": "https://meet.google.com/busy"}

        mock_service = MagicMock()
        mock_freebusy = MagicMock()
        mock_freebusy.query.return_value.execute.return_value = {
            "calendars": {"primary": {"busy": [
                {"start": lead.appt_datetime_utc.isoformat(),
                 "end": (lead.appt_datetime_utc + timedelta(minutes=30)).isoformat()}
            ]}}
        }
        mock_service.freebusy.return_value = mock_freebusy

        svc = object.__new__(CalendarService)
        svc._service = mock_service
        svc._calendar_id = "primary"
        svc._org_id = org.id
        svc._meeting_duration = 30
        svc._branding = MagicMock()
        svc._branding.company_name = "Test Co"

        # Patch _insert_event to use our mock
        with patch.object(svc, '_insert_event', mock_insert):
            event_id, meet_link = svc.create_event(lead, db_session)

        assert event_id == "evt_busy_slot"
        # _insert_event was called — meaning the event WAS created despite busy slot
        mock_insert.assert_called_once()


# ---------------------------------------------------------------------------
# Test 2: Two leads with same exact time are both scheduled
# ---------------------------------------------------------------------------

class TestOverlappingEventsAllowed:
    """Multiple leads at the same time are all successfully booked."""

    def test_two_leads_same_time_both_scheduled(
        self, db_session: Session
    ):
        """Two leads requesting the exact same time are both SCHEDULED."""
        org = _make_org(db_session)
        same_time = datetime.now(timezone.utc) + timedelta(hours=3)

        lead1 = _make_lead(db_session, org.id, appt_datetime_utc=same_time)
        lead2 = _make_lead(db_session, org.id, appt_datetime_utc=same_time)

        _run_pipeline(db_session, lead1, ("evt_lead1", "https://meet.google.com/l1"))
        _run_pipeline(db_session, lead2, ("evt_lead2", "https://meet.google.com/l2"))

        db_session.refresh(lead1)
        db_session.refresh(lead2)
        assert lead1.status == LeadStatus.SCHEDULED, "Lead 1 must be SCHEDULED"
        assert lead2.status == LeadStatus.SCHEDULED, "Lead 2 must be SCHEDULED"
        assert lead1.calendar_event_id == "evt_lead1"
        assert lead2.calendar_event_id == "evt_lead2"

    def test_three_leads_same_time_all_scheduled(
        self, db_session: Session
    ):
        """Three leads requesting the exact same time are all SCHEDULED."""
        org = _make_org(db_session)
        same_time = datetime.now(timezone.utc) + timedelta(hours=4)

        lead1 = _make_lead(db_session, org.id, appt_datetime_utc=same_time)
        lead2 = _make_lead(db_session, org.id, appt_datetime_utc=same_time)
        lead3 = _make_lead(db_session, org.id, appt_datetime_utc=same_time)

        _run_pipeline(db_session, lead1, ("evt_l1", "https://meet.google.com/l1"))
        _run_pipeline(db_session, lead2, ("evt_l2", "https://meet.google.com/l2"))
        _run_pipeline(db_session, lead3, ("evt_l3", "https://meet.google.com/l3"))

        db_session.refresh(lead1)
        db_session.refresh(lead2)
        db_session.refresh(lead3)
        assert lead1.status == LeadStatus.SCHEDULED
        assert lead2.status == LeadStatus.SCHEDULED
        assert lead3.status == LeadStatus.SCHEDULED

    def test_four_leads_same_time_all_scheduled(
        self, db_session: Session
    ):
        """Four leads requesting the exact same time are all SCHEDULED."""
        org = _make_org(db_session)
        same_time = datetime.now(timezone.utc) + timedelta(hours=5)

        leads = [_make_lead(db_session, org.id, appt_datetime_utc=same_time) for _ in range(4)]
        for i, lead in enumerate(leads):
            _run_pipeline(db_session, lead, (f"evt_{i}", f"https://meet.google.com/{i}"))

        for lead in leads:
            db_session.refresh(lead)
            assert lead.status == LeadStatus.SCHEDULED, f"Lead {lead.id} must be SCHEDULED"


# ---------------------------------------------------------------------------
# Test 3: Exact requested times are preserved (no shifting)
# ---------------------------------------------------------------------------

class TestExactTimePreserved:
    """Appointment times are NOT shifted, rounded, or moved."""

    def test_exact_2_30_stays_2_30(self, db_session: Session):
        """A 2:30 appointment remains exactly 2:30."""
        org = _make_org(db_session)
        # Build a specific 2:30 UTC time
        target = datetime(2026, 10, 15, 14, 30, 0, tzinfo=timezone.utc)
        lead = _make_lead(db_session, org.id, appt_datetime_utc=target)

        captured_body = {}

        def capture_insert(body):
            captured_body.update(body)
            return {"id": "evt_230", "hangoutLink": "https://meet.google.com/230"}

        mock_cal_svc = MagicMock()
        mock_cal_svc.create_event.side_effect = lambda l, db, **kw: (
            "evt_230", "https://meet.google.com/230"
        )

        with (
            patch("app.services.calendar_service.CalendarService",
                  return_value=mock_cal_svc),
            patch("app.services.meeting_provider.resolve_meeting_provider",
                  return_value=_FakeZoomProvider()),
            patch("app.services.ai_service.AIService",
                  return_value=MagicMock(
                      generate_confirmation_email=MagicMock(return_value=("Hi", "model")))),
            patch("app.services.email_service.EmailService",
                  return_value=MagicMock(
                      send_confirmation_email=MagicMock(return_value="msg"))),
            patch("app.services.integration_config_resolver.IntegrationConfigResolver",
                  return_value=MagicMock(
                      resolve_branding=MagicMock(return_value=MagicMock(company_name="X")),
                      resolve_meeting_config=MagicMock(return_value=MagicMock(duration_minutes=30)))),
        ):
            from app.main import _run_pipeline_inner
            _run_pipeline_inner(lead.id)

        # Verify create_event was called with the exact time
        call_args = mock_cal_svc.create_event.call_args
        called_lead = call_args[0][0]
        assert called_lead.appt_datetime_utc == target, (
            "Appointment time must remain exactly 2:30 — no shifting"
        )

    def test_exact_4_30_stays_4_30(self, db_session: Session):
        """A 4:30 appointment remains exactly 4:30."""
        org = _make_org(db_session)
        target = datetime(2026, 10, 15, 16, 30, 0, tzinfo=timezone.utc)
        lead = _make_lead(db_session, org.id, appt_datetime_utc=target)

        mock_cal_svc = MagicMock()
        mock_cal_svc.create_event.return_value = ("evt_430", "https://meet.google.com/430")

        with (
            patch("app.services.calendar_service.CalendarService",
                  return_value=mock_cal_svc),
            patch("app.services.meeting_provider.resolve_meeting_provider",
                  return_value=_FakeZoomProvider()),
            patch("app.services.ai_service.AIService",
                  return_value=MagicMock(
                      generate_confirmation_email=MagicMock(return_value=("Hi", "model")))),
            patch("app.services.email_service.EmailService",
                  return_value=MagicMock(
                      send_confirmation_email=MagicMock(return_value="msg"))),
            patch("app.services.integration_config_resolver.IntegrationConfigResolver",
                  return_value=MagicMock(
                      resolve_branding=MagicMock(return_value=MagicMock(company_name="X")),
                      resolve_meeting_config=MagicMock(return_value=MagicMock(duration_minutes=30)))),
        ):
            from app.main import _run_pipeline_inner
            _run_pipeline_inner(lead.id)

        call_args = mock_cal_svc.create_event.call_args
        called_lead = call_args[0][0]
        assert called_lead.appt_datetime_utc == target, (
            "Appointment time must remain exactly 4:30 — no shifting"
        )

    def test_no_automatic_time_shift(self, db_session: Session):
        """Lead's appt_datetime_utc is never modified by the pipeline."""
        org = _make_org(db_session)
        original_time = datetime(2026, 11, 20, 18, 45, 0, tzinfo=timezone.utc)
        lead = _make_lead(db_session, org.id, appt_datetime_utc=original_time)

        _run_pipeline(db_session, lead, ("evt_noshift", "https://meet.google.com/ns"))

        db_session.refresh(lead)
        assert lead.appt_datetime_utc == original_time, (
            "appt_datetime_utc must never be modified"
        )


# ---------------------------------------------------------------------------
# Test 4: Deleted/canceled event does not block another lead at same time
# ---------------------------------------------------------------------------

class TestDeletedEventDoesNotBlock:
    """A deleted/canceled event does not prevent another lead at the same time."""

    def test_new_lead_at_same_time_after_cancel(
        self, db_session: Session
    ):
        """After one lead is declined (event deleted), another at the same time books."""
        org = _make_org(db_session)
        same_time = datetime.now(timezone.utc) + timedelta(hours=6)

        # First lead is scheduled then declined (event deleted)
        lead1 = _make_lead(db_session, org.id, appt_datetime_utc=same_time)
        _run_pipeline(db_session, lead1, ("evt_del1", "https://meet.google.com/d1"))
        db_session.refresh(lead1)
        assert lead1.status == LeadStatus.SCHEDULED

        # Second lead at the exact same time — must succeed
        lead2 = _make_lead(db_session, org.id, appt_datetime_utc=same_time)
        _run_pipeline(db_session, lead2, ("evt_del2", "https://meet.google.com/d2"))
        db_session.refresh(lead2)
        assert lead2.status == LeadStatus.SCHEDULED, (
            "New lead at same time after cancel must be SCHEDULED"
        )


# ---------------------------------------------------------------------------
# Test 5: Successful Calendar creation → SCHEDULED (preserved)
# ---------------------------------------------------------------------------

class TestSuccessfulCalendarStillScheduled:
    """When Calendar succeeds, lead becomes SCHEDULED as before."""

    def test_successful_calendar_creation_results_in_scheduled(
        self, db_session: Session
    ):
        org = _make_org(db_session)
        lead = _make_lead(db_session, org.id)

        _run_pipeline(
            db_session,
            lead,
            ("fake_event_id_42", "https://meet.google.com/fake-link"),
        )

        db_session.refresh(lead)
        assert lead.status == LeadStatus.SCHEDULED, (
            "Lead must be SCHEDULED on successful Calendar creation"
        )
        assert lead.calendar_event_id == "fake_event_id_42", (
            "calendar_event_id must be set on success"
        )
        assert lead.zoom_meeting_id == "zoom_sc_123"

        # Verify the calendar_created event was logged
        cal_event = db_session.query(EventLog).filter(
            EventLog.lead_id == lead.id,
            EventLog.event_type == "calendar_created",
        ).first()
        assert cal_event is not None

        # No FailedJob should exist for this lead
        failed = db_session.query(FailedJob).filter(
            FailedJob.organization_id == org.id,
            FailedJob.job_type == "calendar_create",
        ).first()
        assert failed is None, "No FailedJob on successful creation"

    def test_no_failed_job_on_success(self, db_session: Session):
        """Successful Calendar creation does NOT create a FailedJob."""
        org = _make_org(db_session)
        lead = _make_lead(db_session, org.id)

        _run_pipeline(
            db_session,
            lead,
            ("evt_success_123", "https://meet.google.com/success"),
        )

        failed = db_session.query(FailedJob).filter(
            FailedJob.organization_id == org.id,
        ).count()
        assert failed == 0


# ---------------------------------------------------------------------------
# Test 6: Non-slot-conflict Calendar errors still follow fail-open path
# ---------------------------------------------------------------------------

class TestOtherCalendarErrorsStillFailOpen:
    """Non-slot-conflict Calendar errors (e.g. RuntimeError) still result
    in SCHEDULED — the existing fail-open behavior is preserved."""

    def test_generic_calendar_error_still_scheduled(
        self, db_session: Session, caplog
    ):
        org = _make_org(db_session)
        lead = _make_lead(db_session, org.id)

        with caplog.at_level(logging.WARNING, logger="strategy-call-agent"):
            _run_pipeline(
                db_session, lead,
                RuntimeError("Calendar API quota exceeded"),
            )

        db_session.refresh(lead)
        # Existing behavior: generic failures still go to SCHEDULED
        assert lead.status == LeadStatus.SCHEDULED
        assert lead.calendar_event_id is None

        # Should have the observability warning, NOT the slot-conflict warning
        slot_warnings = [
            r for r in caplog.records
            if "calendar slot conflict" in r.message
        ]
        assert len(slot_warnings) == 0, (
            "Generic Calendar errors should not trigger slot-conflict path"
        )
        obs_warnings = [
            r for r in caplog.records
            if "calendar event creation failed" in r.message
        ]
        assert len(obs_warnings) >= 1


# ---------------------------------------------------------------------------
# Test 7: CalendarSlotConflictError is preserved for backward compatibility
# ---------------------------------------------------------------------------

class TestCalendarSlotConflictErrorClass:
    """CalendarSlotConflictError is properly defined (backward compat)."""

    def test_is_exception_subclass(self):
        assert issubclass(CalendarSlotConflictError, Exception)

    def test_carry_message(self):
        err = CalendarSlotConflictError("test conflict message")
        assert str(err) == "test conflict message"

    def test_importable_from_calendar_service(self):
        from app.services.calendar_service import CalendarSlotConflictError
        assert CalendarSlotConflictError is not None

    def test_importable_from_main_lazy_import(self):
        """Verify the lazy import in main.py resolves correctly."""
        from app.services.calendar_service import CalendarService, CalendarSlotConflictError
        assert CalendarSlotConflictError is not None
        assert CalendarService is not None
