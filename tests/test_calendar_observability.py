"""Observability-only regression tests for Calendar exception logging.

Verifies that:
  1. The pipeline boundary logs full exception details (type, message,
     traceback) when CalendarService.create_event fails for a Zoom lead.
  2. CalendarService.check_slot_available logs full exception details
     when the free/busy API call fails.
  3. Existing behavior is unchanged: check_slot_available returns True
     on error (fail-open), and the pipeline continues to SCHEDULED.

NO business behavior changes are tested — only logging output.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from app.models import EventLog, Lead, LeadStatus, FailedJob
from app.models_multi_tenant import Organization
from app.services.meeting_provider import ZoomMeetingProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_org(db: Session) -> Organization:
    """Insert a minimal Organization row and return it."""
    org = Organization(
        name=f"Obs Test Org {uuid.uuid4().hex[:6]}",
        slug=f"obs-test-{uuid.uuid4().hex[:6]}",
        display_name="Obs Test Org",
    )
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


def _make_lead(db: Session, org_id: uuid.UUID) -> Lead:
    """Insert a PENDING lead with all required fields."""
    lead = Lead(
        name="Obs Test Lead",
        email=f"obs-{uuid.uuid4().hex[:8]}@example.com",
        company_address="123 Obs St",
        appt_datetime_raw="tomorrow 3pm",
        appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=2),
        status=LeadStatus.PENDING,
        organization_id=org_id,
        dedupe_key=f"obs-lead-{uuid.uuid4().hex[:12]}",
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


# ---------------------------------------------------------------------------
# Test 1: Pipeline boundary logs full exception details on Calendar failure
# ---------------------------------------------------------------------------


class _FakeZoomProvider(ZoomMeetingProvider):
    """Lightweight stand-in that passes isinstance(ZoomMeetingProvider).

    Subclasses the real ZoomMeetingProvider so isinstance checks work,
    but overrides __init__ and all API methods to avoid real Zoom calls.
    """

    def __init__(
        self,
        meeting_id: str = "zoom_obs_123",
        meeting_link: str = "https://zoom.us/j/obs123?pwd=test",
    ):
        self._meeting_id = meeting_id
        self._meeting_link = meeting_link

    def create_meeting(self, **kwargs):
        from app.services.meeting_provider import MeetingDetails

        return MeetingDetails(
            meeting_id=self._meeting_id,
            meeting_link=self._meeting_link,
        )


class TestPipelineCalendarExceptionLogging:
    """When CalendarService raises during the Zoom pipeline path,
    the WARNING log must include exception type, message, and traceback."""

    def _run_pipeline_with_calendar_failure(
        self, db_session, lead, exception_to_raise
    ):
        """Run the pipeline with CalendarService.create_event mocked to raise."""
        from app.main import _run_pipeline_inner

        mock_cal_svc = MagicMock()
        mock_cal_svc.create_event.side_effect = exception_to_raise

        mock_ai_svc = MagicMock()
        mock_ai_svc.generate_confirmation_email.return_value = (
            "Hello!", "gpt-test"
        )

        mock_email_svc = MagicMock()
        mock_email_svc.send_confirmation_email.return_value = "msg_123"

        mock_resolver = MagicMock()
        mock_resolver.resolve_branding.return_value = MagicMock(
            company_name="Test Co"
        )
        mock_resolver.resolve_meeting_config.return_value = MagicMock(
            duration_minutes=30
        )

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

    def test_calendar_exception_logged_with_exc_info(
        self, db_session: Session, caplog
    ):
        """Pipeline WARNING includes exc_info=True for Calendar failures."""
        org = _make_org(db_session)
        lead = _make_lead(db_session, org.id)

        with caplog.at_level(logging.WARNING, logger="strategy-call-agent"):
            self._run_pipeline_with_calendar_failure(
                db_session, lead,
                RuntimeError("Calendar API quota exceeded"),
            )

        # --- Assertions on log output ---
        # Find the WARNING that contains our calendar failure message
        calendar_warnings = [
            r
            for r in caplog.records
            if r.levelno == logging.WARNING
            and "calendar event creation failed" in r.message
        ]
        assert len(calendar_warnings) >= 1, (
            "Expected at least one WARNING with 'calendar event creation failed'"
        )

        warning = calendar_warnings[-1]

        # The message must contain structured fields
        assert "org_id=" in warning.message
        assert "operation=calendar_create" in warning.message
        assert "exception_type=RuntimeError" in warning.message
        assert "exception_message=Calendar API quota exceeded" in warning.message
        assert str(lead.id) in warning.message

        # exc_info=True was passed — the record must have exception info
        assert warning.exc_info is not None, (
            "exc_info must be set on the WARNING log record"
        )
        exc_type, exc_value, exc_tb = warning.exc_info
        assert exc_type is RuntimeError
        assert "Calendar API quota exceeded" in str(exc_value)

    def test_http_error_exception_logged_with_exc_info(
        self, db_session: Session, caplog
    ):
        """Pipeline WARNING includes exc_info for HttpError (auth failures)."""
        from googleapiclient.errors import HttpError

        org = _make_org(db_session)
        lead = _make_lead(db_session, org.id)

        mock_resp = MagicMock()
        mock_resp.status = 401
        mock_resp.reason = "Unauthorized"
        http_error = HttpError(
            resp=mock_resp,
            content=b'{"error": {"message": "Token expired"}}',
        )

        with caplog.at_level(logging.WARNING, logger="strategy-call-agent"):
            self._run_pipeline_with_calendar_failure(
                db_session, lead, http_error,
            )

        calendar_warnings = [
            r
            for r in caplog.records
            if r.levelno == logging.WARNING
            and "calendar event creation failed" in r.message
        ]
        assert len(calendar_warnings) >= 1
        warning = calendar_warnings[-1]
        assert "exception_type=HttpError" in warning.message
        assert warning.exc_info is not None
        assert warning.exc_info[0] is HttpError

    def test_lead_becomes_scheduled_despite_calendar_failure(
        self, db_session: Session
    ):
        """Existing behavior: pipeline continues to SCHEDULED even when
        Calendar fails. This test confirms we didn't accidentally change
        that behavior."""
        org = _make_org(db_session)
        lead = _make_lead(db_session, org.id)

        self._run_pipeline_with_calendar_failure(
            db_session, lead,
            RuntimeError("Simulated failure"),
        )

        db_session.refresh(lead)
        # Business behavior unchanged: lead becomes SCHEDULED
        assert lead.status == LeadStatus.SCHEDULED
        # Calendar event was NOT created
        assert lead.calendar_event_id is None
        # Zoom fields ARE set
        assert lead.zoom_meeting_id == "zoom_obs_123"
        assert "zoom.us" in lead.zoom_join_url


# ---------------------------------------------------------------------------
# Test 2: check_slot_available logs exception details on freebusy failure
# ---------------------------------------------------------------------------


class TestFreebusyExceptionLogging:
    """When the free/busy query fails, check_slot_available must log the
    full exception type, message, and traceback while still returning True."""

    def test_freebusy_exception_logged_with_exc_info(self, caplog):
        """check_slot_available logs exc_info=True on freebusy failure."""
        from app.services.calendar_service import CalendarService

        mock_service = MagicMock()
        mock_service.freebusy().query().execute.side_effect = ConnectionError(
            "Google API connection refused"
        )

        svc = object.__new__(CalendarService)
        svc._service = mock_service
        svc._calendar_id = "test-calendar-id"

        start = datetime.now(timezone.utc)
        end = start + timedelta(minutes=30)

        with caplog.at_level(logging.WARNING, logger="app.services.calendar_service"):
            result = svc.check_slot_available(start, end)

        # Must still return True (fail-open behavior unchanged)
        assert result is True

        # Find the freebusy WARNING
        freebusy_warnings = [
            r
            for r in caplog.records
            if r.levelno == logging.WARNING
            and "free/busy check failed" in r.message
        ]
        assert len(freebusy_warnings) >= 1, (
            "Expected at least one WARNING with 'free/busy check failed'"
        )

        warning = freebusy_warnings[-1]

        # Structured fields present in the message
        assert "calendar_id=test-calendar-id" in warning.message
        assert "exception_type=ConnectionError" in warning.message
        assert "exception_message=Google API connection refused" in warning.message

        # exc_info=True was passed
        assert warning.exc_info is not None, (
            "exc_info must be set on the freebusy WARNING log record"
        )
        exc_type, exc_value, _ = warning.exc_info
        assert exc_type is ConnectionError
        assert "Google API connection refused" in str(exc_value)

    def test_freebusy_timeout_also_logged(self, caplog):
        """TimeoutError is also logged with full exception info."""
        from app.services.calendar_service import CalendarService

        mock_service = MagicMock()
        mock_service.freebusy().query().execute.side_effect = TimeoutError(
            "Request timed out after 30s"
        )

        svc = object.__new__(CalendarService)
        svc._service = mock_service
        svc._calendar_id = "primary"

        start = datetime.now(timezone.utc)
        end = start + timedelta(minutes=30)

        with caplog.at_level(logging.WARNING, logger="app.services.calendar_service"):
            result = svc.check_slot_available(start, end)

        assert result is True

        freebusy_warnings = [
            r
            for r in caplog.records
            if r.levelno == logging.WARNING
            and "free/busy check failed" in r.message
        ]
        assert len(freebusy_warnings) >= 1

        warning = freebusy_warnings[-1]
        assert "exception_type=TimeoutError" in warning.message
        assert "exception_message=Request timed out after 30s" in warning.message
        assert warning.exc_info is not None
        assert warning.exc_info[0] is TimeoutError

    def test_freebusy_auth_error_also_logged(self, caplog):
        """HttpError (auth failure) is also logged with full exception info."""
        from app.services.calendar_service import CalendarService

        # Simulate a Google API HttpError
        mock_resp = MagicMock()
        mock_resp.status = 401
        mock_resp.reason = "Unauthorized"

        from googleapiclient.errors import HttpError

        mock_service = MagicMock()
        mock_service.freebusy().query().execute.side_effect = HttpError(
            resp=mock_resp, content=b'{"error": {"message": "Token expired"}}'
        )

        svc = object.__new__(CalendarService)
        svc._service = mock_service
        svc._calendar_id = "primary"

        start = datetime.now(timezone.utc)
        end = start + timedelta(minutes=30)

        with caplog.at_level(logging.WARNING, logger="app.services.calendar_service"):
            result = svc.check_slot_available(start, end)

        assert result is True

        freebusy_warnings = [
            r
            for r in caplog.records
            if r.levelno == logging.WARNING
            and "free/busy check failed" in r.message
        ]
        assert len(freebusy_warnings) >= 1

        warning = freebusy_warnings[-1]
        assert "exception_type=HttpError" in warning.message
        assert warning.exc_info is not None
        assert warning.exc_info[0] is HttpError
