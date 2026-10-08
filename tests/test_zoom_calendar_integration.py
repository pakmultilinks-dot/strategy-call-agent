"""Tests for Zoom + Google Calendar integration (post-audit fixes).

Covers:
  1. CalendarService.create_event with external_meeting_link (Zoom path)
  2. Pipeline creates Calendar event for Zoom leads
  3. Pipeline preserves zoom_meeting_id and zoom_join_url
  4. Calendar event does NOT create Google Meet for Zoom
  5. Zoom join URL stored as Calendar event location
  6. Google Meet organizations retain existing behavior
  7. RSVP polling sees Zoom-backed leads
  8. Accepted RSVP handling for Zoom leads
  9. Declined RSVP handling and slot-release for Zoom leads
  10. Reminder uses Zoom join URL
  11. Google Meet reminders still work
  12. Retry/idempotency does not create duplicates
  13. Multi-tenant isolation
  14. Calendar failure does not duplicate Zoom meetings on retry
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy.orm import Session

from app.config import settings
from app.models import EventLog, Lead, LeadStatus
from app.models_multi_tenant import Organization
from app.services.meeting_provider import ZoomMeetingProvider


@pytest.fixture(autouse=True)
def _platform_oauth_clients(monkeypatch):
    """Platform-owned OAuth clients for tests that construct services
    without vault credentials (one-click model)."""
    monkeypatch.setattr(settings, "google_client_id", "test-platform-client-id")
    monkeypatch.setattr(settings, "google_client_secret", "test-platform-secret")
    monkeypatch.setattr(
        settings, "google_redirect_uri", "https://example.com/auth/google/callback"
    )
    monkeypatch.setattr(settings, "zoom_client_id", "test-platform-zoom-id")
    monkeypatch.setattr(settings, "zoom_client_secret", "test-platform-zoom-secret")
    monkeypatch.setattr(
        settings, "zoom_redirect_uri", "https://example.com/auth/zoom/callback"
    )


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

_TZ = ZoneInfo("America/Chicago")


def _future_appt() -> datetime:
    return (datetime.now(_TZ) + timedelta(hours=2)).astimezone(timezone.utc)


def _cleanup(db: Session) -> None:
    from app.models import FailedJob, FollowUp
    db.query(EventLog).delete()
    db.query(FailedJob).delete()
    db.query(FollowUp).delete()
    db.query(Lead).delete()
    db.commit()


def _make_lead(
    db: Session,
    *,
    org_id: uuid.UUID | None = None,
    status: LeadStatus = LeadStatus.PENDING,
    calendar_event_id: str | None = None,
    zoom_meeting_id: str | None = None,
    zoom_join_url: str | None = None,
    appt: datetime | None = None,
    email: str = "test@example.com",
) -> Lead:
    from app.tenant import _DEFAULT_ORG_ID

    lead = Lead(
        name="Test Lead",
        email=email,
        company_address="123 Test St",
        phone_number="555-0000",
        courses="Python",
        status=status,
        appt_datetime_raw="2026-09-15 10:00 AM",
        appt_datetime_utc=appt or _future_appt(),
        calendar_event_id=calendar_event_id,
        zoom_meeting_id=zoom_meeting_id,
        zoom_join_url=zoom_join_url,
        dedupe_key=f"zoomcal-{uuid.uuid4().hex[:12]}",
        organization_id=org_id or _DEFAULT_ORG_ID,
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


@pytest.fixture()
def test_org(db_session):
    """Create a test organization with business plan (unlimited features)."""
    org = Organization(
        name="ZoomCal Test Org",
        slug=f"zoomcal-test-{uuid.uuid4().hex[:8]}",
        plan="business",
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)
    return org


class _FakeZoomProvider(ZoomMeetingProvider):
    """A lightweight stand-in that passes ``isinstance(..., ZoomMeetingProvider)``.

    Subclasses the real ZoomMeetingProvider so isinstance checks work,
    but overrides __init__ and all API methods to avoid real Zoom calls.
    """

    def __init__(
        self,
        meeting_id: str = "zoom_82628844150",
        meeting_link: str = "https://us05web.zoom.us/j/82628844150?pwd=test",
    ):
        # Skip ZoomMeetingProvider.__init__ (needs org_context/db)
        self._meeting_id = meeting_id
        self._meeting_link = meeting_link

    def create_meeting(self, **kwargs):
        from app.services.meeting_provider import MeetingDetails
        return MeetingDetails(
            meeting_id=self._meeting_id,
            meeting_link=self._meeting_link,
            provider="zoom",
        )

    def get_meeting_link(self, meeting_id):
        return self._meeting_link

    def cancel_meeting(self, meeting_id):
        pass

    def get_meeting(self, meeting_id):
        return None


def _make_zoom_event(db: Session, test_org: Organization) -> None:
    """Seed org with Zoom credentials in the vault."""
    from app.services.credential_vault import CredentialVault
    from app.services.crypto import generate_key

    key = generate_key()
    with patch.object(settings, "credential_encryption_key", key), \
         patch.object(settings, "app_env", "test"):
        CredentialVault.save_credentials(
            db=db,
            org_id=test_org.id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials={
                "account_id": "test-acc",
                "client_id": "test-cid",
                "client_secret": "test-csec",
                "redirect_uri": "https://example.com/auth/zoom/callback",
            },
        )


# ---------------------------------------------------------------------------
# 1. CalendarService.create_event with external_meeting_link
# ---------------------------------------------------------------------------


class TestCalendarEventForZoom:
    """Verify create_event with external_meeting_link skips Google Meet."""

    @patch("app.services.calendar_service.CalendarService._insert_event")
    @patch("app.services.calendar_service.CalendarService.check_slot_available", return_value=True)
    @patch("app.services.calendar_service.get_google_credentials")
    def test_external_link_sets_location(self, mock_gauth, mock_slot, mock_insert, db_session, test_org):
        from app.services.calendar_service import CalendarService
        from app.services.org_context import OrganizationContext

        mock_gauth.return_value = MagicMock()
        mock_insert.return_value = {"id": "cal_event_123"}
        org_ctx = OrganizationContext.from_id(test_org.id)
        lead = _make_lead(db_session, org_id=test_org.id)
        zoom_url = "https://zoom.us/j/123456789?pwd=abc"

        cal = CalendarService(org_context=org_ctx, db=db_session)
        event_id, meet_link = cal.create_event(
            lead, db_session, external_meeting_link=zoom_url
        )

        assert event_id == "cal_event_123"
        assert meet_link is None

        body = mock_insert.call_args[0][0]
        assert body["location"] == zoom_url
        assert "conferenceData" not in body

    @patch("app.services.calendar_service.CalendarService._insert_event")
    @patch("app.services.calendar_service.CalendarService.check_slot_available", return_value=True)
    @patch("app.services.calendar_service.get_google_credentials")
    def test_no_external_link_creates_meet(self, mock_gauth, mock_slot, mock_insert, db_session, test_org):
        from app.services.calendar_service import CalendarService
        from app.services.org_context import OrganizationContext

        mock_gauth.return_value = MagicMock()
        mock_insert.return_value = {
            "id": "cal_event_456",
            "hangoutLink": "https://meet.google.com/abc-defg-hij",
        }
        org_ctx = OrganizationContext.from_id(test_org.id)
        lead = _make_lead(db_session, org_id=test_org.id)

        cal = CalendarService(org_context=org_ctx, db=db_session)
        event_id, meet_link = cal.create_event(lead, db_session)

        assert event_id == "cal_event_456"
        assert meet_link == "https://meet.google.com/abc-defg-hij"

        body = mock_insert.call_args[0][0]
        assert "conferenceData" in body
        assert "location" not in body

    @patch("app.services.calendar_service.CalendarService._insert_event")
    @patch("app.services.calendar_service.CalendarService.check_slot_available", return_value=True)
    @patch("app.services.calendar_service.get_google_credentials")
    def test_external_link_stored_in_event_body(self, mock_gauth, mock_slot, mock_insert, db_session, test_org):
        """The Zoom join URL is stored as the event location for attendees."""
        from app.services.calendar_service import CalendarService
        from app.services.org_context import OrganizationContext

        mock_gauth.return_value = MagicMock()
        mock_insert.return_value = {"id": "cal_loc_test"}
        org_ctx = OrganizationContext.from_id(test_org.id)
        lead = _make_lead(db_session, org_id=test_org.id)
        zoom_url = "https://zoom.us/j/999?pwd=secret"

        cal = CalendarService(org_context=org_ctx, db=db_session)
        cal.create_event(lead, db_session, external_meeting_link=zoom_url)

        body = mock_insert.call_args[0][0]
        assert body["location"] == zoom_url
        # iCalUID must still be set for idempotency
        assert body["iCalUID"] == f"lead-{lead.id}@strategy-call-agent"


# ---------------------------------------------------------------------------
# 2-6. Pipeline: Zoom path creates Calendar event + preserves fields
# ---------------------------------------------------------------------------


class TestPipelineZoomCreatesCalendarEvent:
    """End-to-end pipeline: Zoom meeting + Calendar event + email."""

    def _run_pipeline_zoom(self, db_session, lead):
        from app.main import _run_pipeline_inner

        # Use a unique calendar_event_id per call to avoid UNIQUE constraint
        # violations when multiple tests share the same DB session.
        unique_cal_id = f"cal_zoom_{uuid.uuid4().hex[:12]}"

        with patch("app.services.meeting_provider.resolve_meeting_provider") as mock_resolve, \
             patch("app.services.calendar_service.CalendarService") as MockCalCls, \
             patch("app.services.ai_service.AIService") as MockAI, \
             patch("app.services.email_service.EmailService") as MockEmail, \
             patch("app.services.integration_config_resolver.IntegrationConfigResolver") as MockResolver:

            mock_resolve.return_value = _FakeZoomProvider()

            mock_cal_instance = MagicMock()
            mock_cal_instance.create_event.return_value = (unique_cal_id, None)
            MockCalCls.return_value = mock_cal_instance

            mock_ai_instance = MagicMock()
            mock_ai_instance.generate_confirmation_email.return_value = (
                "Your strategy call is confirmed.", "test-model",
            )
            MockAI.return_value = mock_ai_instance

            mock_email_instance = MagicMock()
            mock_email_instance.send_confirmation_email.return_value = "msg_123"
            MockEmail.return_value = mock_email_instance

            mock_resolver_instance = MagicMock()
            mock_resolver_instance.resolve_branding.return_value = MagicMock()
            MockResolver.return_value = mock_resolver_instance

            _run_pipeline_inner(lead.id)

        db_session.refresh(lead)
        return lead

    def test_zoom_pipeline_sets_calendar_event_id(self, db_session, test_org):
        _make_zoom_event(db_session, test_org)
        lead = _make_lead(db_session, org_id=test_org.id)
        result = self._run_pipeline_zoom(db_session, lead)
        assert result.calendar_event_id is not None
        assert result.calendar_event_id.startswith("cal_zoom_")

    def test_zoom_pipeline_preserves_zoom_fields(self, db_session, test_org):
        _make_zoom_event(db_session, test_org)
        lead = _make_lead(db_session, org_id=test_org.id)
        result = self._run_pipeline_zoom(db_session, lead)
        assert result.zoom_meeting_id == "zoom_82628844150"
        assert "zoom.us" in result.zoom_join_url

    def test_zoom_pipeline_logs_calendar_created(self, db_session, test_org):
        _make_zoom_event(db_session, test_org)
        lead = _make_lead(db_session, org_id=test_org.id)
        result = self._run_pipeline_zoom(db_session, lead)
        events = db_session.query(EventLog).filter_by(
            lead_id=result.id, event_type="calendar_created"
        ).all()
        assert len(events) == 1
        import json
        payload = json.loads(events[0].payload)
        assert payload["provider"] == "zoom"

    def test_zoom_pipeline_completes_scheduled(self, db_session, test_org):
        _make_zoom_event(db_session, test_org)
        lead = _make_lead(db_session, org_id=test_org.id)
        result = self._run_pipeline_zoom(db_session, lead)
        assert result.status == LeadStatus.SCHEDULED
        assert result.processing_started_at is None

    def test_zoom_pipeline_passes_external_meeting_link(self, db_session, test_org):
        """CalendarService.create_event is called with external_meeting_link."""
        _make_zoom_event(db_session, test_org)
        lead = _make_lead(db_session, org_id=test_org.id)
        captured = []

        with patch("app.services.meeting_provider.resolve_meeting_provider") as mock_resolve, \
             patch("app.services.calendar_service.CalendarService") as MockCalCls, \
             patch("app.services.ai_service.AIService") as MockAI, \
             patch("app.services.email_service.EmailService") as MockEmail, \
             patch("app.services.integration_config_resolver.IntegrationConfigResolver") as MockResolver:

            mock_resolve.return_value = _FakeZoomProvider(
                meeting_link="https://us05web.zoom.us/j/82628844150?pwd=test"
            )

            def capture(*args, **kwargs):
                captured.append(kwargs)
                return ("cal_captured", None)

            mock_cal = MagicMock()
            mock_cal.create_event.side_effect = capture
            MockCalCls.return_value = mock_cal

            mock_ai = MagicMock()
            mock_ai.generate_confirmation_email.return_value = ("OK", "m")
            MockAI.return_value = mock_ai
            mock_email = MagicMock()
            mock_email.send_confirmation_email.return_value = "mid"
            MockEmail.return_value = mock_email
            mock_res = MagicMock()
            mock_res.resolve_branding.return_value = MagicMock()
            MockResolver.return_value = mock_res

            from app.main import _run_pipeline_inner
            _run_pipeline_inner(lead.id)

        assert len(captured) == 1
        assert captured[0]["external_meeting_link"] == "https://us05web.zoom.us/j/82628844150?pwd=test"


# ---------------------------------------------------------------------------
# 7-9. RSVP: Zoom-backed leads
# ---------------------------------------------------------------------------


class TestRSVPForZoomLeads:
    """RSVP poller correctly processes Zoom-backed leads."""

    @patch("app.services.rsvp_poller.CalendarService")
    def test_rsvp_poller_finds_zoom_lead(self, MockCal, db_session, test_org):
        from app.services.rsvp_poller import poll_rsvp_updates
        _cleanup(db_session)
        lead = _make_lead(
            db_session, org_id=test_org.id, status=LeadStatus.SCHEDULED,
            calendar_event_id="cal_zoom_rsvp", zoom_meeting_id="zoom_rsvp_123",
            zoom_join_url="https://zoom.us/j/123",
        )
        mock_cal = MagicMock()
        mock_cal.get_attendee_status.return_value = "needsAction"
        MockCal.return_value = mock_cal
        result = poll_rsvp_updates()
        assert result["checked"] >= 1

    @patch("app.services.rsvp_poller.CalendarService")
    def test_accepted_rsvp_transitions_status(self, MockCal, db_session, test_org):
        from app.services.rsvp_poller import poll_rsvp_updates
        _cleanup(db_session)
        lead = _make_lead(
            db_session, org_id=test_org.id, status=LeadStatus.SCHEDULED,
            calendar_event_id="cal_accepted", zoom_meeting_id="zoom_a",
            zoom_join_url="https://zoom.us/j/a",
        )
        mock_cal = MagicMock()
        mock_cal.get_attendee_status.return_value = "accepted"
        MockCal.return_value = mock_cal
        poll_rsvp_updates()
        db_session.refresh(lead)
        assert lead.status == LeadStatus.ACCEPTED

    @patch("app.services.rsvp_poller.CalendarService")
    def test_declined_rsvp_releases_slot(self, MockCal, db_session, test_org):
        from app.services.rsvp_poller import poll_rsvp_updates
        _cleanup(db_session)
        lead = _make_lead(
            db_session, org_id=test_org.id, status=LeadStatus.SCHEDULED,
            calendar_event_id="cal_declined", zoom_meeting_id="zoom_d",
            zoom_join_url="https://zoom.us/j/d",
        )
        mock_cal = MagicMock()
        mock_cal.get_attendee_status.return_value = "declined"
        mock_cal._get_event.return_value = {"summary": "Strategy Call: Test"}
        MockCal.return_value = mock_cal
        poll_rsvp_updates()
        db_session.refresh(lead)
        assert lead.status == LeadStatus.DECLINED
        mock_cal.update_event_declined.assert_called_once()


# ---------------------------------------------------------------------------
# 10-11. Reminder: Zoom join URL preference
# ---------------------------------------------------------------------------


class TestReminderZoomJoinURL:
    """Reminder service uses Zoom join URL when available."""

    @patch("app.services.reminder_service.EmailService")
    @patch("app.services.reminder_service.CalendarService")
    def test_reminder_uses_zoom_join_url(self, MockCal, MockEmail, db_session, test_org):
        from app.services.reminder_service import send_daily_reminders
        _cleanup(db_session)
        lead = _make_lead(
            db_session, org_id=test_org.id, status=LeadStatus.SCHEDULED,
            calendar_event_id="cal_zoom_remind", zoom_meeting_id="zm_r",
            zoom_join_url="https://zoom.us/j/remind123?pwd=xyz",
        )
        mock_cal = MagicMock()
        MockCal.return_value = mock_cal
        mock_email = MagicMock()
        MockEmail.return_value = mock_email

        result = send_daily_reminders()
        assert result["sent"] >= 1
        # Zoom URL was used, not CalendarService.get_meet_link
        mock_cal.get_meet_link.assert_not_called()
        call_args = mock_email.send_email.call_args
        plain_body = call_args[0][2]
        assert "zoom.us" in plain_body

    @patch("app.services.reminder_service.EmailService")
    @patch("app.services.reminder_service.CalendarService")
    def test_reminder_google_meet_still_works(self, MockCal, MockEmail, db_session, test_org):
        from app.services.reminder_service import send_daily_reminders
        _cleanup(db_session)
        lead = _make_lead(
            db_session, org_id=test_org.id, status=LeadStatus.SCHEDULED,
            calendar_event_id="cal_meet_remind",
        )
        mock_cal = MagicMock()
        mock_cal.get_meet_link.return_value = "https://meet.google.com/abc-defg"
        MockCal.return_value = mock_cal
        mock_email = MagicMock()
        MockEmail.return_value = mock_email

        result = send_daily_reminders()
        assert result["sent"] >= 1
        mock_cal.get_meet_link.assert_called_once_with("cal_meet_remind")

    @patch("app.services.reminder_service.EmailService")
    @patch("app.services.reminder_service.CalendarService")
    def test_reminder_zoom_fallback_to_calendar(self, MockCal, MockEmail, db_session, test_org):
        """Zoom lead with no zoom_join_url falls back to CalendarService."""
        from app.services.reminder_service import send_daily_reminders
        _cleanup(db_session)
        lead = _make_lead(
            db_session, org_id=test_org.id, status=LeadStatus.SCHEDULED,
            calendar_event_id="cal_fb", zoom_meeting_id="zm_fb",
            zoom_join_url=None,
        )
        mock_cal = MagicMock()
        mock_cal.get_meet_link.return_value = "https://meet.google.com/fallback"
        MockCal.return_value = mock_cal
        mock_email = MagicMock()
        MockEmail.return_value = mock_email
        result = send_daily_reminders()
        assert result["sent"] >= 1


# ---------------------------------------------------------------------------
# 12. Retry/idempotency
# ---------------------------------------------------------------------------


class TestPipelineIdempotency:
    """Retry does not create duplicates."""

    def _make_fakes(self):
        """Return common mock factories for pipeline retry tests."""
        mock_cal = MagicMock()
        mock_cal.create_event.return_value = ("cal_new", None)
        mock_ai = MagicMock()
        mock_ai.generate_confirmation_email.return_value = ("OK", "m")
        mock_email = MagicMock()
        mock_email.send_confirmation_email.return_value = "mid"
        mock_resolver = MagicMock()
        mock_resolver.resolve_branding.return_value = MagicMock()
        return mock_cal, mock_ai, mock_email, mock_resolver

    def test_existing_zoom_meeting_not_recreated(self, db_session, test_org):
        _make_zoom_event(db_session, test_org)
        lead = _make_lead(
            db_session, org_id=test_org.id, status=LeadStatus.PENDING,
            zoom_meeting_id="existing_zoom_123",
            zoom_join_url="https://zoom.us/j/existing",
        )
        mc, ma, me, mr = self._make_fakes()

        with patch("app.services.meeting_provider.resolve_meeting_provider") as mock_resolve, \
             patch("app.services.calendar_service.CalendarService", return_value=mc), \
             patch("app.services.ai_service.AIService", return_value=ma), \
             patch("app.services.email_service.EmailService", return_value=me), \
             patch("app.services.integration_config_resolver.IntegrationConfigResolver", return_value=mr):
            mock_resolve.return_value = _FakeZoomProvider()
            from app.main import _run_pipeline_inner
            _run_pipeline_inner(lead.id)

        db_session.refresh(lead)
        assert lead.zoom_meeting_id == "existing_zoom_123"
        assert lead.calendar_event_id == "cal_new"
        assert lead.status == LeadStatus.SCHEDULED

    def test_existing_calendar_event_not_recreated(self, db_session, test_org):
        _make_zoom_event(db_session, test_org)
        lead = _make_lead(
            db_session, org_id=test_org.id, status=LeadStatus.PENDING,
            zoom_meeting_id="zoom_ec", zoom_join_url="https://zoom.us/j/ec",
            calendar_event_id="existing_cal_event",
        )
        mc, ma, me, mr = self._make_fakes()

        with patch("app.services.meeting_provider.resolve_meeting_provider") as mock_resolve, \
             patch("app.services.calendar_service.CalendarService") as MockCalCls, \
             patch("app.services.ai_service.AIService", return_value=ma), \
             patch("app.services.email_service.EmailService", return_value=me), \
             patch("app.services.integration_config_resolver.IntegrationConfigResolver", return_value=mr):
            mock_resolve.return_value = _FakeZoomProvider()
            from app.main import _run_pipeline_inner
            _run_pipeline_inner(lead.id)

        db_session.refresh(lead)
        assert lead.calendar_event_id == "existing_cal_event"
        MockCalCls.assert_not_called()

    def test_calendar_failure_no_duplicate_zoom_on_retry(self, db_session, test_org):
        _make_zoom_event(db_session, test_org)
        lead = _make_lead(db_session, org_id=test_org.id)
        mc, ma, me, mr = self._make_fakes()
        mc.create_event.side_effect = Exception("Calendar API error")

        with patch("app.services.meeting_provider.resolve_meeting_provider") as mock_resolve, \
             patch("app.services.calendar_service.CalendarService", return_value=mc), \
             patch("app.services.ai_service.AIService", return_value=ma), \
             patch("app.services.email_service.EmailService", return_value=me), \
             patch("app.services.integration_config_resolver.IntegrationConfigResolver", return_value=mr):
            mock_resolve.return_value = _FakeZoomProvider()
            from app.main import _run_pipeline_inner
            _run_pipeline_inner(lead.id)

        db_session.refresh(lead)
        assert lead.zoom_meeting_id == "zoom_82628844150"
        assert lead.calendar_event_id is None

        # Retry
        mc2, ma2, me2, mr2 = self._make_fakes()
        mc2.create_event.return_value = ("cal_retry_123", None)
        lead.processing_started_at = None
        lead.status = LeadStatus.PENDING
        db_session.commit()

        with patch("app.services.meeting_provider.resolve_meeting_provider") as mock_resolve2, \
             patch("app.services.calendar_service.CalendarService", return_value=mc2), \
             patch("app.services.ai_service.AIService", return_value=ma2), \
             patch("app.services.email_service.EmailService", return_value=me2), \
             patch("app.services.integration_config_resolver.IntegrationConfigResolver", return_value=mr2):
            mock_resolve2.return_value = _FakeZoomProvider()
            _run_pipeline_inner(lead.id)

        db_session.refresh(lead)
        assert lead.zoom_meeting_id == "zoom_82628844150"
        assert lead.calendar_event_id == "cal_retry_123"
        assert lead.status == LeadStatus.SCHEDULED


# ---------------------------------------------------------------------------
# 13. Multi-tenant isolation
# ---------------------------------------------------------------------------


class TestMultiTenantIsolation:
    """Calendar events use the correct org credentials."""

    @patch("app.services.calendar_service.CalendarService._insert_event")
    @patch("app.services.calendar_service.CalendarService.check_slot_available", return_value=True)
    @patch("app.services.calendar_service.get_google_credentials")
    def test_zoom_calendar_uses_org_credentials(self, mock_gauth, mock_slot, mock_insert, db_session):
        from app.services.calendar_service import CalendarService
        from app.services.org_context import OrganizationContext

        org_a = Organization(name="Org A", slug=f"org-a-{uuid.uuid4().hex[:8]}")
        org_b = Organization(name="Org B", slug=f"org-b-{uuid.uuid4().hex[:8]}")
        db_session.add_all([org_a, org_b])
        db_session.commit()

        mock_gauth.return_value = MagicMock()
        mock_insert.return_value = {"id": "cal_org_a"}
        org_ctx_a = OrganizationContext.from_id(org_a.id)
        lead_a = _make_lead(db_session, org_id=org_a.id)

        cal = CalendarService(org_context=org_ctx_a, db=db_session)
        event_id, _ = cal.create_event(
            lead_a, db_session, external_meeting_link="https://zoom.us/j/orga"
        )
        assert event_id == "cal_org_a"
        assert cal._org_id == org_a.id
