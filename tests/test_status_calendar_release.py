"""Regression tests: update_lead_status() must release the Calendar event
when transitioning to a terminal state (e.g. scheduled → declined).

Bug: PATCH /dashboard/api/leads/{id}/status allowed terminal transitions
without calling release_calendar_event(), leaving the Google Calendar slot
opaque/busy and blocking new bookings for the same time window.

Fix: After the follow-up cancellation cascade, when the new status is
terminal AND the lead has a calendar_event_id, the endpoint now calls
release_calendar_event() - matching the existing cancel_call() pattern.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.models import EventLog, FailedJob, Lead, LeadStatus
from app.models_multi_tenant import UserRole


@pytest.fixture(autouse=True)
def _platform_google_client(monkeypatch):
    """Platform-owned OAuth client for tests that construct services
    without vault credentials (CalendarService resolves via the platform
    client in the new one-click model)."""
    from app.config import settings as _settings
    monkeypatch.setattr(_settings, "google_client_id", "test-platform-client-id")
    monkeypatch.setattr(_settings, "google_client_secret", "test-platform-secret")
    monkeypatch.setattr(
        _settings, "google_redirect_uri", "https://example.com/auth/google/callback"
    )
from tests.test_auth import _auth_header, _create_org_and_user, _make_token


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


def _create_lead_raw(db, org_id, *, status=LeadStatus.PENDING, name="Raw Lead",
                     calendar_event_id=None, appt_hours=24):
    """Insert a Lead directly via ORM."""
    email = f"raw-{uuid.uuid4().hex[:8]}@example.com"
    appt_raw = "tomorrow 3pm"
    import dateparser
    from datetime import timezone as tz
    parsed = dateparser.parse(appt_raw, settings={"RETURN_AS_TIMEZONE_AWARE": True})
    if parsed and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=tz.utc)
    dedupe_key = f"manual|{email.strip().lower()}|{appt_raw.strip().lower()}"

    lead = Lead(
        id=uuid.uuid4(),
        name=name,
        email=email,
        appt_datetime_raw=appt_raw,
        appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=appt_hours),
        status=status,
        dedupe_key=dedupe_key,
        organization_id=org_id,
        calendar_event_id=calendar_event_id,
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


# ══════════════════════════════════════════════════════════════════════════════
# A. scheduled → declined WITH calendar_event_id → release called
# ══════════════════════════════════════════════════════════════════════════════


class TestStatusChangeReleasesCalendar:
    """PATCH /leads/{id}/status with terminal status and a calendar_event_id
    must call release_calendar_event()."""

    def test_scheduled_to_declined_releases_calendar(self, client, db):
        """Terminal transition with calendar_event_id triggers release."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        event_id = f"cal-evt-{uuid.uuid4().hex[:12]}"
        lead = _create_lead_raw(
            db, org.id, status=LeadStatus.SCHEDULED,
            calendar_event_id=event_id,
        )

        token = _make_token(user.id, org.id, "owner")
        with patch("app.services.calendar_service.CalendarService") as MockCal:
            mock_svc = MagicMock()
            mock_svc.release_calendar_event.return_value = True
            MockCal.return_value = mock_svc

            resp = client.patch(
                f"/dashboard/api/leads/{lead.id}/status",
                json={"status": "declined"},
                headers=_auth_header(token),
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "updated"
            assert resp.json()["lead"]["status"] == "declined"

            # release_calendar_event must have been called with correct args
            mock_svc.release_calendar_event.assert_called_once()
            call_args = mock_svc.release_calendar_event.call_args
            assert call_args[0][0] == event_id
            assert call_args[0][1] == lead.name

    def test_scheduled_to_completed_releases_calendar(self, client, db):
        """Any terminal state triggers release, not just declined."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        event_id = f"cal-evt-{uuid.uuid4().hex[:12]}"
        lead = _create_lead_raw(
            db, org.id, status=LeadStatus.SCHEDULED,
            calendar_event_id=event_id,
        )

        token = _make_token(user.id, org.id, "owner")
        with patch("app.services.calendar_service.CalendarService") as MockCal:
            mock_svc = MagicMock()
            mock_svc.release_calendar_event.return_value = True
            MockCal.return_value = mock_svc

            resp = client.patch(
                f"/dashboard/api/leads/{lead.id}/status",
                json={"status": "completed"},
                headers=_auth_header(token),
            )
            assert resp.status_code == 200
            mock_svc.release_calendar_event.assert_called_once()

    def test_non_terminal_does_not_release_calendar(self, client, db):
        """Non-terminal transitions (pending → scheduled) must NOT release."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        event_id = f"cal-evt-{uuid.uuid4().hex[:12]}"
        lead = _create_lead_raw(
            db, org.id, status=LeadStatus.PENDING,
            calendar_event_id=event_id,
        )

        token = _make_token(user.id, org.id, "owner")
        with patch("app.services.calendar_service.CalendarService") as MockCal:
            mock_svc = MagicMock()
            MockCal.return_value = mock_svc

            resp = client.patch(
                f"/dashboard/api/leads/{lead.id}/status",
                json={"status": "scheduled"},
                headers=_auth_header(token),
            )
            assert resp.status_code == 200
            mock_svc.release_calendar_event.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# B. scheduled → declined WITHOUT calendar_event_id → still works normally
# ══════════════════════════════════════════════════════════════════════════════


class TestStatusChangeWithoutCalendarEvent:
    """Terminal transition without a calendar_event_id must succeed
    without attempting any calendar release."""

    def test_no_calendar_event_id_succeeds(self, client, db):
        """Decline a lead that has no calendar_event_id - no crash."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(
            db, org.id, status=LeadStatus.SCHEDULED,
            calendar_event_id=None,
        )

        token = _make_token(user.id, org.id, "owner")
        with patch("app.services.calendar_service.CalendarService") as MockCal:
            mock_svc = MagicMock()
            MockCal.return_value = mock_svc

            resp = client.patch(
                f"/dashboard/api/leads/{lead.id}/status",
                json={"status": "declined"},
                headers=_auth_header(token),
            )
            assert resp.status_code == 200
            assert resp.json()["lead"]["status"] == "declined"

            # CalendarService should not even be instantiated
            MockCal.assert_not_called()
            mock_svc.release_calendar_event.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# C. cancel_call() behavior remains intact
# ══════════════════════════════════════════════════════════════════════════════


class TestCancelCallUnchanged:
    """POST /leads/{id}/cancel still releases calendar and sets call_outcome."""

    def test_cancel_still_releases_calendar(self, client, db):
        """cancel_call should still call release_calendar_event."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        event_id = f"cancel-evt-{uuid.uuid4().hex[:12]}"
        lead = _create_lead_raw(
            db, org.id, status=LeadStatus.SCHEDULED,
            calendar_event_id=event_id,
        )

        token = _make_token(user.id, org.id, "owner")
        with patch("app.services.calendar_service.CalendarService") as MockCal:
            mock_svc = MagicMock()
            mock_svc.release_calendar_event.return_value = True
            MockCal.return_value = mock_svc

            resp = client.post(
                f"/dashboard/api/leads/{lead.id}/cancel",
                json={"reason": "test"},
                headers=_auth_header(token),
            )
            assert resp.status_code == 200
            assert resp.json()["lead"]["status"] == "declined"
            mock_svc.release_calendar_event.assert_called_once()


# ══════════════════════════════════════════════════════════════════════════════
# D. Status-transition validation remains intact
# ══════════════════════════════════════════════════════════════════════════════


class TestTransitionValidationUnchanged:
    """Invalid transitions must still be rejected."""

    def test_invalid_transition_rejected(self, client, db):
        """pending → completed is not allowed."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.PENDING)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "completed"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_terminal_rejected(self, client, db):
        """Cannot transition from a terminal state."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.DECLINED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "pending"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_same_status_rejected(self, client, db):
        """Transitioning to the same status returns 400."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.PENDING)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "pending"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# E. Tenant/authorization protections remain intact
# ══════════════════════════════════════════════════════════════════════════════


class TestTenantIsolationUnchanged:
    """Cross-org access must still be blocked."""

    def test_cross_org_blocked(self, client, db):
        """Org B user cannot change Org A's lead status."""
        org_a, user_a = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org_a.id, status=LeadStatus.PENDING)

        org_b, user_b = _create_org_and_user(db, role=UserRole.OWNER)
        token_b = _make_token(user_b.id, org_b.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "scheduled"},
            headers=_auth_header(token_b),
        )
        assert resp.status_code == 404

    def test_member_cannot_change_status(self, client, db):
        """Member role should return 403."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.PENDING)

        token = _make_token(user.id, org.id, "member")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "scheduled"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# F. Uses existing release_calendar_event() - not duplicated API code
# ══════════════════════════════════════════════════════════════════════════════


class TestUsesReleaseCalendarEvent:
    """Verify the fix delegates to CalendarService.release_calendar_event(),
    not to duplicated Google Calendar API logic."""

    def test_uses_calendar_service_release(self, client, db):
        """Must instantiate CalendarService with org context and call release."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        event_id = f"release-check-{uuid.uuid4().hex[:12]}"
        lead = _create_lead_raw(
            db, org.id, status=LeadStatus.SCHEDULED,
            calendar_event_id=event_id,
        )

        token = _make_token(user.id, org.id, "owner")
        with patch("app.services.calendar_service.CalendarService") as MockCal:
            mock_svc = MagicMock()
            mock_svc.release_calendar_event.return_value = True
            MockCal.return_value = mock_svc

            resp = client.patch(
                f"/dashboard/api/leads/{lead.id}/status",
                json={"status": "declined"},
                headers=_auth_header(token),
            )
            assert resp.status_code == 200

            # CalendarService was constructed (with org context)
            MockCal.assert_called_once()
            # release_calendar_event was the method called
            mock_svc.release_calendar_event.assert_called_once()
            # No other CalendarService methods should be called
            assert not mock_svc.update_event_declined.called
            assert not mock_svc.delete_event.called
            assert not mock_svc.create_event.called

    def test_release_failure_logged_not_fatal(self, client, db):
        """Calendar release failure should NOT fail the status update."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        event_id = f"fail-evt-{uuid.uuid4().hex[:12]}"
        lead = _create_lead_raw(
            db, org.id, status=LeadStatus.SCHEDULED,
            calendar_event_id=event_id,
        )

        token = _make_token(user.id, org.id, "owner")
        with patch("app.services.calendar_service.CalendarService") as MockCal:
            mock_svc = MagicMock()
            mock_svc.release_calendar_event.side_effect = Exception("Google API error")
            MockCal.return_value = mock_svc

            resp = client.patch(
                f"/dashboard/api/leads/{lead.id}/status",
                json={"status": "declined"},
                headers=_auth_header(token),
            )
            # The status update should still succeed
            assert resp.status_code == 200
            assert resp.json()["lead"]["status"] == "declined"

            # A calendar_cancel_error event should be logged
            events = db.query(EventLog).filter(
                EventLog.lead_id == lead.id,
                EventLog.event_type == "calendar_cancel_error",
            ).all()
            assert len(events) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# G-extra. release_calendar_event() calls delete_event, NOT update_event_declined
# ══════════════════════════════════════════════════════════════════════════════


class TestReleaseDeletesEvent:
    """release_calendar_event() must DELETE the Google Calendar event,
    not just mark it as [DECLINED] with transparency=transparent."""

    @patch("app.services.calendar_service.get_google_credentials")
    def test_release_calls_delete_event(self, mock_gauth):
        """release_calendar_event delegates to delete_event internally."""
        mock_gauth.return_value = MagicMock()
        from app.services.calendar_service import CalendarService
        from app.services.org_context import OrganizationContext

        db = SessionLocal()
        try:
            org_ctx = OrganizationContext.from_id(
                uuid.UUID("d61b9011-0a57-44f6-96b9-97e1773b70f6")
            )
            svc = CalendarService(org_context=org_ctx, db=db)
            with patch.object(svc, "delete_event") as mock_delete:
                result = svc.release_calendar_event("evt-to-delete", "Test Lead", db)
                assert result is True
                mock_delete.assert_called_once_with("evt-to-delete", db)
        finally:
            db.close()

    @patch("app.services.calendar_service.get_google_credentials")
    def test_release_does_not_call_update_event_declined(self, mock_gauth):
        """release_calendar_event must NOT call update_event_declined."""
        mock_gauth.return_value = MagicMock()
        from app.services.calendar_service import CalendarService
        from app.services.org_context import OrganizationContext

        db = SessionLocal()
        try:
            org_ctx = OrganizationContext.from_id(
                uuid.UUID("d61b9011-0a57-44f6-96b9-97e1773b70f6")
            )
            svc = CalendarService(org_context=org_ctx, db=db)
            with patch.object(svc, "delete_event"):
                with patch.object(svc, "update_event_declined") as mock_declined:
                    svc.release_calendar_event("evt-123", "Lead", db)
                    mock_declined.assert_not_called()
        finally:
            db.close()

    @patch("app.services.calendar_service.get_google_credentials")
    def test_release_delete_failure_returns_false(self, mock_gauth):
        """If delete_event raises, release_calendar_event returns False."""
        mock_gauth.return_value = MagicMock()
        from app.services.calendar_service import CalendarService
        from app.services.org_context import OrganizationContext

        db = SessionLocal()
        try:
            org_ctx = OrganizationContext.from_id(
                uuid.UUID("d61b9011-0a57-44f6-96b9-97e1773b70f6")
            )
            svc = CalendarService(org_context=org_ctx, db=db)
            with patch.object(
                svc, "delete_event", side_effect=Exception("Google API timeout")
            ):
                result = svc.release_calendar_event("evt-fail", "Lead", db)
                assert result is False
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# H. After deletion, the exact same 30-minute slot is available for rebooking
# ══════════════════════════════════════════════════════════════════════════════


class TestSlotAvailableAfterDeletion:
    """After a calendar event is deleted via release_calendar_event(),
    check_slot_available() must report the slot as free."""

    @patch("app.services.calendar_service.get_google_credentials")
    def test_slot_free_after_release(self, mock_gauth):
        """delete_event removes the event; freebusy query shows slot as free."""
        mock_gauth.return_value = MagicMock()
        from app.services.calendar_service import CalendarService
        from app.services.org_context import OrganizationContext

        db = SessionLocal()
        try:
            org_ctx = OrganizationContext.from_id(
                uuid.UUID("d61b9011-0a57-44f6-96b9-97e1773b70f6")
            )
            svc = CalendarService(org_context=org_ctx, db=db)
            slot_start = datetime(2026, 9, 15, 16, 0, tzinfo=timezone.utc)
            slot_end = datetime(2026, 9, 15, 16, 30, tzinfo=timezone.utc)

            # Step 1: Mock delete_event to succeed (event is removed)
            with patch.object(svc, "delete_event") as mock_delete:
                result = svc.release_calendar_event("evt-to-delete", "Lead", db)
                assert result is True
                mock_delete.assert_called_once()

            # Step 2: Mock freebusy query to return empty (slot is free)
            with patch.object(svc, "_freebusy_query") as mock_fb:
                mock_fb.return_value = {
                    "calendars": {
                        svc._calendar_id: {"busy": []}
                    }
                }
                is_free = svc.check_slot_available(slot_start, slot_end)
                assert is_free is True
        finally:
            db.close()

    @patch("app.services.calendar_service.get_google_credentials")
    def test_slot_busy_before_release(self, mock_gauth):
        """Before deletion, freebusy shows the slot as busy."""
        mock_gauth.return_value = MagicMock()
        from app.services.calendar_service import CalendarService
        from app.services.org_context import OrganizationContext

        db = SessionLocal()
        try:
            org_ctx = OrganizationContext.from_id(
                uuid.UUID("d61b9011-0a57-44f6-96b9-97e1773b70f6")
            )
            svc = CalendarService(org_context=org_ctx, db=db)
            slot_start = datetime(2026, 9, 15, 16, 0, tzinfo=timezone.utc)
            slot_end = datetime(2026, 9, 15, 16, 30, tzinfo=timezone.utc)

            # Mock freebusy query to return a busy slot
            with patch.object(svc, "_freebusy_query") as mock_fb:
                mock_fb.return_value = {
                    "calendars": {
                        svc._calendar_id: {
                            "busy": [
                                {
                                    "start": "2026-09-15T16:00:00Z",
                                    "end": "2026-09-15T16:30:00Z",
                                }
                            ]
                        }
                    }
                }
                is_free = svc.check_slot_available(slot_start, slot_end)
                assert is_free is False
        finally:
            db.close()
