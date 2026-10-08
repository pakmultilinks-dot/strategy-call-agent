"""Phase 28: Meeting Decline → Google Calendar Slot Release tests.

Comprehensive tests covering:
1. release_calendar_event() — idempotency, error handling, empty event_id
2. update_event_declined() — body shape, 404/410 handling, FailedJob recording
3. cancel_call endpoint — tenant isolation, calendar release integration
4. Slot availability — transparency=transparent frees the slot
5. Concurrency — race conditions between cancel and completion
6. Background services — reminder/RSVP/followup exclusion of DECLINED leads
7. Terminal state — DECLINED has no outgoing transitions
8. Event ID preservation on decline
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.database import SessionLocal
from app.models import (
    CallOutcome,
    EventLog,
    FailedJob,
    Lead,
    LeadStatus,
)
from app.services.org_context import OrganizationContext
from app.tenant import _DEFAULT_ORG_ID


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_lead(**overrides):
    """Insert a Lead row directly and return it. Commits to the DB."""
    defaults = {
        "name": "Test Lead",
        "email": f"test-{uuid.uuid4().hex[:8]}@example.com",
        "company_address": "Test Co",
        "appt_datetime_raw": "tomorrow 2pm",
        "dedupe_key": f"test-{uuid.uuid4().hex}",
        "status": LeadStatus.PENDING,
        "organization_id": _DEFAULT_ORG_ID,
    }
    defaults.update(overrides)
    db = SessionLocal()
    try:
        lead = Lead(**defaults)
        db.add(lead)
        db.commit()
        db.refresh(lead)
        return lead
    finally:
        db.close()


def _make_svc():
    """Create a CalendarService instance with mocked internals."""
    from app.services.calendar_service import CalendarService

    svc = CalendarService.__new__(CalendarService)
    # Use the seeded default org so that FailedJob FK constraints
    # are satisfied (organization_id must reference an existing row).
    svc._org_id = _DEFAULT_ORG_ID
    return svc


# ══════════════════════════════════════════════════════════════════════════════
# UNIT TESTS — No auth fixtures needed (all mocked)
# ══════════════════════════════════════════════════════════════════════════════


# ── TEST 1: release_calendar_event() ────────────────────────────────────────


class TestReleaseCalendarEvent:
    """release_calendar_event() should be idempotent, safe on errors,
    and organization-scoped."""

    def test_release_empty_event_id_returns_true(self):
        """Calling release_calendar_event with empty event_id is a no-op."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            result = svc.release_calendar_event("", "Test Lead", db)
            assert result is True
        finally:
            db.close()

    def test_release_none_event_id_returns_true(self):
        """Calling release_calendar_event with None event_id is a no-op."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            result = svc.release_calendar_event(None, "Test Lead", db)
            assert result is True
        finally:
            db.close()

    def test_release_success(self):
        """Successful release calls delete_event and returns True."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            with patch.object(svc, "delete_event") as mock_delete:
                result = svc.release_calendar_event("event-123", "Test Lead", db)
                assert result is True
                mock_delete.assert_called_once_with("event-123", db)
        finally:
            db.close()

    def test_release_returns_false_on_error(self):
        """If delete_event raises, release returns False."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            with patch.object(
                svc, "delete_event", side_effect=Exception("Google API 404")
            ):
                result = svc.release_calendar_event("event-123", "Test Lead", db)
                assert result is False
        finally:
            db.close()

    def test_release_calls_delete_event(self):
        """release_calendar_event delegates to delete_event (not update_event_declined)."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            with patch.object(svc, "delete_event") as mock_delete:
                svc.release_calendar_event("evt-abc", "Acme Corp Prospect", db)
                mock_delete.assert_called_once_with("evt-abc", db)
        finally:
            db.close()

    def test_release_logs_warning_on_failure(self):
        """release_calendar_event should log a warning on failure."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            with patch.object(
                svc, "delete_event", side_effect=Exception("API error")
            ):
                with patch("app.services.calendar_service.logger") as mock_logger:
                    svc.release_calendar_event("evt-fail", "Fail Lead", db)
                    mock_logger.warning.assert_called()
                    # Verify the log message mentions the event_id
                    warning_args = mock_logger.warning.call_args
                    assert "evt-fail" in str(warning_args)
        finally:
            db.close()

    def test_release_logs_info_on_success(self):
        """release_calendar_event should log an info message on success."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            with patch.object(svc, "delete_event") as mock_delete:
                with patch("app.services.calendar_service.logger") as mock_logger:
                    svc.release_calendar_event("evt-ok", "OK Lead", db)
                    mock_logger.info.assert_called()
                    info_args = mock_logger.info.call_args
                    assert "evt-ok" in str(info_args)
        finally:
            db.close()


# ── TEST 2: update_event_declined() ─────────────────────────────────────────


class TestUpdateEventDeclined:
    """update_event_declined should set [DECLINED] prefix, colorId=11,
    transparency=transparent, and handle 404/410 gracefully."""

    @pytest.fixture(autouse=True)
    def _clean_failed_jobs(self):
        """Remove stale calendar_update_declined FailedJob records before each test.

        Two tests in this class (test_declined_records_failed_job_on_500 and
        test_declined_records_failed_job_on_generic_exception) each create a
        FailedJob and then query ALL records of that job_type. Without cleanup,
        the earlier test's record pollutes the later test's ``jobs[-1]``
        assertion.
        """
        db = SessionLocal()
        try:
            db.query(FailedJob).filter(
                FailedJob.job_type == "calendar_update_declined",
                FailedJob.organization_id == _DEFAULT_ORG_ID,
            ).delete()
            db.commit()
        finally:
            db.close()

    def test_declined_sets_transparency_transparent(self):
        """Declined event should set transparency=transparent to free the slot."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            with patch.object(svc, "_patch_event") as mock_patch:
                svc.update_event_declined("event-456", "Strategy Call: Acme", db)
                mock_patch.assert_called_once()
                body = mock_patch.call_args[0][1]
                assert body["transparency"] == "transparent"
        finally:
            db.close()

    def test_declined_sets_color_red(self):
        """Declined event should set colorId=11 (Google Calendar red)."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            with patch.object(svc, "_patch_event") as mock_patch:
                svc.update_event_declined("evt", "Test", db)
                body = mock_patch.call_args[0][1]
                assert body["colorId"] == "11"
        finally:
            db.close()

    def test_declined_prefixes_summary(self):
        """Summary should be prefixed with [DECLINED]."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            with patch.object(svc, "_patch_event") as mock_patch:
                svc.update_event_declined("evt", "Original Title", db)
                body = mock_patch.call_args[0][1]
                assert body["summary"] == "[DECLINED] Original Title"
        finally:
            db.close()

    def test_declined_idempotent_on_404(self):
        """A 404 from Google API means the event is already gone — no error."""
        from googleapiclient.errors import HttpError

        svc = _make_svc()
        db = SessionLocal()
        try:
            resp = MagicMock()
            resp.status = 404
            error_404 = HttpError(resp=resp, content=b"Not Found")
            with patch.object(svc, "_patch_event", side_effect=error_404):
                # Should NOT raise
                svc.update_event_declined("event-456", "Test", db)
        finally:
            db.close()

    def test_declined_idempotent_on_410(self):
        """A 410 from Google API means the event was deleted — no error."""
        from googleapiclient.errors import HttpError

        svc = _make_svc()
        db = SessionLocal()
        try:
            resp = MagicMock()
            resp.status = 410
            error_410 = HttpError(resp=resp, content=b"Gone")
            with patch.object(svc, "_patch_event", side_effect=error_410):
                # Should NOT raise
                svc.update_event_declined("event-456", "Test", db)
        finally:
            db.close()

    def test_declined_records_failed_job_on_500(self):
        """A non-404/410 error should record a FailedJob and re-raise."""
        from googleapiclient.errors import HttpError

        svc = _make_svc()
        db = SessionLocal()
        try:
            resp = MagicMock()
            resp.status = 500
            error_500 = HttpError(resp=resp, content=b"Server Error")
            with patch.object(svc, "_patch_event", side_effect=error_500):
                with pytest.raises(HttpError):
                    svc.update_event_declined("event-456", "Test", db)
                # Verify FailedJob was recorded
                jobs = (
                    db.query(FailedJob)
                    .filter(FailedJob.job_type == "calendar_update_declined")
                    .all()
                )
                assert len(jobs) >= 1
                payload = json.loads(jobs[-1].payload)
                assert payload["event_id"] == "event-456"
        finally:
            db.close()

    def test_declined_records_failed_job_on_generic_exception(self):
        """A non-HTTP exception should also record a FailedJob."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            with patch.object(
                svc, "_patch_event", side_effect=RuntimeError("Network timeout")
            ):
                with pytest.raises(RuntimeError):
                    svc.update_event_declined("event-789", "Test", db)
                jobs = (
                    db.query(FailedJob)
                    .filter(FailedJob.job_type == "calendar_update_declined")
                    .all()
                )
                assert len(jobs) >= 1
                payload = json.loads(jobs[-1].payload)
                assert payload["event_id"] == "event-789"
        finally:
            db.close()

    def test_declined_does_not_modify_event_times(self):
        """Declining should NOT change start/end times — only metadata."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            with patch.object(svc, "_patch_event") as mock_patch:
                svc.update_event_declined("evt-1", "Test", db)
                body = mock_patch.call_args[0][1]
                assert "start" not in body
                assert "end" not in body
        finally:
            db.close()


# ── TEST 3: Slot availability (transparency) ────────────────────────────────


class TestSlotAvailability:
    """When an event is declined, transparency=transparent should free
    the time slot so other appointments can be booked."""

    def test_declined_body_has_required_fields(self):
        """The declined event body should have summary, colorId, and transparency."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            with patch.object(svc, "_patch_event") as mock_patch:
                svc.update_event_declined("evt-1", "Test", db)
                body = mock_patch.call_args[0][1]
                assert "summary" in body
                assert "colorId" in body
                assert "transparency" in body
        finally:
            db.close()

    def test_transparency_is_the_slot_freeing_mechanism(self):
        """transparency=transparent is what removes the event from free/busy."""
        svc = _make_svc()
        db = SessionLocal()
        try:
            with patch.object(svc, "_patch_event") as mock_patch:
                svc.update_event_declined("evt-1", "Test", db)
                body = mock_patch.call_args[0][1]
                # This is THE key property: transparency=transparent
                # means the event does NOT block the time slot
                assert body["transparency"] == "transparent"
                # contrast: opaque would block the slot (default for new events)
                assert body["transparency"] != "opaque"
        finally:
            db.close()


# ── TEST 4: Concurrency between cancel and completion ───────────────────────


class TestConcurrencyCancelCompletion:
    """Race condition: if cancel and meeting_completion run concurrently,
    the lead should end up in a consistent terminal state."""

    def test_cancelled_lead_not_completed(self):
        """A DECLINED lead should not be moved to COMPLETED."""
        from app.main import _mark_completed_meetings

        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Concurrency Test",
                status=LeadStatus.DECLINED,
                appt_datetime_utc=datetime.now(timezone.utc) - timedelta(hours=5),
                cancelled_at=datetime.now(timezone.utc) - timedelta(hours=4),
            )

            _mark_completed_meetings()

            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.DECLINED
        finally:
            db.close()

    def test_completed_lead_stays_completed(self):
        """A COMPLETED lead should remain COMPLETED."""
        from app.main import _mark_completed_meetings

        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Completed Test",
                status=LeadStatus.COMPLETED,
                appt_datetime_utc=datetime.now(timezone.utc) - timedelta(hours=5),
            )

            _mark_completed_meetings()

            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.COMPLETED
        finally:
            db.close()

    def test_not_interested_not_completed(self):
        """A NOT_INTERESTED lead should not be moved to COMPLETED."""
        from app.main import _mark_completed_meetings

        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Not Interested Test",
                status=LeadStatus.NOT_INTERESTED,
                appt_datetime_utc=datetime.now(timezone.utc) - timedelta(hours=5),
            )

            _mark_completed_meetings()

            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.NOT_INTERESTED
        finally:
            db.close()

    def test_error_lead_not_completed(self):
        """An ERROR lead should not be moved to COMPLETED."""
        from app.main import _mark_completed_meetings

        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Error Test",
                status=LeadStatus.ERROR,
                appt_datetime_utc=datetime.now(timezone.utc) - timedelta(hours=5),
            )

            _mark_completed_meetings()

            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.ERROR
        finally:
            db.close()


# ── TEST 5: Background services exclude DECLINED ───────────────────────────


class TestBackgroundServicesExcludeDeclined:
    """Reminder service, RSVP poller, and auto-followup should all
    skip DECLINED leads — no stale reminders or follow-ups."""

    def test_reminder_query_excludes_declined(self):
        """The _REMINDABLE tuple in reminder_service should not include DECLINED."""
        from app.services.reminder_service import _REMINDABLE

        assert LeadStatus.DECLINED not in _REMINDABLE

    def test_reminder_query_reminds_only_remindable(self):
        """_REMINDABLE should contain exactly SCHEDULED, ACCEPTED, TENTATIVE."""
        from app.services.reminder_service import _REMINDABLE

        expected = {LeadStatus.SCHEDULED, LeadStatus.ACCEPTED, LeadStatus.TENTATIVE}
        assert set(_REMINDABLE) == expected

    def test_rsvp_poller_excludes_declined(self):
        """RSVP poller should only poll SCHEDULED/ACCEPTED/TENTATIVE leads."""
        from app.services.rsvp_poller import _POLLABLE

        assert LeadStatus.DECLINED not in _POLLABLE

    def test_meeting_completion_excludes_declined(self):
        """_mark_completed_meetings should not select DECLINED leads."""
        from app.main import _mark_completed_meetings

        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Declined Past",
                status=LeadStatus.DECLINED,
                appt_datetime_utc=datetime.now(timezone.utc) - timedelta(hours=5),
                cancelled_at=datetime.now(timezone.utc) - timedelta(hours=4),
            )

            _mark_completed_meetings()

            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.DECLINED
        finally:
            db.close()

    def test_auto_followup_no_cancelled_template(self):
        """Auto follow-up service should have no template for 'cancelled'
        outcome — cancellations should NOT generate follow-ups."""
        from app.services.auto_followup_service import get_followup_templates

        assert get_followup_templates("cancelled") == []

    def test_auto_followup_no_not_interested_template(self):
        """Auto follow-up service should have no template for 'not_interested'
        outcome — rejections should NOT generate follow-ups."""
        from app.services.auto_followup_service import get_followup_templates

        assert get_followup_templates("not_interested") == []


# ── TEST 6: Terminal state transitions ──────────────────────────────────────


class TestTerminalStateTransitions:
    """DECLINED is a terminal state — no further status transitions should
    be allowed from DECLINED."""

    def test_declined_is_terminal(self):
        """Once DECLINED, the lead cannot be transitioned to another state."""
        from app.schemas import ALLOWED_STATUS_TRANSITIONS

        transitions_from_declined = ALLOWED_STATUS_TRANSITIONS.get(
            LeadStatus.DECLINED, set()
        )
        assert len(transitions_from_declined) == 0

    def test_other_terminal_states(self):
        """COMPLETED and NOT_INTERESTED are also terminal."""
        from app.schemas import ALLOWED_STATUS_TRANSITIONS

        for terminal in [LeadStatus.COMPLETED, LeadStatus.NOT_INTERESTED]:
            transitions = ALLOWED_STATUS_TRANSITIONS.get(terminal, set())
            assert len(transitions) == 0, f"{terminal} should be terminal"


# ── TEST 7: Event ID preservation on decline ────────────────────────────────


class TestEventIdPreservationOnDecline:
    """calendar_event_id should be preserved after decline for
    historical traceability."""

    def test_rsvp_decline_preserves_event_id(self):
        """RSVP poller decline should preserve calendar_event_id."""
        from app.services.rsvp_poller import _process_lead

        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Preserve Test",
                status=LeadStatus.SCHEDULED,
                calendar_event_id="preserve-event-123",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )

            mock_cal = MagicMock()
            mock_cal.get_attendee_status.return_value = "declined"
            mock_cal._get_event.return_value = {"summary": "Strategy Call: X <> Y"}

            summary = {"checked": 0, "declined": 0, "updated": 0, "errors": 0}
            _process_lead(db, mock_cal, lead, summary)

            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.DECLINED
            assert fresh.calendar_event_id == "preserve-event-123"
        finally:
            db.close()

    def test_rsvp_decline_logs_event_type(self):
        """RSVP poller decline should create a 'declined' EventLog."""
        from app.services.rsvp_poller import _process_lead

        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Log Test",
                status=LeadStatus.SCHEDULED,
                calendar_event_id="log-event-456",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )

            mock_cal = MagicMock()
            mock_cal.get_attendee_status.return_value = "declined"
            mock_cal._get_event.return_value = {"summary": "Strategy Call: X <> Y"}

            summary = {"checked": 0, "declined": 0, "updated": 0, "errors": 0}
            _process_lead(db, mock_cal, lead, summary)

            events = (
                db.query(EventLog)
                .filter(
                    EventLog.lead_id == lead.id,
                    EventLog.event_type == "declined",
                )
                .all()
            )
            assert len(events) == 1
            payload = json.loads(events[0].payload)
            assert payload["event_id"] == "log-event-456"
            assert payload["via"] == "rsvp"
        finally:
            db.close()

    def test_missing_event_still_declines(self):
        """If the calendar event is missing (None status), lead should
        still be DECLINED with calendar_event_id preserved."""
        from app.services.rsvp_poller import _process_lead

        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Missing Event Test",
                status=LeadStatus.SCHEDULED,
                calendar_event_id="gone-event-789",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )

            mock_cal = MagicMock()
            mock_cal.get_attendee_status.return_value = None  # event missing

            summary = {"checked": 0, "declined": 0, "updated": 0, "errors": 0}
            _process_lead(db, mock_cal, lead, summary)

            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.DECLINED
            assert fresh.calendar_event_id == "gone-event-789"  # preserved
        finally:
            db.close()

    def test_rsvp_decline_calls_update_not_delete(self):
        """RSVP poller should call update_event_declined, not delete_event."""
        from app.services.rsvp_poller import _process_lead

        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Update vs Delete Test",
                status=LeadStatus.SCHEDULED,
                calendar_event_id="evt-update-not-delete",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )

            mock_cal = MagicMock()
            mock_cal.get_attendee_status.return_value = "declined"
            mock_cal._get_event.return_value = {"summary": "Strategy Call: X <> Y"}

            summary = {"checked": 0, "declined": 0, "updated": 0, "errors": 0}
            _process_lead(db, mock_cal, lead, summary)

            # Verify update_event_declined was called (not delete_event)
            mock_cal.update_event_declined.assert_called_once()
            mock_cal.delete_event.assert_not_called()
        finally:
            db.close()


# ── TEST 8: OrganizationContext creation ────────────────────────────────────


class TestOrganizationContextCreation:
    """OrganizationContext.from_id should correctly create org-scoped
    contexts for CalendarService instantiation."""

    def test_from_id_with_uuid(self):
        """Should accept UUID objects."""
        org_id = uuid.uuid4()
        ctx = OrganizationContext.from_id(org_id)
        assert ctx.organization_id == org_id

    def test_from_id_with_string(self):
        """Should accept string UUIDs and convert them."""
        org_id = uuid.uuid4()
        ctx = OrganizationContext.from_id(str(org_id))
        assert ctx.organization_id == org_id

    def test_context_is_frozen(self):
        """OrganizationContext should be immutable (frozen dataclass)."""
        ctx = OrganizationContext.from_id(uuid.uuid4())
        with pytest.raises(AttributeError):
            ctx.organization_id = uuid.uuid4()


# ── TEST 9: cancel_call endpoint integration ────────────────────────────────


class TestCancelCallEndpoint:
    """Integration tests for the cancel_call endpoint.
    Uses HTTP Basic auth (platform admin) for simplicity."""

    def test_cancel_sets_declined_status(self, client):
        """Cancel should set status=DECLINED."""
        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Cancel Status Test",
                status=LeadStatus.SCHEDULED,
                calendar_event_id="cancel-test-evt",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            lead_id = lead.id
        finally:
            db.close()

        import base64
        from app.config import settings
        basic = base64.b64encode(
            f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
        ).decode()

        r = client.post(
            f"/dashboard/api/leads/{lead_id}/cancel",
            json={"reason": "Status test"},
            headers={"Authorization": f"Basic {basic}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "cancelled"
        assert data["lead"]["status"].lower() == "declined"

    def test_cancel_sets_cancelled_call_outcome(self, client):
        """Cancel should set call_outcome=CANCELLED."""
        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Cancel Outcome Test",
                status=LeadStatus.SCHEDULED,
                calendar_event_id="cancel-outcome-evt",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            lead_id = lead.id
        finally:
            db.close()

        import base64
        from app.config import settings
        basic = base64.b64encode(
            f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
        ).decode()

        r = client.post(
            f"/dashboard/api/leads/{lead_id}/cancel",
            json={},
            headers={"Authorization": f"Basic {basic}"},
        )
        assert r.status_code == 200

        db = SessionLocal()
        try:
            lead = db.get(Lead, lead_id)
            assert lead.call_outcome == CallOutcome.CANCELLED
        finally:
            db.close()

    def test_cancel_sets_cancelled_at(self, client):
        """Cancel should set cancelled_at timestamp."""
        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Cancel Timestamp Test",
                status=LeadStatus.SCHEDULED,
                calendar_event_id="cancel-ts-evt",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            lead_id = lead.id
        finally:
            db.close()

        import base64
        from app.config import settings
        basic = base64.b64encode(
            f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
        ).decode()

        r = client.post(
            f"/dashboard/api/leads/{lead_id}/cancel",
            json={},
            headers={"Authorization": f"Basic {basic}"},
        )
        assert r.status_code == 200

        db = SessionLocal()
        try:
            lead = db.get(Lead, lead_id)
            assert lead.cancelled_at is not None
        finally:
            db.close()

    def test_cancel_logs_audit_event(self, client):
        """Cancel should create a 'call_cancelled' audit event."""
        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Cancel Audit Test",
                status=LeadStatus.SCHEDULED,
                calendar_event_id="cancel-audit-evt",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            lead_id = lead.id
        finally:
            db.close()

        import base64
        from app.config import settings
        basic = base64.b64encode(
            f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
        ).decode()

        r = client.post(
            f"/dashboard/api/leads/{lead_id}/cancel",
            json={"reason": "Audit check"},
            headers={"Authorization": f"Basic {basic}"},
        )
        assert r.status_code == 200

        db = SessionLocal()
        try:
            events = (
                db.query(EventLog)
                .filter(
                    EventLog.lead_id == lead_id,
                    EventLog.event_type == "call_cancelled",
                )
                .all()
            )
            assert len(events) >= 1
            payload = json.loads(events[-1].payload)
            assert payload["reason"] == "Audit check"
        finally:
            db.close()

    def test_cancel_preserves_calendar_event_id(self, client):
        """After cancel, calendar_event_id should still be set."""
        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Cancel Preserve Test",
                status=LeadStatus.SCHEDULED,
                calendar_event_id="preserve-evt-999",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            lead_id = lead.id
        finally:
            db.close()

        import base64
        from app.config import settings
        basic = base64.b64encode(
            f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
        ).decode()

        r = client.post(
            f"/dashboard/api/leads/{lead_id}/cancel",
            json={},
            headers={"Authorization": f"Basic {basic}"},
        )
        assert r.status_code == 200

        db = SessionLocal()
        try:
            lead = db.get(Lead, lead_id)
            assert lead.calendar_event_id == "preserve-evt-999"
        finally:
            db.close()

    def test_cancel_without_event_id_succeeds(self, client):
        """Cancel should succeed even if calendar_event_id is None."""
        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Cancel No Event Test",
                status=LeadStatus.SCHEDULED,
                calendar_event_id=None,
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            lead_id = lead.id
        finally:
            db.close()

        import base64
        from app.config import settings
        basic = base64.b64encode(
            f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
        ).decode()

        r = client.post(
            f"/dashboard/api/leads/{lead_id}/cancel",
            json={},
            headers={"Authorization": f"Basic {basic}"},
        )
        assert r.status_code == 200
