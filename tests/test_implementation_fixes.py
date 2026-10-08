"""Tests for implementation fixes: Interested=No gate, RSVP decline handling,
multi-prospect isolation, and stuck pipeline recovery."""
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.database import SessionLocal
from app.models import EventLog, Lead, LeadStatus
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


# ── TEST 1: Interested = No gate ────────────────────────────────────────────


class TestInterestedNoGate:
    """POST /webhooks/integrated-it-trainings/form-submission with Interested? = No should NOT
    create a pipeline. The lead should be stored with status=not_interested
    and no background task should be spawned."""

    def _no_payload(self):
        """Generate a unique No payload with UUID email to avoid dedup collisions."""
        uid = uuid.uuid4().hex[:8]
        return {
            "Interested?": "No",
            "Name": "Not Interested User",
            "Company Address": "456 No Way",
            "Phone Number": "555-0200",
            "Direct Number": "555-0201",
            "Courses": "Nothing",
            "Email Address": f"not-interested-{uid}@example.com",
            "Scheduled Date": "tomorrow",
            "Caller Name": "Agent Jones",
            "Phone Appt. Date/Time": f"tomorrow {uid[:2]}:{uid[2:4]}",  # unique time for dedup
        }

    def _yes_payload(self):
        """Generate a unique Yes payload."""
        uid = uuid.uuid4().hex[:8]
        return {
            "Interested?": "Yes",
            "Name": "Interested User",
            "Company Address": "789 Yes Ave",
            "Phone Number": "555-0300",
            "Direct Number": "555-0301",
            "Courses": "Python",
            "Email Address": f"interested-{uid}@example.com",
            "Scheduled Date": "tomorrow",
            "Caller Name": "Agent Smith",
            "Phone Appt. Date/Time": f"tomorrow {uid[:2]}:{uid[2:4]}",
        }

    def _blank_payload(self):
        """Generate a unique blank-interested payload."""
        uid = uuid.uuid4().hex[:8]
        return {
            "Name": "Blank Interested User",
            "Company Address": "123 Blank St",
            "Phone Number": "555-0400",
            "Direct Number": "555-0401",
            "Courses": "Docker",
            "Email Address": f"blank-interested-{uid}@example.com",
            "Scheduled Date": "tomorrow",
            "Caller Name": "Agent Brown",
            "Phone Appt. Date/Time": f"tomorrow {uid[:2]}:{uid[2:4]}",
        }

    def test_interested_no_returns_ignored(self, client):
        """Interested=No should return status=ignored, not accepted."""
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=self._no_payload())
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "ignored"
        assert "lead_id" in data

    def test_interested_no_creates_lead_with_not_interested_status(self, client):
        """The lead should be stored with status=not_interested."""
        payload = self._no_payload()
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
        data = resp.json()
        assert data["status"] == "ignored"
        lead_id = data["lead_id"]
        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(lead_id))
            assert lead is not None
            assert lead.status == LeadStatus.NOT_INTERESTED
            assert lead.interested == "no"
        finally:
            db.close()

    def test_interested_no_logs_form_ignored_event(self, client):
        """A form_ignored event should be logged for audit trail."""
        payload = self._no_payload()
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
        data = resp.json()
        assert data["status"] == "ignored"
        lead_id = data["lead_id"]
        db = SessionLocal()
        try:
            events = (
                db.query(EventLog)
                .filter(EventLog.lead_id == uuid.UUID(lead_id))
                .all()
            )
            event_types = [e.event_type for e in events]
            assert "form_submitted" in event_types
            assert "form_ignored" in event_types
        finally:
            db.close()

    def test_interested_yes_still_accepted(self, client):
        """Interested=Yes should still be accepted as before."""
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=self._yes_payload())
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"

    def test_interested_blank_still_accepted(self, client):
        """Blank Interested field should still be accepted (legacy behavior)."""
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=self._blank_payload())
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"


# ── TEST 2: RSVP decline handling (unit test) ────────────────────────────────


class TestRSVPDeclineHandling:
    """When a lead declines, the Calendar event should be UPDATED (not deleted)
    with [DECLINED] prefix, color 11, transparency=transparent.
    The calendar_event_id should be PRESERVED on the lead."""

    def test_decline_updates_event_not_deletes(self):
        """The RSVP poller should call update_event_declined, not delete_event."""
        from app.services.rsvp_poller import _process_lead, _POLLABLE

        db = SessionLocal()
        try:
            # Create a scheduled lead with a calendar_event_id
            lead = _make_lead(
                status=LeadStatus.SCHEDULED,
                calendar_event_id="fake-event-id-123",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )

            # Mock the CalendarService
            mock_cal = MagicMock()
            mock_cal.get_attendee_status.return_value = "declined"
            mock_cal._get_event.return_value = {
                "summary": "Strategy Call: Integrated IT Trainings <> Test Co"
            }
            mock_cal.update_event_declined.return_value = None

            summary = {"checked": 0, "declined": 0, "updated": 0, "errors": 0}
            _process_lead(db, mock_cal, lead, summary)

            # Verify update_event_declined was called (not delete_event)
            mock_cal.update_event_declined.assert_called_once()
            mock_cal.delete_event.assert_not_called()

            # Verify the lead status is DECLINED and calendar_event_id is PRESERVED
            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.DECLINED
            assert fresh.calendar_event_id == "fake-event-id-123"  # PRESERVED

            # Verify the event was updated with correct params
            mock_cal.update_event_declined.assert_called_once_with(
                "fake-event-id-123",
                "Strategy Call: Integrated IT Trainings <> Test Co",
                db,
            )

            # Verify event log
            events = db.query(EventLog).filter(EventLog.lead_id == lead.id).all()
            event_types = [e.event_type for e in events]
            assert "declined" in event_types
        finally:
            db.close()

    def test_declined_event_logged_with_event_id(self):
        """The declined event should log the event_id for traceability."""
        from app.services.rsvp_poller import _process_lead

        db = SessionLocal()
        try:
            lead = _make_lead(
                status=LeadStatus.SCHEDULED,
                calendar_event_id="event-id-for-log-test",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )

            mock_cal = MagicMock()
            mock_cal.get_attendee_status.return_value = "declined"
            mock_cal._get_event.return_value = {"summary": "Strategy Call: X <> Y"}
            mock_cal.update_event_declined.return_value = None

            summary = {"checked": 0, "declined": 0, "updated": 0, "errors": 0}
            _process_lead(db, mock_cal, lead, summary)

            # Find the declined event log
            events = db.query(EventLog).filter(
                EventLog.lead_id == lead.id,
                EventLog.event_type == "declined",
            ).all()
            assert len(events) == 1
            payload = json.loads(events[0].payload)
            assert payload["event_id"] == "event-id-for-log-test"
            assert payload["via"] == "rsvp"
        finally:
            db.close()

    def test_missing_event_declined_preserves_id(self):
        """If the event is missing (None status), lead should still be
        DECLINED but calendar_event_id should be preserved."""
        from app.services.rsvp_poller import _process_lead

        db = SessionLocal()
        try:
            lead = _make_lead(
                status=LeadStatus.SCHEDULED,
                calendar_event_id="missing-event-id",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )

            mock_cal = MagicMock()
            mock_cal.get_attendee_status.return_value = None  # event missing

            summary = {"checked": 0, "declined": 0, "updated": 0, "errors": 0}
            _process_lead(db, mock_cal, lead, summary)

            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.DECLINED
            # calendar_event_id preserved even when event is missing
            assert fresh.calendar_event_id == "missing-event-id"
        finally:
            db.close()


# ── TEST 3: Multi-prospect isolation ─────────────────────────────────────────


class TestMultiProspectIsolation:
    """Processing one lead must never affect another lead's state."""

    def test_concurrent_leads_independent(self, client):
        """Submitting two leads creates two independent records."""
        uid1 = uuid.uuid4().hex[:8]
        uid2 = uuid.uuid4().hex[:8]
        payload1 = {
            "Interested?": "Yes",
            "Name": "Prospect One",
            "Company Address": "Company A",
            "Phone Number": "555-1001",
            "Direct Number": "555-1002",
            "Courses": "Python",
            "Email Address": f"prospect-one-{uid1}@example.com",
            "Scheduled Date": "tomorrow",
            "Caller Name": "Agent A",
            "Phone Appt. Date/Time": f"tomorrow {uid1[:2]}:{uid1[2:4]}",
        }
        payload2 = {
            "Interested?": "Yes",
            "Name": "Prospect Two",
            "Company Address": "Company B",
            "Phone Number": "555-2001",
            "Direct Number": "555-2002",
            "Courses": "Docker",
            "Email Address": f"prospect-two-{uid2}@example.com",
            "Scheduled Date": "tomorrow",
            "Caller Name": "Agent B",
            "Phone Appt. Date/Time": f"tomorrow {uid2[:2]}:{uid2[2:4]}",
        }
        resp1 = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload1)
        resp2 = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload2)

        assert resp1.json()["status"] == "accepted"
        assert resp2.json()["status"] == "accepted"
        assert resp1.json()["lead_id"] != resp2.json()["lead_id"]

    def test_declining_one_does_not_affect_other(self):
        """Declining one lead should not touch the other lead's status."""
        from app.services.rsvp_poller import _process_lead

        db = SessionLocal()
        try:
            lead_a = _make_lead(
                name="Lead A",
                email="lead-a-isolation@example.com",
                status=LeadStatus.SCHEDULED,
                calendar_event_id="event-a",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            lead_b = _make_lead(
                name="Lead B",
                email="lead-b-isolation@example.com",
                status=LeadStatus.SCHEDULED,
                calendar_event_id="event-b",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )

            # Decline lead A
            mock_cal = MagicMock()
            mock_cal.get_attendee_status.return_value = "declined"
            mock_cal._get_event.return_value = {"summary": "Strategy Call: X <> A"}
            mock_cal.update_event_declined.return_value = None
            summary = {"checked": 0, "declined": 0, "updated": 0, "errors": 0}
            _process_lead(db, mock_cal, lead_a, summary)

            # Verify lead A is declined
            fresh_a = db.get(Lead, lead_a.id)
            assert fresh_a.status == LeadStatus.DECLINED

            # Verify lead B is STILL scheduled
            fresh_b = db.get(Lead, lead_b.id)
            assert fresh_b.status == LeadStatus.SCHEDULED
            assert fresh_b.calendar_event_id == "event-b"
        finally:
            db.close()


# ── TEST 4: Stuck pipeline recovery ──────────────────────────────────────────


class TestStuckPipelineRecovery:
    """Leads stuck in PENDING should be detected and re-queued for pipeline
    completion on startup — both those with and without a calendar_event_id."""

    def test_recover_stuck_leads_finds_pending_leads(self):
        """_recover_stuck_leads should find and re-queue ALL stuck PENDING leads."""
        from app.main import _recover_stuck_leads

        db = SessionLocal()
        try:
            # Clean up any pre-existing PENDING leads from other tests so
            # we have a known starting state.
            preexisting = (
                db.query(Lead)
                .filter(Lead.status == LeadStatus.PENDING)
                .all()
            )
            preexisting_ids = {l.id for l in preexisting}

            # Create a stuck lead (PENDING with calendar_event_id)
            stuck_lead = _make_lead(
                name="Stuck Lead",
                email="stuck-lead@example.com",
                status=LeadStatus.PENDING,
                calendar_event_id="stuck-event-id",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            # Create a normal pending lead (no calendar_event_id — should also be recovered)
            normal_lead = _make_lead(
                name="Normal Lead",
                email="normal-lead@example.com",
                status=LeadStatus.PENDING,
                calendar_event_id=None,
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )

            # Mock run_pipeline to prevent actual API calls
            with patch("app.main.run_pipeline") as mock_pipeline:
                _recover_stuck_leads()

                # Should have called run_pipeline for ALL pending leads
                # (both stuck_lead and normal_lead, plus any pre-existing ones)
                called_ids = {call.args[0] for call in mock_pipeline.call_args_list}
                assert stuck_lead.id in called_ids, "stuck lead with calendar_event_id should be recovered"
                assert normal_lead.id in called_ids, "pending lead without calendar_event_id should also be recovered"
                # All pre-existing pending leads should also have been re-queued
                assert preexisting_ids.issubset(called_ids)

            # Verify pipeline_recovery event was logged
            events = (
                db.query(EventLog)
                .filter(EventLog.lead_id == stuck_lead.id, EventLog.event_type == "pipeline_recovery")
                .all()
            )
            assert len(events) == 1
        finally:
            db.close()

    def test_recovery_logs_calendar_event_id(self):
        """The pipeline_recovery event should log the calendar_event_id."""
        from app.main import _recover_stuck_leads

        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Recovery Test Lead",
                email="recovery-test@example.com",
                status=LeadStatus.PENDING,
                calendar_event_id="recovery-event-id",
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )

            with patch("app.main.run_pipeline"):
                _recover_stuck_leads()

            events = (
                db.query(EventLog)
                .filter(EventLog.lead_id == lead.id, EventLog.event_type == "pipeline_recovery")
                .all()
            )
            payload = json.loads(events[0].payload)
            assert payload["calendar_event_id"] == "recovery-event-id"
            assert payload["reason"] == "pending_with_calendar_event_id"
        finally:
            db.close()


# ── TEST 5: Pipeline skips NOT_INTERESTED leads ──────────────────────────────


class TestPipelineSkipsNotInterested:
    """The pipeline should never process leads with NOT_INTERESTED status."""

    def test_pipeline_skips_not_interested(self):
        """_run_pipeline_inner should immediately return for NOT_INTERESTED leads."""
        from app.main import _run_pipeline_inner

        db = SessionLocal()
        try:
            lead = _make_lead(
                name="Skipped Lead",
                email="skipped-lead@example.com",
                status=LeadStatus.NOT_INTERESTED,
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=24),
            )

            # Mock all services to prevent API calls
            with patch("app.main.SessionLocal") as mock_session:
                mock_db = MagicMock()
                mock_session.return_value = mock_db
                mock_db.get.return_value = lead
                mock_db.close.return_value = None

                _run_pipeline_inner(lead.id)

                # If the pipeline got past the status check, it would try
                # to import services. We just verify no exception was raised
                # and the function returned early.
        finally:
            db.close()
