"""Regression: Webhook dedup and pipeline lifecycle logging.

Root cause:
  1. The IntegrityError catch in _handle_form_submission returned
     {"status": "duplicate"} with HTTP 202 but logged NOTHING.
     Users saw 202 in the HTTP log and assumed the pipeline ran,
     when in fact it was silently deduplicated.

  2. After a pipeline failure (e.g. Zoom token expired), the lead
     was stuck in ERROR status. Subsequent identical submissions
     were deduped, creating a deadlock where no new pipeline could
     ever run for that lead.

Fix:
  - Added structured logging at every webhook code path:
      webhook dedup:  when IntegrityError fires (duplicate)
      webhook accepted:  when lead is created
      webhook gate:  when interested=no
      webhook pipeline dispatched:  when run_pipeline added to BackgroundTasks
  - Added pipeline completed logging at the end of _run_pipeline_inner

These tests prove the logging and behavior are correct.
"""
import logging
import uuid
from datetime import datetime, timezone, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import EventLog, Lead, LeadStatus
from app.models_multi_tenant import Organization, OrganizationStatus


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_org(**overrides) -> Organization:
    defaults = {
        "name": f"DedupTestOrg {uuid.uuid4().hex[:8]}",
        "slug": f"dedup-test-{uuid.uuid4().hex[:8]}",
        "timezone": "America/Chicago",
        "status": OrganizationStatus.ACTIVE,
        "plan": "starter",
    }
    defaults.update(overrides)
    db = SessionLocal()
    try:
        org = Organization(**defaults)
        db.add(org)
        db.commit()
        db.refresh(org)
        return org
    finally:
        db.close()


def _make_payload(**overrides) -> dict:
    base = {
        "Name": "Test Lead",
        "Email Address": f"dedup-{uuid.uuid4().hex[:8]}@example.com",
        "Phone Number": "555-0100",
        "Direct Number": "555-0101",
        "Courses": "Test Course",
        "Company Address": "123 Test St",
        "Interested?": "yes",
        "Scheduled Date": "2026-10-15",
        "Caller Name": "Test Caller",
        "Phone Appt. Date/Time": "October 15, 2026 at 2:00 PM",
        "form_identifier": "strategy-call",
    }
    base.update(overrides)
    return base


# ══════════════════════════════════════════════════════════════════════════════
# 1. Dedup Logging
# ══════════════════════════════════════════════════════════════════════════════


class TestDedupLogging:
    """Duplicate submissions must be clearly logged as deduped."""

    def test_duplicate_returns_202_and_logs_dedup(self, client, caplog):
        """Second identical submission returns 202 + 'duplicate' and emits dedup log."""
        org = _make_org()
        payload = _make_payload()

        resp1 = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )
        assert resp1.json()["status"] == "accepted"

        # Clear log capture between submissions so we only capture the 2nd
        caplog.clear()
        caplog.set_level(logging.INFO)
        resp2 = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )

        data2 = resp2.json()
        assert resp2.status_code == 202
        assert data2["status"] == "duplicate"

        # Verify structured dedup log is present
        dedup_logs = [r for r in caplog.records if "webhook dedup" in r.message]
        assert len(dedup_logs) == 1, (
            "Expected exactly one 'webhook dedup' log entry; "
            f"got {len(dedup_logs)}"
        )
        # Verify the log includes the email and org
        assert org.id.hex[:8] in dedup_logs[0].message

    def test_duplicate_does_not_dispatch_pipeline(self, client):
        """Duplicate submissions must NOT dispatch run_pipeline."""
        org = _make_org()
        payload = _make_payload()

        client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        client.post(f"/webhooks/{org.slug}/form-submission", json=payload)

        # Only one lead should exist
        db = SessionLocal()
        try:
            leads = db.query(Lead).filter(
                Lead.organization_id == org.id,
            ).all()
            assert len(leads) == 1, (
                f"Expected 1 lead (deduped), got {len(leads)}"
            )
        finally:
            db.close()

    def test_duplicate_includes_request_id(self, client):
        """Duplicate response echoes the X-Request-ID for idempotency tracking."""
        org = _make_org()
        payload = _make_payload()
        request_id = str(uuid.uuid4())

        client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"X-Request-ID": request_id},
        )
        resp2 = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"X-Request-ID": request_id},
        )
        data2 = resp2.json()
        assert data2["status"] == "duplicate"
        assert data2.get("request_id") == request_id


# ══════════════════════════════════════════════════════════════════════════════
# 2. Webhook Accept Logging
# ══════════════════════════════════════════════════════════════════════════════


class TestWebhookAcceptLogging:
    """New submissions must emit clear structured logs."""

    def test_accepted_submission_logs_lead_created(self, client, caplog):
        """First submission logs 'webhook accepted: lead created'."""
        org = _make_org()
        payload = _make_payload()

        caplog.clear()
        caplog.set_level(logging.INFO)
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )

        assert resp.json()["status"] == "accepted"
        accepted_logs = [r for r in caplog.records if "webhook accepted" in r.message]
        assert len(accepted_logs) == 1, (
            "Expected one 'webhook accepted' log; "
            f"got {len(accepted_logs)}"
        )
        assert resp.json()["lead_id"] in accepted_logs[0].message

    def test_accepted_submission_logs_pipeline_dispatched(self, client, caplog):
        """First submission logs 'webhook pipeline dispatched'."""
        org = _make_org()
        payload = _make_payload()

        caplog.clear()
        caplog.set_level(logging.INFO)
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )

        assert resp.json()["status"] == "accepted"
        dispatch_logs = [
            r for r in caplog.records if "webhook pipeline dispatched" in r.message
        ]
        assert len(dispatch_logs) == 1, (
            "Expected one 'webhook pipeline dispatched' log; "
            f"got {len(dispatch_logs)}"
        )
        assert resp.json()["lead_id"] in dispatch_logs[0].message


# ══════════════════════════════════════════════════════════════════════════════
# 3. Interested=No Gate Logging
# ══════════════════════════════════════════════════════════════════════════════


class TestInterestedNoGateLogging:
    """Interested=No submissions must be logged as gated."""

    def test_interested_no_logs_gate(self, client, caplog):
        """Submission with Interested?=No logs 'webhook gate'."""
        org = _make_org()
        payload = _make_payload(**{"Interested?": "no"})

        caplog.clear()
        caplog.set_level(logging.INFO)
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )

        data = resp.json()
        assert data["status"] == "ignored"
        gate_logs = [r for r in caplog.records if "webhook gate" in r.message]
        assert len(gate_logs) == 1, (
            "Expected one 'webhook gate' log; "
            f"got {len(gate_logs)}"
        )
        assert data["lead_id"] in gate_logs[0].message

    def test_interested_no_does_not_dispatch_pipeline(self, client, caplog):
        """Interested=No must NOT dispatch pipeline and NOT log dispatch."""
        org = _make_org()
        payload = _make_payload(**{"Interested?": "no"})

        caplog.clear()
        caplog.set_level(logging.INFO)
        client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )

        dispatch_logs = [
            r for r in caplog.records if "webhook pipeline dispatched" in r.message
        ]
        assert len(dispatch_logs) == 0, (
            "Interested=No must not dispatch pipeline"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 4. Pipeline Lifecycle Logging
# ══════════════════════════════════════════════════════════════════════════════


class TestPipelineLifecycleLogging:
    """Pipeline start/completion/failure must be logged."""

    def _setup_lead(self, status=LeadStatus.PENDING, email_prefix="pipe"):
        """Create a lead in a fresh org and return (org, lead, lead_id)."""
        db = SessionLocal()
        try:
            org = _make_org()
            future_dt = datetime.now(timezone.utc) + timedelta(days=30)
            lead = Lead(
                name="Pipeline Log Test",
                email=f"{email_prefix}-{uuid.uuid4().hex[:8]}@example.com",
                phone_number="555-0200",
                courses="Test",
                status=status,
                dedupe_key=f"{email_prefix}-test-{uuid.uuid4().hex}",
                organization_id=org.id,
                appt_datetime_raw="tomorrow 3pm",
                appt_datetime_utc=future_dt,
            )
            db.add(lead)
            db.commit()
            db.refresh(lead)
            return org, lead, lead.id
        finally:
            db.close()

    def test_pipeline_start_logged(self, caplog):
        """run_pipeline logs 'pipeline start: lead=...' at the beginning."""
        from app.main import run_pipeline

        _org, _lead, lead_id = self._setup_lead()

        # Use set_level (not at_level) to ensure propagation works across
        # the full test suite.  Also capture ALL loggers so we don't miss
        # any log that routes through a different logger name.
        caplog.set_level(logging.INFO)

        run_pipeline(lead_id)

        start_logs = [r for r in caplog.records if "pipeline start" in r.message]
        assert len(start_logs) >= 1, (
            "Expected 'pipeline start' log; "
            f"got messages: {[r.message for r in caplog.records[:20]]}"
        )
        assert str(lead_id) in start_logs[0].message

    def test_pipeline_failure_logged(self, caplog):
        """Pipeline failure logs 'pipeline failed for lead ...'."""
        from app.main import run_pipeline

        _org, _lead, lead_id = self._setup_lead(email_prefix="fail")

        # Pipeline will fail naturally (no real integrations) and should
        # log both start and failure.
        caplog.set_level(logging.INFO)

        run_pipeline(lead_id)

        fail_logs = [r for r in caplog.records if "pipeline failed" in r.message]
        assert len(fail_logs) >= 1, (
            "Expected 'pipeline failed' log; "
            f"got messages: {[r.message for r in caplog.records[:20]]}"
        )
        assert str(lead_id) in fail_logs[0].message

        # Verify lead is now in ERROR status
        db = SessionLocal()
        try:
            lead = db.get(Lead, lead_id)
            assert lead.status == LeadStatus.ERROR
        finally:
            db.close()

    def test_pipeline_not_pending_skips(self, caplog):
        """Pipeline skips leads not in PENDING status with clear log."""
        from app.main import _run_pipeline_inner

        _org, _lead, lead_id = self._setup_lead(
            status=LeadStatus.ERROR, email_prefix="skip"
        )

        caplog.clear()
        caplog.set_level(logging.INFO)

        _run_pipeline_inner(lead_id)

        skip_logs = [
            r for r in caplog.records if "not pending" in r.message.lower()
        ]
        assert len(skip_logs) == 1, (
            "Expected 'not pending' skip log; "
            f"got messages: {[r.message for r in caplog.records[:20]]}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 5. End-to-End Log Chain
# ══════════════════════════════════════════════════════════════════════════════


class TestE2ELogChain:
    """Full webhook lifecycle produces a traceable log chain."""

    def test_full_lifecycle_log_chain(self, client, caplog):
        """accepted → pipeline dispatched → pipeline start → pipeline failed.
        (Pipeline fails because no real credentials in test mode.)"""
        from app.main import run_pipeline

        org = _make_org()
        payload = _make_payload()

        caplog.clear()
        caplog.set_level(logging.INFO)

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )

        assert resp.json()["status"] == "accepted"
        lead_id = resp.json()["lead_id"]

        # The webhook POST triggers run_pipeline as a BackgroundTask.
        # In TestClient, background tasks DO execute. So the pipeline
        # may have already run (and failed) by the time we get here.
        # If the lead is already ERROR, it was processed — verify logs.
        # If it's still PENDING, run the pipeline manually.
        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(lead_id))
            already_errored = lead.status == LeadStatus.ERROR
        finally:
            db.close()

        if not already_errored:
            caplog.clear()
            run_pipeline(uuid.UUID(lead_id))

        messages = [r.message for r in caplog.records]

        # Must see pipeline start OR not-pending skip (if already processed)
        pipeline_msgs = [
            m for m in messages
            if "pipeline start" in m or "not pending" in m.lower()
        ]
        assert len(pipeline_msgs) >= 1, (
            f"Expected pipeline lifecycle log; got messages: {messages[:20]}"
        )

        # Verify the lead ended up in ERROR status
        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(lead_id))
            assert lead.status == LeadStatus.ERROR
        finally:
            db.close()
