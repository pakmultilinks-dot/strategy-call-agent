"""Failed job recovery tests (Phase 29 P1-11).

Tests the expanded _recover_failed_jobs() function that now handles:
  - pipeline (existing)
  - ai_generate (NEW)
  - calendar_create (NEW)
  - followup_email_send (NEW)
  - Unrecoverable types: calendar_update_reschedule, calendar_delete,
    email_send, daily_reminder, rsvp_poll (NEW)
"""
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from app.database import SessionLocal
from app.models import EventLog, FailedJob, FollowUp, FollowUpStatus, Lead, LeadStatus
from app.tenant import _DEFAULT_ORG_ID
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_db():
    """Clean all test data BEFORE and AFTER each test to prevent
    cross-test and cross-module contamination.

    _recover_failed_jobs() processes ALL unresolved jobs in the DB, so
    leftover jobs from previous tests or other modules would leak into
    the current test and cause false mock assertions.
    """
    def _do_clean():
        session = SessionLocal()
        try:
            session.query(FailedJob).delete(synchronize_session=False)
            session.query(FollowUp).delete(synchronize_session=False)
            session.query(EventLog).delete(synchronize_session=False)
            session.query(Lead).delete(synchronize_session=False)
            session.query(User).delete(synchronize_session=False)
            session.query(Organization).filter(
                Organization.id != _DEFAULT_ORG_ID
            ).delete(synchronize_session=False)
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    # Clean BEFORE test — removes leftover data from other modules
    _do_clean()
    yield
    # Clean AFTER test — removes data created by this test
    _do_clean()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_org() -> Organization:
    """Create a minimal org for testing."""
    session = SessionLocal()
    try:
        org = Organization(
            name=f"Recovery Test Org {uuid.uuid4().hex[:8]}",
            slug=f"recovery-test-{uuid.uuid4().hex[:8]}",
            timezone="America/Chicago",
            status=OrganizationStatus.ACTIVE,
            plan="business",
        )
        session.add(org)
        session.commit()
        session.refresh(org)
        return org
    finally:
        session.close()


def _make_user(org_id: uuid.UUID) -> User:
    """Create a user for testing (needed as created_by for FollowUp)."""
    session = SessionLocal()
    try:
        user = User(
            organization_id=org_id,
            email=f"user-{uuid.uuid4().hex[:8]}@test.example.com",
            password_hash="not-a-real-hash",
            full_name="Test User",
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user
    finally:
        session.close()


def _make_lead(org_id: uuid.UUID, status: LeadStatus = LeadStatus.PENDING) -> Lead:
    """Create a lead for testing."""
    session = SessionLocal()
    try:
        lead = Lead(
            organization_id=org_id,
            name="Test Lead",
            email=f"test-{uuid.uuid4().hex[:8]}@example.com",
            appt_datetime_raw="Tomorrow at 2pm",
            dedupe_key=f"dedupe-{uuid.uuid4().hex[:8]}",
            status=status,
        )
        session.add(lead)
        session.commit()
        session.refresh(lead)
        return lead
    finally:
        session.close()


def _make_followup(
    lead_id: uuid.UUID,
    org_id: uuid.UUID,
    status: FollowUpStatus = FollowUpStatus.PENDING,
) -> FollowUp:
    """Create a follow-up for testing (includes required created_by user)."""
    user = _make_user(org_id)
    session = SessionLocal()
    try:
        fu = FollowUp(
            lead_id=lead_id,
            organization_id=org_id,
            created_by=user.id,
            title="Test Follow-up",
            status=status,
        )
        session.add(fu)
        session.commit()
        session.refresh(fu)
        return fu
    finally:
        session.close()


def _create_job(
    job_type: str,
    payload: dict | None = None,
    resolved: bool = False,
    retry_count: int = 0,
    org_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Create a FailedJob and return its ID."""
    session = SessionLocal()
    try:
        job = FailedJob(
            job_type=job_type,
            payload=json.dumps(payload) if payload is not None else None,
            error="test error",
            resolved=resolved,
            retry_count=retry_count,
            organization_id=org_id,
        )
        session.add(job)
        session.commit()
        session.refresh(job)
        return job.id
    finally:
        session.close()


def _create_raw_job(
    job_type: str,
    raw_payload: str,
    resolved: bool = False,
    retry_count: int = 0,
    org_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Create a FailedJob with a raw (possibly invalid) payload string."""
    session = SessionLocal()
    try:
        job = FailedJob(
            job_type=job_type,
            payload=raw_payload,
            error="test error",
            resolved=resolved,
            retry_count=retry_count,
            organization_id=org_id,
        )
        session.add(job)
        session.commit()
        session.refresh(job)
        return job.id
    finally:
        session.close()


def _get_job(job_id: uuid.UUID) -> FailedJob:
    """Retrieve a FailedJob by ID."""
    session = SessionLocal()
    try:
        return session.get(FailedJob, job_id)
    finally:
        session.close()


def _get_followup(fu_id: uuid.UUID) -> FollowUp:
    """Retrieve a FollowUp by ID."""
    session = SessionLocal()
    try:
        return session.get(FollowUp, fu_id)
    finally:
        session.close()


# ===========================================================================
# Pipeline job recovery (existing, should still work)
# ===========================================================================

class TestRecoveryPipeline:
    """Pipeline job recovery — existing behavior preserved."""

    def test_retries_pending_lead(self):
        from app.main import _recover_failed_jobs

        org = _make_org()
        lead = _make_lead(org.id, status=LeadStatus.PENDING)
        job_id = _create_job("pipeline", {"lead_id": str(lead.id)}, org_id=org.id)

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            mock_pipeline.assert_called_once_with(lead.id)

        assert _get_job(job_id).retry_count == 1

    def test_skips_non_pending_lead(self):
        from app.main import _recover_failed_jobs

        org = _make_org()
        lead = _make_lead(org.id, status=LeadStatus.SCHEDULED)
        job_id = _create_job("pipeline", {"lead_id": str(lead.id)}, org_id=org.id)

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            mock_pipeline.assert_not_called()

        assert _get_job(job_id).resolved is True


# ===========================================================================
# AI generate job recovery (NEW)
# ===========================================================================

class TestRecoveryAIGenerate:
    """AI generate job recovery — re-runs pipeline for lead."""

    def test_retries_ai_generate_for_pending_lead(self):
        from app.main import _recover_failed_jobs

        org = _make_org()
        lead = _make_lead(org.id, status=LeadStatus.PENDING)
        job_id = _create_job("ai_generate", {"lead_id": str(lead.id)}, org_id=org.id)

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            mock_pipeline.assert_called_once_with(lead.id)

        assert _get_job(job_id).retry_count == 1

    def test_ai_generate_best_effort_non_pending_lead(self):
        """AI generate retries even for non-pending leads (best-effort)."""
        from app.main import _recover_failed_jobs

        org = _make_org()
        lead = _make_lead(org.id, status=LeadStatus.SCHEDULED)
        job_id = _create_job("ai_generate", {"lead_id": str(lead.id)}, org_id=org.id)

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            # ai_generate is best-effort: pipeline is called even for non-pending
            mock_pipeline.assert_called_once_with(lead.id)

        assert _get_job(job_id).retry_count == 1


# ===========================================================================
# Calendar create job recovery (NEW)
# ===========================================================================

class TestRecoveryCalendarCreate:
    """Calendar create job recovery — re-runs pipeline for lead."""

    def test_retries_calendar_create_for_pending_lead(self):
        from app.main import _recover_failed_jobs

        org = _make_org()
        lead = _make_lead(org.id, status=LeadStatus.PENDING)
        job_id = _create_job("calendar_create", {"lead_id": str(lead.id)}, org_id=org.id)

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            mock_pipeline.assert_called_once_with(lead.id)

        assert _get_job(job_id).retry_count == 1

    def test_calendar_create_best_effort_non_pending(self):
        """Calendar create retries even for non-pending leads (best-effort)."""
        from app.main import _recover_failed_jobs

        org = _make_org()
        lead = _make_lead(org.id, status=LeadStatus.SCHEDULED)
        job_id = _create_job("calendar_create", {"lead_id": str(lead.id)}, org_id=org.id)

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            # calendar_create is best-effort: pipeline is called even for non-pending
            mock_pipeline.assert_called_once_with(lead.id)

        assert _get_job(job_id).retry_count == 1


# ===========================================================================
# Follow-up email send job recovery (NEW)
# ===========================================================================

class TestRecoveryFollowupEmail:
    """Follow-up email send job recovery — resets follow-up to PENDING."""

    def test_resets_pending_followup_to_pending(self):
        from app.main import _recover_failed_jobs

        org = _make_org()
        lead = _make_lead(org.id)
        fu = _make_followup(lead.id, org.id, status=FollowUpStatus.IN_PROGRESS)
        job_id = _create_job(
            "followup_email_send",
            {"follow_up_id": str(fu.id), "lead_id": str(lead.id)},
            org_id=org.id,
        )

        _recover_failed_jobs()

        assert _get_job(job_id).retry_count == 1
        # Follow-up should be reset to PENDING
        refreshed_fu = _get_followup(fu.id)
        assert refreshed_fu.status == FollowUpStatus.PENDING

    def test_followup_send_skips_completed_followup(self):
        from app.main import _recover_failed_jobs

        org = _make_org()
        lead = _make_lead(org.id)
        fu = _make_followup(lead.id, org.id, status=FollowUpStatus.COMPLETED)
        job_id = _create_job(
            "followup_email_send",
            {"follow_up_id": str(fu.id), "lead_id": str(lead.id)},
            org_id=org.id,
        )

        _recover_failed_jobs()

        # Should be marked resolved (not retryable)
        assert _get_job(job_id).resolved is True

    def test_followup_send_skips_cancelled_followup(self):
        from app.main import _recover_failed_jobs

        org = _make_org()
        lead = _make_lead(org.id)
        fu = _make_followup(lead.id, org.id, status=FollowUpStatus.CANCELLED)
        job_id = _create_job(
            "followup_email_send",
            {"follow_up_id": str(fu.id), "lead_id": str(lead.id)},
            org_id=org.id,
        )

        _recover_failed_jobs()

        assert _get_job(job_id).resolved is True

    def test_followup_send_marks_resolved_when_not_found(self):
        from app.main import _recover_failed_jobs

        org = _make_org()
        fake_fu_id = uuid.uuid4()
        job_id = _create_job(
            "followup_email_send",
            {"follow_up_id": str(fake_fu_id), "lead_id": str(uuid.uuid4())},
            org_id=org.id,
        )

        _recover_failed_jobs()

        assert _get_job(job_id).resolved is True

    def test_followup_send_marks_resolved_without_followup_id(self):
        from app.main import _recover_failed_jobs

        org = _make_org()
        job_id = _create_job(
            "followup_email_send",
            {"lead_id": str(uuid.uuid4())},  # missing follow_up_id
            org_id=org.id,
        )

        _recover_failed_jobs()

        assert _get_job(job_id).resolved is True


# ===========================================================================
# Unrecoverable job types (NEW)
# ===========================================================================

class TestRecoveryUnrecoverable:
    """Unrecoverable job types are immediately marked resolved."""

    @pytest.mark.parametrize("job_type", [
        "calendar_update_reschedule",
        "calendar_delete",
        "email_send",
        "daily_reminder",
        "rsvp_poll",
    ])
    def test_unrecoverable_types_marked_resolved(self, job_type):
        from app.main import _recover_failed_jobs

        org = _make_org()
        job_id = _create_job(job_type, {"some": "payload"}, org_id=org.id)

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            mock_pipeline.assert_not_called()

        assert _get_job(job_id).resolved is True


# ===========================================================================
# Max retries (shared)
# ===========================================================================

class TestRecoveryMaxRetries:
    """Jobs exceeding max retries are resolved."""

    @pytest.mark.parametrize("job_type,payload", [
        ("pipeline", {"lead_id": str(uuid.uuid4())}),
        ("ai_generate", {"lead_id": str(uuid.uuid4())}),
        ("calendar_create", {"lead_id": str(uuid.uuid4())}),
    ])
    def test_max_retries_resolves(self, job_type, payload):
        from app.main import _recover_failed_jobs

        org = _make_org()
        job_id = _create_job(job_type, payload, retry_count=3, org_id=org.id)

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            mock_pipeline.assert_not_called()

        assert _get_job(job_id).resolved is True


# ===========================================================================
# Bad payload handling
# ===========================================================================

class TestRecoveryBadPayload:
    """Jobs with bad payloads are resolved."""

    @pytest.mark.parametrize("job_type,payload", [
        ("pipeline", None),
        ("pipeline", {}),
        ("ai_generate", {}),
        ("followup_email_send", {}),
    ])
    def test_bad_payload_resolves(self, job_type, payload):
        from app.main import _recover_failed_jobs

        org = _make_org()
        job_id = _create_job(job_type, payload, org_id=org.id)

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            # pipeline/ai_generate without lead_id should not call run_pipeline
            if job_type in ("pipeline", "ai_generate"):
                mock_pipeline.assert_not_called()

        assert _get_job(job_id).resolved is True

    def test_not_json_payload_resolves(self):
        """A payload that is not valid JSON is marked resolved."""
        from app.main import _recover_failed_jobs

        org = _make_org()
        # Write raw invalid JSON directly (bypass json.dumps wrapping)
        job_id = _create_raw_job("pipeline", "not-json", org_id=org.id)

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            mock_pipeline.assert_not_called()

        assert _get_job(job_id).resolved is True


# ===========================================================================
# Unknown job type
# ===========================================================================

class TestRecoveryUnknownType:
    """Unknown job types are marked resolved."""

    def test_unknown_type_resolved(self):
        from app.main import _recover_failed_jobs

        org = _make_org()
        job_id = _create_job("some_future_job_type", {"data": 1}, org_id=org.id)

        _recover_failed_jobs()

        assert _get_job(job_id).resolved is True
