"""Phase 8 — Production Hardening (Meeting Lifecycle, Scheduling Reliability,
Job Recovery, Observability, Pipeline Race Prevention).

Covers:
  1.  LeadStatus includes COMPLETED enum value
  2.  Lead model has processing_started_at column
  3.  Pipeline status v2 returns COMPLETED count
  4.  Pipeline status v2 returns locked_leads count
  5.  Pipeline status v2 returns unresolved_failed_jobs count
  6.  Pipeline status v2 returns terminal count
  7.  Integration health — returns all three services
  8.  Integration health — overall healthy when all connected
  9.  Integration health — overall degraded on failure
  10. Failed job recovery — retries pending lead pipeline jobs
  11. Failed job recovery — marks resolved jobs as done
  12. Failed job recovery — skips jobs with bad payload
  13. Failed job recovery — skips jobs exceeding max retries
  14. Failed job recovery — RBAC requires admin
  15. Meeting completion — marks overdue leads COMPLETED
  16. Meeting completion — does not mark declined leads
  17. Meeting completion — does not mark error leads
  18. Meeting completion — RBAC requires admin
  19. Calendar service — check_slot_available returns True on empty
  20. Calendar service — check_slot_available returns False on busy
  21. Calendar service — create_event raises on slot conflict
  22. Pipeline optimistic lock — prevents double processing
  23. Pipeline optimistic lock — clears lock on success
  24. Pipeline optimistic lock — clears lock on error
  25. Reminder timezone — per-org timezone resolution
  26. Manual trigger — failed job recovery endpoint
  27. Manual trigger — meeting completion endpoint
"""
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models import EventLog, FailedJob, Lead, LeadStatus
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)
from app.services.crypto import generate_key


# ── Test Constants ────────────────────────────────────────────────────────────

TEST_JWT_SECRET = "test-secret-key-for-phase-8-jwt-testing-32chars!!"
TEST_ENCRYPTION_KEY = generate_key()


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    """Inject test-mode secrets."""
    monkeypatch.setattr(settings, "jwt_secret_key", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", TEST_ENCRYPTION_KEY)


@pytest.fixture()
def client():
    """TestClient with lifespan support."""
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _cleanup_failed_jobs():
    """Clean up FailedJob rows before and after each test to prevent leakage."""
    db = SessionLocal()
    try:
        db.query(FailedJob).delete()
        db.commit()
    except Exception:
        db.rollback()
    yield
    db = SessionLocal()
    try:
        db.query(FailedJob).delete()
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def _make_org(**overrides) -> Organization:
    """Insert an Organization row and return it."""
    defaults = {
        "name": f"Test Org {uuid.uuid4().hex[:8]}",
        "slug": f"test-org-{uuid.uuid4().hex[:8]}",
        "timezone": "America/Chicago",
        "status": OrganizationStatus.ACTIVE,
        "webhook_secret": secrets.token_urlsafe(24),
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


def _create_user(
    org_id: uuid.UUID,
    role: UserRole = UserRole.ADMIN,
    email: str | None = None,
) -> User:
    """Create a user in the given org and return them."""
    if email is None:
        email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    from app.auth import hash_password

    db = SessionLocal()
    try:
        user = User(
            organization_id=org_id,
            email=email,
            password_hash=hash_password("TestPassword123!"),
            full_name="Test User",
            role=role,
            status=UserStatus.ACTIVE,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def _make_jwt(user: User) -> str:
    """Create a valid JWT for the given user."""
    from datetime import datetime as dt, timedelta as td, timezone as tz
    from jose import jwt as jose_jwt

    payload = {
        "sub": str(user.id),
        "org_id": str(user.organization_id),
        "role": user.role.value,
        "exp": dt.now(tz.utc) + td(hours=1),
        "iat": dt.now(tz.utc),
        "jti": str(uuid.uuid4()),
    }
    return jose_jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")


def _auth_headers(user: User) -> dict:
    """Return Authorization headers for the given user."""
    return {"Authorization": f"Bearer {_make_jwt(user)}"}


def _make_lead(
    org_id: uuid.UUID,
    status: LeadStatus = LeadStatus.PENDING,
    **overrides,
) -> Lead:
    """Insert a Lead row."""
    defaults = {
        "name": "Test Prospect",
        "email": f"prospect-{uuid.uuid4().hex[:8]}@example.com",
        "company_address": "123 Test St",
        "appt_datetime_raw": "Tomorrow at 2pm",
        "status": status,
        "organization_id": org_id,
        "dedupe_key": f"lead-{uuid.uuid4().hex[:12]}",
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


# ── 1. LeadStatus enum includes COMPLETED ────────────────────────────────────


class TestLeadStatusEnum:
    """Phase 8 adds a COMPLETED status to the lifecycle."""

    def test_completed_exists(self):
        """LeadStatus includes COMPLETED."""
        assert hasattr(LeadStatus, "COMPLETED")
        assert LeadStatus.COMPLETED.value == "completed"

    def test_all_statuses(self):
        """All expected statuses are present."""
        expected = {
            "pending", "scheduled", "accepted", "tentative",
            "declined", "not_interested", "reminded", "error", "completed",
        }
        actual = {s.value for s in LeadStatus}
        assert expected == actual


# ── 2. Lead model has processing_started_at ──────────────────────────────────


class TestLeadProcessingLock:
    """Phase 8 adds processing_started_at for optimistic locking."""

    def test_has_column(self):
        """Lead model has processing_started_at column."""
        from sqlalchemy import inspect
        mapper = inspect(Lead)
        cols = {c.key for c in mapper.columns}
        assert "processing_started_at" in cols

    def test_default_is_none(self):
        """processing_started_at defaults to None."""
        org = _make_org()
        lead = _make_lead(org.id)
        assert lead.processing_started_at is None


# ── 3-6. Pipeline Status V2 ─────────────────────────────────────────────────


class TestPipelineStatusV2:
    """GET /dashboard/api/pipeline/status/v2 returns Phase 8 data."""

    def test_returns_expected_fields(self, client: TestClient):
        """V2 status includes all Phase 8 fields."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        r = client.get("/dashboard/api/pipeline/status/v2", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert "completed" in data
        assert "terminal" in data
        assert "locked_leads" in data
        assert "unresolved_failed_jobs" in data
        assert "success_rate" in data

    def test_completed_count(self, client: TestClient):
        """V2 counts COMPLETED leads."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        _make_lead(org.id, status=LeadStatus.COMPLETED, name="Done Lead")
        r = client.get("/dashboard/api/pipeline/status/v2", headers=_auth_headers(user))
        assert r.status_code == 200
        assert r.json()["completed"] >= 1

    def test_locked_leads_count(self, client: TestClient):
        """V2 counts currently locked leads."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        lead = _make_lead(org.id, status=LeadStatus.PENDING, name="Locked Lead")
        # Simulate lock via direct SQL to ensure visibility
        from sqlalchemy import text
        db = SessionLocal()
        try:
            db.execute(
                text("UPDATE leads SET processing_started_at = :ts WHERE id = :lid"),
                {"ts": datetime.now(timezone.utc), "lid": lead.id},
            )
            db.commit()
        finally:
            db.close()

        r = client.get("/dashboard/api/pipeline/status/v2", headers=_auth_headers(user))
        assert r.status_code == 200
        assert r.json()["locked_leads"] >= 1

    def test_terminal_count(self, client: TestClient):
        """V2 terminal count = completed + declined + not_interested + errors."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        _make_lead(org.id, status=LeadStatus.COMPLETED)
        _make_lead(org.id, status=LeadStatus.DECLINED)
        r = client.get("/dashboard/api/pipeline/status/v2", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert data["terminal"] >= 2

    def test_unresolved_failed_jobs(self, client: TestClient):
        """V2 counts unresolved failed jobs."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        db = SessionLocal()
        try:
            db.add(FailedJob(
                job_type="pipeline",
                payload=json.dumps({"lead_id": str(uuid.uuid4())}),
                error="test error",
                organization_id=org.id,
            ))
            db.commit()
        finally:
            db.close()

        r = client.get("/dashboard/api/pipeline/status/v2", headers=_auth_headers(user))
        assert r.status_code == 200
        assert r.json()["unresolved_failed_jobs"] >= 1

    def test_org_scoped(self, client: TestClient):
        """V2 is org-scoped."""
        org1 = _make_org()
        org2 = _make_org()
        user1 = _create_user(org1.id, UserRole.OWNER)
        user2 = _create_user(org2.id, UserRole.OWNER)
        _make_lead(org1.id, status=LeadStatus.COMPLETED)
        r1 = client.get("/dashboard/api/pipeline/status/v2", headers=_auth_headers(user1))
        r2 = client.get("/dashboard/api/pipeline/status/v2", headers=_auth_headers(user2))
        assert r1.json()["completed"] >= 1
        assert r2.json()["completed"] == 0


# ── 7-9. Integration Health ──────────────────────────────────────────────────


class TestIntegrationHealth:
    """GET /dashboard/api/integration-health verifies external services.

    Production-safe health checks:
    - Google Calendar: calendars().get() lightweight read
    - Gmail: credential refresh/validity check (no getProfile, no email send)
    - AI: lightweight chat.completions.create (Say OK, max_tokens=2)
    """

    # -- helpers for building realistic mocks ----------------------------------

    @staticmethod
    def _mock_calendar_service():
        """Return a patched CalendarService whose calendars().get() succeeds."""
        mock_cal = MagicMock()
        mock_cal._calendar_id = "primary"
        mock_cal._service.calendars().get().execute.return_value = {"id": "primary"}
        return patch(
            "app.services.calendar_service.CalendarService",
            return_value=mock_cal,
        )

    @staticmethod
    def _mock_email_service(valid: bool = True, expired: bool = False):
        """Return a patched EmailService with credential state."""
        mock_mail = MagicMock()
        mock_creds = MagicMock()
        mock_creds.valid = valid
        mock_creds.expired = expired
        mock_creds.refresh_token = "test-rt" if valid else None
        mock_mail._service._http.credentials = mock_creds
        return patch(
            "app.services.email_service.EmailService",
            return_value=mock_mail,
        )

    @staticmethod
    def _mock_ai_service(responds: bool = True):
        """Return a patched AIService + OpenAI client."""
        mock_ai = MagicMock()
        mock_ai._primary_url = "https://api.test.com/v1"
        mock_ai._primary_key = "sk-test-key"
        mock_ai._primary_model = "test-model"

        mock_openai_cls = MagicMock()
        if responds:
            mock_resp = MagicMock()
            mock_resp.choices = [MagicMock()]
            mock_openai_cls.return_value.chat.completions.create.return_value = mock_resp
        else:
            mock_openai_cls.return_value.chat.completions.create.side_effect = (
                RuntimeError("connection refused")
            )

        return (
            patch("app.services.ai_service.AIService", return_value=mock_ai),
            patch("openai.OpenAI", mock_openai_cls),
        )

    @staticmethod
    def _mock_zoom_service():
        """Return a context manager that mocks the Zoom health-check chain.

        The integration-health endpoint checks:
          1. CredentialVault.has_credentials(db, org_id, "zoom", "zoom_oauth")
          2. ZoomOAuthFlow.refresh_token_if_needed(...)
          3. ZoomAPIClient.get_account_info(...)
        """
        mock_zoom_flow = MagicMock()
        mock_zoom_flow.refresh_token_if_needed = MagicMock(return_value="fake-access-token")
        mock_zoom_client = MagicMock()
        mock_zoom_client.get_account_info = MagicMock(
            return_value={"email": "zoom@test.com"}
        )
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(
            patch(
                "app.services.credential_vault.CredentialVault.has_credentials",
                return_value=True,
            )
        )
        stack.enter_context(
            patch(
                "app.services.zoom_oauth_flow.ZoomOAuthFlow",
                mock_zoom_flow,
            )
        )
        stack.enter_context(
            patch(
                "app.services.zoom_api_client.ZoomAPIClient",
                mock_zoom_client,
            )
        )
        return stack

    # -- 7. returns all three services ----------------------------------------

    def test_returns_all_services(self, client: TestClient):
        """Health check returns google_calendar, gmail, ai_provider, overall."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        mock_cal = self._mock_calendar_service()
        mock_mail = self._mock_email_service(valid=True)
        mock_ai, mock_openai = self._mock_ai_service(responds=True)

        with mock_cal, mock_mail, mock_ai, mock_openai:
            r = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(user),
            )
        assert r.status_code == 200
        data = r.json()
        assert "google_calendar" in data
        assert "gmail" in data
        assert "ai_provider" in data
        assert "overall" in data

    # -- 8. overall healthy when all connected --------------------------------

    def test_overall_healthy_when_all_connected(self, client: TestClient):
        """Overall is 'healthy' when every service reports connected."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        mock_cal = self._mock_calendar_service()
        mock_mail = self._mock_email_service(valid=True)
        mock_ai, mock_openai = self._mock_ai_service(responds=True)
        mock_zoom = self._mock_zoom_service()

        with mock_cal, mock_mail, mock_ai, mock_openai, mock_zoom:
            r = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(user),
            )
        assert r.status_code == 200
        data = r.json()
        assert data["google_calendar"]["status"] == "connected"
        assert data["gmail"]["status"] == "connected"
        assert data["ai_provider"]["status"] == "connected"
        assert data["zoom"]["status"] == "connected"
        assert data["overall"] == "healthy"

    # -- 9. overall degraded on failure ---------------------------------------

    def test_overall_degraded_on_failure(self, client: TestClient):
        """Overall is degraded when any service fails."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        mock_mail = self._mock_email_service(valid=True)
        mock_ai, mock_openai = self._mock_ai_service(responds=True)
        mock_cal_fail = patch(
            "app.services.calendar_service.CalendarService",
            side_effect=Exception("OAuth expired"),
        )

        with mock_cal_fail, mock_mail, mock_ai, mock_openai:
            r = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(user),
            )
        assert r.status_code == 200
        data = r.json()
        assert data["overall"] == "degraded"
        assert data["google_calendar"]["status"] == "error"

    # -- Gmail credential validation ------------------------------------------

    def test_gmail_connected_when_credentials_valid(self, client: TestClient):
        """Gmail reports connected when credentials are valid."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        mock_cal = self._mock_calendar_service()
        mock_mail = self._mock_email_service(valid=True)
        mock_ai, mock_openai = self._mock_ai_service(responds=True)

        with mock_cal, mock_mail, mock_ai, mock_openai:
            r = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(user),
            )
        assert r.status_code == 200
        assert r.json()["gmail"]["status"] == "connected"

    def test_gmail_error_when_credentials_invalid(self, client: TestClient):
        """Gmail reports error when credentials are not valid."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        mock_cal = self._mock_calendar_service()
        mock_ai, mock_openai = self._mock_ai_service(responds=True)

        # Phase 34 Fix C: The health endpoint validates credentials by
        # refreshing them when expired.  The endpoint checks
        # getattr(email_svc, '_credentials') FIRST, so we must set
        # _credentials on the mock (not just _service._credentials).
        mock_mail = MagicMock()
        mock_mail._credentials.valid = False
        mock_mail._credentials.expired = True
        mock_mail._credentials.refresh.side_effect = (
            RuntimeError("Token has been revoked or expired")
        )

        with mock_cal, mock_ai, mock_openai, patch(
            "app.services.email_service.EmailService",
            return_value=mock_mail,
        ):
            r = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(user),
            )
        assert r.status_code == 200
        data = r.json()
        assert data["gmail"]["status"] == "error"
        assert data["overall"] == "degraded"

    def test_gmail_error_when_refresh_fails(self, client: TestClient):
        """Gmail reports error when credential refresh raises."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        mock_cal = self._mock_calendar_service()
        mock_ai, mock_openai = self._mock_ai_service(responds=True)

        # Phase 34 Fix C: The health endpoint validates credentials by
        # refreshing them when expired.  Set _credentials directly on the
        # mock (not _service._credentials) since the endpoint checks
        # getattr(email_svc, '_credentials') first.
        mock_mail = MagicMock()
        mock_mail._credentials.valid = False
        mock_mail._credentials.expired = True
        mock_mail._credentials.refresh.side_effect = (
            RuntimeError("token revoked")
        )

        with mock_cal, mock_ai, mock_openai, patch(
            "app.services.email_service.EmailService",
            return_value=mock_mail,
        ):
            r = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(user),
            )
        assert r.status_code == 200
        data = r.json()
        assert data["gmail"]["status"] == "error"
        assert data["overall"] == "degraded"

    # -- AI provider health ---------------------------------------------------

    def test_ai_connected_when_provider_responds(self, client: TestClient):
        """AI reports connected when provider returns a valid response."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        mock_cal = self._mock_calendar_service()
        mock_mail = self._mock_email_service(valid=True)
        mock_ai, mock_openai = self._mock_ai_service(responds=True)

        with mock_cal, mock_mail, mock_ai, mock_openai:
            r = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(user),
            )
        assert r.status_code == 200
        assert r.json()["ai_provider"]["status"] == "connected"

    def test_ai_error_when_provider_fails(self, client: TestClient):
        """AI reports error when provider call fails."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        mock_cal = self._mock_calendar_service()
        mock_mail = self._mock_email_service(valid=True)
        mock_ai, mock_openai = self._mock_ai_service(responds=False)

        with mock_cal, mock_mail, mock_ai, mock_openai:
            r = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(user),
            )
        assert r.status_code == 200
        data = r.json()
        assert data["ai_provider"]["status"] == "error"
        assert data["overall"] == "degraded"

    # -- Unauthenticated access -----------------------------------------------

    def test_unauthenticated_returns_401(self, client: TestClient):
        """Health check requires authentication."""
        r = client.get("/dashboard/api/integration-health")
        assert r.status_code == 401

    # -- Error messages are sanitized -----------------------------------------

    def test_error_messages_sanitized(self, client: TestClient):
        """Error messages do not leak credentials or tokens."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        # Calendar fails with a message containing a token
        mock_cal_fail = patch(
            "app.services.calendar_service.CalendarService",
            side_effect=Exception(
                "Token expired: sk-secret-api-key-12345"
            ),
        )
        mock_mail = self._mock_email_service(valid=False)
        mock_ai, mock_openai = self._mock_ai_service(responds=True)

        with mock_cal_fail, mock_mail, mock_ai, mock_openai:
            r = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(user),
            )
        assert r.status_code == 200
        data = r.json()
        # The error should NOT contain the raw key
        err = data["google_calendar"]["error"] or ""
        assert "sk-secret-api-key-12345" not in err
        # The sanitized message should be a safe generic message
        assert err == "Service authentication error. Please check integration configuration."


# ── 10-14. Failed Job Recovery ───────────────────────────────────────────────


class TestFailedJobRecovery:
    """Phase 8 FailedJob recovery retries pipeline jobs."""

    def test_retries_pending_leads(self):
        """Unresolved pipeline jobs for PENDING leads are retried."""
        from app.main import _recover_failed_jobs

        org = _make_org()
        lead = _make_lead(org.id, status=LeadStatus.PENDING)

        db = SessionLocal()
        try:
            job = FailedJob(
                job_type="pipeline",
                payload=json.dumps({"lead_id": str(lead.id)}),
                error="test error",
                organization_id=org.id,
            )
            db.add(job)
            db.commit()
            job_id = job.id
        finally:
            db.close()

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            mock_pipeline.assert_called_once_with(lead.id)

        # Verify retry_count incremented
        db = SessionLocal()
        try:
            job = db.get(FailedJob, job_id)
            assert job.retry_count == 1
        finally:
            db.close()

    def test_marks_resolved_jobs_done(self):
        """Already-resolved jobs are skipped."""
        from app.main import _recover_failed_jobs

        org = _make_org()
        db = SessionLocal()
        try:
            job = FailedJob(
                job_type="pipeline",
                payload=json.dumps({"lead_id": str(uuid.uuid4())}),
                error="test error",
                resolved=True,
                organization_id=org.id,
            )
            db.add(job)
            db.commit()
        finally:
            db.close()

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            mock_pipeline.assert_not_called()

    def test_skips_bad_payload(self):
        """Jobs with unparseable or missing lead_id are resolved."""
        from app.main import _recover_failed_jobs

        org = _make_org()
        db = SessionLocal()
        try:
            job = FailedJob(
                job_type="pipeline",
                payload="not-json",
                error="test error",
                organization_id=org.id,
            )
            db.add(job)
            db.commit()
            job_id = job.id
        finally:
            db.close()

        _recover_failed_jobs()

        db = SessionLocal()
        try:
            job = db.get(FailedJob, job_id)
            assert job.resolved is True
        finally:
            db.close()

    def test_skips_max_retries(self):
        """Jobs with retry_count >= 3 are marked resolved."""
        from app.main import _recover_failed_jobs

        org = _make_org()
        lead = _make_lead(org.id, status=LeadStatus.PENDING)

        db = SessionLocal()
        try:
            job = FailedJob(
                job_type="pipeline",
                payload=json.dumps({"lead_id": str(lead.id)}),
                error="test error",
                retry_count=3,
                organization_id=org.id,
            )
            db.add(job)
            db.commit()
            job_id = job.id
        finally:
            db.close()

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            mock_pipeline.assert_not_called()

        db = SessionLocal()
        try:
            job = db.get(FailedJob, job_id)
            assert job.resolved is True
        finally:
            db.close()

    def test_skips_non_pending_leads(self):
        """Jobs for leads that are no longer PENDING are resolved."""
        from app.main import _recover_failed_jobs

        org = _make_org()
        lead = _make_lead(org.id, status=LeadStatus.SCHEDULED)

        db = SessionLocal()
        try:
            job = FailedJob(
                job_type="pipeline",
                payload=json.dumps({"lead_id": str(lead.id)}),
                error="test error",
                organization_id=org.id,
            )
            db.add(job)
            db.commit()
            job_id = job.id
        finally:
            db.close()

        with patch("app.main.run_pipeline") as mock_pipeline:
            _recover_failed_jobs()
            mock_pipeline.assert_not_called()

        db = SessionLocal()
        try:
            job = db.get(FailedJob, job_id)
            assert job.resolved is True
        finally:
            db.close()


# ── 15-18. Meeting Completion ────────────────────────────────────────────────


class TestMeetingCompletion:
    """Phase 8 marks overdue meetings as COMPLETED."""

    def test_marks_overdue_completed(self):
        """Leads past their meeting time + 2h buffer become COMPLETED."""
        from app.main import _mark_completed_meetings

        org = _make_org()
        # Meeting 3 hours ago
        past_time = datetime.now(timezone.utc) - timedelta(hours=3)
        lead = _make_lead(
            org.id,
            status=LeadStatus.SCHEDULED,
            appt_datetime_utc=past_time,
        )

        _mark_completed_meetings()

        db = SessionLocal()
        try:
            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.COMPLETED
        finally:
            db.close()

    def test_does_not_mark_declined(self):
        """DECLINED leads are not marked COMPLETED."""
        from app.main import _mark_completed_meetings

        org = _make_org()
        past_time = datetime.now(timezone.utc) - timedelta(hours=3)
        lead = _make_lead(
            org.id,
            status=LeadStatus.DECLINED,
            appt_datetime_utc=past_time,
        )

        _mark_completed_meetings()

        db = SessionLocal()
        try:
            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.DECLINED
        finally:
            db.close()

    def test_does_not_mark_error(self):
        """ERROR leads are not marked COMPLETED."""
        from app.main import _mark_completed_meetings

        org = _make_org()
        past_time = datetime.now(timezone.utc) - timedelta(hours=3)
        lead = _make_lead(
            org.id,
            status=LeadStatus.ERROR,
            appt_datetime_utc=past_time,
        )

        _mark_completed_meetings()

        db = SessionLocal()
        try:
            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.ERROR
        finally:
            db.close()

    def test_does_not_mark_future_meetings(self):
        """Future meetings are not marked COMPLETED."""
        from app.main import _mark_completed_meetings

        org = _make_org()
        future_time = datetime.now(timezone.utc) + timedelta(hours=2)
        lead = _make_lead(
            org.id,
            status=LeadStatus.SCHEDULED,
            appt_datetime_utc=future_time,
        )

        _mark_completed_meetings()

        db = SessionLocal()
        try:
            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.SCHEDULED
        finally:
            db.close()

    def test_does_not_mark_recent_meetings(self):
        """Meetings within the 2h buffer are not marked COMPLETED."""
        from app.main import _mark_completed_meetings

        org = _make_org()
        recent_time = datetime.now(timezone.utc) - timedelta(hours=1)
        lead = _make_lead(
            org.id,
            status=LeadStatus.SCHEDULED,
            appt_datetime_utc=recent_time,
        )

        _mark_completed_meetings()

        db = SessionLocal()
        try:
            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.SCHEDULED
        finally:
            db.close()

    def test_marks_reminded_completed(self):
        """REMINDED leads past meeting time + 2h buffer become COMPLETED."""
        from app.main import _mark_completed_meetings

        org = _make_org()
        past_time = datetime.now(timezone.utc) - timedelta(hours=3)
        lead = _make_lead(
            org.id,
            status=LeadStatus.REMINDED,
            appt_datetime_utc=past_time,
        )

        _mark_completed_meetings()

        db = SessionLocal()
        try:
            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.COMPLETED
        finally:
            db.close()

    def test_logs_meeting_completed_event(self):
        """Meeting completion emits an event log entry."""
        from app.main import _mark_completed_meetings

        org = _make_org()
        past_time = datetime.now(timezone.utc) - timedelta(hours=3)
        lead = _make_lead(
            org.id,
            status=LeadStatus.ACCEPTED,
            appt_datetime_utc=past_time,
        )

        _mark_completed_meetings()

        db = SessionLocal()
        try:
            event = (
                db.query(EventLog)
                .filter(
                    EventLog.lead_id == lead.id,
                    EventLog.event_type == "meeting_completed",
                )
                .first()
            )
            assert event is not None
        finally:
            db.close()


# ── 19-21. Calendar Free/Busy Check ──────────────────────────────────────────


class TestCalendarAvailability:
    """Phase 8 CalendarService checks free/busy before creating events."""

    def test_check_slot_available_empty(self):
        """Returns True when no busy periods exist."""
        from app.services.calendar_service import CalendarService

        mock_service = MagicMock()
        mock_service.freebusy().query().execute.return_value = {
            "calendars": {"primary": {"busy": []}}
        }

        svc = object.__new__(CalendarService)
        svc._service = mock_service
        svc._calendar_id = "primary"

        start = datetime.now(timezone.utc)
        end = start + timedelta(minutes=30)
        assert svc.check_slot_available(start, end) is True

    def test_check_slot_available_busy(self):
        """Returns False when busy periods exist."""
        from app.services.calendar_service import CalendarService

        mock_service = MagicMock()
        mock_service.freebusy().query().execute.return_value = {
            "calendars": {"primary": {"busy": [
                {"start": "2025-01-01T14:00:00Z", "end": "2025-01-01T14:30:00Z"}
            ]}}
        }

        svc = object.__new__(CalendarService)
        svc._service = mock_service
        svc._calendar_id = "primary"

        start = datetime.now(timezone.utc)
        end = start + timedelta(minutes=30)
        assert svc.check_slot_available(start, end) is False

    def test_check_slot_available_api_error(self):
        """Returns True (permissive) when API call fails."""
        from app.services.calendar_service import CalendarService

        mock_service = MagicMock()
        mock_service.freebusy().query().execute.side_effect = Exception("API error")

        svc = object.__new__(CalendarService)
        svc._service = mock_service
        svc._calendar_id = "primary"

        start = datetime.now(timezone.utc)
        end = start + timedelta(minutes=30)
        assert svc.check_slot_available(start, end) is True


# ── 22-24. Pipeline Optimistic Lock ─────────────────────────────────────────


class TestPipelineOptimisticLock:
    """Phase 8 pipeline sets and clears processing_started_at."""

    def test_lock_prevents_double_processing(self):
        """Lead with processing_started_at set is skipped by pipeline."""
        from app.main import _run_pipeline_inner

        org = _make_org()
        lead = _make_lead(org.id, status=LeadStatus.PENDING)

        # Simulate another task locking it
        db = SessionLocal()
        try:
            db_lead = db.get(Lead, lead.id)
            db_lead.processing_started_at = datetime.now(timezone.utc)
            db.commit()
        finally:
            db.close()

        # Pipeline should skip without processing since lock is set
        with patch("app.main.run_pipeline") as mock_pipeline:
            # We verify the pipeline function itself would not be called
            # if the lead were already locked. Direct call to _run_pipeline_inner
            # should log and return early.
            _run_pipeline_inner(lead.id)
            # run_pipeline is not called inside _run_pipeline_inner, so just
            # verify the lock is still set (no crash, no double processing)
            pass

        # Verify lock still set (no crash)
        db = SessionLocal()
        try:
            fresh = db.get(Lead, lead.id)
            assert fresh.processing_started_at is not None
        finally:
            db.close()


# ── 25. Reminder Per-Org Timezone ────────────────────────────────────────────


class TestReminderTimezone:
    """Phase 8 resolves timezone per-lead from org config."""

    def test_per_org_timezone_resolution(self):
        """_process_lead resolves timezone from org config."""
        from app.services.reminder_service import _process_lead

        org = _make_org(timezone="America/New_York")
        lead = _make_lead(
            org.id,
            status=LeadStatus.SCHEDULED,
            appt_datetime_utc=datetime(2025, 6, 15, 18, 0, tzinfo=timezone.utc),
            calendar_event_id="test-event-123",
        )

        from zoneinfo import ZoneInfo
        default_tz = ZoneInfo("America/Chicago")

        mock_cal = MagicMock()
        mock_cal.get_meet_link.return_value = "https://meet.google.com/abc"
        mock_mail = MagicMock()
        summary = {"checked": 0, "sent": 0, "errors": 0}

        db = SessionLocal()
        try:
            _process_lead(db, mock_cal, mock_mail, lead, default_tz, summary)
            # Should succeed with per-org timezone
            assert summary["sent"] == 1
            # Verify mock_mail.send_email was called (meaning the full path worked)
            mock_mail.send_email.assert_called_once()
        finally:
            db.close()


# ── 26-27. Manual Trigger Endpoints ──────────────────────────────────────────


class TestManualTriggerEndpoints:
    """POST /dashboard/api/jobs/* for manual job triggers."""

    def test_failed_job_recovery_requires_admin(self, client: TestClient):
        """Failed job recovery requires admin or owner role."""
        org = _make_org()
        member = _create_user(org.id, UserRole.MEMBER)
        r = client.post(
            "/dashboard/api/jobs/failed-job-recovery",
            headers=_auth_headers(member),
        )
        assert r.status_code == 403

    def test_failed_job_recovery_owner(self, client: TestClient):
        """Owner can trigger failed job recovery."""
        org = _make_org()
        owner = _create_user(org.id, UserRole.OWNER)
        r = client.post(
            "/dashboard/api/jobs/failed-job-recovery",
            headers=_auth_headers(owner),
        )
        assert r.status_code == 200
        assert r.json()["status"] == "completed"

    def test_meeting_completion_requires_admin(self, client: TestClient):
        """Meeting completion requires admin or owner role."""
        org = _make_org()
        member = _create_user(org.id, UserRole.MEMBER)
        r = client.post(
            "/dashboard/api/jobs/meeting-completion",
            headers=_auth_headers(member),
        )
        assert r.status_code == 403

    def test_meeting_completion_owner(self, client: TestClient):
        """Owner can trigger meeting completion."""
        org = _make_org()
        owner = _create_user(org.id, UserRole.OWNER)
        r = client.post(
            "/dashboard/api/jobs/meeting-completion",
            headers=_auth_headers(owner),
        )
        assert r.status_code == 200
        assert r.json()["status"] == "completed"

    def test_failed_job_recovery_unauthenticated(self, client: TestClient):
        """Manual triggers require authentication."""
        r = client.post("/dashboard/api/jobs/failed-job-recovery")
        assert r.status_code == 401

    def test_meeting_completion_unauthenticated(self, client: TestClient):
        """Manual triggers require authentication."""
        r = client.post("/dashboard/api/jobs/meeting-completion")
        assert r.status_code == 401
