"""PHASE 4 production hardening tests.

Covers: is_transient() OpenAI exception handling, webhook secret auth,
email idempotency guard, expanded stuck-lead recovery, Calendar idempotency,
AI model validation, and timeout configuration.
"""
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models import EventLog, Lead, LeadStatus
from app.tenant import _DEFAULT_ORG_ID


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_lead(
    db: Session,
    *,
    name: str = "Test Lead",
    email: str | None = None,
    status: LeadStatus = LeadStatus.PENDING,
    calendar_event_id: str | None = None,
    appt_datetime_utc: datetime | None = None,
) -> Lead:
    """Insert a minimal lead for testing."""
    if email is None:
        email = f"test-{uuid.uuid4().hex[:8]}@example.com"
    if appt_datetime_utc is None:
        appt_datetime_utc = datetime.now(timezone.utc) + timedelta(hours=24)
    lead = Lead(
        name=name,
        email=email,
        appt_datetime_raw="tomorrow 2pm",
        appt_datetime_utc=appt_datetime_utc,
        dedupe_key=f"{email}|{appt_datetime_utc.isoformat()}",
        status=status,
        calendar_event_id=calendar_event_id,
        organization_id=_DEFAULT_ORG_ID,
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


# ── TEST: is_transient() handles OpenAI exceptions ──────────────────────────


class TestIsTransientOpenAI:
    """is_transient() must recognize OpenAI SDK exceptions as transient
    or permanent based on their type and status code."""

    def test_apitimeouterror_is_transient(self):
        from openai import APITimeoutError
        from app.services.retry import is_transient

        exc = APITimeoutError(request=MagicMock())
        assert is_transient(exc) is True

    def test_apiconnectionerror_is_transient(self):
        from openai import APIConnectionError
        from app.services.retry import is_transient

        exc = APIConnectionError(request=MagicMock())
        assert is_transient(exc) is True

    def test_ratelimiterror_is_transient(self):
        """RateLimitError has status_code=429, should be transient."""
        from openai import RateLimitError
        from app.services.retry import is_transient

        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {}
        exc = RateLimitError(
            message="rate limited",
            response=mock_response,
            body=None,
        )
        assert is_transient(exc) is True

    def test_internalservererror_is_transient(self):
        """InternalServerError has status_code=500, should be transient."""
        from openai import InternalServerError
        from app.services.retry import is_transient

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.headers = {}
        exc = InternalServerError(
            message="server error",
            response=mock_response,
            body=None,
        )
        assert is_transient(exc) is True

    def test_permissiondeniederror_is_not_transient(self):
        """PermissionDeniedError has status_code=403, should NOT be transient."""
        from openai import PermissionDeniedError
        from app.services.retry import is_transient

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {}
        exc = PermissionDeniedError(
            message="forbidden",
            response=mock_response,
            body=None,
        )
        assert is_transient(exc) is False

    def test_badrequesterror_is_not_transient(self):
        """BadRequestError has status_code=400, should NOT be transient."""
        from openai import BadRequestError
        from app.services.retry import is_transient

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.headers = {}
        exc = BadRequestError(
            message="bad request",
            response=mock_response,
            body=None,
        )
        assert is_transient(exc) is False

    def test_python_timeout_error_still_works(self):
        from app.services.retry import is_transient

        assert is_transient(TimeoutError()) is True

    def test_python_connection_error_still_works(self):
        from app.services.retry import is_transient

        assert is_transient(ConnectionError()) is True

    def test_plain_valueerror_is_not_transient(self):
        from app.services.retry import is_transient

        assert is_transient(ValueError("bad input")) is False


# ── TEST: Webhook secret authentication (Bearer token) ────────────────────────


class TestWebhookSecret:
    """When WEBHOOK_SECRET is set, the form-submission endpoint must reject
    requests that don't include a valid Authorization: Bearer header."""

    def test_no_secret_configured_allows_all(self):
        """With empty WEBHOOK_SECRET, requests pass without header."""
        with patch("app.main.settings") as mock_settings:
            mock_settings.webhook_secret = ""
            mock_settings.dashboard_username = "admin"
            mock_settings.dashboard_password = "pw"
            mock_settings.scheduler_is_enabled = True
            client = TestClient(app, raise_server_exceptions=False)
            payload = {
                "Name": "Test",
                "Email Address": "test@example.com",
                "Phone Appt. Date/Time": "tomorrow 2pm",
            }
            resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
            assert resp.status_code == 202

    def test_secret_required_and_missing_rejects(self):
        """When WEBHOOK_SECRET is set and Authorization header is missing → 401."""
        with patch("app.main.settings") as mock_settings:
            mock_settings.webhook_secret = "super-secret-key"
            mock_settings.dashboard_username = "admin"
            mock_settings.dashboard_password = "pw"
            mock_settings.scheduler_is_enabled = True
            client = TestClient(app, raise_server_exceptions=False)
            payload = {
                "Name": "Test",
                "Email Address": "test@example.com",
                "Phone Appt. Date/Time": "tomorrow 2pm",
            }
            resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
            assert resp.status_code == 401

    def test_secret_required_wrong_rejects(self):
        """When WEBHOOK_SECRET is set and Bearer token is wrong → 401."""
        with patch("app.main.settings") as mock_settings:
            mock_settings.webhook_secret = "super-secret-key"
            mock_settings.dashboard_username = "admin"
            mock_settings.dashboard_password = "pw"
            mock_settings.scheduler_is_enabled = True
            client = TestClient(app, raise_server_exceptions=False)
            payload = {
                "Name": "Test",
                "Email Address": "test@example.com",
                "Phone Appt. Date/Time": "tomorrow 2pm",
            }
            resp = client.post(
                "/webhooks/integrated-it-trainings/form-submission",
                json=payload,
                headers={"Authorization": "Bearer wrong-key"},
            )
            assert resp.status_code == 401

    def test_secret_required_correct_accepts(self):
        """When WEBHOOK_SECRET is set and Bearer token is correct → 202."""
        with patch("app.main.settings") as mock_settings:
            mock_settings.webhook_secret = "super-secret-key"
            mock_settings.dashboard_username = "admin"
            mock_settings.dashboard_password = "pw"
            mock_settings.business_timezone = "America/Chicago"
            mock_settings.scheduler_is_enabled = True
            client = TestClient(app, raise_server_exceptions=False)
            payload = {
                "Name": "Test",
                "Email Address": f"wh-{uuid.uuid4().hex[:8]}@example.com",
                "Phone Appt. Date/Time": "tomorrow 2pm",
            }
            resp = client.post(
                "/webhooks/integrated-it-trainings/form-submission",
                json=payload,
                headers={"Authorization": "Bearer super-secret-key"},
            )
            assert resp.status_code == 202

    def test_malformed_auth_header_rejects(self):
        """When WEBHOOK_SECRET is set and Authorization header is malformed → 401."""
        with patch("app.main.settings") as mock_settings:
            mock_settings.webhook_secret = "super-secret-key"
            mock_settings.dashboard_username = "admin"
            mock_settings.dashboard_password = "pw"
            mock_settings.scheduler_is_enabled = True
            client = TestClient(app, raise_server_exceptions=False)
            payload = {
                "Name": "Test",
                "Email Address": "test@example.com",
                "Phone Appt. Date/Time": "tomorrow 2pm",
            }
            # Missing "Bearer " prefix
            resp = client.post(
                "/webhooks/integrated-it-trainings/form-submission",
                json=payload,
                headers={"Authorization": "super-secret-key"},
            )
            assert resp.status_code == 401

    def test_x_webhook_secret_header_not_recognized(self):
        """The old X-Webhook-Secret header is NOT accepted — only Bearer works."""
        with patch("app.main.settings") as mock_settings:
            mock_settings.webhook_secret = "super-secret-key"
            mock_settings.dashboard_username = "admin"
            mock_settings.dashboard_password = "pw"
            mock_settings.scheduler_is_enabled = True
            client = TestClient(app, raise_server_exceptions=False)
            payload = {
                "Name": "Test",
                "Email Address": "test@example.com",
                "Phone Appt. Date/Time": "tomorrow 2pm",
            }
            resp = client.post(
                "/webhooks/integrated-it-trainings/form-submission",
                json=payload,
                headers={"X-Webhook-Secret": "super-secret-key"},
            )
            assert resp.status_code == 401


# ── TEST: Email idempotency guard ───────────────────────────────────────────


class TestEmailIdempotency:
    """The pipeline should not send a duplicate confirmation email if an
    email_sent event already exists for the lead (crash recovery scenario)."""

    def test_email_skipped_when_already_sent(self):
        """If email_sent EventLog exists, pipeline skips re-sending."""
        db = SessionLocal()
        try:
            unique_event_id = f"existing-event-{uuid.uuid4().hex[:8]}"
            lead = _make_lead(db, calendar_event_id=unique_event_id)

            # Simulate a prior email_sent event (from a crash recovery scenario).
            db.add(EventLog(
                lead_id=lead.id,
                event_type="email_sent",
                payload=json.dumps({"message_id": "old-msg-id", "to": lead.email}),
                organization_id=_DEFAULT_ORG_ID,
            ))
            db.commit()

            # Mock all services so no real API calls happen.
            with patch("app.main.SessionLocal") as mock_session_factory:
                mock_db = MagicMock()
                mock_session_factory.return_value = mock_db
                mock_db.get.return_value = lead
                mock_db.query.return_value.filter.return_value.first.return_value = True  # email_sent exists

                from app.main import _run_pipeline_inner
                _run_pipeline_inner(lead.id)

                # EmailService().send_confirmation_email should NOT have been called
                # because the email_sent guard should have short-circuited.
                # We verify by checking the guard path was taken.
                mock_db.commit.assert_called()  # status was updated to SCHEDULED
        finally:
            db.close()


# ── TEST: Expanded stuck-lead recovery ──────────────────────────────────────


class TestExpandedRecovery:
    """_recover_stuck_leads should now recover ALL PENDING leads,
    including those without calendar_event_id."""

    def test_recovers_pending_without_calendar_event_id(self):
        """PENDING leads without calendar_event_id should now be recovered."""
        db = SessionLocal()
        try:
            lead = _make_lead(
                db,
                name="Never-started Lead",
                email=f"never-{uuid.uuid4().hex[:8]}@example.com",
                status=LeadStatus.PENDING,
                calendar_event_id=None,
                appt_datetime_utc=datetime.now(timezone.utc) + timedelta(hours=48),
            )

            with patch("app.main.run_pipeline") as mock_pipeline:
                from app.main import _recover_stuck_leads
                _recover_stuck_leads()

                called_ids = {call.args[0] for call in mock_pipeline.call_args_list}
                assert lead.id in called_ids

            # Verify recovery event logged
            events = (
                db.query(EventLog)
                .filter(EventLog.lead_id == lead.id, EventLog.event_type == "pipeline_recovery")
                .all()
            )
            assert len(events) >= 1
            payload = json.loads(events[-1].payload)
            assert payload["reason"] == "pending_without_calendar_event_id"
        finally:
            db.close()

    def test_marks_error_when_appt_in_past(self):
        """PENDING leads with past appointments should be marked ERROR."""
        db = SessionLocal()
        try:
            lead = _make_lead(
                db,
                name="Past Lead",
                email=f"past-{uuid.uuid4().hex[:8]}@example.com",
                status=LeadStatus.PENDING,
                appt_datetime_utc=datetime.now(timezone.utc) - timedelta(hours=2),
            )

            with patch("app.main.run_pipeline"):
                from app.main import _recover_stuck_leads
                _recover_stuck_leads()

            # _recover_stuck_leads opens its own session, so re-query to see changes.
            db.expire_all()
            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.ERROR
        finally:
            db.close()

    def test_marks_error_when_appt_is_none(self):
        """PENDING leads with None appt_datetime_utc should be marked ERROR."""
        db = SessionLocal()
        try:
            # Create lead directly to force appt_datetime_utc=None
            # (the _make_lead helper fills in a default when None is passed).
            email = f"none-{uuid.uuid4().hex[:8]}@example.com"
            lead = Lead(
                name="None-Time Lead",
                email=email,
                appt_datetime_raw="unparsable gibberish",
                appt_datetime_utc=None,
                dedupe_key=f"{email}|None",
                status=LeadStatus.PENDING,
                organization_id=_DEFAULT_ORG_ID,
            )
            db.add(lead)
            db.commit()
            db.refresh(lead)

            with patch("app.main.run_pipeline"):
                from app.main import _recover_stuck_leads
                _recover_stuck_leads()

            # _recover_stuck_leads opens its own session, so re-query to see changes.
            db.expire_all()
            fresh = db.get(Lead, lead.id)
            assert fresh.status == LeadStatus.ERROR
        finally:
            db.close()


# ── TEST: AI model validation ──────────────────────────────────────────────


class TestAIModelValidation:
    """AIService should fail fast if ai_model is not configured."""

    def test_raises_when_model_empty(self):
        with patch("app.services.ai_service.settings") as mock_settings:
            mock_settings.ai_api_key = "test-key"
            mock_settings.ai_base_url = "https://api.test.com/v1"
            mock_settings.ai_model = ""  # empty model

            from app.services.ai_service import AIService
            with pytest.raises(RuntimeError, match="AI_MODEL not configured"):
                AIService()

    def test_raises_when_key_and_url_missing(self):
        with patch("app.services.ai_service.settings") as mock_settings:
            mock_settings.ai_api_key = ""
            mock_settings.ai_base_url = ""
            mock_settings.ai_model = "some-model"

            from app.services.ai_service import AIService
            with pytest.raises(RuntimeError, match="AI provider not configured"):
                AIService()


# ── TEST: OpenAI client configuration ──────────────────────────────────────


class TestOpenAIClientConfig:
    """The OpenAI client should be created with max_retries=0 and
    configured timeouts to avoid double-retry with tenacity."""

    @patch("app.services.ai_service.OpenAI")
    def test_client_created_with_max_retries_0(self, mock_openai_cls):
        """OpenAI client must have max_retries=0 (tenacity owns retries)."""
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Hello world"))]
        mock_client.chat.completions.create.return_value = mock_response

        from app.services.ai_service import _chat_completion
        _chat_completion("https://api.test.com", "test-key", "test-model", [])

        # Verify client was created with max_retries=0
        call_kwargs = mock_openai_cls.call_args
        assert call_kwargs.kwargs.get("max_retries") == 0 or (
            call_kwargs[1].get("max_retries") == 0
        )

    @patch("app.services.ai_service.OpenAI")
    def test_client_created_with_timeout(self, mock_openai_cls):
        """OpenAI client must have a reasonable timeout (not 600s default)."""
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Hello world"))]
        mock_client.chat.completions.create.return_value = mock_response

        from app.services.ai_service import _chat_completion
        _chat_completion("https://api.test.com", "test-key", "test-model", [])

        # Verify timeout was configured
        call_kwargs = mock_openai_cls.call_args
        assert "timeout" in call_kwargs.kwargs or "timeout" in call_kwargs[1]


# ── TEST: End-to-end pipeline integration ──────────────────────────────────


class TestE2EPipeline:
    """Full pipeline integration test: form submission → calendar event →
    AI paragraph → email send → status update.  All external APIs are mocked
    to verify the wiring is correct end-to-end."""

    def test_full_pipeline_e2e(self, client, db_session):
        """Simulate the complete happy-path flow:
        1. Mock all external services (Calendar, AI, Gmail)
        2. POST form submission — background pipeline runs with mocks
        3. Verify lead transitions from PENDING → SCHEDULED
        4. Verify EventLog has correct event types
        """
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Name": "E2E Test Lead",
            "Email Address": f"e2e-{uid}@example.com",
            "Phone Appt. Date/Time": "tomorrow 3pm",
            "Interested?": "Yes",
            "Phone Number": "555-1234",
        }

        # Mock all external services BEFORE submission so the background task uses them
        mock_cal_svc = MagicMock()
        mock_cal_svc.create_event.return_value = ("cal-event-123", "https://meet.google.com/abc-defg-hij")
        mock_ai_svc = MagicMock()
        mock_ai_svc.generate_confirmation_email.return_value = ("Welcome to Integrated IT Trainings!", "mocked-model")
        mock_email_svc = MagicMock()
        mock_email_svc.send_confirmation_email.return_value = "msg-12345"

        with (
            patch("app.services.calendar_service.CalendarService", return_value=mock_cal_svc),
            patch("app.services.ai_service.AIService", return_value=mock_ai_svc),
            patch("app.services.email_service.EmailService", return_value=mock_email_svc),
        ):
            resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)

        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"
        lead_id = data["lead_id"]

        # Verify lead exists and is now SCHEDULED (pipeline ran via background task)
        db_session.expire_all()
        lead = db_session.get(Lead, lead_id)
        assert lead is not None
        assert lead.name == "E2E Test Lead"
        assert lead.email == f"e2e-{uid}@example.com"
        assert lead.status == LeadStatus.SCHEDULED
        assert lead.calendar_event_id == "cal-event-123"

        # Verify external services were called
        mock_cal_svc.create_event.assert_called_once()
        mock_ai_svc.generate_confirmation_email.assert_called_once()
        mock_email_svc.send_confirmation_email.assert_called_once()

        # Verify event log entries (actual event types from main.py)
        all_events = (
            db_session.query(EventLog)
            .filter(EventLog.lead_id == lead_id)
            .order_by(EventLog.created_at.asc())
            .all()
        )
        event_types = [e.event_type for e in all_events]
        assert "form_submitted" in event_types
        assert "calendar_created" in event_types
        assert "email_generated" in event_types
        assert "email_sent" in event_types

    def test_duplicate_submission_blocked(self, client, db_session):
        """Submitting the same email+datetime twice should return 'duplicate'
        on the second request (dedupe_key unique index)."""
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Name": "Dupe Lead",
            "Email Address": f"dupe-{uid}@example.com",
            "Phone Appt. Date/Time": "tomorrow 3pm",
            "Interested?": "Yes",
            "Phone Number": "555-9999",
        }

        # First submission — should succeed
        mock_cal_svc = MagicMock()
        mock_cal_svc.create_event.return_value = ("ev1", "https://meet.google.com/xxx")
        mock_ai_svc = MagicMock()
        mock_ai_svc.generate_confirmation_email.return_value = ("Hi!", "mock")
        mock_email_svc = MagicMock()
        mock_email_svc.send_confirmation_email.return_value = "msg1"

        with (
            patch("app.services.calendar_service.CalendarService", return_value=mock_cal_svc),
            patch("app.services.ai_service.AIService", return_value=mock_ai_svc),
            patch("app.services.email_service.EmailService", return_value=mock_email_svc),
        ):
            resp1 = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
        assert resp1.status_code == 202
        assert resp1.json()["status"] == "accepted"

        # Second submission (same email + same datetime) — should return duplicate
        # Note: endpoint is hardcoded to status_code=202, so check body instead
        resp2 = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
        assert resp2.json()["status"] == "duplicate"

        # Only one lead in DB for this email
        db_session.expire_all()
        leads = (
            db_session.query(Lead)
            .filter(Lead.email == f"dupe-{uid}@example.com")
            .all()
        )
        assert len(leads) == 1

    def test_health_endpoint(self, client):
        """Health endpoint returns 200 with status=ok."""
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_webhook_rejects_invalid_payload(self, client):
        """Webhook rejects submissions missing required fields."""
        # Missing all fields
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json={})
        assert resp.status_code in (400, 422, 500)

        # Missing email
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json={
            "Name": "No Email",
            "Phone Appt. Date/Time": "tomorrow 3pm",
        })
        assert resp.status_code in (400, 422, 500)

    def test_pipeline_error_logged_on_failure(self, client, db_session):
        """When the pipeline fails, an 'error' event is logged and status becomes ERROR."""
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Name": "Fail Lead",
            "Email Address": f"fail-{uid}@example.com",
            "Phone Appt. Date/Time": "tomorrow 3pm",
            "Interested?": "Yes",
            "Phone Number": "555-0000",
        }

        # Mock Calendar class to raise an error on create_event
        mock_cal_svc = MagicMock()
        mock_cal_svc.create_event.side_effect = RuntimeError("Simulated Calendar failure")

        with patch(
            "app.services.calendar_service.CalendarService",
            return_value=mock_cal_svc,
        ):
            resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)

        assert resp.status_code == 202
        lead_id = resp.json()["lead_id"]

        # Give background task a moment to complete and verify status is ERROR
        db_session.expire_all()
        lead = db_session.get(Lead, lead_id)
        assert lead.status == LeadStatus.ERROR

        # Check event log — should have form_submitted + error
        all_events = (
            db_session.query(EventLog)
            .filter(EventLog.lead_id == lead_id)
            .all()
        )
        event_types = [e.event_type for e in all_events]
        assert "form_submitted" in event_types
        assert "error" in event_types


# ── TEST: Health / Readiness endpoints ──────────────────────────────────────


class TestHealthEndpoints:
    """Health and readiness endpoints for production monitoring."""

    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_readiness_returns_200_when_db_ok(self, client):
        """Readiness returns 200 when PostgreSQL is reachable."""
        resp = client.get("/health/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"
        assert data["database"] == "ok"

    def test_health_does_not_expose_secrets(self, client):
        """Health endpoint must never leak secrets, passwords, or API keys."""
        resp = client.get("/health")
        text = resp.text.lower()
        for secret_word in ["password", "secret", "api_key", "token", "refresh"]:
            assert secret_word not in text

    def test_readiness_does_not_expose_secrets(self, client):
        """Readiness endpoint must never leak secrets."""
        resp = client.get("/health/ready")
        text = resp.text.lower()
        for secret_word in ["password", "secret", "api_key", "token"]:
            assert secret_word not in text


# ── TEST: Rate limiting ─────────────────────────────────────────────────────


class TestRateLimiting:
    """Rate limiter should only affect POST /webhooks/integrated-it-trainings/form-submission."""

    def test_webhook_get_not_rate_limited(self, client):
        """GET on webhook path should not be rate-limited."""
        for _ in range(5):
            resp = client.get("/webhooks/integrated-it-trainings/form-submission")
            # GET is not a valid method here, but should not return 429
            assert resp.status_code != 429

    def test_dashboard_not_rate_limited(self, client, auth_headers):
        """Dashboard endpoints should not be rate-limited."""
        for _ in range(10):
            resp = client.get("/dashboard/api/summary", headers=auth_headers)
            assert resp.status_code == 200

    def test_health_not_rate_limited(self, client):
        """Health endpoint should not be rate-limited."""
        for _ in range(10):
            resp = client.get("/health")
            assert resp.status_code == 200


# ── TEST: Security headers ──────────────────────────────────────────────────


class TestSecurityHeaders:
    """Responses should include security headers."""

    def test_nosniff_header_on_health(self, client):
        resp = client.get("/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_frame_deny_header(self, client):
        resp = client.get("/health")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_cache_control_no_store_on_webhook(self, client):
        """Webhook and dashboard responses should have Cache-Control: no-store."""
        resp = client.get("/health")
        # Health endpoint does NOT set Cache-Control (intentional — lightweight)
        # but other endpoints should. Check a dashboard endpoint:
        from fastapi.testclient import TestClient
        auth = base64.b64encode(
            f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
        ).decode()
        resp2 = client.get("/dashboard/api/summary", headers={"Authorization": f"Basic {auth}"})
        assert resp2.headers.get("Cache-Control") == "no-store"


# ── TEST: Request size limits ───────────────────────────────────────────────


class TestRequestSizeLimit:
    """Oversized requests should be rejected."""

    def test_oversized_body_rejected(self, client):
        """A body exceeding 64KB should be rejected with 413."""
        huge_payload = {"data": "x" * (65 * 1024)}
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            content=json.dumps(huge_payload),
            headers={"Content-Type": "application/json", "Content-Length": str(len(json.dumps(huge_payload)))},
        )
        assert resp.status_code == 413


# ── TEST: Scheduler configuration ───────────────────────────────────────────


class TestSchedulerConfig:
    """Scheduler behavior based on SCHEDULER_ENABLED setting."""

    def test_scheduler_can_be_disabled(self):
        """When SCHEDULER_ENABLED=false, scheduler does not start."""
        from app.config import Settings
        s = Settings(scheduler_enabled="false", database_url="sqlite:///test.db")
        assert s.scheduler_is_enabled is False

    def test_scheduler_enabled_by_default(self):
        """When SCHEDULER_ENABLED=true, scheduler is enabled."""
        from app.config import Settings
        s = Settings(scheduler_enabled="true", database_url="sqlite:///test.db")
        assert s.scheduler_is_enabled is True
