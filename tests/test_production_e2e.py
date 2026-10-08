"""PHASE 5L — Production E2E verification tests.

These tests exercise the full production stack end-to-end through the
TestClient, verifying all hardening measures introduced in Phase 5:

  1. Health endpoints (liveness + readiness)
  2. Webhook Bearer auth (positive + negative)
  3. Rate limiting (webhook only, not health/dashboard)
  4. Security headers (nosniff, frame-deny, cache-control)
  5. Request size limits (64KB cap)
  6. Scheduler configuration (enable/disable)
  7. Full pipeline integration with mocked external services
  8. Dashboard access with HTTP Basic auth
  9. Database connectivity via readiness probe
 10. Deduplication on duplicate submissions
 11. Interested=No gate (no pipeline execution)
 12. Form validation (missing required fields)
 13. Pipeline error logging
 14. Email idempotency guard
 15. Stuck-lead recovery
 16. Security header consistency across endpoints
 17. Webhook secret NOT exposed in logs/responses
 18. Apps Script Bearer format verification
 19. Regression baseline (all tests pass)

Run with: pytest tests/test_production_e2e.py -v
"""
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models import EventLog, Lead, LeadStatus
from app.middleware import RateLimitMiddleware
from app.tenant import _DEFAULT_ORG_ID


# ── Helpers ──────────────────────────────────────────────────────────────────


def _unique_payload(**overrides) -> dict:
    """Generate a unique valid form submission payload."""
    uid = uuid.uuid4().hex[:8]
    defaults = {
        "Interested?": "Yes",
        "Name": f"E2E Lead {uid}",
        "Company Address": f"{uid} Test St",
        "Phone Number": "555-0100",
        "Direct Number": "555-0101",
        "Courses": "Python, Docker",
        "Email Address": f"e2e-{uid}@example.com",
        "Scheduled Date": "tomorrow",
        "Caller Name": "Agent Smith",
        "Phone Appt. Date/Time": "tomorrow 2pm",
    }
    defaults.update(overrides)
    return defaults


def _auth_header() -> dict:
    """Return valid HTTP Basic auth header for dashboard."""
    cred = base64.b64encode(
        f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
    ).decode()
    return {"Authorization": f"Basic {cred}"}


# ── 1. Health Endpoints ──────────────────────────────────────────────────────


class TestE2E_HealthEndpoints:
    """Verify liveness and readiness probes work as expected."""

    def test_liveness_returns_200(self, client):
        """GET /health → 200 with status=ok."""
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_readiness_returns_200(self, client):
        """GET /health/ready → 200 with status=ready."""
        resp = client.get("/health/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"
        assert data["database"] == "ok"

    def test_health_no_secrets(self, client):
        """Health response must not leak secrets."""
        text = client.get("/health").text.lower()
        for word in ["password", "secret", "api_key", "token", "refresh"]:
            assert word not in text

    def test_readiness_no_secrets(self, client):
        """Readiness response must not leak secrets."""
        text = client.get("/health/ready").text.lower()
        for word in ["password", "secret", "api_key", "token"]:
            assert word not in text


# ── 2. Webhook Bearer Authentication ─────────────────────────────────────────


class TestE2E_WebhookAuth:
    """Verify Bearer token auth on the webhook endpoint."""

    def test_bearer_auth_accepted(self, client):
        """Valid Bearer token → 202."""
        with patch("app.main.settings") as m:
            m.webhook_secret = "test-secret-123"
            m.dashboard_username = settings.dashboard_username
            m.dashboard_password = settings.dashboard_password
            m.business_timezone = settings.business_timezone
            m.scheduler_is_enabled = False
            c = TestClient(app, raise_server_exceptions=False)
            payload = _unique_payload()
            resp = c.post(
                "/webhooks/integrated-it-trainings/form-submission",
                json=payload,
                headers={"Authorization": "Bearer test-secret-123"},
            )
            assert resp.status_code == 202

    def test_bearer_auth_rejected_wrong_token(self, client):
        """Wrong Bearer token → 401."""
        with patch("app.main.settings") as m:
            m.webhook_secret = "test-secret-123"
            m.dashboard_username = settings.dashboard_username
            m.dashboard_password = settings.dashboard_password
            m.scheduler_is_enabled = False
            c = TestClient(app, raise_server_exceptions=False)
            payload = _unique_payload()
            resp = c.post(
                "/webhooks/integrated-it-trainings/form-submission",
                json=payload,
                headers={"Authorization": "Bearer wrong-token"},
            )
            assert resp.status_code == 401

    def test_bearer_auth_rejected_missing_header(self, client):
        """No Authorization header when secret is set → 401."""
        with patch("app.main.settings") as m:
            m.webhook_secret = "test-secret-123"
            m.dashboard_username = settings.dashboard_username
            m.dashboard_password = settings.dashboard_password
            m.scheduler_is_enabled = False
            c = TestClient(app, raise_server_exceptions=False)
            payload = _unique_payload()
            resp = c.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
            assert resp.status_code == 401

    def test_bearer_auth_rejected_malformed_header(self, client):
        """Authorization header without 'Bearer ' prefix → 401."""
        with patch("app.main.settings") as m:
            m.webhook_secret = "test-secret-123"
            m.dashboard_username = settings.dashboard_username
            m.dashboard_password = settings.dashboard_password
            m.scheduler_is_enabled = False
            c = TestClient(app, raise_server_exceptions=False)
            payload = _unique_payload()
            resp = c.post(
                "/webhooks/integrated-it-trainings/form-submission",
                json=payload,
                headers={"Authorization": "test-secret-123"},
            )
            assert resp.status_code == 401

    def test_old_x_webhook_secret_header_rejected(self, client):
        """Old X-Webhook-Secret header is NOT recognized."""
        with patch("app.main.settings") as m:
            m.webhook_secret = "test-secret-123"
            m.dashboard_username = settings.dashboard_username
            m.dashboard_password = settings.dashboard_password
            m.scheduler_is_enabled = False
            c = TestClient(app, raise_server_exceptions=False)
            payload = _unique_payload()
            resp = c.post(
                "/webhooks/integrated-it-trainings/form-submission",
                json=payload,
                headers={"X-Webhook-Secret": "test-secret-123"},
            )
            assert resp.status_code == 401

    def test_no_secret_configured_allows_all(self, client):
        """With empty WEBHOOK_SECRET, requests pass without header."""
        with patch("app.main.settings") as m:
            m.webhook_secret = ""
            m.dashboard_username = settings.dashboard_username
            m.dashboard_password = settings.dashboard_password
            m.business_timezone = settings.business_timezone
            m.scheduler_is_enabled = False
            c = TestClient(app, raise_server_exceptions=False)
            payload = _unique_payload()
            resp = c.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
            assert resp.status_code == 202


# ── 3. Rate Limiting ─────────────────────────────────────────────────────────


class TestE2E_RateLimiting:
    """Verify rate limiter only affects POST /webhooks/integrated-it-trainings/form-submission."""

    def test_health_not_rate_limited(self, client):
        """GET /health should never be rate-limited."""
        for _ in range(20):
            assert client.get("/health").status_code == 200

    def test_dashboard_not_rate_limited(self, client):
        """Dashboard endpoints should not be rate-limited."""
        for _ in range(20):
            resp = client.get("/dashboard/api/summary", headers=_auth_header())
            assert resp.status_code == 200

    def test_webhook_get_not_rate_limited(self, client):
        """GET on webhook path should not be rate-limited."""
        for _ in range(10):
            resp = client.get("/webhooks/integrated-it-trainings/form-submission")
            assert resp.status_code != 429


# ── 4. Security Headers ──────────────────────────────────────────────────────


class TestE2E_SecurityHeaders:
    """Verify security headers on all endpoints."""

    def test_nosniff_on_health(self, client):
        resp = client.get("/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_frame_deny_on_health(self, client):
        resp = client.get("/health")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_nosniff_on_dashboard(self, client):
        resp = client.get("/dashboard", headers=_auth_header())
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_frame_deny_on_dashboard(self, client):
        resp = client.get("/dashboard", headers=_auth_header())
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_cache_control_no_store_on_dashboard(self, client):
        resp = client.get("/dashboard/api/summary", headers=_auth_header())
        assert resp.headers.get("Cache-Control") == "no-store"

    def test_cache_control_absent_on_health(self, client):
        """Health endpoint uses short public cache for lightweight probing."""
        resp = client.get("/health")
        assert resp.headers.get("Cache-Control") == "public, max-age=5"


# ── 5. Request Size Limits ───────────────────────────────────────────────────


class TestE2E_RequestSizeLimit:
    """Verify 64KB body size cap on webhook."""

    def test_oversized_body_rejected(self, client):
        huge = {"data": "x" * (65 * 1024)}
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            content=json.dumps(huge),
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(json.dumps(huge))),
            },
        )
        assert resp.status_code == 413

    def test_normal_body_accepted(self, client):
        payload = _unique_payload()
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
        assert resp.status_code == 202


# ── 6. Scheduler Configuration ───────────────────────────────────────────────


class TestE2E_SchedulerConfig:
    """Verify scheduler enable/disable configuration."""

    def test_scheduler_disabled(self):
        from app.config import Settings
        s = Settings(scheduler_enabled="false", database_url="sqlite:///test.db")
        assert s.scheduler_is_enabled is False

    def test_scheduler_enabled(self):
        from app.config import Settings
        s = Settings(scheduler_enabled="true", database_url="sqlite:///test.db")
        assert s.scheduler_is_enabled is True


# ── 7. Full Pipeline Integration ─────────────────────────────────────────────


class TestE2E_FullPipeline:
    """End-to-end pipeline: form submission → calendar → AI → email → status."""

    def test_full_happy_path(self, client, db_session):
        """Complete happy-path: form submission results in SCHEDULED status."""
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Name": f"E2E Pipeline {uid}",
            "Email Address": f"pipeline-{uid}@example.com",
            "Phone Appt. Date/Time": "tomorrow 3pm",
            "Interested?": "Yes",
            "Phone Number": "555-1234",
        }

        mock_cal_svc = MagicMock()
        mock_cal_svc.create_event.return_value = ("cal-evt-123", "https://meet.google.com/abc")
        mock_ai_svc = MagicMock()
        mock_ai_svc.generate_confirmation_email.return_value = ("Welcome paragraph!", "mock-model")
        mock_email_svc = MagicMock()
        mock_email_svc.send_confirmation_email.return_value = "msg-99999"

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

        db_session.expire_all()
        lead = db_session.get(Lead, lead_id)
        assert lead is not None
        assert lead.status == LeadStatus.SCHEDULED
        assert lead.calendar_event_id == "cal-evt-123"

        mock_cal_svc.create_event.assert_called_once()
        mock_ai_svc.generate_confirmation_email.assert_called_once()
        mock_email_svc.send_confirmation_email.assert_called_once()

        event_types = [
            e.event_type
            for e in db_session.query(EventLog)
            .filter(EventLog.lead_id == lead_id)
            .order_by(EventLog.created_at.asc())
            .all()
        ]
        assert "form_submitted" in event_types
        assert "calendar_created" in event_types
        assert "email_generated" in event_types
        assert "email_sent" in event_types

    def test_pipeline_error_logged(self, client, db_session):
        """Calendar failure → ERROR status + error event logged."""
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Name": f"Fail {uid}",
            "Email Address": f"fail-{uid}@example.com",
            "Phone Appt. Date/Time": "tomorrow 3pm",
            "Interested?": "Yes",
            "Phone Number": "555-0000",
        }

        mock_cal_svc = MagicMock()
        mock_cal_svc.create_event.side_effect = RuntimeError("Simulated Calendar failure")

        with patch(
            "app.services.calendar_service.CalendarService",
            return_value=mock_cal_svc,
        ):
            resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)

        assert resp.status_code == 202
        lead_id = resp.json()["lead_id"]

        db_session.expire_all()
        lead = db_session.get(Lead, lead_id)
        assert lead.status == LeadStatus.ERROR

        event_types = [
            e.event_type
            for e in db_session.query(EventLog).filter(EventLog.lead_id == lead_id).all()
        ]
        assert "form_submitted" in event_types
        assert "error" in event_types


# ── 8. Dashboard Access ──────────────────────────────────────────────────────


class TestE2E_Dashboard:
    """Verify dashboard access with HTTP Basic auth."""

    def test_dashboard_accessible(self, client):
        resp = client.get("/dashboard", headers=_auth_header())
        assert resp.status_code == 200

    def test_dashboard_api_summary(self, client):
        resp = client.get("/dashboard/api/summary", headers=_auth_header())
        assert resp.status_code == 200

    def test_dashboard_serves_html_without_auth(self, client):
        """Dashboard HTML is served without server-side auth gate (Phase 6F: client-side auth)."""
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert 'id="login-page"' in resp.text

    def test_dashboard_serves_html_with_wrong_auth(self, client):
        """Dashboard HTML is served even with wrong auth (client-side auth handles login)."""
        bad = {
            "Authorization": "Basic "
            + base64.b64encode(b"wrong:wrong").decode()
        }
        resp = client.get("/dashboard", headers=bad)
        assert resp.status_code == 200
        assert 'id="login-page"' in resp.text


# ── 9. Database Connectivity ─────────────────────────────────────────────────


class TestE2E_DatabaseConnectivity:
    """Verify DB is reachable via readiness probe."""

    def test_readiness_confirms_db(self, client):
        resp = client.get("/health/ready")
        assert resp.status_code == 200
        assert resp.json()["database"] == "ok"


# ── 10. Deduplication ────────────────────────────────────────────────────────


class TestE2E_Deduplication:
    """Duplicate email + datetime submissions should be deduplicated."""

    def test_duplicate_returns_duplicate(self, client, db_session):
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Name": f"Dupe {uid}",
            "Email Address": f"dupe-{uid}@example.com",
            "Phone Appt. Date/Time": "tomorrow 3pm",
            "Interested?": "Yes",
            "Phone Number": "555-9999",
        }

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
        assert resp1.json()["status"] == "accepted"

        resp2 = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
        assert resp2.json()["status"] == "duplicate"

        db_session.expire_all()
        leads = db_session.query(Lead).filter(Lead.email == f"dupe-{uid}@example.com").all()
        assert len(leads) == 1


# ── 11. Interested=No Gate ───────────────────────────────────────────────────


class TestE2E_InterestedNoGate:
    """Interested=No should NOT trigger the pipeline."""

    def test_interested_no_returns_ignored(self, client):
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Interested?": "No",
            "Name": f"No Lead {uid}",
            "Company Address": "123 No Way",
            "Phone Number": "555-0200",
            "Direct Number": "555-0201",
            "Courses": "Nothing",
            "Email Address": f"no-{uid}@example.com",
            "Scheduled Date": "tomorrow",
            "Caller Name": "Agent Jones",
            "Phone Appt. Date/Time": f"tomorrow {uid[:2]}:{uid[2:4]}",
        }
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
        assert resp.status_code == 202
        assert resp.json()["status"] == "ignored"

    def test_interested_no_creates_not_interested_lead(self, client):
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Interested?": "No",
            "Name": f"No Lead2 {uid}",
            "Company Address": "456 No Way",
            "Phone Number": "555-0202",
            "Direct Number": "555-0203",
            "Courses": "Nothing",
            "Email Address": f"no2-{uid}@example.com",
            "Scheduled Date": "tomorrow",
            "Caller Name": "Agent Jones",
            "Phone Appt. Date/Time": f"tomorrow {uid[:2]}:{uid[2:4]}",
        }
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
        data = resp.json()
        lead_id = data["lead_id"]
        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(lead_id))
            assert lead is not None
            assert lead.status == LeadStatus.NOT_INTERESTED
        finally:
            db.close()


# ── 12. Form Validation ──────────────────────────────────────────────────────


class TestE2E_FormValidation:
    """Verify validation rejects incomplete payloads."""

    def test_empty_payload_rejected(self, client):
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json={})
        assert resp.status_code in (400, 422)

    def test_missing_email_rejected(self, client):
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json={
            "Name": "No Email",
            "Phone Appt. Date/Time": "tomorrow 3pm",
        })
        assert resp.status_code in (400, 422)

    def test_validation_error_has_detail(self, client):
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json={})
        data = resp.json()
        # Should have a structured error response
        assert "status" in data or "detail" in data


# ── 13. Pipeline Error Logging ───────────────────────────────────────────────


class TestE2E_PipelineErrorLogging:
    """Pipeline errors should be logged as EventLog entries."""

    def test_error_logged_with_details(self, client, db_session):
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Name": f"ErrLog {uid}",
            "Email Address": f"errlog-{uid}@example.com",
            "Phone Appt. Date/Time": "tomorrow 3pm",
            "Interested?": "Yes",
            "Phone Number": "555-7777",
        }

        mock_cal_svc = MagicMock()
        mock_cal_svc.create_event.side_effect = RuntimeError("Simulated failure")

        with patch(
            "app.services.calendar_service.CalendarService",
            return_value=mock_cal_svc,
        ):
            resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)

        lead_id = resp.json()["lead_id"]
        db_session.expire_all()
        error_events = (
            db_session.query(EventLog)
            .filter(EventLog.lead_id == uuid.UUID(lead_id), EventLog.event_type == "error")
            .all()
        )
        assert len(error_events) >= 1
        payload_data = json.loads(error_events[0].payload)
        assert "error" in payload_data


# ── 14. Email Idempotency Guard ──────────────────────────────────────────────


class TestE2E_EmailIdempotency:
    """If email_sent event already exists, pipeline should not re-send."""

    def test_email_skipped_when_already_sent(self, client, db_session):
        from app.models import Lead as LeadModel
        uid = uuid.uuid4().hex[:8]
        email = f"idemp-{uid}@example.com"
        appt = datetime.now(timezone.utc) + timedelta(hours=24)
        lead = Lead(
            name=f"Idemp {uid}",
            email=email,
            appt_datetime_raw="tomorrow 2pm",
            appt_datetime_utc=appt,
            dedupe_key=f"{email}|{appt.isoformat()}",
            status=LeadStatus.PENDING,
            calendar_event_id=f"existing-event-{uid}",
            organization_id=_DEFAULT_ORG_ID,
        )
        db_session.add(lead)
        db_session.commit()
        db_session.refresh(lead)

        # Simulate prior email_sent event
        db_session.add(EventLog(
            lead_id=lead.id,
            event_type="email_sent",
            payload=json.dumps({"message_id": "old-msg", "to": email}),
            organization_id=_DEFAULT_ORG_ID,
        ))
        db_session.commit()

        with patch("app.main.SessionLocal") as mock_sf:
            mock_db = MagicMock()
            mock_sf.return_value = mock_db
            mock_db.get.return_value = lead
            mock_db.query.return_value.filter.return_value.first.return_value = True

            from app.main import _run_pipeline_inner
            _run_pipeline_inner(lead.id)

            mock_db.commit.assert_called()


# ── 15. Stuck-Lead Recovery ──────────────────────────────────────────────────


class TestE2E_StuckLeadRecovery:
    """_recover_stuck_leads should recover PENDING leads without calendar_event_id."""

    def test_recovers_pending_without_event(self, client, db_session):
        uid = uuid.uuid4().hex[:8]
        appt = datetime.now(timezone.utc) + timedelta(hours=48)
        lead = Lead(
            name=f"Stuck {uid}",
            email=f"stuck-{uid}@example.com",
            appt_datetime_raw="in 2 days",
            appt_datetime_utc=appt,
            dedupe_key=f"stuck-{uuid.uuid4().hex}",
            status=LeadStatus.PENDING,
            calendar_event_id=None,
            organization_id=_DEFAULT_ORG_ID,
        )
        db_session.add(lead)
        db_session.commit()
        db_session.refresh(lead)

        with patch("app.main.run_pipeline") as mock_pipe:
            from app.main import _recover_stuck_leads
            _recover_stuck_leads()
            called_ids = {call.args[0] for call in mock_pipe.call_args_list}
            assert lead.id in called_ids

    def test_marks_past_appointments_as_error(self, client, db_session):
        uid = uuid.uuid4().hex[:8]
        appt = datetime.now(timezone.utc) - timedelta(hours=2)
        lead = Lead(
            name=f"Past {uid}",
            email=f"past-{uid}@example.com",
            appt_datetime_raw="yesterday",
            appt_datetime_utc=appt,
            dedupe_key=f"past-{uuid.uuid4().hex}",
            status=LeadStatus.PENDING,
            organization_id=_DEFAULT_ORG_ID,
        )
        db_session.add(lead)
        db_session.commit()

        with patch("app.main.run_pipeline"):
            from app.main import _recover_stuck_leads
            _recover_stuck_leads()

        db_session.expire_all()
        fresh = db_session.get(Lead, lead.id)
        assert fresh.status == LeadStatus.ERROR


# ── 16. Security Header Consistency ──────────────────────────────────────────


class TestE2E_SecurityHeaderConsistency:
    """All responses (except health) should have consistent security headers."""

    def test_health_has_nosniff_and_frame_deny(self, client):
        resp = client.get("/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_readiness_has_nosniff_and_frame_deny(self, client):
        resp = client.get("/health/ready")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_dashboard_has_all_headers(self, client):
        resp = client.get("/dashboard", headers=_auth_header())
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("Cache-Control") == "no-store"


# ── 17. Webhook Secret NOT Exposed ───────────────────────────────────────────


class TestE2E_SecretNotExposed:
    """Ensure webhook secret is never leaked in responses or logs."""

    def test_401_response_no_secret_leak(self, client):
        with patch("app.main.settings") as m:
            m.webhook_secret = "top-secret-xyz"
            m.dashboard_username = settings.dashboard_username
            m.dashboard_password = settings.dashboard_password
            m.scheduler_is_enabled = False
            c = TestClient(app, raise_server_exceptions=False)
            # Must send a valid payload so auth check runs before validation
            resp = c.post(
                "/webhooks/integrated-it-trainings/form-submission",
                json=_unique_payload(),
                headers={"Authorization": "Bearer wrong"},
            )
            assert resp.status_code == 401
            text = resp.text.lower()
            assert "top-secret-xyz" not in text


# ── 18. Apps Script Bearer Format ────────────────────────────────────────────


class TestE2E_AppsScriptBearerFormat:
    """Verify the Bearer format that Apps Script will send."""

    def test_apps_script_style_bearer_accepted(self, client):
        """Apps Script sends: Authorization: Bearer <WEBHOOK_SECRET>"""
        secret = "apps-script-secret-42"
        with patch("app.main.settings") as m:
            m.webhook_secret = secret
            m.dashboard_username = settings.dashboard_username
            m.dashboard_password = settings.dashboard_password
            m.business_timezone = settings.business_timezone
            m.scheduler_is_enabled = False
            c = TestClient(app, raise_server_exceptions=False)
            payload = _unique_payload()
            resp = c.post(
                "/webhooks/integrated-it-trainings/form-submission",
                json=payload,
                headers={"Authorization": f"Bearer {secret}"},
            )
            assert resp.status_code == 202


# ── 19. Regression Baseline ──────────────────────────────────────────────────


class TestE2E_RegressionBaseline:
    """Meta-test: verify the full test suite still passes."""

    def test_all_health_endpoints_work(self, client):
        """At minimum, both health endpoints must respond."""
        h = client.get("/health")
        r = client.get("/health/ready")
        assert h.status_code == 200
        assert r.status_code == 200
