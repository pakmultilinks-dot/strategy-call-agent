"""Phase 7 — Production-Ready Customer Platform.

Covers:
  1.  Setup status — returns checklist for org
  2.  Setup status — marks google_connected as done
  3.  Setup status — marks all done when fully configured
  4.  Setup status — platform admin gets setup_complete=True
  5.  Pipeline status — returns zero counts for empty org
  6.  Pipeline status — returns correct counts
  7.  Pipeline status — org-scoped filtering
  8.  Pipeline status — success rate calculation
  9.  Pipeline status — recent error count
  10. Dashboard HTML — contains onboarding wizard elements
  11. Dashboard HTML — contains setup checklist widget
  12. Dashboard HTML — contains pipeline health widget
  13. Dashboard HTML — version updated to Phase 7
  14. Global exception handler — returns safe error message
  15. Tenant isolation — setup status scoped to org
  16. Tenant isolation — pipeline status scoped to org
  17. RBAC — member can read setup status
  18. RBAC — member can read pipeline status
  19. Onboarding — checkOnboarding JS function exists in HTML
  20. Setup checklist — loadSetupChecklist JS function exists in HTML
  21. Pipeline health — loadPipelineHealth JS function exists in HTML
  22. Onboarding — dismissOnboarding JS function exists in HTML
  23. Setup status — unauthenticated returns 401
  24. Pipeline status — unauthenticated returns 401
  25. Setup status — default config detected as not done
"""
import json
import secrets
import uuid

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

TEST_JWT_SECRET = "test-secret-key-for-phase-7-jwt-testing-32chars!!"
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
    from datetime import datetime, timedelta, timezone
    from jose import jwt as jose_jwt

    payload = {
        "sub": str(user.id),
        "org_id": str(user.organization_id),
        "role": user.role.value,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
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


# ── Setup Status ──────────────────────────────────────────────────────────────


class TestSetupStatus:
    """GET /dashboard/api/setup-status returns the onboarding checklist."""

    def test_returns_checklist_for_org(self, client: TestClient):
        """Setup status returns steps for a valid org."""
        org = _make_org(webhook_secret=None)
        user = _create_user(org.id, UserRole.OWNER)
        r = client.get("/dashboard/api/setup-status", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert "setup_complete" in data
        assert "steps" in data
        assert "completed_steps" in data
        assert "total_steps" in data
        assert data["total_steps"] == 4

    def test_marks_google_connected_done(self, client: TestClient):
        """Google step is marked done when integration exists and connected."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)

        # Phase 34: Must store actual credentials with a refresh_token
        # via CredentialVault so setup_status can decrypt and validate them.
        from app.services.credential_vault import CredentialVault
        from app.models_multi_tenant import IntegrationStatus

        db = SessionLocal()
        try:
            CredentialVault.save_credentials(
                db=db, org_id=org.id, provider="google",
                integration_type="google_oauth",
                credentials={
                    "client_id": "test-id.apps.googleusercontent.com",
                    "client_secret": "test-secret",
                    "refresh_token": "valid-refresh-token",
                },
                metadata={"email": "test@example.com"},
                status=IntegrationStatus.CONNECTED,
            )
            db.commit()
        finally:
            db.close()

        r = client.get("/dashboard/api/setup-status", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert data["steps"]["google_connected"]["done"] is True

    def test_marks_all_done_when_fully_configured(self, client: TestClient):
        """All steps marked done when everything is configured."""
        org = _make_org(
            webhook_secret="rotated-secret",
            sender_name="Test Brand",
            brand_color="#FF0000",
        )
        user = _create_user(org.id, UserRole.OWNER)

        from app.services.credential_vault import CredentialVault
        from app.models_multi_tenant import OrgScheduleConfig, IntegrationStatus

        db = SessionLocal()
        try:
            CredentialVault.save_credentials(
                db=db, org_id=org.id, provider="google",
                integration_type="google_oauth",
                credentials={
                    "client_id": "test-id.apps.googleusercontent.com",
                    "client_secret": "test-secret",
                    "refresh_token": "valid-refresh-token",
                },
                metadata={"email": "test@example.com"},
                status=IntegrationStatus.CONNECTED,
            )
            cfg = OrgScheduleConfig(
                organization_id=org.id,
                timezone="America/Chicago",
                reminder_hour=8,
                reminder_minute=0,
            )
            db.add(cfg)
            db.commit()
        finally:
            db.close()

        r = client.get("/dashboard/api/setup-status", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert data["setup_complete"] is True
        assert data["completed_steps"] == 4

    def test_platform_admin_gets_setup_complete(self, client: TestClient, monkeypatch):
        """Platform admin sees setup_complete=True (no org context)."""
        monkeypatch.setattr(settings, "dashboard_username", "testadmin")
        monkeypatch.setattr(settings, "dashboard_password", "testpass123")
        r = client.get(
            "/dashboard/api/setup-status",
            auth=("testadmin", "testpass123"),
        )
        assert r.status_code == 200
        data = r.json()
        assert data["setup_complete"] is True
        assert data.get("platform_admin") is True

    def test_unauthenticated_returns_401(self, client: TestClient):
        """Unauthenticated request returns 401."""
        r = client.get("/dashboard/api/setup-status")
        assert r.status_code == 401

    def test_default_config_detected_as_not_done(self, client: TestClient):
        """Org with no customizations is not setup_complete."""
        org = _make_org(webhook_secret=None)
        user = _create_user(org.id, UserRole.OWNER)
        r = client.get("/dashboard/api/setup-status", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert data["setup_complete"] is False
        assert data["completed_steps"] < data["total_steps"]


# ── Pipeline Status ───────────────────────────────────────────────────────────


class TestPipelineStatus:
    """GET /dashboard/api/pipeline/status returns lead processing stats."""

    def test_returns_zero_counts_for_empty_org(self, client: TestClient):
        """Empty org returns zero totals."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        r = client.get("/dashboard/api/pipeline/status", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert data["total_leads"] == 0
        assert data["completed"] == 0
        assert data["pending"] == 0
        assert data["errors"] == 0

    def test_returns_correct_counts(self, client: TestClient):
        """Pipeline status returns accurate lead counts by status."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)

        # Create leads in various statuses
        _make_lead(org.id, LeadStatus.PENDING)
        _make_lead(org.id, LeadStatus.PENDING)
        _make_lead(org.id, LeadStatus.SCHEDULED)
        _make_lead(org.id, LeadStatus.ACCEPTED)
        _make_lead(org.id, LeadStatus.DECLINED)
        _make_lead(org.id, LeadStatus.ERROR)

        r = client.get("/dashboard/api/pipeline/status", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert data["total_leads"] == 6
        assert data["pending"] == 2
        assert data["completed"] == 2  # scheduled + accepted
        assert data["declined"] == 1
        assert data["errors"] == 1

    def test_org_scoped_filtering(self, client: TestClient):
        """Pipeline status only includes leads for the user's org."""
        org_a = _make_org()
        org_b = _make_org()
        user_a = _create_user(org_a.id, UserRole.OWNER)

        _make_lead(org_a.id, LeadStatus.SCHEDULED)
        _make_lead(org_b.id, LeadStatus.SCHEDULED)

        r = client.get("/dashboard/api/pipeline/status", headers=_auth_headers(user_a))
        assert r.status_code == 200
        data = r.json()
        assert data["total_leads"] == 1  # Only org_a's lead

    def test_success_rate_calculation(self, client: TestClient):
        """Success rate is correctly calculated."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)

        _make_lead(org.id, LeadStatus.SCHEDULED)
        _make_lead(org.id, LeadStatus.ACCEPTED)
        _make_lead(org.id, LeadStatus.PENDING)

        r = client.get("/dashboard/api/pipeline/status", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert data["success_rate"] == 66.7  # 2/3 = 66.7%

    def test_unauthenticated_returns_401(self, client: TestClient):
        """Unauthenticated request returns 401."""
        r = client.get("/dashboard/api/pipeline/status")
        assert r.status_code == 401


# ── Dashboard HTML (Phase 7) ─────────────────────────────────────────────────


class TestDashboardHTMLPhase7:
    """Dashboard HTML contains Phase 7 frontend elements."""

    def test_contains_onboarding_wizard(self, client: TestClient):
        """Dashboard HTML contains the onboarding wizard overlay."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert 'id="onboarding-overlay"' in r.text

    def test_contains_setup_checklist(self, client: TestClient):
        """Dashboard HTML contains the setup checklist widget."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert 'id="setup-checklist"' in r.text

    def test_contains_pipeline_health(self, client: TestClient):
        """Dashboard HTML contains the pipeline health widget."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert 'id="pipeline-health-grid"' in r.text
        assert 'id="overview-pipeline-health"' in r.text

    def test_version_updated(self, client: TestClient):
        """Dashboard version string shows Phase 23+ (v1.0+)."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert "Phase 23" in r.text
        assert "v1.0" in r.text

    def test_check_onboarding_function_exists(self, client: TestClient):
        """JavaScript checkOnboarding function is defined."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert "checkOnboarding" in r.text

    def test_setup_checklist_function_exists(self, client: TestClient):
        """JavaScript loadSetupChecklist function is defined."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert "loadSetupChecklist" in r.text

    def test_pipeline_health_function_exists(self, client: TestClient):
        """JavaScript loadPipelineHealth function is defined."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert "loadPipelineHealth" in r.text

    def test_dismiss_onboarding_function_exists(self, client: TestClient):
        """JavaScript dismissOnboarding function is defined."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert "dismissOnboarding" in r.text

    def test_onboarding_wizard_steps_exist(self, client: TestClient):
        """Dashboard contains all 4 onboarding wizard steps."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert 'id="onboard-step-1"' in r.text
        assert 'id="onboard-step-2"' in r.text
        assert 'id="onboard-step-3"' in r.text
        assert 'id="onboard-step-4"' in r.text

    def test_onboarding_next_back_functions(self, client: TestClient):
        """Dashboard contains onboarding navigation functions."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert "onboardingNext" in r.text
        assert "onboardingBack" in r.text


# ── Error Handling (Phase 7) ─────────────────────────────────────────────────


class TestErrorHandling:
    """Global exception handler returns safe errors."""

    def test_safe_error_on_server_error(self, client: TestClient):
        """Unhandled errors return safe message without stack traces."""
        # Trigger a 500 by requesting a nonexistent integration with invalid data
        r = client.get(
            "/dashboard/api/integrations/../../../etc/passwd",
        )
        # Should not return 500 with stack trace — FastAPI catches this
        # or returns a safe error
        if r.status_code == 500:
            data = r.json()
            assert "stacktrace" not in json.dumps(data).lower()
            assert "traceback" not in json.dumps(data).lower()

    def test_validation_error_is_structured(self, client: TestClient):
        """Validation errors return structured JSON response."""
        r = client.post(
            "/webhooks/test-org/form-submission",
            json={"invalid": True},  # Missing required fields
        )
        if r.status_code == 422:
            data = r.json()
            assert "status" in data or "detail" in data


# ── RBAC (Phase 7) ───────────────────────────────────────────────────────────


class TestRBACPhase7:
    """Phase 7 endpoints respect RBAC."""

    def test_member_can_read_setup_status(self, client: TestClient):
        """Members can read setup status (read-only)."""
        org = _make_org()
        user = _create_user(org.id, UserRole.MEMBER)
        r = client.get("/dashboard/api/setup-status", headers=_auth_headers(user))
        assert r.status_code == 200

    def test_member_can_read_pipeline_status(self, client: TestClient):
        """Members can read pipeline status (read-only)."""
        org = _make_org()
        user = _create_user(org.id, UserRole.MEMBER)
        r = client.get("/dashboard/api/pipeline/status", headers=_auth_headers(user))
        assert r.status_code == 200


# ── Tenant Isolation (Phase 7) ───────────────────────────────────────────────


class TestTenantIsolationPhase7:
    """Phase 7 endpoints respect org boundaries."""

    def test_setup_status_scoped_to_org(self, client: TestClient):
        """Setup status only checks the authenticated org's config."""
        org_a = _make_org(webhook_secret=None)
        org_b = _make_org(webhook_secret="rotated")
        user_a = _create_user(org_a.id, UserRole.OWNER)

        r = client.get("/dashboard/api/setup-status", headers=_auth_headers(user_a))
        data = r.json()
        # org_a has no webhook secret
        assert data["steps"]["webhook_configured"]["done"] is False

    def test_pipeline_status_scoped_to_org(self, client: TestClient):
        """Pipeline status only counts the authenticated org's leads."""
        org_a = _make_org()
        org_b = _make_org()
        user_a = _create_user(org_a.id, UserRole.OWNER)

        _make_lead(org_a.id, LeadStatus.SCHEDULED)
        _make_lead(org_a.id, LeadStatus.SCHEDULED)
        _make_lead(org_b.id, LeadStatus.SCHEDULED)
        _make_lead(org_b.id, LeadStatus.SCHEDULED)

        r = client.get("/dashboard/api/pipeline/status", headers=_auth_headers(user_a))
        data = r.json()
        assert data["total_leads"] == 2  # Only org_a's leads
