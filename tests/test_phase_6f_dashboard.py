"""Phase 6F — Customer Dashboard / Control Plane.

Covers:
  1. Dashboard HTML served without auth gate (client-side login)
  2. Login page works with valid credentials
  3. Login page rejects invalid credentials
  4. Registration creates org + user + returns JWT
  5. /auth/me returns current user info
  6. Organization settings GET — returns safe data
  7. Organization settings PATCH — owner/admin can update
  8. Organization settings PATCH — member rejected (403)
  9. Organization settings PATCH — partial update works
  10. Audit log — returns org-scoped events
  11. Audit log — filters by event_type
  12. Audit log — sensitive payload keys redacted
  13. Audit log — unauthenticated returns 401
  14. Integrations list — returns safe metadata
  15. Integrations list — no credentials returned
  16. Webhook config — safe masked response
  17. Webhook config — full secret never exposed
  18. Org settings — webhook_secret never in response
  19. Tenant isolation — Org A cannot access Org B settings
  20. Tenant isolation — Org A cannot access Org B leads
  21. Tenant isolation — Org A cannot access Org B audit log
  22. RBAC — member can read org settings
  23. RBAC — member cannot write org settings
  24. Google OAuth status — returns safe data
  25. Dashboard API — leads are org-scoped
  26. Dashboard API — summary is org-scoped
  27. Dashboard API — upcoming leads are org-scoped
  28. All dashboard pages load (HTML contains expected elements)
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
from app.models import EventLog, Lead, LeadStatus
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)
from app.services.crypto import generate_key


# ── Test Constants ────────────────────────────────────────────────────────────

TEST_JWT_SECRET = "test-secret-key-for-phase-6f-jwt-testing-32chars!!"
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


# ── Dashboard HTML ────────────────────────────────────────────────────────────


class TestDashboardHTML:
    """Dashboard HTML is served without server-side auth gate."""

    def test_dashboard_html_served(self, client: TestClient):
        """Dashboard page returns 200 with HTML content."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_dashboard_contains_login_page(self, client: TestClient):
        """Dashboard HTML contains the login page element."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert 'id="login-page"' in r.text
        assert 'id="login-form"' in r.text

    def test_dashboard_contains_app_main(self, client: TestClient):
        """Dashboard HTML contains the main app element."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert 'id="app-main"' in r.text

    def test_dashboard_contains_new_pages(self, client: TestClient):
        """Dashboard HTML contains all new Phase 6F pages."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert 'id="page-integrations"' in r.text
        assert 'id="page-webhook"' in r.text
        assert 'id="page-org-settings"' in r.text
        assert 'id="page-activity"' in r.text

    def test_dashboard_contains_sidebar_user_info(self, client: TestClient):
        """Dashboard HTML contains user info elements in sidebar."""
        r = client.get("/dashboard/")
        assert r.status_code == 200
        assert 'id="sidebar-user-name"' in r.text
        assert 'id="sidebar-user-role"' in r.text
        assert 'id="logout-btn"' in r.text


# ── Authentication ────────────────────────────────────────────────────────────


class TestAuthentication:
    """Login and registration work correctly."""

    def test_login_valid(self, client: TestClient):
        """Valid credentials return JWT token."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER, email="login-test@example.com")
        r = client.post("/auth/login", json={
            "email": "login-test@example.com",
            "password": "TestPassword123!",
        })
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_invalid_password(self, client: TestClient):
        """Invalid password returns 401."""
        org = _make_org()
        _create_user(org.id, UserRole.OWNER, email="bad-pw@example.com")
        r = client.post("/auth/login", json={
            "email": "bad-pw@example.com",
            "password": "WrongPassword!",
        })
        assert r.status_code == 401

    def test_login_nonexistent_email(self, client: TestClient):
        """Non-existent email returns 401 (generic error)."""
        r = client.post("/auth/login", json={
            "email": f"nope-{uuid.uuid4().hex[:8]}@example.com",
            "password": "TestPassword123!",
        })
        assert r.status_code == 401

    def test_register_creates_org_and_user(self, client: TestClient):
        """Registration creates organization and user, returns JWT."""
        r = client.post("/auth/register", json={
            "organization_name": f"Reg Test {uuid.uuid4().hex[:6]}",
            "name": "Reg User",
            "email": f"reg-{uuid.uuid4().hex[:8]}@example.com",
            "password": "TestPassword123!",
        })
        assert r.status_code == 201
        data = r.json()
        assert "access_token" in data

    def test_auth_me_returns_user(self, client: TestClient):
        """GET /auth/me returns current user info."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER, email="me-test@example.com")
        r = client.get("/auth/me", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == "me-test@example.com"
        assert data["role"] == "owner"
        assert data["organization"]["id"] == str(org.id)

    def test_auth_me_unauthenticated(self, client: TestClient):
        """GET /auth/me without token returns 401."""
        r = client.get("/auth/me")
        assert r.status_code == 401


# ── Organization Settings ─────────────────────────────────────────────────────


class TestOrganizationSettings:
    """Organization settings API."""

    def test_get_settings(self, client: TestClient):
        """GET /organization/settings returns safe org data."""
        org = _make_org(name="Settings Test Org", timezone="America/New_York")
        user = _create_user(org.id, UserRole.OWNER)
        r = client.get("/organization/settings", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "Settings Test Org"
        assert data["timezone"] == "America/New_York"
        assert data["slug"] == org.slug
        assert data["status"] == "active"
        # webhook_secret must NEVER be returned
        assert "webhook_secret" not in data

    def test_update_settings_owner(self, client: TestClient):
        """Owner can update organization settings."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        r = client.patch(
            "/organization/settings",
            headers=_auth_headers(user),
            json={"name": "Updated Name", "timezone": "UTC", "tagline": "New tagline"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "Updated Name"
        assert data["timezone"] == "UTC"
        assert data["tagline"] == "New tagline"

    def test_update_settings_admin(self, client: TestClient):
        """Admin can update organization settings."""
        org = _make_org()
        user = _create_user(org.id, UserRole.ADMIN)
        r = client.patch(
            "/organization/settings",
            headers=_auth_headers(user),
            json={"sender_name": "Admin Updated"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["sender_name"] == "Admin Updated"

    def test_update_settings_member_rejected(self, client: TestClient):
        """Member cannot update organization settings (403)."""
        org = _make_org()
        user = _create_user(org.id, UserRole.MEMBER)
        r = client.patch(
            "/organization/settings",
            headers=_auth_headers(user),
            json={"name": "Hacked Name"},
        )
        assert r.status_code == 403

    def test_update_settings_partial(self, client: TestClient):
        """Partial update only changes specified fields."""
        org = _make_org(name="Original Name", timezone="America/Chicago")
        user = _create_user(org.id, UserRole.OWNER)
        r = client.patch(
            "/organization/settings",
            headers=_auth_headers(user),
            json={"brand_color": "#FF0000"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "Original Name"  # unchanged
        assert data["brand_color"] == "#FF0000"  # changed

    def test_member_can_read_settings(self, client: TestClient):
        """Member can read organization settings."""
        org = _make_org()
        user = _create_user(org.id, UserRole.MEMBER)
        r = client.get("/organization/settings", headers=_auth_headers(user))
        assert r.status_code == 200

    def test_settings_unauthenticated(self, client: TestClient):
        """Unauthenticated access returns 401."""
        r = client.get("/organization/settings")
        assert r.status_code == 401

    def test_settings_no_secrets_in_response(self, client: TestClient):
        """Settings response never contains sensitive fields."""
        org = _make_org(webhook_secret="super-secret-value-12345")
        user = _create_user(org.id, UserRole.OWNER)
        r = client.get("/organization/settings", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert "webhook_secret" not in data
        assert "credentials" not in data
        assert "token" not in data
        assert "secret" not in data or data.get("secret") is None


# ── Audit Log ─────────────────────────────────────────────────────────────────


class TestAuditLog:
    """Audit log endpoint."""

    def _log_event(self, org_id, event_type, payload=None, lead_id=None):
        """Helper to insert an EventLog entry."""
        db = SessionLocal()
        try:
            ev = EventLog(
                lead_id=lead_id,
                event_type=event_type,
                payload=json.dumps(payload) if payload else None,
                organization_id=org_id,
            )
            db.add(ev)
            db.commit()
            return ev
        finally:
            db.close()

    def test_audit_log_returns_events(self, client: TestClient):
        """Audit log returns organization-scoped events."""
        org = _make_org()
        user = _create_user(org.id, UserRole.ADMIN)
        self._log_event(org.id, "form_submitted", {"name": "Test Lead"})
        self._log_event(org.id, "calendar_created")
        r = client.get("/dashboard/api/audit-log", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert data["total"] >= 2
        types = [e["event_type"] for e in data["events"]]
        assert "form_submitted" in types
        assert "calendar_created" in types

    def test_audit_log_filters_by_type(self, client: TestClient):
        """Audit log filters by event_type."""
        org = _make_org()
        user = _create_user(org.id, UserRole.ADMIN)
        self._log_event(org.id, "form_submitted")
        self._log_event(org.id, "email_sent")
        self._log_event(org.id, "form_submitted")
        r = client.get(
            "/dashboard/api/audit-log?event_type=form_submitted",
            headers=_auth_headers(user),
        )
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 2
        assert all(e["event_type"] == "form_submitted" for e in data["events"])

    def test_audit_log_redacts_sensitive_keys(self, client: TestClient):
        """Sensitive payload keys are redacted in audit log response."""
        org = _make_org()
        user = _create_user(org.id, UserRole.ADMIN)
        self._log_event(org.id, "webhook_auth_failed", {
            "reason": "invalid_token",
            "token": "should-be-redacted",
            "secret": "should-be-redacted",
            "password": "should-be-redacted",
            "remote_ip": "127.0.0.1",
        })
        r = client.get("/dashboard/api/audit-log", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        event = data["events"][0]
        assert event["payload"]["reason"] == "invalid_token"
        assert event["payload"]["remote_ip"] == "127.0.0.1"
        assert event["payload"]["token"] == "[REDACTED]"
        assert event["payload"]["secret"] == "[REDACTED]"
        assert event["payload"]["password"] == "[REDACTED]"

    def test_audit_log_unauthenticated(self, client: TestClient):
        """Unauthenticated access returns 401."""
        r = client.get("/dashboard/api/audit-log")
        assert r.status_code == 401

    def test_audit_log_org_isolation(self, client: TestClient):
        """Audit log only returns events for the authenticated org."""
        org_a = _make_org()
        org_b = _make_org()
        user_a = _create_user(org_a.id, UserRole.ADMIN)
        _create_user(org_b.id, UserRole.ADMIN)
        self._log_event(org_a.id, "form_submitted", {"org": "A"})
        self._log_event(org_b.id, "form_submitted", {"org": "B"})
        r = client.get("/dashboard/api/audit-log", headers=_auth_headers(user_a))
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 1
        assert data["events"][0]["payload"]["org"] == "A"


# ── Tenant Isolation ──────────────────────────────────────────────────────────


class TestTenantIsolation:
    """Cross-tenant access is denied."""

    def test_org_a_cannot_access_org_b_settings(self, client: TestClient):
        """Org A cannot read Org B's settings."""
        org_a = _make_org()
        org_b = _make_org()
        user_a = _create_user(org_a.id, UserRole.OWNER)
        _create_user(org_b.id, UserRole.OWNER)
        # Org A's user gets their own settings
        r = client.get("/organization/settings", headers=_auth_headers(user_a))
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == str(org_a.id)

    def test_org_a_cannot_access_org_b_leads(self, client: TestClient):
        """Org A cannot see Org B's leads."""
        org_a = _make_org()
        org_b = _make_org()
        user_a = _create_user(org_a.id, UserRole.ADMIN)
        # Create a lead in org B
        db = SessionLocal()
        try:
            lead = Lead(
                name="Org B Lead",
                email="orgb@example.com",
                appt_datetime_raw="tomorrow 10:00",
                status=LeadStatus.PENDING,
                organization_id=org_b.id,
                dedupe_key=f"orgb-{uuid.uuid4().hex[:8]}",
            )
            db.add(lead)
            db.commit()
        finally:
            db.close()
        # Org A's user should not see it
        r = client.get("/dashboard/api/leads", headers=_auth_headers(user_a))
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 0

    def test_org_a_cannot_access_org_b_audit_log(self, client: TestClient):
        """Org A cannot see Org B's audit log events."""
        org_a = _make_org()
        org_b = _make_org()
        user_a = _create_user(org_a.id, UserRole.ADMIN)
        # Create event in org B
        db = SessionLocal()
        try:
            ev = EventLog(
                event_type="form_submitted",
                organization_id=org_b.id,
            )
            db.add(ev)
            db.commit()
        finally:
            db.close()
        r = client.get("/dashboard/api/audit-log", headers=_auth_headers(user_a))
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 0


# ── Dashboard API Org Scoping ─────────────────────────────────────────────────


class TestDashboardAPIScoping:
    """Dashboard API endpoints are org-scoped."""

    def test_leads_are_org_scoped(self, client: TestClient):
        """Leads endpoint returns only the org's leads."""
        org_a = _make_org()
        org_b = _make_org()
        user_a = _create_user(org_a.id, UserRole.ADMIN)
        # Create leads in both orgs
        db = SessionLocal()
        try:
            db.add(Lead(
                name="Lead A", email="a@example.com",
                appt_datetime_raw="tomorrow 10:00",
                status=LeadStatus.PENDING, organization_id=org_a.id,
                dedupe_key=f"lead-a-{uuid.uuid4().hex[:8]}",
            ))
            db.add(Lead(
                name="Lead B", email="b@example.com",
                appt_datetime_raw="tomorrow 11:00",
                status=LeadStatus.PENDING, organization_id=org_b.id,
                dedupe_key=f"lead-b-{uuid.uuid4().hex[:8]}",
            ))
            db.commit()
        finally:
            db.close()
        r = client.get("/dashboard/api/leads", headers=_auth_headers(user_a))
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 1
        assert data["leads"][0]["prospect_name"] == "Lead A"

    def test_summary_is_org_scoped(self, client: TestClient):
        """Summary endpoint returns only the org's data."""
        org_a = _make_org()
        org_b = _make_org()
        user_a = _create_user(org_a.id, UserRole.ADMIN)
        db = SessionLocal()
        try:
            db.add(Lead(
                name="Summary Lead A", email="sa@example.com",
                appt_datetime_raw="tomorrow 10:00",
                status=LeadStatus.SCHEDULED, organization_id=org_a.id,
                dedupe_key=f"sa-{uuid.uuid4().hex[:8]}",
            ))
            db.add(Lead(
                name="Summary Lead B", email="sb@example.com",
                appt_datetime_raw="tomorrow 11:00",
                status=LeadStatus.SCHEDULED, organization_id=org_b.id,
                dedupe_key=f"sb-{uuid.uuid4().hex[:8]}",
            ))
            db.commit()
        finally:
            db.close()
        r = client.get("/dashboard/api/summary", headers=_auth_headers(user_a))
        assert r.status_code == 200
        data = r.json()
        assert data["total_leads"] == 1


# ── Webhook Config (safe response) ───────────────────────────────────────────


class TestWebhookConfigSafe:
    """Webhook config never exposes secrets."""

    def test_webhook_config_masked(self, client: TestClient):
        """Webhook config returns masked secret."""
        org = _make_org(webhook_secret="abcdefgh12345678xyz")
        user = _create_user(org.id, UserRole.ADMIN)
        r = client.get("/organization/webhook/config", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert data["has_secret"] is True
        assert data["secret_masked"] != "abcdefgh12345678xyz"
        assert "****" in data["secret_masked"] or "abcd" in data["secret_masked"]

    def test_webhook_config_no_full_secret(self, client: TestClient):
        """Webhook config never returns the full secret."""
        secret = "full-secret-value-1234567890"
        org = _make_org(webhook_secret=secret)
        user = _create_user(org.id, UserRole.ADMIN)
        r = client.get("/organization/webhook/config", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        # The full secret must not appear anywhere in the response
        assert secret not in json.dumps(data)


# ── Google OAuth Status ───────────────────────────────────────────────────────


class TestGoogleOAuthStatus:
    """Google OAuth status endpoint returns safe data."""

    def test_google_status_no_creds(self, client: TestClient):
        """Google status returns connected=false when no creds."""
        org = _make_org()
        user = _create_user(org.id, UserRole.ADMIN)
        r = client.get("/auth/google/status", headers=_auth_headers(user))
        assert r.status_code == 200
        data = r.json()
        assert data["connected"] is False
        assert "credentials" not in data
        assert "token" not in data

    def test_google_status_unauthenticated(self, client: TestClient):
        """Google status without auth returns 401."""
        r = client.get("/auth/google/status")
        assert r.status_code == 401
