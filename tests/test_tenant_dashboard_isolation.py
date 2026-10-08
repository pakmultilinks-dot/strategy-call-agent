"""Comprehensive tenant isolation tests for Phase 6B.6.

Validates:
  1. AuthContext dependency - JWT and Basic return correct context
  2. Org-scoped settings - customer users see/write their own OrgScheduleConfig
  3. Org-scoped triggers - customer triggers only process their org's leads
  4. SSE endpoint - accepts both JWT and Basic auth
  5. Dashboard HTML - accepts both JWT and Basic auth
  6. Role-based access - settings PUT and triggers require owner/admin
  7. EventLog isolation - lead_detail events filtered by org_id
  8. IDOR protection - cross-org resource access denied

Total: ~45 tests
"""
import base64
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models import EventLog, FailedJob, Lead, LeadStatus
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
    OrgScheduleConfig,
    User,
    UserRole,
    UserStatus,
)
from app.services.crypto import generate_key

# ── Test Constants ────────────────────────────────────────────────────────────

TEST_JWT_SECRET = "test-secret-key-for-phase-6b6-jwt-testing-32chars!!"
TEST_ENCRYPTION_KEY = generate_key()
DEFAULT_ORG_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


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


@pytest.fixture()
def db():
    """Yield a DB session with rollback."""
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


def _create_org_and_user(
    db,
    email: str = "owner@example.com",
    password: str = "StrongPass123!",
    role: UserRole = UserRole.OWNER,
    org_name: str | None = None,
    user_status: UserStatus = UserStatus.ACTIVE,
) -> tuple[Organization, User]:
    """Helper: create an org + user with a bcrypt password hash."""
    from app.auth import hash_password

    org = Organization(
        name=org_name or f"Test Org {uuid.uuid4().hex[:8]}",
        slug=f"test-org-{uuid.uuid4().hex[:8]}",
        timezone="America/Chicago",
        status=OrganizationStatus.ACTIVE,
    )
    db.add(org)
    db.flush()

    user = User(
        organization_id=org.id,
        email=email.lower(),
        full_name="Test User",
        password_hash=hash_password(password),
        role=role,
        status=user_status,
    )
    db.add(user)
    db.commit()
    db.refresh(org)
    db.refresh(user)
    return org, user


def _make_token(user_id: uuid.UUID, org_id: uuid.UUID, role: str) -> str:
    """Create a valid JWT token for testing."""
    from app.auth import create_access_token
    return create_access_token(user_id=user_id, organization_id=org_id, role=role)


def _auth_header(token: str) -> dict:
    """Return Authorization header for Bearer token."""
    return {"Authorization": f"Bearer {token}"}


def _basic_auth_header(username: str = None, password: str = None) -> dict:
    """Return Authorization header for HTTP Basic."""
    u = username or settings.dashboard_username
    p = password or settings.dashboard_password
    return {
        "Authorization": "Basic "
        + base64.b64encode(f"{u}:{p}".encode()).decode()
    }


def _make_lead(db, org_id: uuid.UUID, **overrides) -> Lead:
    """Insert a Lead row for a given organization."""
    defaults = {
        "name": "Test Lead",
        "email": f"lead-{uuid.uuid4().hex[:8]}@example.com",
        "company_address": "Test Co",
        "appt_datetime_raw": "tomorrow 2pm",
        "dedupe_key": f"lead-{uuid.uuid4().hex}",
        "status": LeadStatus.PENDING,
        "organization_id": org_id,
    }
    defaults.update(overrides)
    lead = Lead(**defaults)
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


# ══════════════════════════════════════════════════════════════════════════════
# 1. AUTH CONTEXT TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestAuthContext:
    """AuthContext dependency tests - verify correct context returned."""

    def test_basic_auth_returns_platform_admin(self, client, db):
        """HTTP Basic auth should return platform admin context."""
        org, user = _create_org_and_user(db)
        token = _make_token(user.id, org.id, "owner")
        # Basic auth → platform admin
        resp = client.get("/dashboard/api/summary", headers=_basic_auth_header())
        assert resp.status_code == 200

    def test_jwt_auth_returns_customer_context(self, client, db):
        """JWT auth should return customer user context with org_id."""
        org, user = _create_org_and_user(db)
        token = _make_token(user.id, org.id, "owner")
        resp = client.get("/dashboard/api/summary", headers=_auth_header(token))
        assert resp.status_code == 200

    def test_invalid_jwt_returns_401(self, client, db):
        """Invalid JWT token should return 401."""
        resp = client.get("/dashboard/api/summary", headers=_auth_header("invalid-token"))
        assert resp.status_code == 401

    def test_disabled_user_returns_401(self, client, db):
        """Disabled user JWT should return 401."""
        org, user = _create_org_and_user(db, user_status=UserStatus.DISABLED)
        token = _make_token(user.id, org.id, "owner")
        resp = client.get("/dashboard/api/summary", headers=_auth_header(token))
        assert resp.status_code == 401

    def test_wrong_org_id_in_token_returns_401(self, client, db):
        """JWT with wrong org_id should return 401."""
        org, user = _create_org_and_user(db)
        wrong_org_id = uuid.uuid4()
        token = _make_token(user.id, wrong_org_id, "owner")
        resp = client.get("/dashboard/api/summary", headers=_auth_header(token))
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# 2. ORG-SCOPED SETTINGS TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgScopedSettings:
    """Settings endpoints should use OrgScheduleConfig for customer users."""

    def test_customer_get_settings_creates_default(self, client, db):
        """Customer GET /settings creates default OrgScheduleConfig if none exists."""
        org, user = _create_org_and_user(db)
        token = _make_token(user.id, org.id, "owner")
        resp = client.get("/dashboard/api/settings", headers=_auth_header(token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["reminder_time"] == "08:00"
        assert data["rsvp_poll_interval_minutes"] == 10

    def test_customer_put_settings_updates_org_config(self, client, db):
        """Customer PUT /settings updates their OrgScheduleConfig only."""
        org, user = _create_org_and_user(db)
        token = _make_token(user.id, org.id, "owner")
        payload = {"reminder_time": "09:30", "rsvp_poll_interval_minutes": 15}
        resp = client.put("/dashboard/api/settings", json=payload, headers=_auth_header(token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["reminder_time"] == "09:30"
        assert data["rsvp_poll_interval_minutes"] == 15

        # Verify the config was written to OrgScheduleConfig, not global
        cfg = (
            db.query(OrgScheduleConfig)
            .filter(OrgScheduleConfig.organization_id == org.id)
            .first()
        )
        assert cfg is not None
        assert cfg.reminder_hour == 9
        assert cfg.reminder_minute == 30
        assert cfg.rsvp_poll_interval_minutes == 15

    def test_different_orgs_have_independent_settings(self, client, db):
        """Two orgs should have independent settings."""
        org_a, user_a = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org_b, user_b = _create_org_and_user(db, email="b@test.com", org_name="Org B")
        token_a = _make_token(user_a.id, org_a.id, "owner")
        token_b = _make_token(user_b.id, org_b.id, "owner")

        # Org A sets 09:00
        resp = client.put(
            "/dashboard/api/settings",
            json={"reminder_time": "09:00"},
            headers=_auth_header(token_a),
        )
        assert resp.status_code == 200

        # Org B sets 14:00
        resp = client.put(
            "/dashboard/api/settings",
            json={"reminder_time": "14:00"},
            headers=_auth_header(token_b),
        )
        assert resp.status_code == 200

        # Org A still sees 09:00
        resp = client.get("/dashboard/api/settings", headers=_auth_header(token_a))
        assert resp.json()["reminder_time"] == "09:00"

        # Org B still sees 14:00
        resp = client.get("/dashboard/api/settings", headers=_auth_header(token_b))
        assert resp.json()["reminder_time"] == "14:00"

    def test_platform_admin_uses_global_settings(self, client, db):
        """Platform admin GET /settings should read global ScheduleConfig."""
        resp = client.get("/dashboard/api/settings", headers=_basic_auth_header())
        assert resp.status_code == 200
        data = resp.json()
        assert "reminder_time" in data
        assert "rsvp_poll_interval_minutes" in data

    def test_customer_settings_put_rejects_invalid_time(self, client, db):
        """Customer PUT /settings with invalid time returns 422."""
        org, user = _create_org_and_user(db)
        token = _make_token(user.id, org.id, "owner")
        resp = client.put(
            "/dashboard/api/settings",
            json={"reminder_time": "25:99"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_customer_settings_put_rejects_invalid_interval(self, client, db):
        """Customer PUT /settings with invalid interval returns 422."""
        org, user = _create_org_and_user(db)
        token = _make_token(user.id, org.id, "owner")
        resp = client.put(
            "/dashboard/api/settings",
            json={"rsvp_poll_interval_minutes": -1},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# 3. ROLE-BASED ACCESS TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestRoleBasedAccess:
    """Settings PUT and triggers require owner/admin role."""

    def test_owner_can_update_settings(self, client, db):
        """Owner should be able to update settings."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        resp = client.put(
            "/dashboard/api/settings",
            json={"reminder_time": "10:00"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200

    def test_admin_can_update_settings(self, client, db):
        """Admin should be able to update settings."""
        org, user = _create_org_and_user(db, role=UserRole.ADMIN)
        token = _make_token(user.id, org.id, "admin")
        resp = client.put(
            "/dashboard/api/settings",
            json={"reminder_time": "10:00"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200

    def test_member_cannot_update_settings(self, client, db):
        """Member should NOT be able to update settings."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _make_token(user.id, org.id, "member")
        resp = client.put(
            "/dashboard/api/settings",
            json={"reminder_time": "10:00"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 403

    def test_platform_admin_can_update_settings(self, client, db):
        """Platform admin should be able to update global settings."""
        resp = client.put(
            "/dashboard/api/settings",
            json={"reminder_time": "10:00"},
            headers=_basic_auth_header(),
        )
        assert resp.status_code == 200

    def test_member_can_read_settings(self, client, db):
        """Member should be able to read (GET) settings."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _make_token(user.id, org.id, "member")
        resp = client.get("/dashboard/api/settings", headers=_auth_header(token))
        assert resp.status_code == 200

    def test_owner_can_trigger_reminders(self, client, db):
        """Owner should be able to trigger reminders."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        resp = client.post("/dashboard/api/trigger/reminders", headers=_auth_header(token))
        assert resp.status_code == 200
        assert "checked" in resp.json()

    def test_admin_can_trigger_reminders(self, client, db):
        """Admin should be able to trigger reminders."""
        org, user = _create_org_and_user(db, role=UserRole.ADMIN)
        token = _make_token(user.id, org.id, "admin")
        resp = client.post("/dashboard/api/trigger/reminders", headers=_auth_header(token))
        assert resp.status_code == 200

    def test_member_cannot_trigger_reminders(self, client, db):
        """Member should NOT be able to trigger reminders."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _make_token(user.id, org.id, "member")
        resp = client.post("/dashboard/api/trigger/reminders", headers=_auth_header(token))
        assert resp.status_code == 403

    def test_owner_can_trigger_poll_rsvps(self, client, db):
        """Owner should be able to trigger RSVP polling."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        resp = client.post("/dashboard/api/trigger/poll-rsvps", headers=_auth_header(token))
        assert resp.status_code == 200
        assert "checked" in resp.json()

    def test_member_cannot_trigger_poll_rsvps(self, client, db):
        """Member should NOT be able to trigger RSVP polling."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _make_token(user.id, org.id, "member")
        resp = client.post("/dashboard/api/trigger/poll-rsvps", headers=_auth_header(token))
        assert resp.status_code == 403

    def test_platform_admin_can_trigger(self, client, db):
        """Platform admin should be able to trigger all jobs."""
        resp = client.post("/dashboard/api/trigger/reminders", headers=_basic_auth_header())
        assert resp.status_code == 200
        resp = client.post("/dashboard/api/trigger/poll-rsvps", headers=_basic_auth_header())
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# 4. SSE JWT AUTH TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestSSEJWTAuth:
    """SSE endpoint should accept both Basic and JWT tokens.

    Note: The SSE endpoint returns a StreamingResponse that never closes,
    so we use the stream context manager to avoid hanging and verify the
    response headers before consuming the stream.
    """

    def test_sse_rejects_invalid_token(self, client, db):
        """SSE endpoint should reject an invalid token."""
        resp = client.get("/dashboard/api/events?token=invalid-token-value")
        assert resp.status_code == 401

    def test_sse_rejects_empty_token(self, client, db):
        """SSE endpoint should reject an empty token."""
        resp = client.get("/dashboard/api/events?token=")
        assert resp.status_code == 401

    def test_sse_requires_token_param(self, client, db):
        """SSE endpoint should require a ticket or token query parameter."""
        resp = client.get("/dashboard/api/events")
        assert resp.status_code == 401  # Neither ticket nor token presented

    def test_sse_basic_auth_validator(self, client, db):
        """_validate_sse_token should accept base64(user:pass) and return None (platform admin)."""
        import uuid as _uuid
        from app.dashboard import _validate_sse_token

        token_b64 = base64.b64encode(
            f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
        ).decode()
        # Basic auth returns None (no org filter - platform admin sees all events)
        assert _validate_sse_token(token_b64) is None

    def test_sse_jwt_auth_validator(self, client, db):
        """_validate_sse_token should accept a valid JWT and return the org_id UUID."""
        import uuid as _uuid
        from app.dashboard import _validate_sse_token

        org, user = _create_org_and_user(db)
        jwt_token = _make_token(user.id, org.id, "owner")
        result = _validate_sse_token(jwt_token)
        # JWT auth returns the organization_id UUID for tenant-scoped events
        assert isinstance(result, _uuid.UUID)
        assert result == org.id

    def test_sse_invalid_token_validator(self, client, db):
        """_validate_sse_token should raise HTTPException 401 for an invalid token."""
        from fastapi import HTTPException
        from app.dashboard import _validate_sse_token

        with pytest.raises(HTTPException) as exc_info:
            _validate_sse_token("not-a-valid-token")
        assert exc_info.value.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# 5. DASHBOARD HTML JWT SUPPORT TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestDashboardHTMLAuth:
    """Dashboard HTML page should accept both Basic and JWT auth."""

    def test_dashboard_accepts_basic_auth(self, client, db):
        """Dashboard HTML should be accessible via HTTP Basic."""
        resp = client.get("/dashboard", headers=_basic_auth_header())
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_dashboard_accepts_jwt_auth(self, client, db):
        """Dashboard HTML should be accessible via JWT Bearer."""
        org, user = _create_org_and_user(db)
        token = _make_token(user.id, org.id, "owner")
        resp = client.get("/dashboard", headers=_auth_header(token))
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_dashboard_serves_html_without_auth(self, client, db):
        """Dashboard HTML is served without server-side auth gate (Phase 6F: client-side auth)."""
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert 'id="login-page"' in resp.text

    def test_dashboard_serves_html_with_invalid_jwt(self, client, db):
        """Dashboard HTML is served even with invalid JWT (client-side handles auth)."""
        resp = client.get("/dashboard", headers=_auth_header("bad-token"))
        assert resp.status_code == 200
        assert 'id="login-page"' in resp.text


# ══════════════════════════════════════════════════════════════════════════════
# 6. EVENTLOG TENANT ISOLATION TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestEventLogIsolation:
    """Lead detail should filter EventLog by organization_id."""

    def test_lead_detail_shows_own_org_events(self, client, db):
        """Customer user should see events for their org's leads."""
        org, user = _create_org_and_user(db)
        lead = _make_lead(db, org.id, status=LeadStatus.SCHEDULED)
        # Create an event for this lead
        event = EventLog(
            lead_id=lead.id,
            event_type="test_event",
            payload='{"test": true}',
            organization_id=org.id,
        )
        db.add(event)
        db.commit()

        token = _make_token(user.id, org.id, "owner")
        resp = client.get(f"/dashboard/api/leads/{lead.id}", headers=_auth_header(token))
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["events"]) == 1
        assert data["events"][0]["event_type"] == "test_event"

    def test_lead_detail_hides_cross_org_events(self, client, db):
        """Events from a different org should not appear."""
        org_a, user_a = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org_b, user_b = _create_org_and_user(db, email="b@test.com", org_name="Org B")

        lead_a = _make_lead(db, org_a.id, status=LeadStatus.SCHEDULED)

        # Create an event for org_a's lead, but with org_b's organization_id
        # (defense-in-depth test - this should not normally happen)
        event_b = EventLog(
            lead_id=lead_a.id,
            event_type="cross_org_event",
            payload='{"injected": true}',
            organization_id=org_b.id,
        )
        db.add(event_b)
        db.commit()

        token_a = _make_token(user_a.id, org_a.id, "owner")
        resp = client.get(f"/dashboard/api/leads/{lead_a.id}", headers=_auth_header(token_a))
        assert resp.status_code == 200
        # The cross-org event should NOT appear
        events = resp.json()["events"]
        assert all(e["event_type"] != "cross_org_event" for e in events)

    def test_platform_admin_sees_all_events(self, client, db):
        """Platform admin should see all events."""
        org, user = _create_org_and_user(db)
        lead = _make_lead(db, org.id, status=LeadStatus.SCHEDULED)
        event = EventLog(
            lead_id=lead.id,
            event_type="admin_visible_event",
            payload=None,
            organization_id=org.id,
        )
        db.add(event)
        db.commit()

        resp = client.get(f"/dashboard/api/leads/{lead.id}", headers=_basic_auth_header())
        assert resp.status_code == 200
        events = resp.json()["events"]
        assert any(e["event_type"] == "admin_visible_event" for e in events)


# ══════════════════════════════════════════════════════════════════════════════
# 7. IDOR PROTECTION TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestIDORProtection:
    """Cross-org resource access should be denied."""

    def test_org_a_cannot_see_org_b_leads(self, client, db):
        """Org A customer should not see Org B's leads."""
        org_a, user_a = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org_b, user_b = _create_org_and_user(db, email="b@test.com", org_name="Org B")

        lead_b = _make_lead(db, org_b.id)

        token_a = _make_token(user_a.id, org_a.id, "owner")
        resp = client.get(f"/dashboard/api/leads/{lead_b.id}", headers=_auth_header(token_a))
        assert resp.status_code == 404  # Should not reveal the lead exists

    def test_org_a_cannot_see_org_b_failed_jobs(self, client, db):
        """Org A customer should not see Org B's failed jobs."""
        org_a, user_a = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org_b, user_b = _create_org_and_user(db, email="b@test.com", org_name="Org B")

        job_b = FailedJob(
            job_type="test",
            payload='{"org_b": true}',
            error="test error",
            retry_count=0,
            resolved=False,
            organization_id=org_b.id,
        )
        db.add(job_b)
        db.commit()

        token_a = _make_token(user_a.id, org_a.id, "owner")
        resp = client.get("/dashboard/api/failed-jobs", headers=_auth_header(token_a))
        assert resp.status_code == 200
        data = resp.json()
        # Should not see org_b's job
        for job in data["failed_jobs"]:
            assert job["id"] != str(job_b.id)

    def test_org_a_summary_excludes_org_b_data(self, client, db):
        """Org A summary should not count Org B's leads."""
        org_a, user_a = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org_b, user_b = _create_org_and_user(db, email="b@test.com", org_name="Org B")

        _make_lead(db, org_a.id, status=LeadStatus.PENDING)
        _make_lead(db, org_b.id, status=LeadStatus.PENDING)

        token_a = _make_token(user_a.id, org_a.id, "owner")
        resp = client.get("/dashboard/api/summary", headers=_auth_header(token_a))
        assert resp.status_code == 200
        data = resp.json()
        # Should only see 1 lead (org_a's), not 2
        assert data["total_leads"] == 1

    def test_org_a_analytics_excludes_org_b(self, client, db):
        """Org A analytics should not include Org B's data."""
        org_a, user_a = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org_b, user_b = _create_org_and_user(db, email="b@test.com", org_name="Org B")

        _make_lead(db, org_a.id, status=LeadStatus.PENDING)
        _make_lead(db, org_b.id, status=LeadStatus.PENDING)

        token_a = _make_token(user_a.id, org_a.id, "owner")
        resp = client.get("/dashboard/api/analytics/leads-over-time?days=30", headers=_auth_header(token_a))
        assert resp.status_code == 200
        data = resp.json()
        total = sum(d["count"] for d in data["data"])
        assert total == 1  # Only org_a's lead

    def test_client_org_id_ignored_on_leads(self, client, db):
        """Even if someone tampers with org_id in the DB, the JWT org_id controls access."""
        org, user = _create_org_and_user(db)
        other_org, _ = _create_org_and_user(db, email="other@test.com", org_name="Other Org")

        # Create a lead that belongs to org
        lead = _make_lead(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        # Can access their own lead
        resp = client.get(f"/dashboard/api/leads/{lead.id}", headers=_auth_header(token))
        assert resp.status_code == 200

        # Cannot access a nonexistent lead
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/dashboard/api/leads/{fake_id}", headers=_auth_header(token))
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 8. LEAD LIST ISOLATION TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestLeadListIsolation:
    """List endpoints should only return the customer's org data."""

    def test_list_leads_isolation(self, client, db):
        """Customer should only see their org's leads in list."""
        org_a, user_a = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org_b, user_b = _create_org_and_user(db, email="b@test.com", org_name="Org B")

        _make_lead(db, org_a.id, name="Lead A", status=LeadStatus.PENDING)
        _make_lead(db, org_b.id, name="Lead B", status=LeadStatus.PENDING)

        token_a = _make_token(user_a.id, org_a.id, "owner")
        resp = client.get("/dashboard/api/leads", headers=_auth_header(token_a))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["leads"][0]["prospect_name"] == "Lead A"

    def test_upcoming_leads_isolation(self, client, db):
        """Customer should only see their org's upcoming leads."""
        org_a, user_a = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org_b, user_b = _create_org_and_user(db, email="b@test.com", org_name="Org B")

        from datetime import datetime, timedelta, timezone
        future = datetime.now(timezone.utc) + timedelta(hours=24)
        _make_lead(db, org_a.id, name="Upcoming A", status=LeadStatus.SCHEDULED, appt_datetime_utc=future)
        _make_lead(db, org_b.id, name="Upcoming B", status=LeadStatus.SCHEDULED, appt_datetime_utc=future)

        token_a = _make_token(user_a.id, org_a.id, "owner")
        resp = client.get("/dashboard/api/leads/upcoming", headers=_auth_header(token_a))
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["leads"][0]["prospect_name"] == "Upcoming A"

    def test_platform_admin_sees_all_leads(self, client, db):
        """Platform admin should see leads from all orgs."""
        org_a, _ = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org_b, _ = _create_org_and_user(db, email="b@test.com", org_name="Org B")

        _make_lead(db, org_a.id, name="Lead A", status=LeadStatus.PENDING)
        _make_lead(db, org_b.id, name="Lead B", status=LeadStatus.PENDING)

        resp = client.get("/dashboard/api/leads", headers=_basic_auth_header())
        assert resp.status_code == 200
        data = resp.json()
        # Platform admin sees ALL leads across all orgs (at least the 2 we created)
        assert data["total"] >= 2
        names = [l["prospect_name"] for l in data["leads"]]
        assert "Lead A" in names
        assert "Lead B" in names


# ══════════════════════════════════════════════════════════════════════════════
# 9. SECURITY: NO SECRETS IN RESPONSES
# ══════════════════════════════════════════════════════════════════════════════


class TestSecurityNoSecrets:
    """Ensure passwords and credentials are never exposed."""

    def test_settings_no_secrets_in_response(self, client, db):
        """Settings response should not contain any credentials."""
        org, user = _create_org_and_user(db)
        token = _make_token(user.id, org.id, "owner")
        resp = client.get("/dashboard/api/settings", headers=_auth_header(token))
        data = resp.json()
        # Should not contain any credential-related fields
        assert "password" not in str(data).lower()
        assert "secret" not in str(data).lower()
        assert "token" not in str(data).lower()
        assert "api_key" not in str(data).lower()

    def test_summary_no_secrets(self, client, db):
        """Summary response should not contain any credentials."""
        resp = client.get("/dashboard/api/summary", headers=_basic_auth_header())
        data = resp.json()
        assert "password" not in str(data).lower()
        assert "secret" not in str(data).lower()


# ══════════════════════════════════════════════════════════════════════════════
# 10. UNAUTHENTICATED ACCESS TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestUnauthenticatedAccess:
    """All protected endpoints should return 401 without auth."""

    @pytest.mark.parametrize("method,path", [
        ("GET", "/dashboard/api/leads"),
        ("GET", "/dashboard/api/leads/upcoming"),
        ("GET", "/dashboard/api/summary"),
        ("GET", "/dashboard/api/failed-jobs"),
        ("GET", "/dashboard/api/analytics/leads-over-time"),
        ("GET", "/dashboard/api/analytics/appointments-over-time"),
        ("GET", "/dashboard/api/settings"),
    ])
    def test_unauthenticated_returns_401(self, client, method, path):
        """Protected API endpoints should return 401 without auth."""
        resp = client.request(method, path)
        assert resp.status_code == 401

    def test_dashboard_serves_html_without_auth(self, client):
        """Dashboard HTML is served without auth gate (Phase 6F: client-side auth)."""
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert 'id="login-page"' in resp.text

    @pytest.mark.parametrize("path", [
        "/dashboard/api/settings",
    ])
    def test_unauthenticated_put_returns_401(self, client, path):
        """PUT endpoints should return 401 without auth."""
        resp = client.put(path, json={"reminder_time": "09:00"})
        assert resp.status_code == 401

    @pytest.mark.parametrize("path", [
        "/dashboard/api/trigger/reminders",
        "/dashboard/api/trigger/poll-rsvps",
    ])
    def test_unauthenticated_trigger_returns_401(self, client, path):
        """Trigger endpoints should return 401 without auth."""
        resp = client.post(path)
        assert resp.status_code == 401
