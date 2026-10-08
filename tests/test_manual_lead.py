"""Tests for Manual Lead Entry - POST /dashboard/api/leads.

Covers:
  1. Authorized creation (owner/admin can create leads)
  2. RBAC - member rejected with 403
  3. Missing required fields rejected (422)
  4. Invalid email rejected (422)
  5. Duplicate lead rejected (409)
  6. Response format validation
  7. DB persistence verification
  8. Unauthenticated access rejected (401)
  9. Platform admin can create leads
 10. Cross-org isolation (org A can't see org B's leads)
"""
import uuid

import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.models import Lead, LeadStatus
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)
from tests.test_auth import (
    _auth_header,
    _create_org_and_user,
    _make_token,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def client():
    """TestClient with lifespan support."""
    from app.main import app
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


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_valid_payload(**overrides):
    """Return a valid manual lead creation payload."""
    payload = {
        "name": "Test Prospect",
        "email": f"test-{uuid.uuid4().hex[:8]}@example.com",
        "appt_datetime_raw": "tomorrow 2pm",
    }
    payload.update(overrides)
    return payload


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestCreateLeadAuthorized:
    """POST /dashboard/api/leads - authorized creation."""

    def test_owner_can_create_lead(self, client, db):
        """Owner role should be able to create leads (201)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        payload = _make_valid_payload()
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=_auth_header(token),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "created"
        assert "lead" in data
        assert data["lead"]["prospect_name"] == "Test Prospect"
        assert data["lead"]["email"] == payload["email"]
        assert data["lead"]["status"] == "pending"

    def test_admin_can_create_lead(self, client, db):
        """Admin role should be able to create leads (201)."""
        org, user = _create_org_and_user(db, role=UserRole.ADMIN)
        token = _make_token(user.id, org.id, "admin")
        payload = _make_valid_payload()
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=_auth_header(token),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "created"

    def test_platform_admin_no_org_returns_400(self, client, auth_headers):
        """Platform admin (Basic auth) has no org context → 400."""
        payload = _make_valid_payload()
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert "Organization context required" in resp.json()["detail"]

    def test_create_lead_with_all_optional_fields(self, client, db):
        """Should accept all optional fields: phone, company, notes."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        payload = {
            "name": "Full Lead",
            "email": f"full-{uuid.uuid4().hex[:8]}@example.com",
            "appt_datetime_raw": "next Monday 10am",
            "phone_number": "555-0123",
            "company_address": "789 Elm St, Townsville",
            "notes": "VIP prospect",
        }
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=_auth_header(token),
        )
        assert resp.status_code == 201
        lead = resp.json()["lead"]
        assert lead["phone_number"] == "555-0123"
        assert lead["company_address"] == "789 Elm St, Townsville"

    def test_create_lead_response_has_expected_fields(self, client, db):
        """Response should contain all expected lead fields."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        payload = _make_valid_payload()
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=_auth_header(token),
        )
        assert resp.status_code == 201
        lead = resp.json()["lead"]
        expected_fields = [
            "id", "prospect_name", "email", "status", "company_address",
            "phone_number", "direct_number", "courses",
            "appt_datetime_utc", "appt_local",
            "calendar_event_id", "reminder_sent_at", "processing_started_at",
            "created_at", "updated_at", "organization_id",
        ]
        for field in expected_fields:
            assert field in lead, f"Missing field: {field}"

    def test_create_lead_persists_to_db(self, client, db):
        """Created lead should be persisted in the database."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        payload = _make_valid_payload()
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=_auth_header(token),
        )
        lead_id = resp.json()["lead"]["id"]
        # Verify in DB
        db_lead = db.query(Lead).filter(Lead.id == lead_id).first()
        assert db_lead is not None
        assert db_lead.name == "Test Prospect"
        assert db_lead.email == payload["email"]
        assert db_lead.organization_id == org.id
        assert db_lead.dedupe_key.startswith(f"{org.id}|manual|")
        # Note: status may change from PENDING to ERROR if the background
        # pipeline runs and fails (e.g., no Google Calendar configured).

    def test_create_lead_logs_event(self, client, db):
        """Creating a lead should log a 'manual_lead_created' event."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        payload = _make_valid_payload()
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=_auth_header(token),
        )
        lead_id = resp.json()["lead"]["id"]
        from app.models import EventLog
        events = db.query(EventLog).filter(
            EventLog.lead_id == lead_id,
            EventLog.event_type == "manual_lead_created",
        ).all()
        assert len(events) >= 1


class TestCreateLeadRBAC:
    """POST /dashboard/api/leads - role-based access control."""

    def test_member_cannot_create_lead(self, client, db):
        """Member role should be rejected with 403."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _make_token(user.id, org.id, "member")
        payload = _make_valid_payload()
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=_auth_header(token),
        )
        assert resp.status_code == 403
        assert "Insufficient permissions" in resp.json()["detail"]

    def test_unauthenticated_cannot_create_lead(self, client):
        """No auth should return 401."""
        payload = _make_valid_payload()
        resp = client.post("/dashboard/api/leads", json=payload)
        assert resp.status_code == 401


class TestCreateLeadValidation:
    """POST /dashboard/api/leads - input validation."""

    def test_missing_name_rejected(self, client, auth_headers):
        """Missing name should return 422."""
        payload = {"email": "test@example.com", "appt_datetime_raw": "tomorrow 2pm"}
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_missing_email_rejected(self, client, auth_headers):
        """Missing email should return 422."""
        payload = {"name": "Test", "appt_datetime_raw": "tomorrow 2pm"}
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_missing_appt_rejected(self, client, auth_headers):
        """Missing appointment datetime should return 422."""
        payload = {"name": "Test", "email": "test@example.com"}
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_invalid_email_rejected(self, client, auth_headers):
        """Invalid email format should return 422."""
        payload = {
            "name": "Test",
            "email": "not-an-email",
            "appt_datetime_raw": "tomorrow 2pm",
        }
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_empty_name_rejected(self, client, auth_headers):
        """Empty name should be rejected."""
        payload = {
            "name": "",
            "email": "test@example.com",
            "appt_datetime_raw": "tomorrow 2pm",
        }
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_placeholder_email_rejected(self, client, db):
        """Placeholder emails (n/a, none, -, etc.) should be rejected."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        payload = {
            "name": "Test",
            "email": "n/a",
            "appt_datetime_raw": "tomorrow 2pm",
        }
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=_auth_header(token),
        )
        assert resp.status_code == 422


class TestCreateLeadDuplicate:
    """POST /dashboard/api/leads - duplicate detection."""

    def test_duplicate_lead_returns_409(self, client, db):
        """Same email + appointment should return 409 Conflict."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        email = f"dup-{uuid.uuid4().hex[:8]}@example.com"
        payload = {
            "name": "Dup Lead",
            "email": email,
            "appt_datetime_raw": "tomorrow 2pm",
        }
        # First creation
        resp1 = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=_auth_header(token),
        )
        assert resp1.status_code == 201
        # Duplicate should fail
        resp2 = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=_auth_header(token),
        )
        assert resp2.status_code == 409
        assert "already exists" in resp2.json()["detail"]

    def test_same_email_different_appt_succeeds(self, client, db):
        """Same email with different appointment time should succeed."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        email = f"multi-{uuid.uuid4().hex[:8]}@example.com"
        # First appointment
        resp1 = client.post(
            "/dashboard/api/leads",
            json={
                "name": "Multi Lead 1",
                "email": email,
                "appt_datetime_raw": "tomorrow 2pm",
            },
            headers=_auth_header(token),
        )
        assert resp1.status_code == 201
        # Different appointment time
        resp2 = client.post(
            "/dashboard/api/leads",
            json={
                "name": "Multi Lead 2",
                "email": email,
                "appt_datetime_raw": "next Monday 10am",
            },
            headers=_auth_header(token),
        )
        assert resp2.status_code == 201


class TestCreateLeadIsolation:
    """POST /dashboard/api/leads - cross-org isolation."""

    def test_lead_belongs_to_correct_org(self, client, db):
        """Lead should be scoped to the creator's organization."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        payload = _make_valid_payload()
        resp = client.post(
            "/dashboard/api/leads",
            json=payload,
            headers=_auth_header(token),
        )
        assert resp.json()["lead"]["organization_id"] == str(org.id)

    def test_cross_org_cannot_see_lead(self, client, db):
        """Org A's leads should not appear in Org B's list."""
        # Create lead in org A
        org_a, user_a = _create_org_and_user(db, role=UserRole.OWNER)
        token_a = _make_token(user_a.id, org_a.id, "owner")
        email = f"isolated-{uuid.uuid4().hex[:8]}@example.com"
        resp = client.post(
            "/dashboard/api/leads",
            json={
                "name": "Org A Lead",
                "email": email,
                "appt_datetime_raw": "tomorrow 3pm",
            },
            headers=_auth_header(token_a),
        )
        assert resp.status_code == 201
        # Create org B and try to list leads
        org_b, user_b = _create_org_and_user(db, role=UserRole.OWNER)
        token_b = _make_token(user_b.id, org_b.id, "owner")
        list_resp = client.get(
            "/dashboard/api/leads",
            headers=_auth_header(token_b),
        )
        lead_emails = [l["email"] for l in list_resp.json()["leads"]]
        assert email not in lead_emails
