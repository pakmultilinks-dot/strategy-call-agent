"""Tests for Phase 23 CRM Router & Followup Router endpoints.

Covers:
  GET  /crm/search, /crm/stats, /crm/leads/{id}/score, /summary, /call-summary, /next-action
  GET  /followups, POST /followups, PATCH /followups/{id}, GET /followups/overdue, POST /followups/{id}/complete
"""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.models import CallOutcome, FollowUp, FollowUpPriority, FollowUpStatus, Lead, LeadStatus
from app.models_multi_tenant import Organization, OrganizationStatus, User, UserRole, UserStatus
from app.services.crypto import generate_key
from tests.test_auth import _auth_header, _create_org_and_user, _make_token


# ── Constants ─────────────────────────────────────────────────────────────────

TEST_JWT_SECRET = "test-secret-for-phase23-router-tests-32char!!"
TEST_ENCRYPTION_KEY = generate_key()


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "jwt_secret_key", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", TEST_ENCRYPTION_KEY)


@pytest.fixture()
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


@pytest.fixture()
def org_and_user(db):
    """Create an org with owner for JWT-based tests."""
    return _create_org_and_user(db)


@pytest.fixture()
def owner_token(org_and_user):
    org, user = org_and_user
    return _make_token(user.id, org.id, UserRole.OWNER.value)


@pytest.fixture()
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture()
def test_lead(db, org_and_user):
    """Insert a lead in the test org for endpoint testing."""
    org, user = org_and_user
    uid = uuid.uuid4().hex[:8]
    lead = Lead(
        organization_id=org.id,
        interested=True,
        name="Router Test Lead",
        email=f"router-{uid}@test.com",
        phone_number="555-0100",
        company_address="456 Test Ave",
        courses="Testing 101",
        caller_name="Test Caller",
        status=LeadStatus.PENDING,
        appt_datetime_raw=f"01/{uid[:4]} 10:00 AM",
        dedupe_key=f"dedupe-{uid}",
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


@pytest.fixture()
def test_lead_with_notes(db, org_and_user):
    """Lead with call notes for call-summary endpoint testing."""
    org, user = org_and_user
    uid = uuid.uuid4().hex[:8]
    lead = Lead(
        organization_id=org.id,
        interested=True,
        name="Notes Lead",
        email=f"notes-{uid}@test.com",
        phone_number="555-0200",
        company_address="789 Notes Rd",
        courses="Advanced Testing",
        status=LeadStatus.SCHEDULED,
        call_notes="Discussed enterprise pricing. Prospect interested in 50-seat license.",
        call_outcome=CallOutcome.CONNECTED,
        call_duration_minutes=25,
        appt_datetime_raw=f"01/{uid[:4]} 10:00 AM",
        dedupe_key=f"dedupe-notes-{uid}",
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


# ══════════════════════════════════════════════════════════════════════════════
# 1. CRM ROUTER — /crm/search
# ══════════════════════════════════════════════════════════════════════════════


class TestCrmSearchEndpoint:
    """GET /crm/search endpoint tests."""

    def test_search_returns_leads(self, client, owner_headers, test_lead):
        """Search returns leads for authenticated org."""
        resp = client.get("/crm/search", headers=owner_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "leads" in data
        assert data["total"] >= 1

    def test_search_with_query(self, client, owner_headers, test_lead):
        """Search with query string filters results."""
        resp = client.get("/crm/search?q=Router", headers=owner_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

    def test_search_with_status_filter(self, client, owner_headers, test_lead):
        """Search with status filter."""
        resp = client.get("/crm/search?status=pending", headers=owner_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

    def test_search_requires_org(self, client):
        """Search without auth returns 401/403."""
        resp = client.get("/crm/search")
        assert resp.status_code in (401, 403)

    def test_search_pagination(self, client, owner_headers, test_lead):
        """Search respects limit/offset params."""
        resp = client.get("/crm/search?limit=1&offset=0", headers=owner_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["limit"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# 2. CRM ROUTER — /crm/stats
# ══════════════════════════════════════════════════════════════════════════════


class TestCrmStatsEndpoint:
    """GET /crm/stats endpoint tests."""

    def test_stats_returns_data(self, client, owner_headers):
        """Stats endpoint returns aggregate data."""
        resp = client.get("/crm/stats", headers=owner_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_leads" in data
        assert "leads_this_month" in data
        assert "conversion_rate" in data


# ══════════════════════════════════════════════════════════════════════════════
# 3. CRM ROUTER — /crm/leads/{id}/score
# ══════════════════════════════════════════════════════════════════════════════


class TestCrmLeadScoreEndpoint:
    """GET /crm/leads/{id}/score endpoint tests."""

    def test_score_lead(self, client, owner_headers, test_lead):
        """Score endpoint returns score, factors, recommendation."""
        resp = client.get(f"/crm/leads/{test_lead.id}/score", headers=owner_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "score" in data
        assert "factors" in data
        assert "recommendation" in data
        assert 1 <= data["score"] <= 100

    def test_score_lead_not_found(self, client, owner_headers):
        """Non-existent lead returns 404."""
        fake_id = uuid.uuid4()
        resp = client.get(f"/crm/leads/{fake_id}/score", headers=owner_headers)
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 4. CRM ROUTER — /crm/leads/{id}/summary
# ══════════════════════════════════════════════════════════════════════════════


class TestCrmLeadSummaryEndpoint:
    """GET /crm/leads/{id}/summary endpoint tests."""

    def test_summary_lead(self, client, owner_headers, test_lead):
        """Summary endpoint returns AI summary or fallback."""
        resp = client.get(f"/crm/leads/{test_lead.id}/summary", headers=owner_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data
        assert len(data["summary"]) > 0


# ══════════════════════════════════════════════════════════════════════════════
# 5. CRM ROUTER — /crm/leads/{id}/call-summary
# ══════════════════════════════════════════════════════════════════════════════


class TestCrmCallSummaryEndpoint:
    """GET /crm/leads/{id}/call-summary endpoint tests."""

    def test_call_summary_with_notes(self, client, owner_headers, test_lead_with_notes):
        """Call summary works when notes exist."""
        resp = client.get(
            f"/crm/leads/{test_lead_with_notes.id}/call-summary",
            headers=owner_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data

    def test_call_summary_no_notes_returns_400(self, client, owner_headers, test_lead):
        """Call summary without notes returns 400."""
        resp = client.get(
            f"/crm/leads/{test_lead.id}/call-summary",
            headers=owner_headers,
        )
        assert resp.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# 6. CRM ROUTER — /crm/leads/{id}/next-action
# ══════════════════════════════════════════════════════════════════════════════


class TestCrmNextActionEndpoint:
    """GET /crm/leads/{id}/next-action endpoint tests."""

    def test_next_action(self, client, owner_headers, test_lead):
        """Next action returns recommendation."""
        resp = client.get(
            f"/crm/leads/{test_lead.id}/next-action",
            headers=owner_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "action" in data
        assert "priority" in data


# ══════════════════════════════════════════════════════════════════════════════
# 7. FOLLOWUP ROUTER — GET /followups
# ══════════════════════════════════════════════════════════════════════════════


class TestFollowupListEndpoint:
    """GET /followups endpoint tests."""

    def test_list_followups_empty(self, client, owner_headers):
        """Empty org returns 0 follow-ups."""
        resp = client.get("/followups", headers=owner_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["followups"] == []

    def test_list_followups_with_data(self, client, owner_headers, test_lead):
        """Create a follow-up, then list returns it."""
        # Create a follow-up via POST
        resp = client.post(
            "/followups",
            json={
                "lead_id": str(test_lead.id),
                "title": "Test follow-up",
                "priority": "high",
            },
            headers=owner_headers,
        )
        assert resp.status_code == 201

        # List
        resp = client.get("/followups", headers=owner_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1


# ══════════════════════════════════════════════════════════════════════════════
# 8. FOLLOWUP ROUTER — POST /followups
# ══════════════════════════════════════════════════════════════════════════════


class TestFollowupCreateEndpoint:
    """POST /followups endpoint tests."""

    def test_create_followup(self, client, owner_headers, test_lead):
        """Create a follow-up for a lead."""
        resp = client.post(
            "/followups",
            json={
                "lead_id": str(test_lead.id),
                "title": "Send proposal",
                "notes": "Follow up on pricing",
                "priority": "high",
            },
            headers=owner_headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "Send proposal"
        assert data["priority"] == "high"
        assert data["status"] == "pending"
        assert "id" in data

    def test_create_followup_missing_lead_id(self, client, owner_headers):
        """Missing lead_id returns 422."""
        resp = client.post(
            "/followups",
            json={"title": "Missing lead"},
            headers=owner_headers,
        )
        assert resp.status_code == 422

    def test_create_followup_lead_not_found(self, client, owner_headers):
        """Non-existent lead returns 404."""
        resp = client.post(
            "/followups",
            json={
                "lead_id": str(uuid.uuid4()),
                "title": "Ghost lead",
            },
            headers=owner_headers,
        )
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 9. FOLLOWUP ROUTER — PATCH /followups/{id}
# ══════════════════════════════════════════════════════════════════════════════


class TestFollowupUpdateEndpoint:
    """PATCH /followups/{id} endpoint tests."""

    def test_update_followup_title(self, client, owner_headers, test_lead):
        """Update follow-up title."""
        # Create
        resp = client.post(
            "/followups",
            json={"lead_id": str(test_lead.id), "title": "Old title"},
            headers=owner_headers,
        )
        fu_id = resp.json()["id"]

        # Update
        resp = client.patch(
            f"/followups/{fu_id}",
            json={"title": "New title"},
            headers=owner_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["title"] == "New title"

    def test_update_followup_not_found(self, client, owner_headers):
        """Update non-existent follow-up returns 404."""
        resp = client.patch(
            f"/followups/{uuid.uuid4()}",
            json={"title": "Ghost"},
            headers=owner_headers,
        )
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 10. FOLLOWUP ROUTER — GET /followups/overdue
# ══════════════════════════════════════════════════════════════════════════════


class TestFollowupOverdueEndpoint:
    """GET /followups/overdue endpoint tests."""

    def test_overdue_empty(self, client, owner_headers):
        """No overdue follow-ups when none exist."""
        resp = client.get("/followups/overdue", headers=owner_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# 11. FOLLOWUP ROUTER — POST /followups/{id}/complete
# ══════════════════════════════════════════════════════════════════════════════


class TestFollowupCompleteEndpoint:
    """POST /followups/{id}/complete endpoint tests."""

    def test_complete_followup(self, client, owner_headers, test_lead):
        """Complete a pending follow-up."""
        # Create
        resp = client.post(
            "/followups",
            json={"lead_id": str(test_lead.id), "title": "Do this"},
            headers=owner_headers,
        )
        fu_id = resp.json()["id"]
        assert resp.json()["status"] == "pending"

        # Complete
        resp = client.post(f"/followups/{fu_id}/complete", headers=owner_headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "completed"
        assert resp.json()["completed_at"] is not None

    def test_complete_already_completed(self, client, owner_headers, test_lead):
        """Completing an already-completed follow-up returns 400."""
        # Create + complete
        resp = client.post(
            "/followups",
            json={"lead_id": str(test_lead.id), "title": "Done once"},
            headers=owner_headers,
        )
        fu_id = resp.json()["id"]
        client.post(f"/followups/{fu_id}/complete", headers=owner_headers)

        # Try again
        resp = client.post(f"/followups/{fu_id}/complete", headers=owner_headers)
        assert resp.status_code == 400

    def test_complete_not_found(self, client, owner_headers):
        """Complete non-existent follow-up returns 404."""
        resp = client.post(f"/followups/{uuid.uuid4()}/complete", headers=owner_headers)
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 12. FOLLOWUP ROUTER — assigned_to validation (regression tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestFollowupAssignedToValidation:
    """Verify assigned_to user validation on create/update endpoints.

    Regression tests for the gap where assigned_to was accepted without
    verifying the user exists and belongs to the same organization.
    """

    def test_create_followup_assigned_to_valid_user(self, client, owner_headers, test_lead, db, org_and_user):
        """Creating a follow-up with a valid same-org user succeeds."""
        org, owner = org_and_user
        # Create a second user in the same org
        from app.auth import hash_password
        member = User(
            organization_id=org.id,
            email=f"member-{uuid.uuid4().hex[:8]}@test.com",
            full_name="Team Member",
            password_hash=hash_password("StrongPass123!"),
            role=UserRole.MEMBER,
            status=UserStatus.ACTIVE,
        )
        db.add(member)
        db.commit()
        db.refresh(member)

        resp = client.post(
            "/followups",
            json={
                "lead_id": str(test_lead.id),
                "title": "Assigned task",
                "assigned_to": str(member.id),
            },
            headers=owner_headers,
        )
        assert resp.status_code == 201
        assert resp.json()["assigned_to"] == str(member.id)

    def test_create_followup_assigned_to_nonexistent_user(self, client, owner_headers, test_lead):
        """Creating a follow-up with a non-existent user UUID returns 400."""
        fake_user_id = str(uuid.uuid4())
        resp = client.post(
            "/followups",
            json={
                "lead_id": str(test_lead.id),
                "title": "Ghost assignment",
                "assigned_to": fake_user_id,
            },
            headers=owner_headers,
        )
        assert resp.status_code == 400
        assert "assigned_to" in resp.json()["detail"].lower()

    def test_create_followup_assigned_to_cross_org_user(self, db, org_and_user, monkeypatch):
        """Creating a follow-up with a user from a different org returns 400."""
        # Mock pipeline recovery to prevent startup background jobs from
        # changing lead status before the test assertion.
        monkeypatch.setattr("app.main._recover_stuck_leads", lambda: None)
        from app.main import app as _app
        client = TestClient(_app)

        org, owner = org_and_user
        # Create a lead directly (avoid pipeline side effects)
        uid = uuid.uuid4().hex[:8]
        lead = Lead(
            organization_id=org.id,
            interested=True,
            name="CrossOrg Test Lead",
            email=f"crossorg-{uid}@test.com",
            phone_number="555-0199",
            company_address="999 Test St",
            courses="Cross-Org 101",
            caller_name="Test Caller",
            status=LeadStatus.PENDING,
            appt_datetime_raw=f"01/{uid[:4]} 10:00 AM",
            dedupe_key=f"dedupe-crossorg-{uid}",
        )
        db.add(lead)
        db.commit()
        db.refresh(lead)

        # Create a second org and user
        other_org, other_user = _create_org_and_user(
            db, email=f"other-{uuid.uuid4().hex[:8]}@other.com"
        )

        token = _make_token(owner.id, org.id, UserRole.OWNER.value)
        headers = {"Authorization": f"Bearer {token}"}

        resp = client.post(
            "/followups",
            json={
                "lead_id": str(lead.id),
                "title": "Cross-org assignment",
                "assigned_to": str(other_user.id),
            },
            headers=headers,
        )
        assert resp.status_code == 400
        assert "assigned_to" in resp.json()["detail"].lower()

    def test_update_followup_assigned_to_valid_user(self, client, owner_headers, test_lead, db, org_and_user):
        """Updating a follow-up with a valid same-org user succeeds."""
        org, owner = org_and_user
        from app.auth import hash_password
        member = User(
            organization_id=org.id,
            email=f"member-{uuid.uuid4().hex[:8]}@test.com",
            full_name="Reassign Member",
            password_hash=hash_password("StrongPass123!"),
            role=UserRole.MEMBER,
            status=UserStatus.ACTIVE,
        )
        db.add(member)
        db.commit()
        db.refresh(member)

        # Create follow-up
        resp = client.post(
            "/followups",
            json={"lead_id": str(test_lead.id), "title": "Reassign me"},
            headers=owner_headers,
        )
        fu_id = resp.json()["id"]

        # Update with valid assignment
        resp = client.patch(
            f"/followups/{fu_id}",
            json={"assigned_to": str(member.id)},
            headers=owner_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["assigned_to"] == str(member.id)

    def test_update_followup_assigned_to_nonexistent_user(self, client, owner_headers, test_lead):
        """Updating a follow-up with a non-existent user UUID returns 400."""
        # Create follow-up
        resp = client.post(
            "/followups",
            json={"lead_id": str(test_lead.id), "title": "Ghost update"},
            headers=owner_headers,
        )
        fu_id = resp.json()["id"]

        # Update with fake user
        resp = client.patch(
            f"/followups/{fu_id}",
            json={"assigned_to": str(uuid.uuid4())},
            headers=owner_headers,
        )
        assert resp.status_code == 400
        assert "assigned_to" in resp.json()["detail"].lower()

    def test_update_followup_assigned_to_cross_org_user(self, db, org_and_user, monkeypatch):
        """Updating a follow-up with a cross-org user returns 400."""
        monkeypatch.setattr("app.main._recover_stuck_leads", lambda: None)
        from app.main import app as _app
        client = TestClient(_app)

        org, owner = org_and_user
        uid = uuid.uuid4().hex[:8]
        lead = Lead(
            organization_id=org.id,
            interested=True,
            name="CrossOrgUpdate Lead",
            email=f"crossorgupd-{uid}@test.com",
            phone_number="555-0198",
            company_address="998 Test St",
            courses="Cross-Org Update 101",
            caller_name="Test Caller",
            status=LeadStatus.PENDING,
            appt_datetime_raw=f"01/{uid[:4]} 10:00 AM",
            dedupe_key=f"dedupe-crossorgupd-{uid}",
        )
        db.add(lead)
        db.commit()
        db.refresh(lead)

        other_org, other_user = _create_org_and_user(
            db, email=f"other-{uuid.uuid4().hex[:8]}@other.com"
        )

        token = _make_token(owner.id, org.id, UserRole.OWNER.value)
        headers = {"Authorization": f"Bearer {token}"}

        # Create follow-up
        resp = client.post(
            "/followups",
            json={"lead_id": str(lead.id), "title": "Cross-org update"},
            headers=headers,
        )
        fu_id = resp.json()["id"]

        # Update with cross-org user
        resp = client.patch(
            f"/followups/{fu_id}",
            json={"assigned_to": str(other_user.id)},
            headers=headers,
        )
        assert resp.status_code == 400
        assert "assigned_to" in resp.json()["detail"].lower()
