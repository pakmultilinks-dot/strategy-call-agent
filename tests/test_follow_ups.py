"""Tests for Phase 18 Follow-Up System endpoints.

Covers:
  POST   /dashboard/api/follow-ups                   — create
  GET    /dashboard/api/follow-ups                   — list (filters)
  GET    /dashboard/api/follow-ups/{id}              — get single
  PATCH  /dashboard/api/follow-ups/{id}              — update details
  PATCH  /dashboard/api/follow-ups/{id}/status       — change status
  DELETE /dashboard/api/follow-ups/{id}              — soft-delete

Test groups:
  1. Create Follow-Up — happy path, validation, org isolation, RBAC
  2. List Follow-Ups — filters, empty, org isolation
  3. Get Follow-Up — happy path, not found, org isolation
  4. Update Follow-Up — partial update, validation, org isolation, RBAC
  5. Status Transitions — valid, invalid, terminal state, timestamps
  6. Delete Follow-Up — soft delete, terminal state, org isolation
  7. Lead Detail Integration — follow-ups appear in lead detail
  8. RBAC — member can't mutate, owner/admin can
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.models import FollowUp, FollowUpPriority, FollowUpStatus, Lead, LeadStatus
from app.models_multi_tenant import UserRole
from tests.test_auth import _auth_header, _create_org_and_user, _make_token


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


def _create_lead_raw(db, org_id, *, status=LeadStatus.PENDING, name="Raw Lead"):
    """Insert a Lead directly via ORM."""
    import dateparser
    email = f"lead-{uuid.uuid4().hex[:8]}@example.com"
    appt_raw = "tomorrow 3pm"
    parsed = dateparser.parse(appt_raw, settings={"RETURN_AS_TIMEZONE_AWARE": True})
    if parsed and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    dedupe_key = f"manual|{email.strip().lower()}|{appt_raw.strip().lower()}"
    lead = Lead(
        id=uuid.uuid4(),
        name=name,
        email=email,
        appt_datetime_raw=appt_raw,
        appt_datetime_utc=parsed.astimezone(timezone.utc) if parsed else None,
        status=status,
        dedupe_key=dedupe_key,
        organization_id=org_id,
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


def _create_followup_raw(db, org_id, lead_id, user_id, **kwargs):
    """Insert a FollowUp directly via ORM."""
    defaults = {
        "title": f"Follow-up {uuid.uuid4().hex[:6]}",
        "priority": FollowUpPriority.MEDIUM,
        "status": FollowUpStatus.PENDING,
    }
    defaults.update(kwargs)
    fu = FollowUp(
        organization_id=org_id,
        lead_id=lead_id,
        created_by=user_id,
        **defaults,
    )
    db.add(fu)
    db.commit()
    db.refresh(fu)
    return fu


def _create_followup_via_api(client, token, lead_id, **kwargs):
    """Create a follow-up via the API and return response JSON."""
    payload = {"lead_id": lead_id, "title": f"API Follow-up {uuid.uuid4().hex[:6]}"}
    payload.update(kwargs)
    resp = client.post(
        "/dashboard/api/follow-ups",
        json=payload,
        headers=_auth_header(token),
    )
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# 1. CREATE FOLLOW-UP
# ══════════════════════════════════════════════════════════════════════════════


class TestCreateFollowUp:
    """POST /dashboard/api/follow-ups"""

    def test_create_success(self, client, db):
        """Owner can create a follow-up for a valid lead."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id), priority="high")
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "created"
        fu = data["follow_up"]
        assert fu["title"].startswith("API Follow-up")
        assert fu["priority"] == "high"
        assert fu["status"] == "pending"
        assert fu["lead_id"] == str(lead.id)
        assert fu["created_by"] == str(user.id)

    def test_create_admin(self, client, db):
        """Admin can also create follow-ups."""
        org, user = _create_org_and_user(db, role=UserRole.ADMIN)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "admin")
        resp = _create_followup_via_api(client, token, str(lead.id))
        assert resp.status_code == 201

    def test_create_member_forbidden(self, client, db):
        """Member role cannot create follow-ups (403)."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "member")
        resp = _create_followup_via_api(client, token, str(lead.id))
        assert resp.status_code == 403

    def test_create_lead_not_found(self, client, db):
        """Creating follow-up for non-existent lead returns 404."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(uuid.uuid4()))
        assert resp.status_code == 404

    def test_create_lead_wrong_org(self, client, db):
        """Creating follow-up for a lead in another org returns 404."""
        org1, user1 = _create_org_and_user(db, role=UserRole.OWNER)
        org2, user2 = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org2.id)  # lead in org2
        token = _make_token(user1.id, org1.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        assert resp.status_code == 404

    def test_create_missing_title(self, client, db):
        """Creating follow-up without title returns 422."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            "/dashboard/api/follow-ups",
            json={"lead_id": str(lead.id)},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_create_with_due_date(self, client, db):
        """Creating follow-up with due_at sets the field."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        due = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
        resp = _create_followup_via_api(client, token, str(lead.id), due_at=due)
        assert resp.status_code == 201
        assert resp.json()["follow_up"]["due_at"] is not None

    def test_create_audit_event(self, client, db):
        """Creating a follow-up logs an audit event."""
        from app.models import EventLog
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        assert resp.status_code == 201
        fu_id = resp.json()["follow_up"]["id"]
        event = db.query(EventLog).filter(
            EventLog.event_type == "follow_up_created",
            EventLog.organization_id == org.id,
        ).first()
        assert event is not None
        assert fu_id in (event.payload or "")

    def test_create_unauthenticated(self, client, db):
        """Unauthenticated request returns 401."""
        resp = client.post(
            "/dashboard/api/follow-ups",
            json={"lead_id": str(uuid.uuid4()), "title": "Test"},
        )
        assert resp.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# 2. LIST FOLLOW-UPS
# ══════════════════════════════════════════════════════════════════════════════


class TestListFollowUps:
    """GET /dashboard/api/follow-ups"""

    def test_list_empty(self, client, db):
        """Empty list returns 0 total."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        resp = client.get("/dashboard/api/follow-ups", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_list_with_data(self, client, db):
        """Lists follow-ups created for this org."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        _create_followup_via_api(client, token, str(lead.id))
        _create_followup_via_api(client, token, str(lead.id))
        resp = client.get("/dashboard/api/follow-ups", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_list_filter_by_status(self, client, db):
        """Filtering by status works."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        _create_followup_via_api(client, token, str(lead.id))
        # Create one directly with completed status
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.COMPLETED)
        resp = client.get("/dashboard/api/follow-ups?status=pending", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_list_filter_by_priority(self, client, db):
        """Filtering by priority works."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        _create_followup_via_api(client, token, str(lead.id), priority="urgent")
        _create_followup_via_api(client, token, str(lead.id), priority="low")
        resp = client.get("/dashboard/api/follow-ups?priority=urgent", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_list_filter_by_lead(self, client, db):
        """Filtering by lead_id works."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead1 = _create_lead_raw(db, org.id, name="Lead 1")
        lead2 = _create_lead_raw(db, org.id, name="Lead 2")
        token = _make_token(user.id, org.id, "owner")
        _create_followup_via_api(client, token, str(lead1.id))
        _create_followup_via_api(client, token, str(lead2.id))
        resp = client.get(
            f"/dashboard/api/follow-ups?lead_id={lead1.id}",
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_list_org_isolation(self, client, db):
        """Follow-ups from other orgs are not visible."""
        org1, user1 = _create_org_and_user(db, role=UserRole.OWNER)
        org2, user2 = _create_org_and_user(db, role=UserRole.OWNER)
        lead1 = _create_lead_raw(db, org1.id)
        lead2 = _create_lead_raw(db, org2.id)
        token1 = _make_token(user1.id, org1.id, "owner")
        token2 = _make_token(user2.id, org2.id, "owner")
        _create_followup_via_api(client, token1, str(lead1.id))
        _create_followup_via_api(client, token2, str(lead2.id))
        resp1 = client.get("/dashboard/api/follow-ups", headers=_auth_header(token1))
        resp2 = client.get("/dashboard/api/follow-ups", headers=_auth_header(token2))
        assert resp1.json()["total"] == 1
        assert resp2.json()["total"] == 1
        assert resp1.json()["follow_ups"][0]["lead_id"] == str(lead1.id)
        assert resp2.json()["follow_ups"][0]["lead_id"] == str(lead2.id)

    def test_list_invalid_status_filter(self, client, db):
        """Invalid status filter returns 400."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        resp = client.get("/dashboard/api/follow-ups?status=bogus", headers=_auth_header(token))
        assert resp.status_code == 400

    def test_list_invalid_priority_filter(self, client, db):
        """Invalid priority filter returns 400."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        resp = client.get("/dashboard/api/follow-ups?priority=bogus", headers=_auth_header(token))
        assert resp.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# 3. GET FOLLOW-UP
# ══════════════════════════════════════════════════════════════════════════════


class TestGetFollowUp:
    """GET /dashboard/api/follow-ups/{id}"""

    def test_get_success(self, client, db):
        """Returns a follow-up by ID."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        resp2 = client.get(f"/dashboard/api/follow-ups/{fu_id}", headers=_auth_header(token))
        assert resp2.status_code == 200
        assert resp2.json()["follow_up"]["id"] == fu_id

    def test_get_not_found(self, client, db):
        """Non-existent ID returns 404."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        resp = client.get(f"/dashboard/api/follow-ups/{uuid.uuid4()}", headers=_auth_header(token))
        assert resp.status_code == 404

    def test_get_wrong_org(self, client, db):
        """Follow-up from another org returns 404."""
        org1, user1 = _create_org_and_user(db, role=UserRole.OWNER)
        org2, user2 = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org2.id)
        token2 = _make_token(user2.id, org2.id, "owner")
        resp = _create_followup_via_api(client, token2, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        token1 = _make_token(user1.id, org1.id, "owner")
        resp2 = client.get(f"/dashboard/api/follow-ups/{fu_id}", headers=_auth_header(token1))
        assert resp2.status_code == 404

    def test_get_resolves_names(self, client, db):
        """Response includes lead_name and created_by_name."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, name="John Doe")
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu = resp.json()["follow_up"]
        assert fu["lead_name"] == "John Doe"
        assert fu["created_by_name"] == "Test User"


# ══════════════════════════════════════════════════════════════════════════════
# 4. UPDATE FOLLOW-UP
# ══════════════════════════════════════════════════════════════════════════════


class TestUpdateFollowUp:
    """PATCH /dashboard/api/follow-ups/{id}"""

    def test_update_title(self, client, db):
        """Owner can update title."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        resp2 = client.patch(
            f"/dashboard/api/follow-ups/{fu_id}",
            json={"title": "Updated Title"},
            headers=_auth_header(token),
        )
        assert resp2.status_code == 200
        assert resp2.json()["follow_up"]["title"] == "Updated Title"

    def test_update_priority(self, client, db):
        """Owner can update priority."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        resp2 = client.patch(
            f"/dashboard/api/follow-ups/{fu_id}",
            json={"priority": "urgent"},
            headers=_auth_header(token),
        )
        assert resp2.status_code == 200
        assert resp2.json()["follow_up"]["priority"] == "urgent"

    def test_update_no_fields(self, client, db):
        """Empty update returns 400."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        resp2 = client.patch(
            f"/dashboard/api/follow-ups/{fu_id}",
            json={},
            headers=_auth_header(token),
        )
        assert resp2.status_code == 400

    def test_update_member_forbidden(self, client, db):
        """Member cannot update follow-ups."""
        org, owner = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        # Create a member user in the same org
        from app.models_multi_tenant import User, UserStatus
        from app.auth import hash_password
        member = User(
            organization_id=org.id,
            email=f"member-{uuid.uuid4().hex[:8]}@example.com",
            full_name="Member User",
            password_hash=hash_password("pass123"),
            role=UserRole.MEMBER,
            status=UserStatus.ACTIVE,
        )
        db.add(member)
        db.commit()
        db.refresh(member)
        token_owner = _make_token(owner.id, org.id, "owner")
        resp = _create_followup_via_api(client, token_owner, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        token_member = _make_token(member.id, org.id, "member")
        resp2 = client.patch(
            f"/dashboard/api/follow-ups/{fu_id}",
            json={"title": "Hacked"},
            headers=_auth_header(token_member),
        )
        assert resp2.status_code == 403

    def test_update_not_found(self, client, db):
        """Updating non-existent follow-up returns 404."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/follow-ups/{uuid.uuid4()}",
            json={"title": "X"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 404

    def test_update_no_changes(self, client, db):
        """Setting same value returns 400 No changes detected."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        original_title = resp.json()["follow_up"]["title"]
        resp2 = client.patch(
            f"/dashboard/api/follow-ups/{fu_id}",
            json={"title": original_title},
            headers=_auth_header(token),
        )
        assert resp2.status_code == 400

    def test_update_audit_event(self, client, db):
        """Updating a follow-up logs an audit event."""
        from app.models import EventLog
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        client.patch(
            f"/dashboard/api/follow-ups/{fu_id}",
            json={"title": "Updated for audit"},
            headers=_auth_header(token),
        )
        event = db.query(EventLog).filter(
            EventLog.event_type == "follow_up_updated",
            EventLog.organization_id == org.id,
        ).first()
        assert event is not None


# ══════════════════════════════════════════════════════════════════════════════
# 5. STATUS TRANSITIONS
# ══════════════════════════════════════════════════════════════════════════════


class TestFollowUpStatusTransitions:
    """PATCH /dashboard/api/follow-ups/{id}/status"""

    def _change_status(self, client, token, fu_id, new_status):
        return client.patch(
            f"/dashboard/api/follow-ups/{fu_id}/status",
            json={"status": new_status},
            headers=_auth_header(token),
        )

    def test_pending_to_in_progress(self, client, db):
        """pending → in_progress is valid."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        resp2 = self._change_status(client, token, fu_id, "in_progress")
        assert resp2.status_code == 200
        assert resp2.json()["follow_up"]["status"] == "in_progress"

    def test_pending_to_completed(self, client, db):
        """pending → completed sets completed_at and completed_by."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        resp2 = self._change_status(client, token, fu_id, "completed")
        assert resp2.status_code == 200
        fu = resp2.json()["follow_up"]
        assert fu["status"] == "completed"
        assert fu["completed_at"] is not None
        assert fu["completed_by"] == str(user.id)

    def test_pending_to_cancelled(self, client, db):
        """pending → cancelled sets cancelled_at and cancelled_by."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        resp2 = self._change_status(client, token, fu_id, "cancelled")
        assert resp2.status_code == 200
        fu = resp2.json()["follow_up"]
        assert fu["status"] == "cancelled"
        assert fu["cancelled_at"] is not None
        assert fu["cancelled_by"] == str(user.id)

    def test_in_progress_to_completed(self, client, db):
        """in_progress → completed is valid."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        fu = _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.IN_PROGRESS)
        resp = self._change_status(client, token, str(fu.id), "completed")
        assert resp.status_code == 200
        assert resp.json()["follow_up"]["status"] == "completed"

    def test_completed_is_terminal(self, client, db):
        """completed → pending is invalid (terminal state)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        fu = _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.COMPLETED)
        resp = self._change_status(client, token, str(fu.id), "pending")
        assert resp.status_code == 422

    def test_cancelled_is_terminal(self, client, db):
        """cancelled → in_progress is invalid (terminal state)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        fu = _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.CANCELLED)
        resp = self._change_status(client, token, str(fu.id), "in_progress")
        assert resp.status_code == 422

    def test_same_status_rejected(self, client, db):
        """Setting the same status returns 400."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        resp2 = self._change_status(client, token, fu_id, "pending")
        assert resp2.status_code == 400

    def test_invalid_transition(self, client, db):
        """Invalid transition returns 422 with helpful message."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        resp2 = self._change_status(client, token, fu_id, "completed")
        # This IS valid (pending → completed), so now try from completed
        resp3 = self._change_status(client, token, fu_id, "pending")
        assert resp3.status_code == 422
        assert "Invalid transition" in resp3.json()["detail"]

    def test_status_audit_event(self, client, db):
        """Status change logs audit event."""
        from app.models import EventLog
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        self._change_status(client, token, fu_id, "completed")
        event = db.query(EventLog).filter(
            EventLog.event_type == "follow_up_status_changed",
            EventLog.organization_id == org.id,
        ).first()
        assert event is not None

    def test_member_cannot_change_status(self, client, db):
        """Member cannot change follow-up status."""
        org, owner = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        from app.models_multi_tenant import User, UserStatus
        from app.auth import hash_password
        member = User(
            organization_id=org.id,
            email=f"member-{uuid.uuid4().hex[:8]}@example.com",
            full_name="Member User",
            password_hash=hash_password("pass123"),
            role=UserRole.MEMBER,
            status=UserStatus.ACTIVE,
        )
        db.add(member)
        db.commit()
        db.refresh(member)
        token_owner = _make_token(owner.id, org.id, "owner")
        resp = _create_followup_via_api(client, token_owner, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        token_member = _make_token(member.id, org.id, "member")
        resp2 = self._change_status(client, token_member, fu_id, "completed")
        assert resp2.status_code == 403

    def test_org_isolation_status(self, client, db):
        """Can't change status of follow-up from another org."""
        org1, user1 = _create_org_and_user(db, role=UserRole.OWNER)
        org2, user2 = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org2.id)
        token2 = _make_token(user2.id, org2.id, "owner")
        resp = _create_followup_via_api(client, token2, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        token1 = _make_token(user1.id, org1.id, "owner")
        resp2 = self._change_status(client, token1, fu_id, "completed")
        assert resp2.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 6. DELETE FOLLOW-UP
# ══════════════════════════════════════════════════════════════════════════════


class TestDeleteFollowUp:
    """DELETE /dashboard/api/follow-ups/{id}"""

    def test_delete_soft(self, client, db):
        """Delete cancels a pending follow-up."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        resp2 = client.delete(f"/dashboard/api/follow-ups/{fu_id}", headers=_auth_header(token))
        assert resp2.status_code == 204
        # Verify it's now cancelled
        resp3 = client.get(f"/dashboard/api/follow-ups/{fu_id}", headers=_auth_header(token))
        assert resp3.json()["follow_up"]["status"] == "cancelled"
        assert resp3.json()["follow_up"]["cancelled_at"] is not None

    def test_delete_already_completed(self, client, db):
        """Deleting an already-completed follow-up is a no-op."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        fu = _create_followup_raw(
            db, org.id, lead.id, user.id,
            status=FollowUpStatus.COMPLETED,
            completed_at=datetime.now(timezone.utc),
            completed_by=user.id,
        )
        resp = client.delete(f"/dashboard/api/follow-ups/{fu.id}", headers=_auth_header(token))
        assert resp.status_code == 204

    def test_delete_not_found(self, client, db):
        """Deleting non-existent follow-up returns 404."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        resp = client.delete(f"/dashboard/api/follow-ups/{uuid.uuid4()}", headers=_auth_header(token))
        assert resp.status_code == 404

    def test_delete_wrong_org(self, client, db):
        """Can't delete follow-up from another org."""
        org1, user1 = _create_org_and_user(db, role=UserRole.OWNER)
        org2, user2 = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org2.id)
        token2 = _make_token(user2.id, org2.id, "owner")
        resp = _create_followup_via_api(client, token2, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        token1 = _make_token(user1.id, org1.id, "owner")
        resp2 = client.delete(f"/dashboard/api/follow-ups/{fu_id}", headers=_auth_header(token1))
        assert resp2.status_code == 404

    def test_delete_member_forbidden(self, client, db):
        """Member cannot delete follow-ups."""
        org, owner = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        from app.models_multi_tenant import User, UserStatus
        from app.auth import hash_password
        member = User(
            organization_id=org.id,
            email=f"member-{uuid.uuid4().hex[:8]}@example.com",
            full_name="Member User",
            password_hash=hash_password("pass123"),
            role=UserRole.MEMBER,
            status=UserStatus.ACTIVE,
        )
        db.add(member)
        db.commit()
        db.refresh(member)
        token_owner = _make_token(owner.id, org.id, "owner")
        resp = _create_followup_via_api(client, token_owner, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        token_member = _make_token(member.id, org.id, "member")
        resp2 = client.delete(f"/dashboard/api/follow-ups/{fu_id}", headers=_auth_header(token_member))
        assert resp2.status_code == 403

    def test_delete_audit_event(self, client, db):
        """Deleting a follow-up logs an audit event."""
        from app.models import EventLog
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        resp = _create_followup_via_api(client, token, str(lead.id))
        fu_id = resp.json()["follow_up"]["id"]
        client.delete(f"/dashboard/api/follow-ups/{fu_id}", headers=_auth_header(token))
        event = db.query(EventLog).filter(
            EventLog.event_type == "follow_up_deleted",
            EventLog.organization_id == org.id,
        ).first()
        assert event is not None


# ══════════════════════════════════════════════════════════════════════════════
# 8. OVERDUE EMAIL NOTIFICATIONS (Phase 19B)
# ══════════════════════════════════════════════════════════════════════════════


class TestOverdueFollowUpEmail:
    """check_overdue_follow_ups() sends overdue email notifications."""

    @staticmethod
    def _cleanup_overdue():
        """Remove all follow-ups and leads to ensure isolation.

        check_overdue_follow_ups() opens its own SessionLocal() and sees
        ALL committed rows. We clean them up to avoid cross-test contamination.
        """
        from app.models import EventLog, FailedJob
        from app.database import SessionLocal as _SL
        s = _SL()
        try:
            s.query(EventLog).delete()
            s.query(FailedJob).delete()
            s.query(FollowUp).delete()
            s.query(Lead).delete()
            s.commit()
        finally:
            s.close()

    def test_overdue_email_sent(self, client, db):
        """Overdue follow-up with no prior email triggers an email send."""
        from unittest.mock import patch, MagicMock
        from app.services.followup_reminder import check_overdue_follow_ups

        self._cleanup_overdue()
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        # Create an overdue follow-up (due yesterday)
        fu = _create_followup_raw(
            db, org.id, lead.id, user.id,
            due_at=datetime.now(timezone.utc) - timedelta(days=1),
            status=FollowUpStatus.PENDING,
        )
        assert fu.overdue_email_sent_at is None

        with patch("app.services.email_service.EmailService") as MockEmail:
            mock_svc = MockEmail.return_value
            mock_svc.send_email.return_value = "msg_123"
            result = check_overdue_follow_ups()

        assert result["total_overdue"] == 1
        assert result["emails_sent"] == 1
        assert result["errors"] == 0
        mock_svc.send_email.assert_called_once()

        # Verify overdue_email_sent_at is set
        db.expire_all()
        db_fu = db.query(FollowUp).filter(FollowUp.id == fu.id).first()
        assert db_fu.overdue_email_sent_at is not None

    def test_overdue_email_not_sent_twice(self, client, db):
        """Follow-up that already had an email sent is not sent again."""
        from unittest.mock import patch, MagicMock
        from app.services.followup_reminder import check_overdue_follow_ups

        self._cleanup_overdue()
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        already_sent = datetime.now(timezone.utc) - timedelta(hours=1)
        fu = _create_followup_raw(
            db, org.id, lead.id, user.id,
            due_at=datetime.now(timezone.utc) - timedelta(days=1),
            status=FollowUpStatus.PENDING,
            overdue_email_sent_at=already_sent,
        )

        with patch("app.services.email_service.EmailService") as MockEmail:
            result = check_overdue_follow_ups()

        assert result["total_overdue"] == 1
        assert result["emails_sent"] == 0
        MockEmail.return_value.send_email.assert_not_called()

    def test_non_overdue_no_email(self, client, db):
        """Follow-up that is not overdue does not trigger an email."""
        from unittest.mock import patch
        from app.services.followup_reminder import check_overdue_follow_ups

        self._cleanup_overdue()
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        # Due next week (not overdue)
        fu = _create_followup_raw(
            db, org.id, lead.id, user.id,
            due_at=datetime.now(timezone.utc) + timedelta(days=7),
            status=FollowUpStatus.PENDING,
        )

        with patch("app.services.email_service.EmailService") as MockEmail:
            result = check_overdue_follow_ups()

        assert result["total_overdue"] == 0
        assert result["emails_sent"] == 0
        MockEmail.return_value.send_email.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# 9. PLATFORM ADMIN (HTTP Basic) FOLLOW-UPS ACCESS
# ══════════════════════════════════════════════════════════════════════════════


class TestPlatformAdminFollowUps:
    """Platform admin (HTTP Basic auth, org_id=None) can access follow-ups.

    Regression tests for the bug where GET /dashboard/api/follow-ups returned
    HTTP 400 "Organization context required" for platform admin users.
    """

    @pytest.fixture()
    def basic_headers(self):
        """Return HTTP Basic auth headers for platform admin."""
        import base64
        from app.config import settings
        return {
            "Authorization": "Basic "
            + base64.b64encode(
                f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
            ).decode()
        }

    # --- Test 1: Platform admin list ---
    def test_platform_admin_list_empty(self, client, basic_headers):
        """Platform admin GET /api/follow-ups returns 200 (not 400)."""
        resp = client.get("/dashboard/api/follow-ups", headers=basic_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "follow_ups" in data
        assert "total" in data

    def test_platform_admin_list_with_data(self, client, db, basic_headers):
        """Platform admin sees follow-ups across all organizations."""
        # Clean up any pre-existing follow-ups from other tests
        db.query(FollowUp).delete()
        db.commit()
        # Create two orgs with follow-ups
        org1, user1 = _create_org_and_user(db, role=UserRole.OWNER)
        org2, user2 = _create_org_and_user(db, role=UserRole.OWNER)
        lead1 = _create_lead_raw(db, org1.id, name="Org1 Lead")
        lead2 = _create_lead_raw(db, org2.id, name="Org2 Lead")
        token1 = _make_token(user1.id, org1.id, "owner")
        token2 = _make_token(user2.id, org2.id, "owner")
        _create_followup_via_api(client, token1, str(lead1.id))
        _create_followup_via_api(client, token2, str(lead2.id))

        # Platform admin should see both
        resp = client.get("/dashboard/api/follow-ups", headers=basic_headers)
        assert resp.status_code == 200
        assert resp.json()["total"] == 2
        lead_ids = {fu["lead_id"] for fu in resp.json()["follow_ups"]}
        assert str(lead1.id) in lead_ids
        assert str(lead2.id) in lead_ids

    # --- Test 2: Platform admin stats ---
    def test_platform_admin_stats(self, client, db, basic_headers):
        """Platform admin GET /api/follow-ups/stats returns 200 with stats shape."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        _create_followup_via_api(client, token, str(lead.id))

        resp = client.get("/dashboard/api/follow-ups/stats", headers=basic_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "active" in data
        assert "completed" in data
        assert "cancelled" in data
        assert "overdue" in data
        assert "avg_time_to_completion_hours" in data
        assert data["total"] >= 1

    def test_platform_admin_stats_cross_org(self, client, db, basic_headers):
        """Platform admin stats include follow-ups from all organizations."""
        # Clean up any pre-existing follow-ups from other tests
        db.query(FollowUp).delete()
        db.commit()
        org1, user1 = _create_org_and_user(db, role=UserRole.OWNER)
        org2, user2 = _create_org_and_user(db, role=UserRole.OWNER)
        lead1 = _create_lead_raw(db, org1.id)
        lead2 = _create_lead_raw(db, org2.id)
        token1 = _make_token(user1.id, org1.id, "owner")
        token2 = _make_token(user2.id, org2.id, "owner")
        _create_followup_via_api(client, token1, str(lead1.id))
        _create_followup_via_api(client, token2, str(lead2.id))

        resp = client.get("/dashboard/api/follow-ups/stats", headers=basic_headers)
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    # --- Test 3: Platform admin lead-specific query ---
    def test_platform_admin_lead_specific_query(self, client, db, basic_headers):
        """Platform admin GET /api/follow-ups?lead_id=<id> returns 200."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")
        _create_followup_via_api(client, token, str(lead.id))

        resp = client.get(
            f"/dashboard/api/follow-ups?lead_id={lead.id}",
            headers=basic_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["follow_ups"][0]["lead_id"] == str(lead.id)

    def test_platform_admin_lead_no_followups(self, client, db, basic_headers):
        """Platform admin query for a lead with no follow-ups returns empty."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)

        resp = client.get(
            f"/dashboard/api/follow-ups?lead_id={lead.id}",
            headers=basic_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    # --- Test 4: Customer tenant isolation ---
    def test_customer_tenant_isolation(self, client, db):
        """Customer user from Org A cannot see Org B follow-ups."""
        org_a, user_a = _create_org_and_user(db, role=UserRole.OWNER)
        org_b, user_b = _create_org_and_user(db, role=UserRole.OWNER)
        lead_a = _create_lead_raw(db, org_a.id, name="OrgA Lead")
        lead_b = _create_lead_raw(db, org_b.id, name="OrgB Lead")
        token_a = _make_token(user_a.id, org_a.id, "owner")
        token_b = _make_token(user_b.id, org_b.id, "owner")
        _create_followup_via_api(client, token_a, str(lead_a.id))
        _create_followup_via_api(client, token_b, str(lead_b.id))

        # Org A user sees only their own
        resp_a = client.get("/dashboard/api/follow-ups", headers=_auth_header(token_a))
        assert resp_a.status_code == 200
        assert resp_a.json()["total"] == 1
        assert resp_a.json()["follow_ups"][0]["lead_id"] == str(lead_a.id)

        # Org B user sees only their own
        resp_b = client.get("/dashboard/api/follow-ups", headers=_auth_header(token_b))
        assert resp_b.status_code == 200
        assert resp_b.json()["total"] == 1
        assert resp_b.json()["follow_ups"][0]["lead_id"] == str(lead_b.id)

    # --- Test 5: Customer lead-specific isolation ---
    def test_customer_cannot_see_other_org_followup_by_lead_id(self, client, db):
        """Org A user requesting follow-ups for Org B's lead gets 0 (not 400, not cross-org data)."""
        org_a, user_a = _create_org_and_user(db, role=UserRole.OWNER)
        org_b, user_b = _create_org_and_user(db, role=UserRole.OWNER)
        lead_b = _create_lead_raw(db, org_b.id, name="OrgB Lead")
        token_b = _make_token(user_b.id, org_b.id, "owner")
        _create_followup_via_api(client, token_b, str(lead_b.id))

        # Org A user queries for Org B's lead — should get 0 results (org filter blocks it)
        token_a = _make_token(user_a.id, org_a.id, "owner")
        resp = client.get(
            f"/dashboard/api/follow-ups?lead_id={lead_b.id}",
            headers=_auth_header(token_a),
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 0


class TestOverdueFollowUpEmailPart2:
    """Remaining overdue email tests (split from TestOverdueFollowUpEmail)."""

    def _cleanup_overdue(self):
        """Remove all follow-ups and leads to ensure isolation."""
        from app.models import EventLog, FailedJob
        from app.database import SessionLocal as _SL
        s = _SL()
        try:
            s.query(EventLog).delete()
            s.query(FailedJob).delete()
            s.query(FollowUp).delete()
            s.query(Lead).delete()
            s.commit()
        finally:
            s.close()

    def test_completed_followup_no_email(self, client, db):
        """Completed follow-up that is past due does not trigger an email."""
        from unittest.mock import patch
        from app.services.followup_reminder import check_overdue_follow_ups

        self._cleanup_overdue()
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        fu = _create_followup_raw(
            db, org.id, lead.id, user.id,
            due_at=datetime.now(timezone.utc) - timedelta(days=1),
            status=FollowUpStatus.COMPLETED,
            completed_at=datetime.now(timezone.utc),
        )

        with patch("app.services.email_service.EmailService") as MockEmail:
            result = check_overdue_follow_ups()

        assert result["total_overdue"] == 0
        assert result["emails_sent"] == 0

    def test_email_error_does_not_crash(self, client, db):
        """Email send failure is caught and counted as error, not crash."""
        from unittest.mock import patch
        from app.services.followup_reminder import check_overdue_follow_ups

        self._cleanup_overdue()
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        fu = _create_followup_raw(
            db, org.id, lead.id, user.id,
            due_at=datetime.now(timezone.utc) - timedelta(days=1),
            status=FollowUpStatus.PENDING,
        )

        with patch("app.services.email_service.EmailService") as MockEmail:
            mock_svc = MockEmail.return_value
            mock_svc.send_email.side_effect = RuntimeError("Gmail API down")
            result = check_overdue_follow_ups()

        assert result["total_overdue"] == 1
        assert result["emails_sent"] == 0
        assert result["errors"] >= 1

    def test_overdue_email_no_lead_skipped(self, client, db):
        """Follow-up with a missing lead is skipped gracefully."""
        from unittest.mock import patch
        from app.services.followup_reminder import check_overdue_follow_ups

        self._cleanup_overdue()
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        fu = _create_followup_raw(
            db, org.id, lead.id, user.id,
            due_at=datetime.now(timezone.utc) - timedelta(days=1),
            status=FollowUpStatus.PENDING,
        )

        # Mock the Lead query inside _send_overdue_email to return None
        with patch("app.services.email_service.EmailService") as MockEmail, \
             patch("app.services.followup_reminder.Lead") as MockLead:
            MockLead.query.filter.return_value.first.return_value = None
            result = check_overdue_follow_ups()

        assert result["total_overdue"] == 1
        # Email not sent because lead is missing
        assert result["emails_sent"] == 0
        MockEmail.return_value.send_email.assert_not_called()

    def test_overdue_email_content(self, client, db):
        """Verify the email subject and body contain expected content."""
        from unittest.mock import patch
        from app.services.followup_reminder import check_overdue_follow_ups

        self._cleanup_overdue()
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, name="Jane Smith")
        fu = _create_followup_raw(
            db, org.id, lead.id, user.id,
            title="Send contract",
            due_at=datetime.now(timezone.utc) - timedelta(days=1),
            status=FollowUpStatus.PENDING,
            priority=FollowUpPriority.HIGH,
        )

        with patch("app.services.email_service.EmailService") as MockEmail:
            mock_svc = MockEmail.return_value
            mock_svc.send_email.return_value = "msg_456"
            check_overdue_follow_ups()

            # Inspect the call args
            call_args = mock_svc.send_email.call_args
            subject = call_args[0][1]  # second positional arg
            plain_body = call_args[0][2]  # third positional arg
            assert "Send contract" in subject
            assert "Jane Smith" in subject
            assert "Send contract" in plain_body
            assert "Jane Smith" in plain_body
            assert "HIGH" in plain_body

    def test_overdue_summary_structure(self, client, db):
        """Summary dict includes emails_sent key."""
        from unittest.mock import patch
        from app.services.followup_reminder import check_overdue_follow_ups

        self._cleanup_overdue()
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        fu = _create_followup_raw(
            db, org.id, lead.id, user.id,
            due_at=datetime.now(timezone.utc) - timedelta(days=1),
            status=FollowUpStatus.PENDING,
        )

        with patch("app.services.email_service.EmailService") as MockEmail:
            mock_svc = MockEmail.return_value
            mock_svc.send_email.return_value = "msg_789"
            result = check_overdue_follow_ups()

        assert "total_overdue" in result
        assert "events_published" in result
        assert "emails_sent" in result
        assert "errors" in result
        assert isinstance(result["emails_sent"], int)
