"""Tests for Lead Management — Edit + Status Endpoints.

Covers:
  Phase 2 — GET /dashboard/api/leads/{id} (detail)
  Phase 3 — PATCH /dashboard/api/leads/{id} (edit)
  Phase 4 — PATCH /dashboard/api/leads/{id}/status (status change)

Test groups:
  1. Lead Detail — org isolation, response shape
  2. Edit Lead — owner/admin authorized, member 403, validation, duplicate, org isolation
  3. Status Change — valid transitions, invalid transitions, owner/admin authorized, member 403
  4. Audit Events — lead_updated / lead_status_changed logged
"""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.models import EventLog, Lead, LeadStatus
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


def _create_lead(client, db, org, user, *, name=None, email=None, appt="tomorrow 2pm"):
    """Create a lead via the API and return the response JSON."""
    token = _make_token(user.id, org.id, "owner")
    payload = {
        "name": name or f"Lead-{uuid.uuid4().hex[:6]}",
        "email": email or f"lead-{uuid.uuid4().hex[:8]}@example.com",
        "appt_datetime_raw": appt,
    }
    resp = client.post(
        "/dashboard/api/leads",
        json=payload,
        headers=_auth_header(token),
    )
    assert resp.status_code == 201
    return resp.json()


def _create_lead_raw(db, org_id, *, status=LeadStatus.PENDING, name="Raw Lead"):
    """Insert a Lead directly via ORM, bypassing the API pipeline."""
    import dateparser
    from datetime import timezone as tz

    email = f"raw-{uuid.uuid4().hex[:8]}@example.com"
    appt_raw = "tomorrow 3pm"
    parsed = dateparser.parse(
        appt_raw, settings={"RETURN_AS_TIMEZONE_AWARE": True}
    )
    if parsed and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=tz.utc)
    dedupe_key = f"manual|{email.strip().lower()}|{appt_raw.strip().lower()}"

    lead = Lead(
        id=uuid.uuid4(),
        name=name,
        email=email,
        appt_datetime_raw=appt_raw,
        appt_datetime_utc=parsed.astimezone(tz.utc) if parsed else None,
        status=status,
        dedupe_key=dedupe_key,
        organization_id=org_id,
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


# ── Phase 2: Lead Detail ─────────────────────────────────────────────────────


class TestLeadDetail:
    """GET /dashboard/api/leads/{id} — read-only detail view."""

    def test_detail_returns_lead(self, client, db):
        """Owner can view lead detail."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.get(
            f"/dashboard/api/leads/{lead_id}",
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "lead" in data
        assert data["lead"]["id"] == lead_id
        assert data["lead"]["prospect_name"] == lead_data["lead"]["prospect_name"]

    def test_detail_includes_appt_datetime_raw(self, client, db):
        """Detail response should include appt_datetime_raw."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.get(
            f"/dashboard/api/leads/{lead_id}",
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        lead = resp.json()["lead"]
        assert "appt_datetime_raw" in lead
        assert lead["appt_datetime_raw"] == "tomorrow 2pm"

    def test_detail_includes_events(self, client, db):
        """Detail response should include events list."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.get(
            f"/dashboard/api/leads/{lead_id}",
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert "events" in resp.json()

    def test_detail_404_nonexistent(self, client, db):
        """Non-existent lead ID should return 404."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        fake_id = str(uuid.uuid4())
        resp = client.get(
            f"/dashboard/api/leads/{fake_id}",
            headers=_auth_header(token),
        )
        assert resp.status_code == 404

    def test_detail_cross_org_isolation(self, client, db):
        """Org A user cannot see Org B's lead detail."""
        org_a, user_a = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org_a, user_a)
        lead_id = lead_data["lead"]["id"]

        org_b, user_b = _create_org_and_user(db, role=UserRole.OWNER)
        token_b = _make_token(user_b.id, org_b.id, "owner")
        resp = client.get(
            f"/dashboard/api/leads/{lead_id}",
            headers=_auth_header(token_b),
        )
        assert resp.status_code == 404


# ── Phase 3: Edit Lead ────────────────────────────────────────────────────────


class TestEditLeadAuthorized:
    """PATCH /dashboard/api/leads/{id} — authorized edits."""

    def test_owner_can_edit_name(self, client, db):
        """Owner should be able to edit lead name."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}",
            json={"name": "Updated Name"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "updated"
        assert data["lead"]["prospect_name"] == "Updated Name"

    def test_admin_can_edit(self, client, db):
        """Admin role should be able to edit leads."""
        org, user = _create_org_and_user(db, role=UserRole.ADMIN)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "admin")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}",
            json={"email": f"admin-edit-{uuid.uuid4().hex[:6]}@example.com"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "updated"

    def test_edit_multiple_fields(self, client, db):
        """Should support editing multiple fields in one call."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        new_email = f"multi-{uuid.uuid4().hex[:6]}@example.com"
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}",
            json={
                "name": "Multi Edit",
                "email": new_email,
                "phone_number": "555-9999",
                "company_address": "42 Wallaby Way",
            },
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        lead = resp.json()["lead"]
        assert lead["prospect_name"] == "Multi Edit"
        assert lead["email"] == new_email
        assert lead["phone_number"] == "555-9999"
        assert lead["company_address"] == "42 Wallaby Way"

    def test_edit_persists_to_db(self, client, db):
        """Edited lead should be persisted in the database."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}",
            json={"name": "Persisted Edit"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200

        db_lead = db.query(Lead).filter(Lead.id == lead_id).first()
        assert db_lead is not None
        assert db_lead.name == "Persisted Edit"

    def test_edit_updates_dedupe_key(self, client, db):
        """Editing email should rebuild the dedupe_key."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]
        original_key = db.query(Lead).filter(Lead.id == lead_id).first().dedupe_key

        new_email = f"newdedupe-{uuid.uuid4().hex[:6]}@example.com"
        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}",
            json={"email": new_email},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        updated_key = db.query(Lead).filter(Lead.id == lead_id).first().dedupe_key
        assert updated_key != original_key
        assert new_email in updated_key

    def test_edit_no_fields_returns_400(self, client, db):
        """Empty body should return 400."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 400
        assert "No fields" in resp.json()["detail"]

    def test_edit_same_value_returns_400(self, client, db):
        """Sending same value as current should return 400 (no changes)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]
        original_name = lead_data["lead"]["prospect_name"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}",
            json={"name": original_name},
            headers=_auth_header(token),
        )
        assert resp.status_code == 400
        assert "No changes" in resp.json()["detail"]


class TestEditLeadRBAC:
    """PATCH /dashboard/api/leads/{id} — role-based access control."""

    def test_member_cannot_edit(self, client, db):
        """Member role should be rejected with 403."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        member_org, member_user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _make_token(member_user.id, member_org.id, "member")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}",
            json={"name": "Hacked"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 403

    def test_unauthenticated_cannot_edit(self, client, db):
        """No auth should return 401."""
        fake_id = str(uuid.uuid4())
        resp = client.patch(
            f"/dashboard/api/leads/{fake_id}",
            json={"name": "Hacked"},
        )
        assert resp.status_code == 401


class TestEditLeadValidation:
    """PATCH /dashboard/api/leads/{id} — input validation."""

    def test_invalid_email_rejected(self, client, db):
        """Invalid email format should return 422."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}",
            json={"email": "not-an-email"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_placeholder_email_rejected(self, client, db):
        """Placeholder emails (n/a, none, etc.) should be rejected."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}",
            json={"email": "n/a"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_empty_name_rejected(self, client, db):
        """Empty name should be rejected."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}",
            json={"name": ""},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_404_nonexistent_lead(self, client, db):
        """Editing a non-existent lead should return 404."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        fake_id = str(uuid.uuid4())
        resp = client.patch(
            f"/dashboard/api/leads/{fake_id}",
            json={"name": "Ghost"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 404


class TestEditLeadIsolation:
    """PATCH /dashboard/api/leads/{id} — cross-org isolation."""

    def test_cross_org_cannot_edit(self, client, db):
        """Org B user should not be able to edit Org A's lead."""
        org_a, user_a = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org_a, user_a)
        lead_id = lead_data["lead"]["id"]

        org_b, user_b = _create_org_and_user(db, role=UserRole.OWNER)
        token_b = _make_token(user_b.id, org_b.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}",
            json={"name": "Stolen"},
            headers=_auth_header(token_b),
        )
        assert resp.status_code == 404


class TestEditLeadAudit:
    """PATCH /dashboard/api/leads/{id} — audit event logging."""

    def test_edit_logs_lead_updated_event(self, client, db):
        """Editing a lead should log a 'lead_updated' event."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}",
            json={"name": "Audit Test"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200

        events = db.query(EventLog).filter(
            EventLog.lead_id == lead_id,
            EventLog.event_type == "lead_updated",
        ).all()
        assert len(events) >= 1
        payload = json.loads(events[0].payload) if isinstance(events[0].payload, str) else events[0].payload
        assert payload["changes"]["name"]["new"] == "Audit Test"


# ── Phase 4: Status Change ────────────────────────────────────────────────────


class TestStatusChangeValid:
    """PATCH /dashboard/api/leads/{id}/status — valid transitions."""

    def test_pending_to_scheduled(self, client, db):
        """PENDING → SCHEDULED should succeed."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.PENDING)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "scheduled"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["lead"]["status"] == "scheduled"

    def test_pending_to_not_interested(self, client, db):
        """PENDING → NOT_INTERESTED should succeed."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.PENDING)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "not_interested"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["lead"]["status"] == "not_interested"

    def test_scheduled_to_accepted(self, client, db):
        """SCHEDULED → ACCEPTED should succeed."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "accepted"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["lead"]["status"] == "accepted"

    def test_scheduled_to_tentative(self, client, db):
        """SCHEDULED → TENTATIVE should succeed."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "tentative"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["lead"]["status"] == "tentative"

    def test_scheduled_to_declined(self, client, db):
        """SCHEDULED → DECLINED should succeed."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "declined"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["lead"]["status"] == "declined"

    def test_accepted_to_completed(self, client, db):
        """ACCEPTED → COMPLETED should succeed."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.ACCEPTED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "completed"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["lead"]["status"] == "completed"

    def test_tentative_to_accepted(self, client, db):
        """TENTATIVE → ACCEPTED should succeed."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.TENTATIVE)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "accepted"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["lead"]["status"] == "accepted"

    def test_reminded_to_completed(self, client, db):
        """REMINDED → COMPLETED should succeed."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.REMINDED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "completed"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["lead"]["status"] == "completed"

    def test_error_to_pending(self, client, db):
        """ERROR → PENDING (retry) should succeed."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.ERROR)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "pending"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["lead"]["status"] == "pending"

    def test_admin_can_change_status(self, client, db):
        """Admin role should be able to change status."""
        org, user = _create_org_and_user(db, role=UserRole.ADMIN)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.PENDING)

        token = _make_token(user.id, org.id, "admin")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "scheduled"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["lead"]["status"] == "scheduled"


class TestStatusChangeInvalid:
    """PATCH /dashboard/api/leads/{id}/status — invalid transitions."""

    def test_same_status_returns_400(self, client, db):
        """Changing to the same status should return 400."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.PENDING)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "pending"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 400
        assert "already in that status" in resp.json()["detail"]

    def test_pending_to_completed_blocked(self, client, db):
        """PENDING → COMPLETED is not a valid transition (422)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.PENDING)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "completed"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422
        assert "Invalid transition" in resp.json()["detail"]

    def test_completed_is_terminal(self, client, db):
        """COMPLETED is a terminal state — no transitions allowed (422)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.COMPLETED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "pending"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422
        assert "terminal state" in resp.json()["detail"]

    def test_declined_is_terminal(self, client, db):
        """DECLINED is a terminal state (422)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.DECLINED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "pending"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_invalid_status_value_returns_422(self, client, db):
        """Invalid status enum value should return 422."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.PENDING)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "nonexistent_status"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_404_nonexistent_lead(self, client, db):
        """Changing status of non-existent lead should return 404."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        fake_id = str(uuid.uuid4())
        resp = client.patch(
            f"/dashboard/api/leads/{fake_id}/status",
            json={"status": "completed"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 404


class TestStatusChangeRBAC:
    """PATCH /dashboard/api/leads/{id}/status — RBAC."""

    def test_member_cannot_change_status(self, client, db):
        """Member role should be rejected with 403."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.PENDING)

        member_org, member_user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _make_token(member_user.id, member_org.id, "member")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "completed"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 403

    def test_unauthenticated_cannot_change_status(self, client):
        """No auth should return 401."""
        fake_id = str(uuid.uuid4())
        resp = client.patch(
            f"/dashboard/api/leads/{fake_id}/status",
            json={"status": "completed"},
        )
        assert resp.status_code == 401


class TestStatusChangeIsolation:
    """PATCH /dashboard/api/leads/{id}/status — cross-org isolation."""

    def test_cross_org_cannot_change_status(self, client, db):
        """Org B user should not be able to change Org A's lead status."""
        org_a, user_a = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org_a.id, status=LeadStatus.PENDING)

        org_b, user_b = _create_org_and_user(db, role=UserRole.OWNER)
        token_b = _make_token(user_b.id, org_b.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "completed"},
            headers=_auth_header(token_b),
        )
        assert resp.status_code == 404


class TestStatusChangeAudit:
    """PATCH /dashboard/api/leads/{id}/status — audit event logging."""

    def test_status_change_logs_event(self, client, db):
        """Status change should log a 'lead_status_changed' event."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.PENDING)

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead.id}/status",
            json={"status": "scheduled"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200

        events = db.query(EventLog).filter(
            EventLog.lead_id == lead.id,
            EventLog.event_type == "lead_status_changed",
        ).all()
        assert len(events) >= 1
        payload = json.loads(events[0].payload) if isinstance(events[0].payload, str) else events[0].payload
        assert payload["old_status"] == "pending"
        assert payload["new_status"] == "scheduled"
