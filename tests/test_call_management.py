"""Tests for Phase 12 Call Management endpoints.

Covers:
  PATCH /dashboard/api/leads/{lead_id}/call  — update call outcome/notes/duration
  POST  /dashboard/api/leads/{lead_id}/cancel  — cancel a scheduled call
  POST  /dashboard/api/leads/{lead_id}/reschedule  — reschedule to new datetime

Test groups:
  1. Update Call — happy path, RBAC, not-found, no fields, no changes, org isolation
  2. Cancel Call — happy path, status/outcome/timestamp, audit, SSE, terminal state, RBAC, org isolation
  3. Reschedule Call — happy path, fields update, reschedule_count, audit, terminal state, RBAC, org isolation, duplicate
  4. LeadOut Schema — new fields present in detail response
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.models import CallOutcome, EventLog, Lead, LeadStatus
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

    email = f"raw-{uuid.uuid4().hex[:8]}@example.com"
    appt_raw = "tomorrow 3pm"
    parsed = dateparser.parse(
        appt_raw, settings={"RETURN_AS_TIMEZONE_AWARE": True}
    )
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


# ══════════════════════════════════════════════════════════════════════════════
# 1. UPDATE CALL — PATCH /dashboard/api/leads/{lead_id}/call
# ══════════════════════════════════════════════════════════════════════════════


class TestUpdateCallHappyPath:
    """PATCH /dashboard/api/leads/{lead_id}/call — authorized updates."""

    def test_update_outcome_notes_duration(self, client, db):
        """Owner can update call_outcome, call_notes, and call_duration_minutes."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}/call",
            json={
                "call_outcome": "connected",
                "call_notes": "Great conversation, very interested in the program.",
                "call_duration_minutes": 45,
            },
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "updated"
        lead = data["lead"]
        assert lead["call_outcome"] == "connected"
        assert lead["call_notes"] == "Great conversation, very interested in the program."
        assert lead["call_duration_minutes"] == 45

    def test_update_outcome_only(self, client, db):
        """Owner can update just the call_outcome field."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}/call",
            json={"call_outcome": "voicemail"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["lead"]["call_outcome"] == "voicemail"
        # notes and duration unchanged (should be None)
        assert resp.json()["lead"]["call_notes"] is None
        assert resp.json()["lead"]["call_duration_minutes"] is None

    def test_update_persists_to_db(self, client, db):
        """Updated call fields should be persisted in the database."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        client.patch(
            f"/dashboard/api/leads/{lead_id}/call",
            json={
                "call_outcome": "no_answer",
                "call_notes": "Left a voicemail.",
                "call_duration_minutes": 3,
            },
            headers=_auth_header(token),
        )

        db.expire_all()
        db_lead = db.query(Lead).filter(Lead.id == uuid.UUID(lead_id)).first()
        assert db_lead is not None
        assert db_lead.call_outcome == CallOutcome.NO_ANSWER
        assert db_lead.call_notes == "Left a voicemail."
        assert db_lead.call_duration_minutes == 3

    def test_admin_can_update_call(self, client, db):
        """Admin role should be able to update call details."""
        org, user = _create_org_and_user(db, role=UserRole.ADMIN)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "admin")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}/call",
            json={"call_outcome": "completed", "call_notes": "Admin updated."},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["lead"]["call_outcome"] == "completed"


class TestUpdateCallRBAC:
    """PATCH /dashboard/api/leads/{lead_id}/call — role-based access control."""

    def test_member_cannot_update_call(self, client, db):
        """Member role should be rejected with 403."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        member_org, member_user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _make_token(member_user.id, member_org.id, "member")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}/call",
            json={"call_outcome": "connected"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 403

    def test_unauthenticated_cannot_update_call(self, client, db):
        """No auth should return 401."""
        fake_id = str(uuid.uuid4())
        resp = client.patch(
            f"/dashboard/api/leads/{fake_id}/call",
            json={"call_outcome": "connected"},
        )
        assert resp.status_code == 401


class TestUpdateCallNotFound:
    """PATCH /dashboard/api/leads/{lead_id}/call — not found."""

    def test_random_uuid_returns_404(self, client, db):
        """Non-existent lead ID should return 404."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        fake_id = str(uuid.uuid4())
        resp = client.patch(
            f"/dashboard/api/leads/{fake_id}/call",
            json={"call_outcome": "connected"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 404


class TestUpdateCallValidation:
    """PATCH /dashboard/api/leads/{lead_id}/call — input validation."""

    def test_empty_body_returns_400(self, client, db):
        """Empty body (no fields) should return 400."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}/call",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 400
        assert "No fields" in resp.json()["detail"]

    def test_no_changes_returns_400(self, client, db):
        """Sending same values as current should return 400 (no changes)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        # First, set some values
        token = _make_token(user.id, org.id, "owner")
        client.patch(
            f"/dashboard/api/leads/{lead_id}/call",
            json={
                "call_outcome": "connected",
                "call_notes": "Test notes",
                "call_duration_minutes": 30,
            },
            headers=_auth_header(token),
        )

        # Now send the same values
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}/call",
            json={
                "call_outcome": "connected",
                "call_notes": "Test notes",
                "call_duration_minutes": 30,
            },
            headers=_auth_header(token),
        )
        assert resp.status_code == 400
        assert "No changes" in resp.json()["detail"]

    def test_invalid_duration_negative_returns_422(self, client, db):
        """Negative call_duration_minutes should be rejected (422)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}/call",
            json={"call_duration_minutes": -5},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_invalid_duration_exceeds_max_returns_422(self, client, db):
        """call_duration_minutes > 1440 should be rejected (422)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}/call",
            json={"call_duration_minutes": 1500},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_invalid_call_outcome_returns_422(self, client, db):
        """Invalid call_outcome enum value should return 422."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}/call",
            json={"call_outcome": "magic_outcome"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422


class TestUpdateCallOrgIsolation:
    """PATCH /dashboard/api/leads/{lead_id}/call — cross-org isolation."""

    def test_cross_org_cannot_update_call(self, client, db):
        """Org B user should not be able to update Org A's lead call details."""
        org_a, user_a = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org_a, user_a)
        lead_id = lead_data["lead"]["id"]

        org_b, user_b = _create_org_and_user(db, role=UserRole.OWNER)
        token_b = _make_token(user_b.id, org_b.id, "owner")
        resp = client.patch(
            f"/dashboard/api/leads/{lead_id}/call",
            json={"call_outcome": "connected"},
            headers=_auth_header(token_b),
        )
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 2. CANCEL CALL — POST /dashboard/api/leads/{lead_id}/cancel
# ══════════════════════════════════════════════════════════════════════════════


class TestCancelCallHappyPath:
    """POST /dashboard/api/leads/{lead_id}/cancel — authorized cancellation."""

    def test_cancel_scheduled_lead(self, client, db):
        """Owner can cancel a scheduled lead."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "cancelled"
        assert data["lead"]["status"] == "declined"

    def test_cancel_sets_status_declined(self, client, db):
        """Cancel should set lead status to DECLINED."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={},
            headers=_auth_header(token),
        )

        db.expire_all()
        db_lead = db.query(Lead).filter(Lead.id == lead.id).first()
        assert db_lead.status == LeadStatus.DECLINED

    def test_cancel_sets_call_outcome_cancelled(self, client, db):
        """Cancel should set call_outcome to CANCELLED."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={},
            headers=_auth_header(token),
        )

        db.expire_all()
        db_lead = db.query(Lead).filter(Lead.id == lead.id).first()
        assert db_lead.call_outcome == CallOutcome.CANCELLED

    def test_cancel_sets_cancelled_at(self, client, db):
        """Cancel should set cancelled_at to a UTC timestamp."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        before_cancel = datetime.now(timezone.utc)
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={},
            headers=_auth_header(token),
        )
        after_cancel = datetime.now(timezone.utc)

        assert resp.status_code == 200
        db.expire_all()
        db_lead = db.query(Lead).filter(Lead.id == lead.id).first()
        assert db_lead.cancelled_at is not None
        # cancelled_at should be between before and after (with small tolerance)
        assert db_lead.cancelled_at >= before_cancel - timedelta(seconds=1)
        assert db_lead.cancelled_at <= after_cancel + timedelta(seconds=1)

    def test_cancel_with_reason(self, client, db):
        """Cancel with a reason should succeed."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={"reason": "Prospect asked to cancel"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"

    def test_cancel_pending_lead(self, client, db):
        """Can also cancel a PENDING lead (non-terminal)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.PENDING)

        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["lead"]["status"] == "declined"


class TestCancelCallAudit:
    """POST /dashboard/api/leads/{lead_id}/cancel — audit + SSE events."""

    def test_cancel_creates_audit_event(self, client, db):
        """Cancel should log a 'call_cancelled' event."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={"reason": "No longer interested"},
            headers=_auth_header(token),
        )

        events = db.query(EventLog).filter(
            EventLog.lead_id == lead.id,
            EventLog.event_type == "call_cancelled",
        ).all()
        assert len(events) >= 1
        payload = json.loads(events[0].payload) if isinstance(events[0].payload, str) else events[0].payload
        assert payload["old_status"] == "scheduled"
        assert payload["reason"] == "No longer interested"

    def test_cancel_creates_sse_event(self, client, db):
        """Cancel should publish a 'call.cancelled' SSE event via EventLog."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={},
            headers=_auth_header(token),
        )

        # Check that a call.cancelled event was published
        events = db.query(EventLog).filter(
            EventLog.event_type == "call_cancelled",
            EventLog.lead_id == lead.id,
        ).all()
        assert len(events) >= 1


class TestCancelCallTerminalState:
    """POST /dashboard/api/leads/{lead_id}/cancel — already terminal."""

    def test_cancel_completed_returns_422(self, client, db):
        """Cannot cancel a COMPLETED lead (422)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.COMPLETED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422
        assert "terminal" in resp.json()["detail"].lower() or "completed" in resp.json()["detail"].lower()

    def test_cancel_declined_returns_422(self, client, db):
        """Cannot cancel a DECLINED lead (422)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.DECLINED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_cancel_not_interested_returns_422(self, client, db):
        """Cannot cancel a NOT_INTERESTED lead (422)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.NOT_INTERESTED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_cancel_error_returns_422(self, client, db):
        """Cannot cancel an ERROR lead (422)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.ERROR)

        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422


class TestCancelCallRBAC:
    """POST /dashboard/api/leads/{lead_id}/cancel — RBAC."""

    def test_member_cannot_cancel(self, client, db):
        """Member role should be rejected with 403."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        member_org, member_user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _make_token(member_user.id, member_org.id, "member")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 403

    def test_unauthenticated_cannot_cancel(self, client, db):
        """No auth should return 401."""
        fake_id = str(uuid.uuid4())
        resp = client.post(
            f"/dashboard/api/leads/{fake_id}/cancel",
            json={},
        )
        assert resp.status_code == 401


class TestCancelCallOrgIsolation:
    """POST /dashboard/api/leads/{lead_id}/cancel — cross-org isolation."""

    def test_cross_org_cannot_cancel(self, client, db):
        """Org B user should not be able to cancel Org A's lead."""
        org_a, user_a = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org_a.id, status=LeadStatus.SCHEDULED)

        org_b, user_b = _create_org_and_user(db, role=UserRole.OWNER)
        token_b = _make_token(user_b.id, org_b.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={},
            headers=_auth_header(token_b),
        )
        assert resp.status_code == 404

    def test_cancel_not_found_returns_404(self, client, db):
        """Non-existent lead ID should return 404."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        fake_id = str(uuid.uuid4())
        resp = client.post(
            f"/dashboard/api/leads/{fake_id}/cancel",
            json={},
            headers=_auth_header(token),
        )
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 3. RESCHEDULE CALL — POST /dashboard/api/leads/{lead_id}/reschedule
# ══════════════════════════════════════════════════════════════════════════════


class TestRescheduleCallHappyPath:
    """POST /dashboard/api/leads/{lead_id}/reschedule — authorized reschedule."""

    def test_reschedule_to_new_time(self, client, db):
        """Owner can reschedule a lead to a new appointment time."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/reschedule",
            json={"appt_datetime_raw": "next friday 10am"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "rescheduled"
        assert data["lead"]["appt_datetime_raw"] == "next friday 10am"

    def test_reschedule_updates_appt_fields(self, client, db):
        """Reschedule should update appt_datetime_raw and appt_datetime_utc."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)
        old_appt_raw = lead.appt_datetime_raw

        token = _make_token(user.id, org.id, "owner")
        # Use explicit datetime so dateparser reliably parses it
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/reschedule",
            json={"appt_datetime_raw": "2026-09-01 3:00 PM"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 200

        db.expire_all()
        db_lead = db.query(Lead).filter(Lead.id == lead.id).first()
        assert db_lead.appt_datetime_raw == "2026-09-01 3:00 PM"
        assert db_lead.appt_datetime_raw != old_appt_raw
        # appt_datetime_utc should be set (dateparser parses explicit datetime)
        assert db_lead.appt_datetime_utc is not None

    def test_reschedule_increments_count(self, client, db):
        """Reschedule should increment reschedule_count by 1."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)
        assert lead.reschedule_count == 0

        token = _make_token(user.id, org.id, "owner")
        client.post(
            f"/dashboard/api/leads/{lead.id}/reschedule",
            json={"appt_datetime_raw": "tomorrow 4pm"},
            headers=_auth_header(token),
        )

        db.expire_all()
        db_lead = db.query(Lead).filter(Lead.id == lead.id).first()
        assert db_lead.reschedule_count == 1

        # Reschedule again
        client.post(
            f"/dashboard/api/leads/{lead.id}/reschedule",
            json={"appt_datetime_raw": "next week 9am"},
            headers=_auth_header(token),
        )

        db.expire_all()
        db_lead = db.query(Lead).filter(Lead.id == lead.id).first()
        assert db_lead.reschedule_count == 2

    def test_reschedule_with_reason(self, client, db):
        """Reschedule with a reason should succeed."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/reschedule",
            json={
                "appt_datetime_raw": "thursday 1pm",
                "reason": "Prospect had a conflict",
            },
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "rescheduled"

    def test_reschedule_preserves_status(self, client, db):
        """Reschedule should NOT change the lead status."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        client.post(
            f"/dashboard/api/leads/{lead.id}/reschedule",
            json={"appt_datetime_raw": "next tuesday 11am"},
            headers=_auth_header(token),
        )

        db_lead = db.query(Lead).filter(Lead.id == lead.id).first()
        assert db_lead.status == LeadStatus.SCHEDULED  # unchanged


class TestRescheduleCallAudit:
    """POST /dashboard/api/leads/{lead_id}/reschedule — audit event logging."""

    def test_reschedule_creates_audit_event(self, client, db):
        """Reschedule should log a 'call_rescheduled' event."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        client.post(
            f"/dashboard/api/leads/{lead.id}/reschedule",
            json={
                "appt_datetime_raw": "next friday 2pm",
                "reason": "Client request",
            },
            headers=_auth_header(token),
        )

        events = db.query(EventLog).filter(
            EventLog.lead_id == lead.id,
            EventLog.event_type == "call_rescheduled",
        ).all()
        assert len(events) >= 1
        payload = json.loads(events[0].payload) if isinstance(events[0].payload, str) else events[0].payload
        assert payload["old_appt"] == "tomorrow 3pm"
        assert payload["new_appt"] == "next friday 2pm"
        assert payload["reason"] == "Client request"
        assert payload["reschedule_count"] == 1


class TestRescheduleCallTerminalState:
    """POST /dashboard/api/leads/{lead_id}/reschedule — already terminal."""

    def test_reschedule_completed_returns_422(self, client, db):
        """Cannot reschedule a COMPLETED lead (422)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.COMPLETED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/reschedule",
            json={"appt_datetime_raw": "next week 2pm"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422
        assert "terminal" in resp.json()["detail"].lower() or "completed" in resp.json()["detail"].lower()

    def test_reschedule_declined_returns_422(self, client, db):
        """Cannot reschedule a DECLINED lead (422)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.DECLINED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/reschedule",
            json={"appt_datetime_raw": "next week 2pm"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422

    def test_reschedule_not_interested_returns_422(self, client, db):
        """Cannot reschedule a NOT_INTERESTED lead (422)."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.NOT_INTERESTED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/reschedule",
            json={"appt_datetime_raw": "next week 2pm"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 422


class TestRescheduleCallRBAC:
    """POST /dashboard/api/leads/{lead_id}/reschedule — RBAC."""

    def test_member_cannot_reschedule(self, client, db):
        """Member role should be rejected with 403."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        member_org, member_user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _make_token(member_user.id, member_org.id, "member")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/reschedule",
            json={"appt_datetime_raw": "next week 2pm"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 403

    def test_unauthenticated_cannot_reschedule(self, client, db):
        """No auth should return 401."""
        fake_id = str(uuid.uuid4())
        resp = client.post(
            f"/dashboard/api/leads/{fake_id}/reschedule",
            json={"appt_datetime_raw": "next week 2pm"},
        )
        assert resp.status_code == 401


class TestRescheduleCallOrgIsolation:
    """POST /dashboard/api/leads/{lead_id}/reschedule — cross-org isolation."""

    def test_cross_org_cannot_reschedule(self, client, db):
        """Org B user should not be able to reschedule Org A's lead."""
        org_a, user_a = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org_a.id, status=LeadStatus.SCHEDULED)

        org_b, user_b = _create_org_and_user(db, role=UserRole.OWNER)
        token_b = _make_token(user_b.id, org_b.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead.id}/reschedule",
            json={"appt_datetime_raw": "next week 2pm"},
            headers=_auth_header(token_b),
        )
        assert resp.status_code == 404

    def test_reschedule_not_found_returns_404(self, client, db):
        """Non-existent lead ID should return 404."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        fake_id = str(uuid.uuid4())
        resp = client.post(
            f"/dashboard/api/leads/{fake_id}/reschedule",
            json={"appt_datetime_raw": "next week 2pm"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 404


class TestRescheduleCallDuplicate:
    """POST /dashboard/api/leads/{lead_id}/reschedule — duplicate appt time."""

    def test_duplicate_appt_time_returns_409(self, client, db):
        """Rescheduling to a conflicting dedupe key should return 409."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        # Create two leads with the SAME email but different appt times
        # so they have different dedupe keys
        shared_email = f"dup-{uuid.uuid4().hex[:8]}@example.com"
        lead_a = _create_lead_raw(
            db, org.id, status=LeadStatus.SCHEDULED, name="Lead A"
        )
        # Override lead_a's email to match our shared email
        lead_a.email = shared_email
        lead_a.dedupe_key = f"manual|{shared_email}|tomorrow 3pm"
        db.commit()
        db.refresh(lead_a)

        # Create lead_b with same email but different appt
        lead_b = _create_lead_raw(
            db, org.id, status=LeadStatus.SCHEDULED, name="Lead B"
        )
        lead_b.email = shared_email
        lead_b.dedupe_key = f"manual|{shared_email}|next tuesday 10am"
        db.commit()
        db.refresh(lead_b)

        # Now reschedule lead_b to lead_a's appt time -> dedupe key collision
        token = _make_token(user.id, org.id, "owner")
        resp = client.post(
            f"/dashboard/api/leads/{lead_b.id}/reschedule",
            json={"appt_datetime_raw": "tomorrow 3pm"},
            headers=_auth_header(token),
        )
        assert resp.status_code == 409
        assert "duplicate" in resp.json()["detail"].lower() or "Reschedule failed" in resp.json()["detail"]


# ══════════════════════════════════════════════════════════════════════════════
# 4. LEAD OUT SCHEMA — verify new fields in detail response
# ══════════════════════════════════════════════════════════════════════════════


class TestLeadOutSchema:
    """Verify that the LeadOut schema includes all new call management fields."""

    def test_lead_out_includes_call_management_fields(self, client, db):
        """Lead detail response should include all Phase 12 fields."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        resp = client.get(
            f"/dashboard/api/leads/{lead.id}",
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        lead_data = resp.json()["lead"]

        # All new call management fields should be present
        assert "call_outcome" in lead_data
        assert "call_notes" in lead_data
        assert "call_duration_minutes" in lead_data
        assert "cancelled_at" in lead_data
        assert "reschedule_count" in lead_data

        # Default values for a fresh lead
        assert lead_data["call_outcome"] is None
        assert lead_data["call_notes"] is None
        assert lead_data["call_duration_minutes"] is None
        assert lead_data["cancelled_at"] is None
        assert lead_data["reschedule_count"] == 0

    def test_lead_out_after_call_update(self, client, db):
        """After updating call details, the lead detail should reflect the changes."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead_data = _create_lead(client, db, org, user)
        lead_id = lead_data["lead"]["id"]

        token = _make_token(user.id, org.id, "owner")
        client.patch(
            f"/dashboard/api/leads/{lead_id}/call",
            json={
                "call_outcome": "connected",
                "call_notes": "Spoke with decision maker.",
                "call_duration_minutes": 25,
            },
            headers=_auth_header(token),
        )

        # Verify via detail endpoint
        resp = client.get(
            f"/dashboard/api/leads/{lead_id}",
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        lead = resp.json()["lead"]
        assert lead["call_outcome"] == "connected"
        assert lead["call_notes"] == "Spoke with decision maker."
        assert lead["call_duration_minutes"] == 25

    def test_lead_out_after_cancel(self, client, db):
        """After cancelling, the lead detail should show cancelled_at and outcome."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        client.post(
            f"/dashboard/api/leads/{lead.id}/cancel",
            json={},
            headers=_auth_header(token),
        )

        resp = client.get(
            f"/dashboard/api/leads/{lead.id}",
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        lead_data = resp.json()["lead"]
        assert lead_data["call_outcome"] == "cancelled"
        assert lead_data["cancelled_at"] is not None
        assert lead_data["status"] == "declined"

    def test_lead_out_after_reschedule(self, client, db):
        """After rescheduling, the lead detail should show updated appt and count."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)

        token = _make_token(user.id, org.id, "owner")
        client.post(
            f"/dashboard/api/leads/{lead.id}/reschedule",
            json={"appt_datetime_raw": "next friday 11am"},
            headers=_auth_header(token),
        )

        resp = client.get(
            f"/dashboard/api/leads/{lead.id}",
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        lead_data = resp.json()["lead"]
        assert lead_data["appt_datetime_raw"] == "next friday 11am"
        assert lead_data["reschedule_count"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# 5. CALENDAR RESCHEDULE — PATCH event when lead has calendar_event_id
# ══════════════════════════════════════════════════════════════════════════════


class TestRescheduleCalendarPatch:
    """POST /dashboard/api/leads/{lead_id}/reschedule — Google Calendar sync."""

    def test_calendar_patched_when_event_exists(self, client, db):
        """Reschedule patches the Calendar event when calendar_event_id is set."""
        from unittest.mock import patch as _patch

        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)
        # Set a calendar_event_id
        lead.calendar_event_id = "evt_test_123"
        db.commit()
        db.refresh(lead)

        token = _make_token(user.id, org.id, "owner")
        with _patch("app.services.calendar_service.CalendarService") as MockCal:
            MockCal.return_value._meeting_duration = 30
            mock_svc = MockCal.return_value
            mock_svc.update_event_reschedule.return_value = None
            resp = client.post(
                f"/dashboard/api/leads/{lead.id}/reschedule",
                json={"appt_datetime_raw": "2026-09-01 3:00 PM"},
                headers=_auth_header(token),
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "rescheduled"
            # Verify CalendarService was called
            MockCal.assert_called_once()
            mock_svc.update_event_reschedule.assert_called_once()
            call_args = mock_svc.update_event_reschedule.call_args
            assert call_args[0][0] == "evt_test_123"  # event_id

    def test_calendar_not_patched_without_event_id(self, client, db):
        """Reschedule skips Calendar patch when calendar_event_id is None."""
        from unittest.mock import patch as _patch

        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)
        assert lead.calendar_event_id is None

        token = _make_token(user.id, org.id, "owner")
        with _patch("app.services.calendar_service.CalendarService") as MockCal:
            resp = client.post(
                f"/dashboard/api/leads/{lead.id}/reschedule",
                json={"appt_datetime_raw": "2026-09-01 3:00 PM"},
                headers=_auth_header(token),
            )
            assert resp.status_code == 200
            # CalendarService should NOT have been called
            MockCal.assert_not_called()

    def test_calendar_error_does_not_fail_reschedule(self, client, db):
        """A Calendar API error is logged but the reschedule still succeeds."""
        from unittest.mock import patch as _patch

        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)
        lead.calendar_event_id = "evt_test_456"
        db.commit()
        db.refresh(lead)

        token = _make_token(user.id, org.id, "owner")
        with _patch("app.services.calendar_service.CalendarService") as MockCal:
            mock_svc = MockCal.return_value
            mock_svc.update_event_reschedule.side_effect = Exception("Calendar API timeout")
            resp = client.post(
                f"/dashboard/api/leads/{lead.id}/reschedule",
                json={"appt_datetime_raw": "2026-09-01 3:00 PM"},
                headers=_auth_header(token),
            )
            # Reschedule still succeeds
            assert resp.status_code == 200
            assert resp.json()["status"] == "rescheduled"
            # DB is updated
            db.expire_all()
            db_lead = db.query(Lead).filter(Lead.id == lead.id).first()
            assert db_lead.appt_datetime_raw == "2026-09-01 3:00 PM"
            assert db_lead.calendar_event_id == "evt_test_456"  # unchanged

    def test_calendar_reschedule_error_logged(self, client, db):
        """Calendar error generates a calendar_reschedule_error audit event."""
        from unittest.mock import patch as _patch

        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id, status=LeadStatus.SCHEDULED)
        lead.calendar_event_id = "evt_test_789"
        db.commit()
        db.refresh(lead)

        token = _make_token(user.id, org.id, "owner")
        with _patch("app.services.calendar_service.CalendarService") as MockCal:
            mock_svc = MockCal.return_value
            mock_svc.update_event_reschedule.side_effect = RuntimeError("GAPI error")
            client.post(
                f"/dashboard/api/leads/{lead.id}/reschedule",
                json={"appt_datetime_raw": "2026-09-01 3:00 PM"},
                headers=_auth_header(token),
            )

        events = db.query(EventLog).filter(
            EventLog.lead_id == lead.id,
            EventLog.event_type == "calendar_reschedule_error",
        ).all()
        assert len(events) >= 1
        payload = json.loads(events[0].payload) if isinstance(events[0].payload, str) else events[0].payload
        assert "GAPI error" in payload["error"]
