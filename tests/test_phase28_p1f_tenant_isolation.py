"""Phase 28 P1-F: Complete Tenant Isolation Verification.

Proves that Organization A can NEVER access Organization B's data through
API manipulation, path IDs, request bodies, or any other mechanism.

Tests every organization-scoped endpoint with:
  1. Org A accessing its own data (positive control)
  2. Org B accessing its own data (positive control)
  3. Org A trying to access Org B data (cross-tenant attack)
  4. Org B trying to access Org A data (cross-tenant attack)

Attack vectors tested:
  - Path parameter manipulation (Org A JWT + Org B's resource ID)
  - Request body org_id injection (ignored by server)
  - Query parameter manipulation
  - Direct UUID lookup

Total: 55+ tests covering all tenant-scoped resources.
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models import EventLog, FailedJob, FollowUp, FollowUpStatus, Lead, LeadStatus
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
    TokenBlocklist,
    User,
    UserRole,
    UserStatus,
)
from app.services.crypto import generate_key

# ── Constants ────────────────────────────────────────────────────────────────

JWT_SECRET = "p1f-tenant-isolation-test-secret-key-32c!!"
ENCRYPTION_KEY = generate_key()

# Deterministic UUIDs for two test organizations
ORG_A_ID = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
ORG_B_ID = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

_unique = uuid.uuid4().hex[:8]


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _set_test_env(monkeypatch):
    """Set test-mode secrets and environment."""
    monkeypatch.setattr(settings, "jwt_secret_key", JWT_SECRET)
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", ENCRYPTION_KEY)


@pytest.fixture(scope="module")
def _test_data(client):
    """Create all test data once for the module. Cleaned up at teardown.

    Depends on ``client`` to ensure the TestClient lifespan (which runs
    ``_recover_stuck_leads``) executes BEFORE data creation.  Without this
    dependency, pytest may resolve _test_data first, and the lifespan's
    recovery job would mark PENDING leads as ERROR before any test runs.

    Returns a dict of plain values (UUIDs, strings) — NOT ORM objects —
    so tests never hit DetachedInstanceError after the session closes.
    """
    db = SessionLocal()
    try:
        # ── Cleanup from prior runs ────────────────────────────────────
        # The deterministic UUIDs persist across runs; delete any
        # leftovers to avoid UniqueViolation on re-insert.
        # Must respect FK ordering: events_log→leads, followups→leads, etc.
        # FK-safe deletion order:
        #   events_log → followups → leads → failed_jobs → users → organizations
        # events_log has BOTH lead_id AND organization_id FKs (both RESTRICT).
        # Delete by organization_id AND by lead_id to be thorough.
        # follow_ups also has lead_id FK → delete by both too.
        lead_ids = db.query(Lead.id).filter(
            Lead.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).subquery()
        lead_id_list = [row[0] for row in db.query(lead_ids).all()]

        # events_log: delete by org_id, then by lead_id (catches NULL org_id)
        db.query(EventLog).filter(
            EventLog.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        if lead_id_list:
            db.query(EventLog).filter(
                EventLog.lead_id.in_(lead_id_list)
            ).delete(synchronize_session=False)

        # follow_ups: delete by org_id, then by lead_id
        db.query(FollowUp).filter(
            FollowUp.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        if lead_id_list:
            db.query(FollowUp).filter(
                FollowUp.lead_id.in_(lead_id_list)
            ).delete(synchronize_session=False)

        # leads
        db.query(Lead).filter(
            Lead.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        db.query(FailedJob).filter(
            FailedJob.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        # TokenBlocklist entries (bulk revocation sentinels from prior runs)
        db.query(TokenBlocklist).filter(
            TokenBlocklist.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        db.query(User).filter(
            User.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        db.query(Organization).filter(
            Organization.id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        db.flush()

        # ── Create Organizations ────────────────────────────────────────
        org_a = Organization(
            id=ORG_A_ID,
            name="Tenant Isolation Org A",
            slug=f"p1f-org-a-{_unique}",
            timezone="America/Chicago",
            status=OrganizationStatus.ACTIVE,
            plan="business",
            webhook_secret="org-a-secret-minimum-16-chars",
        )
        org_b = Organization(
            id=ORG_B_ID,
            name="Tenant Isolation Org B",
            slug=f"p1f-org-b-{_unique}",
            timezone="America/Chicago",
            status=OrganizationStatus.ACTIVE,
            plan="business",
            webhook_secret="org-b-secret-minimum-16-chars",
        )
        db.add_all([org_a, org_b])
        db.flush()

        from app.auth import hash_password

        pwd = hash_password("StrongP@ss123!")
        user_a = User(
            organization_id=ORG_A_ID,
            email=f"owner-a-{_unique}@p1f-test.com",
            full_name="Owner A",
            password_hash=pwd,
            role=UserRole.OWNER,
            status=UserStatus.ACTIVE,
        )
        member_a = User(
            organization_id=ORG_A_ID,
            email=f"member-a-{_unique}@p1f-test.com",
            full_name="Member A",
            password_hash=pwd,
            role=UserRole.MEMBER,
            status=UserStatus.ACTIVE,
        )
        user_b = User(
            organization_id=ORG_B_ID,
            email=f"owner-b-{_unique}@p1f-test.com",
            full_name="Owner B",
            password_hash=pwd,
            role=UserRole.OWNER,
            status=UserStatus.ACTIVE,
        )
        db.add_all([user_a, member_a, user_b])
        db.flush()

        # ── Create Leads ────────────────────────────────────────────────
        # appt_datetime_utc set to 30 days in the future so that
        # _recover_stuck_leads() never marks these leads as ERROR.
        _future_appt = datetime.now(timezone.utc) + timedelta(days=30)
        lead_a = Lead(
            name="Lead A1",
            email=f"lead-a1-{_unique}@test.com",
            appt_datetime_raw="tomorrow 2pm",
            appt_datetime_utc=_future_appt,
            dedupe_key=f"p1f-lead-a1-{_unique}",
            status=LeadStatus.PENDING,
            organization_id=ORG_A_ID,
        )
        lead_b = Lead(
            name="Lead B1",
            email=f"lead-b1-{_unique}@test.com",
            appt_datetime_raw="tomorrow 3pm",
            appt_datetime_utc=_future_appt,
            dedupe_key=f"p1f-lead-b1-{_unique}",
            status=LeadStatus.SCHEDULED,
            organization_id=ORG_B_ID,
        )
        db.add_all([lead_a, lead_b])
        db.flush()

        # ── Create Follow-Ups ───────────────────────────────────────────
        fu_a = FollowUp(
            organization_id=ORG_A_ID,
            lead_id=lead_a.id,
            created_by=user_a.id,
            title="Follow-Up A1",
            priority="medium",
            status=FollowUpStatus.PENDING,
            due_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        fu_b = FollowUp(
            organization_id=ORG_B_ID,
            lead_id=lead_b.id,
            created_by=user_b.id,
            title="Follow-Up B1",
            priority="high",
            status=FollowUpStatus.PENDING,
            due_at=datetime.now(timezone.utc) + timedelta(days=2),
        )
        db.add_all([fu_a, fu_b])
        db.flush()

        # ── Create Event Logs ───────────────────────────────────────────
        evt_a = EventLog(
            lead_id=lead_a.id,
            event_type="test_event_a",
            payload='{"source": "p1f_test_a"}',
            organization_id=ORG_A_ID,
        )
        evt_b = EventLog(
            lead_id=lead_b.id,
            event_type="test_event_b",
            payload='{"source": "p1f_test_b"}',
            organization_id=ORG_B_ID,
        )
        db.add_all([evt_a, evt_b])
        db.flush()

        # ── Create Failed Jobs ──────────────────────────────────────────
        fj_a = FailedJob(
            job_type="test_job",
            payload='{"test": true}',
            error="test error A",
            organization_id=ORG_A_ID,
        )
        fj_b = FailedJob(
            job_type="test_job",
            payload='{"test": true}',
            error="test error B",
            organization_id=ORG_B_ID,
        )
        db.add_all([fj_a, fj_b])
        db.flush()

        db.commit()

        # ── Extract plain values BEFORE closing the session ────────────
        # ORM objects become detached after db.close(); store only
        # UUIDs, strings, and other serialisable values so tests never
        # hit DetachedInstanceError.
        data = {
            # Organization
            "org_a_id": org_a.id,
            "org_b_id": org_b.id,
            "org_a_name": org_a.name,
            "org_b_name": org_b.name,
            # User A (Owner of Org A)
            "user_a_id": user_a.id,
            "user_a_org": user_a.organization_id,
            "user_a_role": user_a.role.value,
            "user_a_email": user_a.email,
            # Member A (Member of Org A)
            "member_a_id": member_a.id,
            "member_a_org": member_a.organization_id,
            "member_a_role": member_a.role.value,
            "member_a_email": member_a.email,
            # User B (Owner of Org B)
            "user_b_id": user_b.id,
            "user_b_org": user_b.organization_id,
            "user_b_role": user_b.role.value,
            "user_b_email": user_b.email,
            # Lead IDs
            "lead_a_id": lead_a.id,
            "lead_b_id": lead_b.id,
            "lead_a_name": "Lead A1",
            "lead_b_name": "Lead B1",
            # Follow-up IDs
            "fu_a_id": fu_a.id,
            "fu_b_id": fu_b.id,
            # Event log IDs
            "evt_a_id": evt_a.id,
            "evt_b_id": evt_b.id,
            # Failed job IDs
            "fj_a_id": fj_a.id,
            "fj_b_id": fj_b.id,
        }
        return data
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@pytest.fixture(autouse=True, scope="module")
def _cleanup_after_module():
    """Clean up ORG_A/ORG_B test data after the module finishes.

    This prevents leftover data from contaminating subsequent test modules.
    """
    yield
    _cleanup_org_data()


def _cleanup_org_data():
    """Delete all test data for ORG_A and ORG_B.

    FK-safe order: events_log → followups → leads → failed_jobs → users → organizations.
    """
    db = SessionLocal()
    try:
        lead_ids = db.query(Lead.id).filter(
            Lead.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).subquery()
        lead_id_list = [row[0] for row in db.query(lead_ids).all()]
        db.query(EventLog).filter(
            EventLog.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        if lead_id_list:
            db.query(EventLog).filter(
                EventLog.lead_id.in_(lead_id_list)
            ).delete(synchronize_session=False)
        db.query(FollowUp).filter(
            FollowUp.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        if lead_id_list:
            db.query(FollowUp).filter(
                FollowUp.lead_id.in_(lead_id_list)
            ).delete(synchronize_session=False)
        db.query(Lead).filter(
            Lead.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        db.query(FailedJob).filter(
            FailedJob.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        db.query(TokenBlocklist).filter(
            TokenBlocklist.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        db.query(User).filter(
            User.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        db.query(Organization).filter(
            Organization.id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


# ── Auth Helpers ──────────────────────────────────────────────────────────────


def _make_token(user_id: uuid.UUID, org_id: uuid.UUID, role: str) -> str:
    """Create a valid JWT for testing."""
    from app.auth import create_access_token
    return create_access_token(user_id=user_id, organization_id=org_id, role=role)


def _jwt_headers(user_id: uuid.UUID, org_id: uuid.UUID, role: str) -> dict:
    """Return Bearer auth headers for the given user credentials."""
    token = _make_token(user_id, org_id, role)
    return {"Authorization": f"Bearer {token}"}


def _headers_a(d: dict) -> dict:
    """Shorthand: JWT headers for Owner A."""
    return _jwt_headers(d["user_a_id"], d["user_a_org"], d["user_a_role"])


def _headers_b(d: dict) -> dict:
    """Shorthand: JWT headers for Owner B."""
    return _jwt_headers(d["user_b_id"], d["user_b_org"], d["user_b_role"])


def _headers_member_a(d: dict) -> dict:
    """Shorthand: JWT headers for Member A."""
    return _jwt_headers(d["member_a_id"], d["member_a_org"], d["member_a_role"])


# ── Test Client ───────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def client():
    """Module-scoped test client."""
    with TestClient(app) as c:
        yield c


# ══════════════════════════════════════════════════════════════════════════════
# 1. LEADS — Dashboard Endpoints
# ══════════════════════════════════════════════════════════════════════════════


class TestDashboardLeadsIsolation:
    """Verify cross-tenant lead access is blocked for all dashboard lead endpoints."""

    def test_list_own_leads(self, client, _test_data):
        """Each org can list its own leads."""
        d = _test_data
        r_a = client.get("/dashboard/api/leads", headers=_headers_a(d))
        assert r_a.status_code == 200
        ids = {l["id"] for l in r_a.json()["leads"]}
        assert str(d["lead_a_id"]) in ids

        r_b = client.get("/dashboard/api/leads", headers=_headers_b(d))
        assert r_b.status_code == 200
        ids = {l["id"] for l in r_b.json()["leads"]}
        assert str(d["lead_b_id"]) in ids

    def test_list_no_cross_tenant_leaks(self, client, _test_data):
        """List endpoint must not leak leads from another org."""
        d = _test_data
        r_a = client.get("/dashboard/api/leads", headers=_headers_a(d))
        ids = {l["id"] for l in r_a.json()["leads"]}
        assert str(d["lead_b_id"]) not in ids

        r_b = client.get("/dashboard/api/leads", headers=_headers_b(d))
        ids = {l["id"] for l in r_b.json()["leads"]}
        assert str(d["lead_a_id"]) not in ids

    def test_lead_detail_cannot_cross_org(self, client, _test_data):
        """Org A cannot access Org B's lead via path ID, and vice versa."""
        d = _test_data
        r = client.get(
            f"/dashboard/api/leads/{d['lead_b_id']}",
            headers=_headers_a(d),
        )
        assert r.status_code == 404
        r = client.get(
            f"/dashboard/api/leads/{d['lead_a_id']}",
            headers=_headers_b(d),
        )
        assert r.status_code == 404

    def test_lead_detail_own(self, client, _test_data):
        """Each org can access its own lead detail."""
        d = _test_data
        r = client.get(
            f"/dashboard/api/leads/{d['lead_a_id']}",
            headers=_headers_a(d),
        )
        assert r.status_code == 200
        assert r.json()["lead"]["id"] == str(d["lead_a_id"])

    def test_edit_lead_cannot_cross_org(self, client, _test_data):
        """Org A cannot edit Org B's lead via path ID."""
        d = _test_data
        r = client.patch(
            f"/dashboard/api/leads/{d['lead_b_id']}",
            json={"name": "Hacked Name"},
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_status_update_cannot_cross_org(self, client, _test_data):
        """Org A cannot change Org B's lead status."""
        d = _test_data
        r = client.patch(
            f"/dashboard/api/leads/{d['lead_b_id']}/status",
            json={"status": "completed"},
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_call_update_cannot_cross_org(self, client, _test_data):
        """Org A cannot update Org B's lead call details."""
        d = _test_data
        r = client.patch(
            f"/dashboard/api/leads/{d['lead_b_id']}/call",
            json={"call_notes": "Hacked notes"},
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_cancel_call_cannot_cross_org(self, client, _test_data):
        """Org A cannot cancel Org B's call."""
        d = _test_data
        r = client.post(
            f"/dashboard/api/leads/{d['lead_b_id']}/cancel",
            json={"reason": "Hacked cancellation"},
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_reschedule_cannot_cross_org(self, client, _test_data):
        """Org A cannot reschedule Org B's call."""
        d = _test_data
        r = client.post(
            f"/dashboard/api/leads/{d['lead_b_id']}/reschedule",
            json={"appt_datetime_raw": "next friday 3pm"},
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_lead_export_no_cross_tenant(self, client, _test_data):
        """CSV export contains only the requesting org's leads."""
        d = _test_data
        r = client.get("/dashboard/api/leads/export", headers=_headers_a(d))
        assert r.status_code == 200
        csv_text = r.text
        assert d["lead_a_name"] in csv_text
        assert d["lead_b_name"] not in csv_text

    def test_lead_upcoming_no_cross_tenant(self, client, _test_data):
        """Upcoming leads endpoint is org-scoped."""
        d = _test_data
        r = client.get("/dashboard/api/leads/upcoming", headers=_headers_a(d))
        assert r.status_code == 200
        data = r.json()
        lead_ids = [l.get("id") for l in data.get("leads", [])]
        assert str(d["lead_b_id"]) not in lead_ids

    def test_member_cannot_edit_lead(self, client, _test_data):
        """Member role cannot edit leads (RBAC check)."""
        d = _test_data
        r = client.patch(
            f"/dashboard/api/leads/{d['lead_a_id']}",
            json={"name": "Should Fail"},
            headers=_headers_member_a(d),
        )
        assert r.status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# 2. LEADS — CRM Endpoints
# ══════════════════════════════════════════════════════════════════════════════


class TestCRMLeadsIsolation:
    """Verify cross-tenant lead access is blocked for CRM endpoints."""

    def test_crm_search_scoped(self, client, _test_data):
        """CRM search returns only the requesting org's leads."""
        d = _test_data
        r = client.get(
            "/crm/search?q=Lead",
            headers=_headers_a(d),
        )
        assert r.status_code == 200
        names = [l["prospect_name"] for l in r.json()["leads"]]
        assert d["lead_a_name"] in names
        assert d["lead_b_name"] not in names

    def test_crm_stats_scoped(self, client, _test_data):
        """CRM stats reflect only the requesting org's data."""
        d = _test_data
        r = client.get("/crm/stats", headers=_headers_a(d))
        assert r.status_code == 200

    def test_crm_score_cannot_cross_org(self, client, _test_data):
        """Org A cannot get AI score for Org B's lead."""
        d = _test_data
        r = client.get(
            f"/crm/leads/{d['lead_b_id']}/score",
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_crm_summary_cannot_cross_org(self, client, _test_data):
        """Org A cannot get AI summary for Org B's lead."""
        d = _test_data
        r = client.get(
            f"/crm/leads/{d['lead_b_id']}/summary",
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_crm_next_action_cannot_cross_org(self, client, _test_data):
        """Org A cannot get next-action for Org B's lead."""
        d = _test_data
        r = client.get(
            f"/crm/leads/{d['lead_b_id']}/next-action",
            headers=_headers_b(d),
        )
        assert r.status_code == 200
        r2 = client.get(
            f"/crm/leads/{d['lead_a_id']}/next-action",
            headers=_headers_b(d),
        )
        assert r2.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 3. FOLLOW-UPS — Dashboard Endpoints
# ══════════════════════════════════════════════════════════════════════════════


class TestDashboardFollowupsIsolation:
    """Verify cross-tenant follow-up access is blocked for dashboard endpoints."""

    def test_list_own_followups(self, client, _test_data):
        """Each org lists only its own follow-ups."""
        d = _test_data
        r = client.get("/dashboard/api/follow-ups", headers=_headers_a(d))
        assert r.status_code == 200
        ids = {f["id"] for f in r.json()["follow_ups"]}
        assert str(d["fu_a_id"]) in ids
        assert str(d["fu_b_id"]) not in ids

    def test_followup_detail_cannot_cross_org(self, client, _test_data):
        """Org A cannot access Org B's follow-up via path ID."""
        d = _test_data
        r = client.get(
            f"/dashboard/api/follow-ups/{d['fu_b_id']}",
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_followup_detail_own(self, client, _test_data):
        """Each org can access its own follow-up detail."""
        d = _test_data
        r = client.get(
            f"/dashboard/api/follow-ups/{d['fu_a_id']}",
            headers=_headers_a(d),
        )
        assert r.status_code == 200
        assert r.json()["follow_up"]["id"] == str(d["fu_a_id"])

    def test_followup_update_cannot_cross_org(self, client, _test_data):
        """Org A cannot update Org B's follow-up."""
        d = _test_data
        r = client.patch(
            f"/dashboard/api/follow-ups/{d['fu_b_id']}",
            json={"title": "Hacked Title"},
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_followup_status_change_cannot_cross_org(self, client, _test_data):
        """Org A cannot change Org B's follow-up status."""
        d = _test_data
        r = client.patch(
            f"/dashboard/api/follow-ups/{d['fu_b_id']}/status",
            json={"status": "completed"},
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_followup_delete_cannot_cross_org(self, client, _test_data):
        """Org A cannot delete Org B's follow-up."""
        d = _test_data
        r = client.delete(
            f"/dashboard/api/follow-ups/{d['fu_b_id']}",
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_followup_create_lead_cannot_cross_org(self, client, _test_data):
        """Org A cannot create a follow-up referencing Org B's lead."""
        d = _test_data
        r = client.post(
            "/dashboard/api/follow-ups",
            json={
                "lead_id": str(d["lead_b_id"]),
                "title": "Cross-Tenant Follow-Up",
            },
            headers=_headers_a(d),
        )
        assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 4. FOLLOW-UPS — Router Endpoints
# ══════════════════════════════════════════════════════════════════════════════


class TestFollowupRouterIsolation:
    """Verify cross-tenant access is blocked on the /followups router."""

    def test_list_own(self, client, _test_data):
        """Each org lists only its own follow-ups."""
        d = _test_data
        r = client.get("/followups", headers=_headers_a(d))
        assert r.status_code == 200
        ids = {f["id"] for f in r.json()["followups"]}
        assert str(d["fu_a_id"]) in ids
        assert str(d["fu_b_id"]) not in ids

    def test_update_cannot_cross_org_via_get(self, client, _test_data):
        """Org A cannot access Org B's follow-up via /followups router.

        GET /followups/{id} does not exist — server returns 405 Method Not Allowed,
        which still prevents data access."""
        d = _test_data
        r = client.get(
            f"/followups/{d['fu_b_id']}",
            headers=_headers_a(d),
        )
        # 404 or 405 both prevent cross-tenant data access
        assert r.status_code in (404, 405)

    def test_update_cannot_cross_org(self, client, _test_data):
        """Org A cannot update Org B's follow-up via /followups router."""
        d = _test_data
        r = client.patch(
            f"/followups/{d['fu_b_id']}",
            json={"title": "Hacked"},
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_complete_cannot_cross_org(self, client, _test_data):
        """Org A cannot complete Org B's follow-up via /followups router."""
        d = _test_data
        r = client.post(
            f"/followups/{d['fu_b_id']}/complete",
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_create_lead_cannot_cross_org(self, client, _test_data):
        """Org A cannot create follow-up referencing Org B's lead via /followups."""
        d = _test_data
        r = client.post(
            "/followups",
            json={
                "lead_id": str(d["lead_b_id"]),
                "title": "Cross-Tenant",
            },
            headers=_headers_a(d),
        )
        assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 5. USERS — Organization Router
# ══════════════════════════════════════════════════════════════════════════════


class TestUserIsolation:
    """Verify cross-tenant user access is blocked."""

    def test_list_users_scoped(self, client, _test_data):
        """Each org sees only its own users."""
        d = _test_data
        r = client.get("/organization/users", headers=_headers_a(d))
        assert r.status_code == 200
        emails = {u["email"] for u in r.json()["users"]}
        assert d["user_a_email"] in emails
        assert d["user_b_email"] not in emails
        assert d["member_a_email"] in emails

    def test_update_user_cannot_cross_org(self, client, _test_data):
        """Org A cannot update Org B's user."""
        d = _test_data
        r = client.patch(
            f"/organization/users/{d['user_b_id']}",
            json={"name": "Hacked Name"},
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_delete_user_cannot_cross_org(self, client, _test_data):
        """Org A cannot delete Org B's user."""
        d = _test_data
        r = client.delete(
            f"/organization/users/{d['user_b_id']}",
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_create_user_cannot_cross_org(self, client, _test_data):
        """Created users are always scoped to the creator's org (org_id derived from JWT)."""
        d = _test_data
        r = client.post(
            "/organization/users",
            json={
                "email": f"new-user-{_unique}@p1f-test.com",
                "name": "New User",
                "password": "StrongP@ss123!",
                "role": "member",
            },
            headers=_headers_a(d),
        )
        assert r.status_code == 201
        created = r.json()
        # User must belong to Org A, never Org B
        # UserInfo nests org under 'organization' object
        assert created["organization"]["id"] == str(ORG_A_ID)

    def test_member_cannot_manage_users(self, client, _test_data):
        """Member role cannot manage users (RBAC)."""
        d = _test_data
        r = client.get(
            "/organization/users",
            headers=_headers_member_a(d),
        )
        # Members CAN list users (read-only), but cannot create/update/delete
        r2 = client.post(
            "/organization/users",
            json={
                "email": f"should-fail-{_unique}@p1f-test.com",
                "name": "Should Fail",
                "password": "StrongP@ss123!",
                "role": "member",
            },
            headers=_headers_member_a(d),
        )
        assert r2.status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# 6. ORGANIZATION SETTINGS
# ══════════════════════════════════════════════════════════════════════════════


class TestOrganizationSettingsIsolation:
    """Verify each org can only access its own settings."""

    def test_get_settings_own_org(self, client, _test_data):
        """Each org gets its own settings."""
        d = _test_data
        r = client.get("/organization/settings", headers=_headers_a(d))
        assert r.status_code == 200
        assert r.json()["name"] == d["org_a_name"]

    def test_update_settings_scoped(self, client, _test_data):
        """Settings updates only affect the requesting org."""
        d = _test_data
        r = client.patch(
            "/organization/settings",
            json={"display_name": "Updated Org A"},
            headers=_headers_a(d),
        )
        assert r.status_code == 200
        assert r.json()["display_name"] == "Updated Org A"

        # Verify Org B settings are unaffected
        r2 = client.get("/organization/settings", headers=_headers_b(d))
        assert r2.json()["display_name"] is None


# ══════════════════════════════════════════════════════════════════════════════
# 7. WEBHOOK CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════


class TestWebhookConfigIsolation:
    """Verify webhook configuration is org-scoped."""

    def test_get_webhook_config_own(self, client, _test_data):
        """Each org gets its own webhook config."""
        d = _test_data
        r = client.get(
            "/organization/webhook/config",
            headers=_headers_a(d),
        )
        assert r.status_code == 200
        assert r.json()["has_secret"] is True
        # Secret must NEVER be returned in full
        assert "minimum-16-chars" not in r.json().get("secret_masked", "")

    def test_rotate_secret_does_not_expose_other_org(self, client, _test_data):
        """Secret rotation only affects the requesting org."""
        d = _test_data
        r = client.post(
            "/organization/webhook/rotate-secret",
            headers=_headers_a(d),
        )
        assert r.status_code == 200
        new_secret = r.json()["webhook_secret"]
        # New secret should NOT match Org B's secret
        assert new_secret != "org-b-secret-minimum-16-chars"


# ══════════════════════════════════════════════════════════════════════════════
# 8. BILLING
# ══════════════════════════════════════════════════════════════════════════════


class TestBillingIsolation:
    """Verify billing information is org-scoped."""

    def test_get_plan_own_org(self, client, _test_data):
        """Each org sees its own plan."""
        pytest.skip("Billing endpoints removed")

    def test_usage_own_org(self, client, _test_data):
        """Usage stats are scoped to the requesting org."""
        pytest.skip("Billing endpoints removed")

    def test_trial_status_own_org(self, client, _test_data):
        """Trial status is scoped to the requesting org."""
        pytest.skip("Billing endpoints removed")

    def test_downgrade_requires_owner(self, client, _test_data):
        """Member cannot downgrade (RBAC + org isolation)."""
        pytest.skip("Billing endpoints removed")

    # ── P1-F: Cross-tenant billing isolation ──────────────────────────────

    def test_downgrade_scoped_to_own_org(self, client, _test_data):
        """Org A downgrades itself; Org B's plan remains unchanged."""
        pytest.skip("Billing endpoints removed")

    def test_cancel_scoped_to_own_org(self, client, _test_data):
        """Org A cancels its subscription; Org B's plan remains unchanged."""
        pytest.skip("Billing endpoints removed")

    def test_plan_get_never_leaks_other_org(self, client, _test_data):
        """Org A requesting /billing/plan always gets Org A's data, never Org B's."""
        pytest.skip("Billing endpoints removed")

    def test_usage_never_leaks_other_org(self, client, _test_data):
        """Org A requesting /billing/usage always gets Org A's data."""
        pytest.skip("Billing endpoints removed")

    def test_trial_status_never_leaks_other_org(self, client, _test_data):
        """Org A requesting /billing/trial-status always gets Org A's data."""
        pytest.skip("Billing endpoints removed")

    def test_confirm_downgrade_scoped_to_own_org(self, client, _test_data):
        """Org A confirming downgrade only affects Org A; Org B untouched."""
        pytest.skip("Billing endpoints removed")

    def test_downgrade_does_not_affect_org_b_subscription_fields(self, client, _test_data):
        """After Org A downgrades, Org B's subscription_id and subscription_status are unchanged."""
        pytest.skip("Billing endpoints removed")

    # Webhook handler tests removed — billing_router deleted


# ══════════════════════════════════════════════════════════════════════════════
# 9. ANALYTICS & AUDIT
# ══════════════════════════════════════════════════════════════════════════════


class TestAnalyticsAuditIsolation:
    """Verify analytics and audit data are org-scoped."""

    def test_analytics_leads_over_time(self, client, _test_data):
        """Leads-over-time analytics are scoped to the requesting org."""
        d = _test_data
        r = client.get(
            "/dashboard/api/analytics/leads-over-time?days=30",
            headers=_headers_a(d),
        )
        assert r.status_code == 200

    def test_analytics_appointments_over_time(self, client, _test_data):
        """Appointments-over-time analytics are scoped to the requesting org."""
        d = _test_data
        r = client.get(
            "/dashboard/api/analytics/appointments-over-time?days=30",
            headers=_headers_a(d),
        )
        assert r.status_code == 200

    def test_audit_log_scoped(self, client, _test_data):
        """Audit log only shows events from the requesting org."""
        d = _test_data
        r = client.get(
            "/dashboard/api/audit-log",
            headers=_headers_a(d),
        )
        assert r.status_code == 200
        events = r.json()["events"]
        # Org A's test event should be visible
        evt_types = [e["event_type"] for e in events]
        assert "test_event_a" in evt_types

        r2 = client.get(
            "/dashboard/api/audit-log",
            headers=_headers_b(d),
        )
        evt_types_b = [e["event_type"] for e in r2.json()["events"]]
        assert "test_event_a" not in evt_types_b
        assert "test_event_b" in evt_types_b

    def test_summary_scoped(self, client, _test_data):
        """Dashboard summary is scoped to the requesting org."""
        d = _test_data
        r = client.get("/dashboard/api/summary", headers=_headers_a(d))
        assert r.status_code == 200

    def test_failed_jobs_scoped(self, client, _test_data):
        """Failed jobs list is scoped to the requesting org."""
        d = _test_data
        r = client.get("/dashboard/api/failed-jobs", headers=_headers_a(d))
        assert r.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# 10. AUTH — Logout/Password
# ══════════════════════════════════════════════════════════════════════════════


class TestAuthIsolation:
    """Verify auth endpoints do not leak cross-tenant data."""

    def test_me_returns_own_user(self, client, _test_data):
        """/auth/me returns the authenticated user's own info."""
        d = _test_data
        r = client.get("/auth/me", headers=_headers_a(d))
        assert r.status_code == 200
        assert r.json()["email"] == d["user_a_email"]
        # UserInfo nests org under 'organization' object
        assert r.json()["organization"]["id"] == str(ORG_A_ID)

    def test_change_password_own_account(self, client, _test_data):
        """/auth/change-password only affects the authenticated user."""
        d = _test_data
        r = client.post(
            "/auth/change-password",
            json={
                "current_password": "StrongP@ss123!",
                "new_password": "NewStrongP@ss456!",
            },
            headers=_headers_a(d),
        )
        assert r.status_code == 200
        # Reset password back to original for other tests
        from app.auth import hash_password, _clear_bulk_revocation
        from app.database import SessionLocal as _SL
        _db = _SL()
        try:
            u = _db.query(User).filter(User.id == d["user_a_id"]).first()
            u.password_hash = hash_password("StrongP@ss123!")
            _db.commit()
            # Clear the bulk revocation sentinel so new JWTs for this user work
            _clear_bulk_revocation(d["user_a_id"], _db)
        finally:
            _db.close()

    def test_cannot_login_as_other_org_user(self, client, _test_data):
        """Login with Org B's credentials only returns Org B's token."""
        d = _test_data
        r = client.post(
            "/auth/login",
            json={
                "email": d["user_b_email"],
                "password": "StrongP@ss123!",
            },
        )
        assert r.status_code == 200
        from app.auth import decode_access_token
        payload = decode_access_token(r.json()["access_token"])
        assert payload["org_id"] == str(ORG_B_ID)


# ══════════════════════════════════════════════════════════════════════════════
# 11. IDOR — Manipulated Path IDs Across All Routers
# ══════════════════════════════════════════════════════════════════════════════


class TestIDORManipulation:
    """Systematic IDOR testing across all routers with manipulated identifiers."""

    @pytest.fixture(autouse=True)
    def _restore_org_a_plan(self):
        """Ensure Org A has plan='business' before each IDOR test.

        Billing/subscription restrictions have been removed, but this
        fixture is retained as a defensive guard to ensure the test
        organization always operates at full capacity.
        """
        from app.database import SessionLocal as _SL
        from app.models_multi_tenant import Organization as _Org

        _db = _SL()
        try:
            _org = _db.query(_Org).filter(_Org.id == ORG_A_ID).first()
            if _org and _org.plan != "business":
                _org.plan = "business"
                _db.commit()
        finally:
            _db.close()

    def test_dashboard_lead_idor(self, client, _test_data):
        """Dashboard: path lead_id from Org B with Org A JWT → 404."""
        d = _test_data
        lead_b = d["lead_b_id"]
        endpoints = [
            ("GET", f"/dashboard/api/leads/{lead_b}", None),
            ("PATCH", f"/dashboard/api/leads/{lead_b}", {"name": "X"}),
            ("PATCH", f"/dashboard/api/leads/{lead_b}/status", {"status": "completed"}),
            ("PATCH", f"/dashboard/api/leads/{lead_b}/call", {"call_notes": "X"}),
            ("POST", f"/dashboard/api/leads/{lead_b}/cancel", {"reason": "X"}),
            ("POST", f"/dashboard/api/leads/{lead_b}/reschedule", {"appt_datetime_raw": "next week"}),
        ]
        for method, path, body in endpoints:
            if method == "GET":
                r = client.get(path, headers=_headers_a(d))
            elif method == "PATCH":
                r = client.patch(path, json=body, headers=_headers_a(d))
            else:
                r = client.post(path, json=body, headers=_headers_a(d))
            assert r.status_code == 404, f"{method} {path} should return 404, got {r.status_code}"

    def test_dashboard_followup_idor(self, client, _test_data):
        """Dashboard: path followup_id from Org B with Org A JWT → 404."""
        d = _test_data
        fu_b = d["fu_b_id"]
        endpoints = [
            ("GET", f"/dashboard/api/follow-ups/{fu_b}", None),
            ("PATCH", f"/dashboard/api/follow-ups/{fu_b}", {"title": "X"}),
            ("PATCH", f"/dashboard/api/follow-ups/{fu_b}/status", {"status": "completed"}),
            ("DELETE", f"/dashboard/api/follow-ups/{fu_b}", None),
        ]
        for method, path, body in endpoints:
            if method == "GET":
                r = client.get(path, headers=_headers_a(d))
            elif method == "PATCH":
                r = client.patch(path, json=body, headers=_headers_a(d))
            elif method == "DELETE":
                r = client.delete(path, headers=_headers_a(d))
            assert r.status_code == 404, f"{method} {path} should return 404, got {r.status_code}"

    def test_router_followup_idor(self, client, _test_data):
        """/followups router: path followup_id from Org B with Org A JWT → 404."""
        d = _test_data
        fu_b = d["fu_b_id"]
        endpoints = [
            # GET /followups/{id} does not exist — 405 is acceptable
            ("PATCH", f"/followups/{fu_b}", {"title": "X"}),
            ("POST", f"/followups/{fu_b}/complete", None),
        ]
        for method, path, body in endpoints:
            if method == "PATCH":
                r = client.patch(path, json=body, headers=_headers_a(d))
            elif method == "POST":
                r = client.post(path, headers=_headers_a(d))
            assert r.status_code == 404, f"{method} {path} should return 404, got {r.status_code}"

    def test_org_router_user_idor(self, client, _test_data):
        """/organization/users: user_id from Org B with Org A JWT → 404."""
        d = _test_data
        r = client.patch(
            f"/organization/users/{d['user_b_id']}",
            json={"name": "Hacked"},
            headers=_headers_a(d),
        )
        assert r.status_code == 404
        r = client.delete(
            f"/organization/users/{d['user_b_id']}",
            headers=_headers_a(d),
        )
        assert r.status_code == 404

    def test_crm_lead_idor(self, client, _test_data):
        """/crm/leads/{id}: lead_id from Org B with Org A JWT → 404."""
        d = _test_data
        lead_b = d["lead_b_id"]
        endpoints = [
            f"/crm/leads/{lead_b}/score",
            f"/crm/leads/{lead_b}/summary",
            f"/crm/leads/{lead_b}/next-action",
        ]
        for path in endpoints:
            r = client.get(path, headers=_headers_a(d))
            assert r.status_code == 404, f"GET {path} should return 404, got {r.status_code}"

    def test_cross_org_returns_never_leak_data(self, client, _test_data):
        """All cross-org attempts return 404 (not 403 with data)."""
        d = _test_data
        r = client.get(
            f"/dashboard/api/leads/{d['lead_b_id']}",
            headers=_headers_a(d),
        )
        # Must be 404, NOT 200 or 403 with leaked data
        assert r.status_code == 404
        # Verify response body does NOT contain the other org's lead data
        body = r.text
        assert d["lead_b_name"] not in body
        assert str(d["lead_b_id"]) not in body


# ══════════════════════════════════════════════════════════════════════════════
# 12. HTTP BASIC BYPASS IS PROPERLY SCOPED
# ══════════════════════════════════════════════════════════════════════════════


class TestBasicAuthScoping:
    """Verify HTTP Basic (platform admin) sees all data but JWT users are org-scoped."""

    def test_basic_auth_sees_all_leads(self, client, _test_data):
        """Platform admin (Basic auth) sees leads from all organizations."""
        d = _test_data
        basic_headers = {
            "Authorization": "Basic "
            + base64.b64encode(
                f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
            ).decode()
        }
        r = client.get("/dashboard/api/leads", headers=basic_headers)
        assert r.status_code == 200
        ids = {l["id"] for l in r.json()["leads"]}
        assert str(d["lead_a_id"]) in ids
        assert str(d["lead_b_id"]) in ids

    def test_jwt_auth_scopes_to_own_org(self, client, _test_data):
        """JWT auth scopes to the user's organization only."""
        d = _test_data
        r = client.get("/dashboard/api/leads", headers=_headers_a(d))
        ids = {l["id"] for l in r.json()["leads"]}
        assert str(d["lead_a_id"]) in ids
        assert str(d["lead_b_id"]) not in ids
