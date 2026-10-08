"""Tests for Phase 7 Part 5 — Dashboard Follow-Up Statistics (SH-1).

Endpoint: GET /dashboard/api/follow-ups/stats

Test groups:
  1. Empty org returns all zeros / null average
  2. Basic counts (pending, in_progress, completed, cancelled)
  3. Active includes pending + in_progress
  4. Cancelled excluded from active
  5. Overdue counting
  6. Future-due not overdue
  7. Average completion time
  8. Null average when no completed records
  9. Tenant isolation
  10. Authentication required
  11. Counts change after status transition
  12. Cancelled not active (regression)
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


def _stats(client, token):
    """Call the stats endpoint and return the JSON response."""
    resp = client.get(
        "/dashboard/api/follow-ups/stats",
        headers=_auth_header(token),
    )
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# 1. EMPTY ORG
# ══════════════════════════════════════════════════════════════════════════════


class TestStatsEmptyOrg:
    """Empty organization returns all zeros and null average."""

    def test_stats_empty_org(self, client, db):
        """Empty org returns zero counts and null average."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _make_token(user.id, org.id, "owner")
        resp = _stats(client, token)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["active"] == 0
        assert body["completed"] == 0
        assert body["cancelled"] == 0
        assert body["overdue"] == 0
        assert body["avg_time_to_completion_hours"] is None


# ══════════════════════════════════════════════════════════════════════════════
# 2. BASIC COUNTS
# ══════════════════════════════════════════════════════════════════════════════


class TestStatsBasicCounts:
    """Verify all count fields return correct values."""

    def test_stats_basic_counts(self, client, db):
        """Create one of each status, verify counts."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")

        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.PENDING)
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.IN_PROGRESS)
        _create_followup_raw(
            db, org.id, lead.id, user.id,
            status=FollowUpStatus.COMPLETED,
            completed_at=datetime.now(timezone.utc),
        )
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.CANCELLED)

        resp = _stats(client, token)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 4
        assert body["active"] == 2  # pending + in_progress
        assert body["completed"] == 1
        assert body["cancelled"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# 3. ACTIVE INCLUDES PENDING AND IN_PROGRESS
# ══════════════════════════════════════════════════════════════════════════════


class TestStatsActiveIncludesBoth:
    """PENDING and IN_PROGRESS are both counted as active."""

    def test_stats_active_includes_pending_and_in_progress(self, client, db):
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")

        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.PENDING)
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.IN_PROGRESS)
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.PENDING)

        resp = _stats(client, token)
        body = resp.json()
        assert body["active"] == 3  # 2 pending + 1 in_progress
        assert body["total"] == 3


# ══════════════════════════════════════════════════════════════════════════════
# 4. CANCELLED EXCLUDED FROM ACTIVE
# ══════════════════════════════════════════════════════════════════════════════


class TestStatsCancelledExcludedFromActive:
    """CANCELLED follow-ups must not appear in the active count."""

    def test_stats_cancelled_excluded_from_active(self, client, db):
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")

        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.CANCELLED)
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.CANCELLED)

        resp = _stats(client, token)
        body = resp.json()
        assert body["active"] == 0
        assert body["cancelled"] == 2
        assert body["total"] == 2


# ══════════════════════════════════════════════════════════════════════════════
# 5. OVERDUE COUNTING
# ══════════════════════════════════════════════════════════════════════════════


class TestStatsOverdue:
    """PENDING/IN_PROGRESS with due_at in the past are overdue."""

    def test_stats_overdue(self, client, db):
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")

        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        # Overdue: PENDING with past due_at
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.PENDING, due_at=yesterday)
        # Overdue: IN_PROGRESS with past due_at
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.IN_PROGRESS, due_at=yesterday)

        resp = _stats(client, token)
        body = resp.json()
        assert body["overdue"] == 2


# ══════════════════════════════════════════════════════════════════════════════
# 6. FUTURE DUE NOT OVERDUE
# ══════════════════════════════════════════════════════════════════════════════


class TestStatsFutureDueNotOverdue:
    """Follow-ups due in the future are NOT overdue."""

    def test_stats_does_not_count_future_due_as_overdue(self, client, db):
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")

        tomorrow = datetime.now(timezone.utc) + timedelta(days=1)
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.PENDING, due_at=tomorrow)
        # Also: NULL due_at is NOT overdue
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.PENDING, due_at=None)

        resp = _stats(client, token)
        body = resp.json()
        assert body["overdue"] == 0
        assert body["active"] == 2  # Both are active, neither is overdue


# ══════════════════════════════════════════════════════════════════════════════
# 7. AVERAGE COMPLETION TIME
# ══════════════════════════════════════════════════════════════════════════════


class TestStatsAverageCompletionTime:
    """Average time-to-completion is calculated correctly."""

    def test_stats_average_completion_time(self, client, db):
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")

        now = datetime.now(timezone.utc)
        # Record 1: 24 hours to complete
        _create_followup_raw(
            db, org.id, lead.id, user.id,
            status=FollowUpStatus.COMPLETED,
            created_at=now - timedelta(hours=24),
            completed_at=now,
        )
        # Record 2: 48 hours to complete
        _create_followup_raw(
            db, org.id, lead.id, user.id,
            status=FollowUpStatus.COMPLETED,
            created_at=now - timedelta(hours=48),
            completed_at=now,
        )
        # Average should be 36 hours
        resp = _stats(client, token)
        body = resp.json()
        assert body["avg_time_to_completion_hours"] == 36.0


# ══════════════════════════════════════════════════════════════════════════════
# 8. NULL AVERAGE WHEN NO COMPLETED RECORDS
# ══════════════════════════════════════════════════════════════════════════════


class TestStatsNullAverage:
    """Average is null when there are no completed records with completed_at."""

    def test_stats_average_is_null_when_no_completed_records(self, client, db):
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")

        # Only PENDING — no completed records
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.PENDING)

        resp = _stats(client, token)
        body = resp.json()
        assert body["avg_time_to_completion_hours"] is None

    def test_stats_average_null_completed_without_timestamp(self, client, db):
        """COMPLETED without completed_at does not contribute to average."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")

        _create_followup_raw(
            db, org.id, lead.id, user.id,
            status=FollowUpStatus.COMPLETED,
            completed_at=None,
        )

        resp = _stats(client, token)
        body = resp.json()
        assert body["avg_time_to_completion_hours"] is None
        assert body["completed"] == 1  # Still counted in completed


# ══════════════════════════════════════════════════════════════════════════════
# 9. TENANT ISOLATION
# ══════════════════════════════════════════════════════════════════════════════


class TestStatsTenantIsolation:
    """Stats are scoped to the authenticated organization."""

    def test_stats_tenant_isolation(self, client, db):
        org_a, user_a = _create_org_and_user(db, role=UserRole.OWNER)
        org_b, user_b = _create_org_and_user(db, role=UserRole.OWNER)
        lead_a = _create_lead_raw(db, org_a.id, name="Lead A")
        lead_b = _create_lead_raw(db, org_b.id, name="Lead B")

        token_a = _make_token(user_a.id, org_a.id, "owner")
        token_b = _make_token(user_b.id, org_b.id, "owner")

        # Org A: 3 follow-ups
        _create_followup_raw(db, org_a.id, lead_a.id, user_a.id, status=FollowUpStatus.PENDING)
        _create_followup_raw(db, org_a.id, lead_a.id, user_a.id, status=FollowUpStatus.COMPLETED,
                             completed_at=datetime.now(timezone.utc))
        _create_followup_raw(db, org_a.id, lead_a.id, user_a.id, status=FollowUpStatus.CANCELLED)

        # Org B: 1 follow-up
        _create_followup_raw(db, org_b.id, lead_b.id, user_b.id, status=FollowUpStatus.PENDING)

        resp_a = _stats(client, token_a)
        resp_b = _stats(client, token_b)

        body_a = resp_a.json()
        body_b = resp_b.json()

        assert body_a["total"] == 3
        assert body_a["active"] == 1
        assert body_a["completed"] == 1
        assert body_a["cancelled"] == 1

        assert body_b["total"] == 1
        assert body_b["active"] == 1
        assert body_b["completed"] == 0
        assert body_b["cancelled"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# 10. AUTHENTICATION REQUIRED
# ══════════════════════════════════════════════════════════════════════════════


class TestStatsAuthentication:
    """Unauthenticated requests are rejected."""

    def test_stats_requires_authentication(self, client):
        resp = client.get("/dashboard/api/follow-ups/stats")
        assert resp.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# 11. COUNTS CHANGE AFTER STATUS TRANSITION
# ══════════════════════════════════════════════════════════════════════════════


class TestStatsAfterTransition:
    """Stats reflect status changes made via the API."""

    def test_stats_after_status_transition(self, client, db):
        """Verify counts change correctly after completing/cancelling a follow-up.

        Uses ORM-level status transitions to avoid depending on the
        pre-existing PATCH /api/follow-ups/{id}/status UUID bug.
        """
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")

        # Create a PENDING follow-up via ORM
        fu = _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.PENDING)

        # Stats: 1 total, 1 active
        body = _stats(client, token).json()
        assert body["total"] == 1
        assert body["active"] == 1
        assert body["completed"] == 0

        # Transition to COMPLETED via ORM
        now_utc = datetime.now(timezone.utc)
        fu.status = FollowUpStatus.COMPLETED
        fu.completed_at = now_utc
        fu.completed_by = user.id
        db.commit()
        db.refresh(fu)

        # Stats: 1 total, 0 active, 1 completed
        body = _stats(client, token).json()
        assert body["total"] == 1
        assert body["active"] == 0
        assert body["completed"] == 1

        # Create another PENDING, then cancel it via ORM
        fu2 = _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.PENDING)
        fu2.status = FollowUpStatus.CANCELLED
        fu2.cancelled_at = now_utc
        fu2.cancelled_by = user.id
        db.commit()
        db.refresh(fu2)

        body = _stats(client, token).json()
        assert body["total"] == 2
        assert body["active"] == 0
        assert body["completed"] == 1
        assert body["cancelled"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# 12. CANCELLED NOT ACTIVE (REGRESSION)
# ══════════════════════════════════════════════════════════════════════════════


class TestStatsCancelledNotActive:
    """Explicit regression test: CANCELLED is never counted as active."""

    def test_stats_cancelled_not_active(self, client, db):
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        lead = _create_lead_raw(db, org.id)
        token = _make_token(user.id, org.id, "owner")

        # Create all 4 statuses
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.PENDING)
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.IN_PROGRESS)
        _create_followup_raw(
            db, org.id, lead.id, user.id,
            status=FollowUpStatus.COMPLETED,
            completed_at=datetime.now(timezone.utc),
        )
        _create_followup_raw(db, org.id, lead.id, user.id, status=FollowUpStatus.CANCELLED)

        body = _stats(client, token).json()
        assert body["total"] == 4
        assert body["active"] == 2
        assert body["completed"] == 1
        assert body["cancelled"] == 1
        # The critical assertion: cancelled + completed = 2, active = 2, total = 4
        assert body["active"] + body["completed"] + body["cancelled"] == body["total"]
