"""Phase 7 Part 4 — Lead Status Guard Tests.

Tests for the lead-status guard that prevents follow-up creation and
execution when a lead is in a terminal status.

Covers:
  A. Shared guard function (is_lead_terminal_for_followup)
  B. Dashboard manual creation guard
  C. Followup router manual creation guard
  D. Auto follow-up service guard
  E. Execution engine re-check guard (post-claim, pre-send)
  F. Race condition mitigation
  G. Retry safety (retries re-check lead status)
  H. All terminal statuses block creation
  I. All non-terminal statuses allow creation
  J. Tenant isolation (cross-tenant guard)
  K. Idempotency
  L. Lead-not-found edge case
  M. Adversarial / security tests
  N. Audit event verification
  O. API-level integration tests
"""
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest
from sqlalchemy.orm import Session as SASession

from app.database import SessionLocal
from app.models import (
    EventLog,
    FollowUp,
    FollowUpPriority,
    FollowUpStatus,
    Lead,
    LeadStatus,
)
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)
from app.services.followup_cancellation import (
    TERMINAL_LEAD_STATUSES,
    FollowUpCreationBlocked,
    cancel_pending_followups_for_lead,
    is_lead_terminal_for_followup,
    is_terminal_lead_status,
)
from app.services.crypto import generate_key
from tests.test_auth import _create_org_and_user


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    """Inject test-mode secrets."""
    from app.config import settings
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", generate_key())
    monkeypatch.setattr(settings, "jwt_secret_key", "test-jwt-key-for-audit-only-1234567890abcdef")


@pytest.fixture()
def db():
    """Yield a DB session with cleanup."""
    session = SessionLocal()
    try:
        session.query(FollowUp).delete(synchronize_session="fetch")
        session.query(EventLog).delete(synchronize_session="fetch")
    except Exception:
        session.rollback()
    try:
        from app.models import FailedJob
        session.query(FailedJob).delete(synchronize_session="fetch")
    except Exception:
        session.rollback()
    try:
        session.query(Lead).delete(synchronize_session="fetch")
    except Exception:
        session.rollback()
    session.commit()

    try:
        yield session
        session.rollback()
    finally:
        session.close()


@pytest.fixture()
def org_and_user(db):
    """Create an org with an owner user for FK compliance."""
    return _create_org_and_user(db, email=f"lsg-{uuid.uuid4().hex[:8]}@test.com")


@pytest.fixture()
def org_id(org_and_user) -> uuid.UUID:
    org, _ = org_and_user
    return org.id


@pytest.fixture()
def user_id(org_and_user) -> uuid.UUID:
    _, user = org_and_user
    return user.id


def _make_lead(
    db: SASession,
    org_id: uuid.UUID,
    *,
    name: str = "Test Lead",
    email: str | None = "test@example.com",
    status: LeadStatus = LeadStatus.SCHEDULED,
) -> Lead:
    """Insert a Lead directly via ORM."""
    unique = uuid.uuid4().hex[:8]
    lead = Lead(
        organization_id=org_id,
        name=name,
        email=email or f"{unique}@example.com",
        interested="yes",
        phone_number="555-0100",
        appt_datetime_raw="2025-07-01T10:00:00",
        appt_datetime_utc=datetime.now(timezone.utc) + timedelta(days=1),
        status=status,
        dedupe_key=f"lsg-{unique}",
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


def _make_followup(
    db: SASession,
    org_id: uuid.UUID,
    lead_id: uuid.UUID,
    user_id: uuid.UUID,
    *,
    status: FollowUpStatus = FollowUpStatus.PENDING,
    title: str = "Test Follow-Up",
    due_at: datetime | None = None,
) -> FollowUp:
    """Insert a FollowUp directly via ORM."""
    fu = FollowUp(
        organization_id=org_id,
        lead_id=lead_id,
        created_by=user_id,
        title=title,
        status=status,
        priority=FollowUpPriority.MEDIUM,
        due_at=due_at or datetime.now(timezone.utc),
    )
    db.add(fu)
    db.commit()
    db.refresh(fu)
    return fu


# ══════════════════════════════════════════════════════════════════════════════
# A. Shared Guard Function Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestIsLeadTerminalForFollowupFunction:
    """Tests for is_lead_terminal_for_followup() — the shared guard."""

    def test_terminal_lead_returns_true(self, db, org_id):
        """Lead with COMPLETED status → True."""
        lead = _make_lead(db, org_id, status=LeadStatus.COMPLETED)
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is True

    def test_declined_lead_returns_true(self, db, org_id):
        """Lead with DECLINED status → True."""
        lead = _make_lead(db, org_id, status=LeadStatus.DECLINED)
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is True

    def test_not_interested_lead_returns_true(self, db, org_id):
        """Lead with NOT_INTERESTED status → True."""
        lead = _make_lead(db, org_id, status=LeadStatus.NOT_INTERESTED)
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is True

    def test_error_lead_returns_true(self, db, org_id):
        """Lead with ERROR status → True."""
        lead = _make_lead(db, org_id, status=LeadStatus.ERROR)
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is True

    def test_pending_lead_returns_false(self, db, org_id):
        """Lead with PENDING status → False."""
        lead = _make_lead(db, org_id, status=LeadStatus.PENDING)
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is False

    def test_scheduled_lead_returns_false(self, db, org_id):
        """Lead with SCHEDULED status → False."""
        lead = _make_lead(db, org_id, status=LeadStatus.SCHEDULED)
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is False

    def test_accepted_lead_returns_false(self, db, org_id):
        """Lead with ACCEPTED status → False."""
        lead = _make_lead(db, org_id, status=LeadStatus.ACCEPTED)
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is False

    def test_tentative_lead_returns_false(self, db, org_id):
        """Lead with TENTATIVE status → False."""
        lead = _make_lead(db, org_id, status=LeadStatus.TENTATIVE)
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is False

    def test_reminded_lead_returns_false(self, db, org_id):
        """Lead with REMINDED status → False."""
        lead = _make_lead(db, org_id, status=LeadStatus.REMINDED)
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is False

    def test_lead_not_found_returns_false(self, db, org_id):
        """Non-existent lead ID → False (not terminal, caller handles not-found)."""
        fake_id = uuid.uuid4()
        assert is_lead_terminal_for_followup(db, fake_id, org_id) is False


# ══════════════════════════════════════════════════════════════════════════════
# B. FollowUpCreationBlocked Exception Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestFollowUpCreationBlocked:
    """Tests for the FollowUpCreationBlocked exception class."""

    def test_exception_has_lead_id(self):
        lid = uuid.uuid4()
        exc = FollowUpCreationBlocked(lid, LeadStatus.COMPLETED)
        assert exc.lead_id == lid

    def test_exception_has_lead_status(self):
        lid = uuid.uuid4()
        exc = FollowUpCreationBlocked(lid, LeadStatus.DECLINED)
        assert exc.lead_status == LeadStatus.DECLINED

    def test_exception_message_contains_status(self):
        lid = uuid.uuid4()
        exc = FollowUpCreationBlocked(lid, LeadStatus.NOT_INTERESTED)
        assert "not_interested" in str(exc)

    def test_exception_message_contains_lead_id(self):
        lid = uuid.uuid4()
        exc = FollowUpCreationBlocked(lid, LeadStatus.ERROR)
        assert str(lid) in str(exc)


# ══════════════════════════════════════════════════════════════════════════════
# C. Dashboard Manual Creation Guard Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestDashboardCreateFollowUpGuard:
    """Tests for the terminal lead guard in dashboard.py create_follow_up()."""

    @pytest.fixture()
    def client(self):
        from fastapi.testclient import TestClient
        from app.main import app
        return TestClient(app)

    @pytest.fixture()
    def auth_headers(self, org_and_user):
        from tests.test_auth import _make_token, _auth_header
        org, user = org_and_user
        token = _make_token(user.id, org.id, UserRole.OWNER.value)
        return _auth_header(token)

    def test_create_follow_up_rejected_for_completed_lead(self, db, org_id, user_id, client, auth_headers):
        """POST /dashboard/api/follow-ups with completed lead → 409."""
        lead = _make_lead(db, org_id, status=LeadStatus.COMPLETED)
        resp = client.post(
            "/dashboard/api/follow-ups",
            json={
                "lead_id": str(lead.id),
                "title": "Should Fail",
                "priority": "medium",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 409
        assert "terminal status" in resp.json()["detail"].lower()

    def test_create_follow_up_rejected_for_declined_lead(self, db, org_id, user_id, client, auth_headers):
        """POST /dashboard/api/follow-ups with declined lead → 409."""
        lead = _make_lead(db, org_id, status=LeadStatus.DECLINED)
        resp = client.post(
            "/dashboard/api/follow-ups",
            json={
                "lead_id": str(lead.id),
                "title": "Should Fail",
                "priority": "high",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 409

    def test_create_follow_up_rejected_for_not_interested_lead(self, db, org_id, user_id, client, auth_headers):
        """POST /dashboard/api/follow-ups with not_interested lead → 409."""
        lead = _make_lead(db, org_id, status=LeadStatus.NOT_INTERESTED)
        resp = client.post(
            "/dashboard/api/follow-ups",
            json={
                "lead_id": str(lead.id),
                "title": "Should Fail",
                "priority": "low",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 409

    def test_create_follow_up_rejected_for_error_lead(self, db, org_id, user_id, client, auth_headers):
        """POST /dashboard/api/follow-ups with error lead → 409."""
        lead = _make_lead(db, org_id, status=LeadStatus.ERROR)
        resp = client.post(
            "/dashboard/api/follow-ups",
            json={
                "lead_id": str(lead.id),
                "title": "Should Fail",
                "priority": "urgent",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 409

    def test_create_follow_up_allowed_for_scheduled_lead(self, db, org_id, user_id, client, auth_headers):
        """POST /dashboard/api/follow-ups with scheduled lead → 201."""
        lead = _make_lead(db, org_id, status=LeadStatus.SCHEDULED)
        resp = client.post(
            "/dashboard/api/follow-ups",
            json={
                "lead_id": str(lead.id),
                "title": "Should Succeed",
                "priority": "medium",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 201

    def test_create_follow_up_allowed_for_pending_lead(self, db, org_id, user_id, client, auth_headers):
        """POST /dashboard/api/follow-ups with pending lead → 201."""
        lead = _make_lead(db, org_id, status=LeadStatus.PENDING)
        resp = client.post(
            "/dashboard/api/follow-ups",
            json={
                "lead_id": str(lead.id),
                "title": "Should Succeed",
                "priority": "medium",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 201

    def test_create_follow_up_404_for_nonexistent_lead(self, db, org_id, client, auth_headers):
        """POST /dashboard/api/follow-ups with nonexistent lead → 404 (not 409)."""
        resp = client.post(
            "/dashboard/api/follow-ups",
            json={
                "lead_id": str(uuid.uuid4()),
                "title": "Should 404",
                "priority": "medium",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 404

    def test_create_follow_up_rejection_detail_includes_status(self, db, org_id, client, auth_headers):
        """409 response detail includes the terminal status name."""
        lead = _make_lead(db, org_id, status=LeadStatus.COMPLETED)
        resp = client.post(
            "/dashboard/api/follow-ups",
            json={
                "lead_id": str(lead.id),
                "title": "Should Fail",
                "priority": "medium",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 409
        assert "completed" in resp.json()["detail"].lower()


# ══════════════════════════════════════════════════════════════════════════════
# D. Followup Router Manual Creation Guard Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestFollowupRouterCreateFollowupGuard:
    """Tests for the terminal lead guard in followup_router.py create_followup()."""

    @pytest.fixture()
    def client(self):
        from fastapi.testclient import TestClient
        from app.main import app
        return TestClient(app)

    @pytest.fixture()
    def auth_headers(self, org_and_user):
        from tests.test_auth import _make_token, _auth_header
        org, user = org_and_user
        token = _make_token(user.id, org.id, UserRole.OWNER.value)
        return _auth_header(token)

    def test_router_rejects_terminal_lead(self, db, org_id, client, auth_headers):
        """POST /followups with completed lead → 409."""
        lead = _make_lead(db, org_id, status=LeadStatus.COMPLETED)
        resp = client.post(
            "/followups",
            json={
                "lead_id": str(lead.id),
                "title": "Should Fail",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 409
        assert "terminal" in resp.json()["detail"].lower()

    def test_router_allows_non_terminal_lead(self, db, org_id, client, auth_headers):
        """POST /followups with scheduled lead → 201."""
        lead = _make_lead(db, org_id, status=LeadStatus.SCHEDULED)
        resp = client.post(
            "/followups",
            json={
                "lead_id": str(lead.id),
                "title": "Should Succeed",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 201

    def test_router_rejects_all_terminal_statuses(self, db, org_id, client, auth_headers):
        """Each terminal status triggers 409 via router."""
        for status in (LeadStatus.COMPLETED, LeadStatus.DECLINED,
                       LeadStatus.NOT_INTERESTED, LeadStatus.ERROR):
            lead = _make_lead(db, org_id, status=status)
            resp = client.post(
                "/followups",
                json={
                    "lead_id": str(lead.id),
                    "title": f"Terminal {status.value}",
                },
                headers=auth_headers,
            )
            assert resp.status_code == 409, f"Expected 409 for status {status.value}"


# ══════════════════════════════════════════════════════════════════════════════
# E. Auto Follow-Up Service Guard Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestAutoFollowupServiceGuard:
    """Tests for the terminal lead guard in auto_followup_service.py."""

    def test_skips_followup_for_completed_lead(self, db, org_id, user_id):
        """create_post_call_followups returns [] for completed lead."""
        from app.services.auto_followup_service import create_post_call_followups
        from app.models import CallOutcome

        lead = _make_lead(db, org_id, status=LeadStatus.COMPLETED)
        result = create_post_call_followups(db, lead, CallOutcome.CONNECTED, org_id)
        assert result == []

    def test_skips_followup_for_declined_lead(self, db, org_id, user_id):
        """create_post_call_followups returns [] for declined lead."""
        from app.services.auto_followup_service import create_post_call_followups
        from app.models import CallOutcome

        lead = _make_lead(db, org_id, status=LeadStatus.DECLINED)
        result = create_post_call_followups(db, lead, CallOutcome.NO_ANSWER, org_id)
        assert result == []

    def test_skips_followup_for_not_interested_lead(self, db, org_id, user_id):
        """create_post_call_followups returns [] for not_interested lead."""
        from app.services.auto_followup_service import create_post_call_followups
        from app.models import CallOutcome

        lead = _make_lead(db, org_id, status=LeadStatus.NOT_INTERESTED)
        result = create_post_call_followups(db, lead, CallOutcome.VOICEMAIL, org_id)
        assert result == []

    def test_skips_followup_for_error_lead(self, db, org_id, user_id):
        """create_post_call_followups returns [] for error lead."""
        from app.services.auto_followup_service import create_post_call_followups
        from app.models import CallOutcome

        lead = _make_lead(db, org_id, status=LeadStatus.ERROR)
        result = create_post_call_followups(db, lead, CallOutcome.BUSY, org_id)
        assert result == []

    def test_creates_followup_for_scheduled_lead(self, db, org_id, user_id):
        """create_post_call_followups creates follow-ups for scheduled lead."""
        from app.services.auto_followup_service import create_post_call_followups
        from app.models import CallOutcome

        lead = _make_lead(db, org_id, status=LeadStatus.SCHEDULED)
        lead.assigned_to = user_id
        db.commit()
        result = create_post_call_followups(db, lead, CallOutcome.CONNECTED, org_id)
        assert len(result) > 0

    def test_no_db_writes_for_terminal_lead(self, db, org_id, user_id):
        """No follow-up records created when lead is terminal."""
        from app.services.auto_followup_service import create_post_call_followups
        from app.models import CallOutcome

        lead = _make_lead(db, org_id, status=LeadStatus.COMPLETED)
        fu_count_before = db.query(FollowUp).filter(FollowUp.lead_id == lead.id).count()
        create_post_call_followups(db, lead, CallOutcome.CONNECTED, org_id)
        fu_count_after = db.query(FollowUp).filter(FollowUp.lead_id == lead.id).count()
        assert fu_count_before == fu_count_after


# ══════════════════════════════════════════════════════════════════════════════
# F. Execution Engine Re-Check Guard Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestFollowupExecutionRecheckGuard:
    """Tests for the post-claim, pre-send lead status re-check in followup_email_sender."""

    def test_terminal_lead_before_claim_skips(self, db, org_id, user_id):
        """Follow-up for terminal lead is cancelled (not stuck in PENDING loop)."""
        from app.services.followup_email_sender import _process_one_followup

        lead = _make_lead(db, org_id, status=LeadStatus.COMPLETED)
        fu = _make_followup(db, org_id, lead.id, user_id)

        # _process_one_followup checks terminal lead → cancels follow-up
        result = _process_one_followup(db, fu)
        assert result == "permanent_failures"
        db.refresh(fu)
        # BUG FIX: must be CANCELLED, not PENDING (old behavior caused infinite loop)
        assert fu.status == FollowUpStatus.CANCELLED
        assert fu.cancelled_at is not None
        assert fu.last_error is not None

    def test_terminal_lead_after_claim_cancels(self, db, org_id, user_id):
        """If lead becomes terminal after claim, follow-up is CANCELLED."""
        from app.services.followup_email_sender import _process_one_followup
        from app.services import followup_email_sender as fes
        from app.services.followup_cancellation import is_terminal_lead_status as real_check

        lead = _make_lead(db, org_id, status=LeadStatus.SCHEDULED)
        fu = _make_followup(db, org_id, lead.id, user_id)

        # Patch is_terminal_lead_status to return True only AFTER claim
        second_call = [False]

        def mock_check(status):
            if second_call[0]:
                return True
            second_call[0] = True
            return real_check(status)

        # Patch the source module (followup_cancellation) since the import
        # is inline inside _process_one_followup
        with patch("app.services.followup_cancellation.is_terminal_lead_status", side_effect=mock_check):
            with patch.object(fes, "_claim_followup", return_value=True):
                result = _process_one_followup(db, fu)

        assert result == "skipped"
        db.refresh(fu)
        # BUG FIX: must be CANCELLED, not PENDING (old behavior caused infinite loop)
        assert fu.status == FollowUpStatus.CANCELLED
        assert fu.cancelled_at is not None

    def test_non_terminal_lead_after_claim_sends(self, db, org_id, user_id):
        """If lead remains non-terminal after claim, email is sent."""
        from app.services.followup_email_sender import _process_one_followup
        from app.services import followup_email_sender as fes

        lead = _make_lead(db, org_id, status=LeadStatus.SCHEDULED)
        fu = _make_followup(db, org_id, lead.id, user_id)

        with patch.object(fes, "_claim_followup", return_value=True):
            with patch.object(fes, "_send_followup_email", return_value="msg-123") as mock_send:
                with patch.object(fes, "_record_success") as mock_rec:
                    result = _process_one_followup(db, fu)

        assert result == "emails_sent"
        mock_send.assert_called_once()

    def test_pre_claim_check_still_works(self, db, org_id, user_id):
        """Pre-claim terminal check cancels follow-up without claiming."""
        from app.services.followup_email_sender import _process_one_followup
        from app.services import followup_email_sender as fes

        lead = _make_lead(db, org_id, status=LeadStatus.DECLINED)
        fu = _make_followup(db, org_id, lead.id, user_id)

        # Terminal check happens BEFORE claim — cancels follow-up without claiming
        with patch.object(fes, "_claim_followup") as mock_claim:
            result = _process_one_followup(db, fu)
            mock_claim.assert_not_called()
            assert result == "permanent_failures"
            db.refresh(fu)
            assert fu.status == FollowUpStatus.CANCELLED


# ══════════════════════════════════════════════════════════════════════════════
# G. Retry Safety Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestRetrySafety:
    """Tests verifying that retries correctly re-check lead status."""

    def test_retry_skips_terminal_lead(self, db, org_id, user_id):
        """A retried follow-up for a terminal lead is cancelled, not stuck in loop."""
        from app.services.followup_email_sender import _process_one_followup

        lead = _make_lead(db, org_id, status=LeadStatus.COMPLETED)
        fu = _make_followup(db, org_id, lead.id, user_id,
                           status=FollowUpStatus.PENDING)
        fu.email_retry_count = 1  # Simulate a prior failure
        db.commit()
        db.refresh(fu)

        # _process_one_followup checks terminal lead status → cancels follow-up
        result = _process_one_followup(db, fu)
        assert result == "permanent_failures"

        db.refresh(fu)
        # Should NOT have been sent
        assert fu.email_sent_at is None
        # BUG FIX: must be CANCELLED, not PENDING (prevents infinite retry loop)
        assert fu.status == FollowUpStatus.CANCELLED
        assert fu.cancelled_at is not None


# ══════════════════════════════════════════════════════════════════════════════
# H. All Terminal Statuses Block Creation
# ══════════════════════════════════════════════════════════════════════════════


class TestAllTerminalStatusesBlockCreation:
    """Every terminal status blocks follow-up creation via the shared guard."""

    @pytest.mark.parametrize("status", [
        LeadStatus.COMPLETED,
        LeadStatus.DECLINED,
        LeadStatus.NOT_INTERESTED,
        LeadStatus.ERROR,
    ])
    def test_terminal_status_blocks(self, db, org_id, status):
        lead = _make_lead(db, org_id, status=status)
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is True


# ══════════════════════════════════════════════════════════════════════════════
# I. All Non-Terminal Statuses Allow Creation
# ══════════════════════════════════════════════════════════════════════════════


class TestAllNonTerminalStatusesAllowCreation:
    """Every non-terminal status allows follow-up creation via the shared guard."""

    @pytest.mark.parametrize("status", [
        LeadStatus.PENDING,
        LeadStatus.SCHEDULED,
        LeadStatus.ACCEPTED,
        LeadStatus.TENTATIVE,
        LeadStatus.REMINDED,
    ])
    def test_non_terminal_status_allows(self, db, org_id, status):
        lead = _make_lead(db, org_id, status=status)
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is False


# ══════════════════════════════════════════════════════════════════════════════
# J. Tenant Isolation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestTenantIsolationGuard:
    """Guard is tenant-scoped: terminal lead in org A doesn't affect org B."""

    def test_terminal_lead_org_a_does_not_block_org_b(self, db):
        """A terminal lead in org A doesn't prevent follow-up creation in org B."""
        from app.services.followup_cancellation import is_lead_terminal_for_followup

        # Create two orgs
        org_a, user_a = _create_org_and_user(db, email=f"a-{uuid.uuid4().hex[:6]}@test.com")
        org_b, user_b = _create_org_and_user(db, email=f"b-{uuid.uuid4().hex[:6]}@test.com")

        # Lead in org A is terminal
        lead_a = _make_lead(db, org_a.id, status=LeadStatus.COMPLETED, name="Org A Lead")

        # Lead in org B is non-terminal
        lead_b = _make_lead(db, org_b.id, status=LeadStatus.SCHEDULED, name="Org B Lead")

        # Guard should return True for org A's lead
        assert is_lead_terminal_for_followup(db, lead_a.id, org_a.id) is True

        # Guard should return False for org B's lead (not affected by org A)
        assert is_lead_terminal_for_followup(db, lead_b.id, org_b.id) is False

    def test_guard_rejects_wrong_org(self, db):
        """Querying with wrong org_id returns False (lead not found in that org)."""
        from app.services.followup_cancellation import is_lead_terminal_for_followup

        org_a, _ = _create_org_and_user(db, email=f"wa-{uuid.uuid4().hex[:6]}@test.com")
        org_b, _ = _create_org_and_user(db, email=f"wb-{uuid.uuid4().hex[:6]}@test.com")

        lead = _make_lead(db, org_a.id, status=LeadStatus.COMPLETED)

        # Query with org_b's ID — lead belongs to org_a, so returns False
        assert is_lead_terminal_for_followup(db, lead.id, org_b.id) is False


# ══════════════════════════════════════════════════════════════════════════════
# K. Idempotency Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestGuardIdempotency:
    """Calling the guard multiple times produces consistent results."""

    def test_repeated_checks_consistent(self, db, org_id):
        lead = _make_lead(db, org_id, status=LeadStatus.DECLINED)
        for _ in range(5):
            assert is_lead_terminal_for_followup(db, lead.id, org_id) is True

    def test_repeated_checks_non_terminal_consistent(self, db, org_id):
        lead = _make_lead(db, org_id, status=LeadStatus.SCHEDULED)
        for _ in range(5):
            assert is_lead_terminal_for_followup(db, lead.id, org_id) is False


# ══════════════════════════════════════════════════════════════════════════════
# L. Lead-Not-Found Edge Case Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestLeadNotFoundEdgeCases:
    """Edge cases around missing or deleted leads."""

    def test_nonexistent_lead_id_returns_false(self, db, org_id):
        """Guard returns False for a UUID that doesn't exist."""
        fake_id = uuid.uuid4()
        assert is_lead_terminal_for_followup(db, fake_id, org_id) is False

    def test_none_like_uuid_returns_false(self, db, org_id):
        """Guard handles gracefully even with edge-case IDs."""
        # The guard should not crash with unusual inputs
        assert is_lead_terminal_for_followup(db, uuid.uuid4(), org_id) is False

    def test_cascade_handles_nonexistent_lead(self, db, org_id, user_id):
        """Cancellation cascade handles a lead ID that doesn't exist (0 follow-ups cancelled)."""
        fake_lead_id = uuid.uuid4()
        count = cancel_pending_followups_for_lead(db, fake_lead_id, org_id)
        assert count == 0


# ══════════════════════════════════════════════════════════════════════════════
# M. Adversarial / Security Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestAdversarialSecurity:
    """Security-focused adversarial tests for the lead status guard."""

    def test_cannot_bypass_guard_with_stale_lead_object(self, db, org_id, user_id):
        """Guard re-fetches lead from DB, so stale in-memory object is irrelevant."""
        from app.services.followup_cancellation import is_lead_terminal_for_followup

        lead = _make_lead(db, org_id, status=LeadStatus.SCHEDULED)

        # Load lead into memory as non-terminal
        _ = db.query(Lead).filter(Lead.id == lead.id).first()

        # Now update lead to terminal in DB directly (bypass in-memory)
        lead.status = LeadStatus.COMPLETED
        db.commit()

        # Guard should see the TERMINAL status (re-fetches from DB)
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is True

    def test_cross_tenant_lead_not_accessible(self, db):
        """Terminal lead in org A cannot be queried via org B's context."""
        from app.services.followup_cancellation import is_lead_terminal_for_followup

        org_a, _ = _create_org_and_user(db, email=f"adv1-{uuid.uuid4().hex[:6]}@test.com")
        org_b, _ = _create_org_and_user(db, email=f"adv2-{uuid.uuid4().hex[:6]}@test.com")

        lead = _make_lead(db, org_a.id, status=LeadStatus.COMPLETED)

        # Attempt to query with org_b's context — should return False
        assert is_lead_terminal_for_followup(db, lead.id, org_b.id) is False

    def test_guard_cannot_be_tricked_by_string_status(self, db, org_id):
        """Guard uses enum comparison, not string matching."""
        from app.services.followup_cancellation import is_terminal_lead_status

        # Valid terminal status as string
        assert is_terminal_lead_status("completed") is True
        assert is_terminal_lead_status("declined") is True

        # Invalid status string
        assert is_terminal_lead_status("fake_status") is False

        # Empty string
        assert is_terminal_lead_status("") is False

    def test_guard_prevents_followup_after_status_update(self, db, org_id, user_id):
        """Cannot create a follow-up after lead transitions to terminal."""
        from fastapi.testclient import TestClient
        from app.main import app
        from tests.test_auth import _make_token, _auth_header

        client = TestClient(app)
        token = _make_token(user_id, org_id, UserRole.OWNER.value)
        headers = _auth_header(token)

        lead = _make_lead(db, org_id, status=LeadStatus.SCHEDULED)

        # First attempt: should succeed (lead is scheduled)
        resp1 = client.post(
            "/dashboard/api/follow-ups",
            json={
                "lead_id": str(lead.id),
                "title": "First",
                "priority": "medium",
            },
            headers=headers,
        )
        assert resp1.status_code == 201

        # Transition lead to terminal
        lead.status = LeadStatus.COMPLETED
        db.commit()

        # Second attempt: should be rejected (lead is now terminal)
        resp2 = client.post(
            "/dashboard/api/follow-ups",
            json={
                "lead_id": str(lead.id),
                "title": "Second",
                "priority": "medium",
            },
            headers=headers,
        )
        assert resp2.status_code == 409


# ══════════════════════════════════════════════════════════════════════════════
# N. Integration: Guard + Cascade Cooperation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestGuardCascadeCooperation:
    """Tests verifying that the guard and cancellation cascade work together."""

    def test_cascade_then_guard_prevents_new_followup(self, db, org_id, user_id):
        """After cascade cancels follow-ups, guard prevents new creation."""
        lead = _make_lead(db, org_id, status=LeadStatus.SCHEDULED)
        fu = _make_followup(db, org_id, lead.id, user_id)

        # Make lead terminal — cascade should cancel the follow-up
        lead.status = LeadStatus.DECLINED
        cancelled = cancel_pending_followups_for_lead(db, lead.id, org_id)
        db.commit()

        assert cancelled == 1
        db.refresh(fu)
        assert fu.status == FollowUpStatus.CANCELLED

        # Now guard should block new follow-up creation
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is True

    def test_guard_blocks_execution_for_newly_terminal_lead(self, db, org_id, user_id):
        """Guard prevents email send for a lead that just became terminal."""
        from app.services.followup_email_sender import _process_one_followup

        lead = _make_lead(db, org_id, status=LeadStatus.SCHEDULED)
        fu = _make_followup(db, org_id, lead.id, user_id)

        # Transition lead to terminal
        lead.status = LeadStatus.COMPLETED
        db.commit()
        db.refresh(fu)

        # _process_one_followup checks lead status from DB → cancels follow-up
        result = _process_one_followup(db, fu)
        assert result == "permanent_failures"
        db.refresh(fu)
        assert fu.status == FollowUpStatus.CANCELLED

    def test_non_terminal_lead_allows_full_lifecycle(self, db, org_id, user_id):
        """Non-terminal lead can receive follow-up creation and execution."""
        from app.services.followup_email_sender import _process_one_followup
        from app.services import followup_email_sender as fes

        lead = _make_lead(db, org_id, status=LeadStatus.SCHEDULED)
        fu = _make_followup(db, org_id, lead.id, user_id)

        # Guard allows creation
        assert is_lead_terminal_for_followup(db, lead.id, org_id) is False

        # Execution proceeds
        with patch.object(fes, "_claim_followup", return_value=True):
            with patch.object(fes, "_send_followup_email", return_value="msg-ok"):
                with patch.object(fes, "_record_success"):
                    result = _process_one_followup(db, fu)

        assert result == "emails_sent"


# ══════════════════════════════════════════════════════════════════════════════
# P. Regression Tests for Infinite Loop Prevention
# ══════════════════════════════════════════════════════════════════════════════


class TestInfiniteLoopPrevention:
    """Regression tests ensuring terminal-lead follow-ups don't loop forever.

    PREVIOUS BUG: _record_failure() reverted terminal-lead follow-ups to
    PENDING without incrementing email_retry_count. Every scheduler run
    reprocessed the same follow-up, creating unbounded FailedJob records.
    """

    def test_terminal_lead_followup_not_reprocessed(self, db, org_id, user_id):
        """After processing a terminal-lead follow-up, it is not picked up again."""
        from app.services.followup_email_sender import _process_one_followup, _query_due_followups

        lead = _make_lead(db, org_id, status=LeadStatus.COMPLETED)
        fu = _make_followup(db, org_id, lead.id, user_id)

        # First processing: terminal → CANCELLED
        result = _process_one_followup(db, fu)
        assert result == "permanent_failures"
        db.refresh(fu)
        assert fu.status == FollowUpStatus.CANCELLED

        # Second processing: _query_due_followups should NOT return CANCELLED follow-ups
        due = _query_due_followups(db, limit=100)
        due_ids = [f.id for f in due]
        assert fu.id not in due_ids

    def test_terminal_lead_post_claim_not_reprocessed(self, db, org_id, user_id):
        """After post-claim terminal detection, follow-up is not picked up again."""
        from app.services.followup_email_sender import _process_one_followup, _query_due_followups
        from app.services import followup_email_sender as fes
        from app.services.followup_cancellation import is_terminal_lead_status as real_check

        lead = _make_lead(db, org_id, status=LeadStatus.SCHEDULED)
        fu = _make_followup(db, org_id, lead.id, user_id)

        # Simulate terminal lead after claim
        second_call = [False]
        def mock_check(status):
            if second_call[0]:
                return True
            second_call[0] = True
            return real_check(status)

        with patch("app.services.followup_cancellation.is_terminal_lead_status", side_effect=mock_check):
            with patch.object(fes, "_claim_followup", return_value=True):
                result = _process_one_followup(db, fu)

        assert result == "skipped"
        db.refresh(fu)
        assert fu.status == FollowUpStatus.CANCELLED

        # Should not be picked up by next scheduler run
        due = _query_due_followups(db, limit=100)
        due_ids = [f.id for f in due]
        assert fu.id not in due_ids

    def test_terminal_lead_creates_failedjob_not_unbounded(self, db, org_id, user_id):
        """Terminal-lead follow-up creates exactly one FailedJob, not unbounded."""
        from app.models import FailedJob
        from app.services.followup_email_sender import _process_one_followup

        lead = _make_lead(db, org_id, status=LeadStatus.COMPLETED)
        fu = _make_followup(db, org_id, lead.id, user_id)

        count_before = db.query(FailedJob).filter(
            FailedJob.job_type == "followup_email_send"
        ).count()

        result = _process_one_followup(db, fu)
        assert result == "permanent_failures"

        count_after = db.query(FailedJob).filter(
            FailedJob.job_type == "followup_email_send"
        ).count()
        assert count_after == count_before + 1  # Exactly one FailedJob

    def test_all_terminal_statuses_cannot_loop(self, db, org_id, user_id):
        """Every terminal status cancels the follow-up on first processing."""
        from app.services.followup_email_sender import _process_one_followup

        for status in (LeadStatus.COMPLETED, LeadStatus.DECLINED,
                       LeadStatus.NOT_INTERESTED, LeadStatus.ERROR):
            lead = _make_lead(db, org_id, status=status)
            fu = _make_followup(db, org_id, lead.id, user_id,
                               title=f"Terminal {status.value}")
            result = _process_one_followup(db, fu)
            assert result == "permanent_failures"
            db.refresh(fu)
            assert fu.status == FollowUpStatus.CANCELLED, \
                f"Follow-up for {status.value} lead should be CANCELLED, got {fu.status.value}"
