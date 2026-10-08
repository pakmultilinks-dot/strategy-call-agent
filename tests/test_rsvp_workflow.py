"""Phase 4 - Customer Accept/Decline RSVP Workflow Tests.

Tests for:
  1. RSVPToken model and migration
  2. Token generation and validation (rsvp_token_service)
  3. Public RSVP routes (/rsvp/{token})
  4. Email template RSVP buttons
  5. Decline notification
  6. Integration with pipeline

Covers:
  A. Token generation - success, invalid lead state, idempotent invalidation
  B. Token validation - valid, expired, consumed, not found
  C. RSVP processing - accept flow, decline flow, calendar release, follow-up cancellation
  D. Public routes - landing pages, status codes
  E. Email templates - RSVP buttons present when URLs provided
  F. Decline notification - email sent to org
  G. Security - cross-lead token isolation, single-use enforcement
"""
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session as SASession

from app.database import SessionLocal
from app.models import (
    EventLog,
    FollowUp,
    FollowUpPriority,
    FollowUpStatus,
    Lead,
    LeadStatus,
    RSVPToken,
)
from app.models_multi_tenant import Organization, OrganizationStatus
from app.services.crypto import generate_key
from app.services.rsvp_token_service import (
    RSVP_TOKEN_EXPIRY_DAYS,
    _hash_token,
    generate_rsvp_tokens,
    validate_and_process_rsvp,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    """Inject test-mode secrets."""
    from app.config import settings
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", generate_key())
    monkeypatch.setattr(settings, "rsvp_base_url", "http://localhost:8000")


@pytest.fixture()
def db():
    """Yield a DB session with cleanup."""
    session = SessionLocal()
    try:
        session.query(FollowUp).delete(synchronize_session="fetch")
        session.query(EventLog).delete(synchronize_session="fetch")
        session.query(RSVPToken).delete(synchronize_session="fetch")
        session.query(Lead).filter(
            Lead.organization_id == _DEFAULT_ORG_ID
        ).delete(synchronize_session="fetch")
        session.commit()
    except Exception:
        session.rollback()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


@pytest.fixture()
def client():
    """TestClient with lifespan support."""
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def org(db):
    """Create a test organization."""
    from tests.conftest import _DEFAULT_ORG_ID
    org = db.query(Organization).filter_by(id=_DEFAULT_ORG_ID).first()
    if org is None:
        org = Organization(
            id=_DEFAULT_ORG_ID,
            name="Test Org",
            slug="test-org",
            status=OrganizationStatus.ACTIVE,
            timezone="America/Chicago",
        )
        db.add(org)
        db.commit()
    return org


@pytest.fixture()
def lead(db, org):
    """Create a SCHEDULED lead for RSVP testing."""
    lead = Lead(
        name="Jane Prospect",
        email="jane@example.com",
        company_address="Acme Corp",
        appt_datetime_raw="2026-10-01 10:00 AM",
        appt_datetime_utc=datetime(2026, 10, 1, 15, 0, tzinfo=timezone.utc),
        dedupe_key=f"rsvp-test|jane@example.com|{uuid.uuid4().hex[:8]}",
        status=LeadStatus.SCHEDULED,
        organization_id=org.id,
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


# ── Helpers ───────────────────────────────────────────────────────────────────

from app.main import app
from tests.conftest import _DEFAULT_ORG_ID


def _make_lead(db, org_id, status=LeadStatus.SCHEDULED, **overrides):
    """Helper to create a lead with specified status."""
    defaults = {
        "name": "Test Lead",
        "email": "test@example.com",
        "appt_datetime_raw": "2026-10-01 10:00 AM",
        "appt_datetime_utc": datetime(2026, 10, 1, 14, 0, tzinfo=timezone.utc),
        "dedupe_key": f"rsvp-test|test@example.com|{uuid.uuid4().hex[:8]}",
        "status": status,
        "organization_id": org_id,
    }
    defaults.update(overrides)
    lead = Lead(**defaults)
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


def _make_followup(db, lead_id, org_id, status=FollowUpStatus.PENDING):
    """Helper to create a follow-up."""
    from app.models_multi_tenant import User, UserRole, UserStatus
    from app.auth import hash_password

    # Get or create a test user
    user = db.query(User).filter(User.organization_id == org_id).first()
    if user is None:
        user = User(
            organization_id=org_id,
            email="testuser@example.com",
            full_name="Test User",
            password_hash=hash_password("TestPass123!"),
            role=UserRole.OWNER,
            status=UserStatus.ACTIVE,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    fu = FollowUp(
        organization_id=org_id,
        lead_id=lead_id,
        created_by=user.id,
        title="Test Follow-up",
        priority=FollowUpPriority.MEDIUM,
        status=status,
    )
    db.add(fu)
    db.commit()
    db.refresh(fu)
    return fu


# ══════════════════════════════════════════════════════════════════════════════
# A. Token Generation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestTokenGeneration:
    """Tests for RSVP token generation."""

    def test_generate_tokens_creates_two_tokens(self, db, lead):
        """Generating tokens creates exactly 2 RSVPToken rows."""
        accept_token, decline_token = generate_rsvp_tokens(db, lead)
        assert accept_token
        assert decline_token
        assert accept_token != decline_token

        tokens = db.query(RSVPToken).filter(
            RSVPToken.lead_id == lead.id
        ).all()
        assert len(tokens) == 2
        choices = {t.choice for t in tokens}
        assert choices == {"accept", "decline"}

    def test_generate_tokens_sets_expiry(self, db, lead):
        """Tokens have expiry set to RSVP_TOKEN_EXPIRY_DAYS in the future."""
        now = datetime.now(timezone.utc)
        accept_token, decline_token = generate_rsvp_tokens(db, lead)

        tokens = db.query(RSVPToken).filter(
            RSVPToken.lead_id == lead.id
        ).all()
        for t in tokens:
            # SQLite returns naive datetimes; attach UTC for comparison.
            expires_at = t.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            assert expires_at > now
            # Should be approximately RSVP_TOKEN_EXPIRY_DAYS from now
            delta = expires_at - now
            assert delta.days == RSVP_TOKEN_EXPIRY_DAYS

    def test_generate_tokens_hashes_plaintext(self, db, lead):
        """Tokens are stored as SHA-256 hashes, not plaintext."""
        accept_token, decline_token = generate_rsvp_tokens(db, lead)

        tokens = db.query(RSVPToken).filter(
            RSVPToken.lead_id == lead.id
        ).all()
        for t in tokens:
            # The stored hash should NOT equal the plaintext
            assert t.token_hash != accept_token
            assert t.token_hash != decline_token
            # But should match the expected hash
            if t.choice == "accept":
                assert t.token_hash == _hash_token(accept_token)
            else:
                assert t.token_hash == _hash_token(decline_token)

    def test_generate_tokens_invalidates_old_tokens(self, db, lead):
        """Regenerating tokens invalidates previous unconsumed tokens."""
        accept1, decline1 = generate_rsvp_tokens(db, lead)
        accept2, decline2 = generate_rsvp_tokens(db, lead)

        # Old tokens should be marked consumed
        old_token = db.query(RSVPToken).filter(
            RSVPToken.token_hash == _hash_token(accept1)
        ).first()
        assert old_token.consumed is True

        # New tokens should be unconsumed
        new_token = db.query(RSVPToken).filter(
            RSVPToken.token_hash == _hash_token(accept2)
        ).first()
        assert new_token.consumed is False

    def test_generate_tokens_rejects_non_pollable_status(self, db, org):
        """Tokens cannot be generated for leads in terminal states."""
        lead = _make_lead(db, org.id, status=LeadStatus.COMPLETED)
        with pytest.raises(ValueError, match="Cannot generate RSVP tokens"):
            generate_rsvp_tokens(db, lead)

    def test_generate_tokens_accepts_tentative(self, db, org):
        """Tokens can be generated for TENTATIVE leads."""
        lead = _make_lead(db, org.id, status=LeadStatus.TENTATIVE)
        accept_token, decline_token = generate_rsvp_tokens(db, lead)
        assert accept_token
        assert decline_token

    def test_generate_tokens_accepts_accepted(self, db, org):
        """Tokens can be generated for ACCEPTED leads."""
        lead = _make_lead(db, org.id, status=LeadStatus.ACCEPTED)
        accept_token, decline_token = generate_rsvp_tokens(db, lead)
        assert accept_token
        assert decline_token

    def test_generate_tokens_not_consumed_initially(self, db, lead):
        """Freshly generated tokens are not consumed."""
        accept_token, decline_token = generate_rsvp_tokens(db, lead)
        tokens = db.query(RSVPToken).filter(
            RSVPToken.lead_id == lead.id
        ).all()
        for t in tokens:
            assert t.consumed is False
            assert t.consumed_at is None


# ══════════════════════════════════════════════════════════════════════════════
# B. Token Validation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestTokenValidation:
    """Tests for RSVP token validation."""

    def test_validate_valid_token(self, db, lead):
        """Valid token returns success."""
        accept_token, _ = generate_rsvp_tokens(db, lead)
        result = validate_and_process_rsvp(db, accept_token)
        assert result.success is True
        assert result.choice == "accept"
        assert result.lead_name == "Jane Prospect"

    def test_validate_not_found_token(self, db):
        """Random token returns not_found."""
        fake_token = secrets.token_urlsafe(32)
        result = validate_and_process_rsvp(db, fake_token)
        assert result.success is False
        assert result.not_found is True

    def test_validate_consumed_token(self, db, lead):
        """Already-consumed token returns already_used."""
        accept_token, _ = generate_rsvp_tokens(db, lead)
        # Consume it
        validate_and_process_rsvp(db, accept_token)
        # Try again
        result = validate_and_process_rsvp(db, accept_token)
        assert result.success is False
        assert result.already_used is True

    def test_validate_expired_token(self, db, lead):
        """Expired token returns expired."""
        accept_token, _ = generate_rsvp_tokens(db, lead)

        # Manually expire the token
        rsvp_token = db.query(RSVPToken).filter(
            RSVPToken.token_hash == _hash_token(accept_token)
        ).first()
        rsvp_token.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()

        result = validate_and_process_rsvp(db, accept_token)
        assert result.success is False
        assert result.expired is True

    def test_validate_non_pollable_lead(self, db, org):
        """Token for a lead in non-pollable state returns error."""
        lead = _make_lead(db, org.id, status=LeadStatus.SCHEDULED)
        accept_token, _ = generate_rsvp_tokens(db, lead)

        # Change lead to COMPLETED
        lead.status = LeadStatus.COMPLETED
        db.commit()

        result = validate_and_process_rsvp(db, accept_token)
        assert result.success is False
        assert "cannot process rsvp" in result.error.lower()

    def test_validate_deleted_lead(self, db, lead):
        """Token for a deleted lead returns not_found."""
        accept_token, _ = generate_rsvp_tokens(db, lead)

        # Delete the lead
        db.delete(lead)
        db.commit()

        result = validate_and_process_rsvp(db, accept_token)
        assert result.success is False
        assert result.not_found is True


# ══════════════════════════════════════════════════════════════════════════════
# C. RSVP Processing Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestRSVPAccept:
    """Tests for the accept flow."""

    def test_accept_changes_status(self, db, lead):
        """Accepting changes lead status to ACCEPTED."""
        assert lead.status == LeadStatus.SCHEDULED
        accept_token, _ = generate_rsvp_tokens(db, lead)
        result = validate_and_process_rsvp(db, accept_token)
        assert result.success is True
        assert result.choice == "accept"

        db.refresh(lead)
        assert lead.status == LeadStatus.ACCEPTED

    def test_accept_logs_event(self, db, lead):
        """Accepting creates an rsvp_accepted event log."""
        accept_token, _ = generate_rsvp_tokens(db, lead)
        validate_and_process_rsvp(db, accept_token)

        events = db.query(EventLog).filter(
            EventLog.lead_id == lead.id,
            EventLog.event_type == "rsvp_accepted",
        ).all()
        assert len(events) == 1
        assert events[0].organization_id == lead.organization_id

    def test_accept_idempotent(self, db, lead):
        """Accepting twice shows 'already used' on second attempt."""
        accept_token, _ = generate_rsvp_tokens(db, lead)
        result1 = validate_and_process_rsvp(db, accept_token)
        assert result1.success is True

        result2 = validate_and_process_rsvp(db, accept_token)
        assert result2.success is False
        assert result2.already_used is True

        # Lead should still be ACCEPTED
        db.refresh(lead)
        assert lead.status == LeadStatus.ACCEPTED

    def test_accept_from_tentative(self, db, org):
        """Accepting from TENTATIVE transitions to ACCEPTED."""
        lead = _make_lead(db, org.id, status=LeadStatus.TENTATIVE)
        accept_token, _ = generate_rsvp_tokens(db, lead)
        result = validate_and_process_rsvp(db, accept_token)
        assert result.success is True

        db.refresh(lead)
        assert lead.status == LeadStatus.ACCEPTED

    def test_accept_preserves_calendar_event(self, db, lead):
        """Accepting does NOT delete the calendar event."""
        lead.calendar_event_id = "test_event_123"
        db.commit()

        accept_token, _ = generate_rsvp_tokens(db, lead)
        validate_and_process_rsvp(db, accept_token)

        db.refresh(lead)
        assert lead.calendar_event_id == "test_event_123"


class TestRSVPDecline:
    """Tests for the decline flow."""

    def test_decline_changes_status(self, db, lead):
        """Declining changes lead status to DECLINED."""
        assert lead.status == LeadStatus.SCHEDULED
        _, decline_token = generate_rsvp_tokens(db, lead)
        result = validate_and_process_rsvp(db, decline_token)
        assert result.success is True
        assert result.choice == "decline"

        db.refresh(lead)
        assert lead.status == LeadStatus.DECLINED

    def test_decline_logs_event(self, db, lead):
        """Declining creates an rsvp_declined event log."""
        _, decline_token = generate_rsvp_tokens(db, lead)
        validate_and_process_rsvp(db, decline_token)

        events = db.query(EventLog).filter(
            EventLog.lead_id == lead.id,
            EventLog.event_type == "rsvp_declined",
        ).all()
        assert len(events) == 1

    def test_decline_cancels_followups(self, db, lead, org):
        """Declining cancels pending follow-ups for the lead."""
        fu = _make_followup(db, lead.id, org.id, FollowUpStatus.PENDING)

        _, decline_token = generate_rsvp_tokens(db, lead)
        validate_and_process_rsvp(db, decline_token)

        db.refresh(fu)
        assert fu.status == FollowUpStatus.CANCELLED

    def test_decline_preserves_completed_followups(self, db, lead, org):
        """Declining does NOT cancel already-completed follow-ups."""
        fu = _make_followup(db, lead.id, org.id, FollowUpStatus.COMPLETED)

        _, decline_token = generate_rsvp_tokens(db, lead)
        validate_and_process_rsvp(db, decline_token)

        db.refresh(fu)
        assert fu.status == FollowUpStatus.COMPLETED

    def test_decline_releases_calendar_event(self, db, lead):
        """Declining releases the calendar event when one exists."""
        lead.calendar_event_id = "test_event_456"
        db.commit()

        with patch("app.services.calendar_service.CalendarService") as mock_cal:
            mock_instance = MagicMock()
            mock_instance.release_calendar_event.return_value = True
            mock_cal.return_value = mock_instance

            _, decline_token = generate_rsvp_tokens(db, lead)
            validate_and_process_rsvp(db, decline_token)

            mock_instance.release_calendar_event.assert_called_once_with(
                "test_event_456", "Jane Prospect", db,
            )

    def test_decline_cancels_zoom_meeting(self, db, lead):
        """Declining cancels the Zoom meeting when one exists."""
        lead.zoom_meeting_id = "zoom_meeting_789"
        db.commit()

        with patch("app.services.meeting_provider.resolve_meeting_provider") as mock_resolve:
            from app.services.meeting_provider import ZoomMeetingProvider
            mock_provider = MagicMock(spec=ZoomMeetingProvider)
            mock_resolve.return_value = mock_provider

            _, decline_token = generate_rsvp_tokens(db, lead)
            validate_and_process_rsvp(db, decline_token)

            mock_provider.cancel_meeting.assert_called_once_with("zoom_meeting_789")

    def test_decline_sends_org_notification(self, db, lead):
        """Declining sends a notification email to the org."""
        with patch("app.services.decline_notification.send_decline_notification") as mock_notify:
            _, decline_token = generate_rsvp_tokens(db, lead)
            validate_and_process_rsvp(db, decline_token)

            mock_notify.assert_called_once_with(db, lead)

    def test_decline_notification_failure_is_swallowed(self, db, lead):
        """Notification failure does not prevent the RSVP from processing."""
        with patch("app.services.decline_notification.send_decline_notification",
                    side_effect=RuntimeError("email service down")):
            _, decline_token = generate_rsvp_tokens(db, lead)
            result = validate_and_process_rsvp(db, decline_token)

            # RSVP should still succeed even if notification fails
            assert result.success is True
            assert result.choice == "decline"

            db.refresh(lead)
            assert lead.status == LeadStatus.DECLINED

    def test_decline_calendar_release_failure_is_swallowed(self, db, lead):
        """Calendar release failure does not prevent the RSVP from processing."""
        lead.calendar_event_id = "test_event_fail"
        db.commit()

        with patch("app.services.calendar_service.CalendarService") as mock_cal:
            mock_instance = MagicMock()
            mock_instance.release_calendar_event.side_effect = RuntimeError("Google API error")
            mock_cal.return_value = mock_instance

            _, decline_token = generate_rsvp_tokens(db, lead)
            result = validate_and_process_rsvp(db, decline_token)

            # RSVP should still succeed even if calendar release fails
            assert result.success is True
            db.refresh(lead)
            assert lead.status == LeadStatus.DECLINED


# ══════════════════════════════════════════════════════════════════════════════
# D. Public Route Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestRSVPRoutes:
    """Tests for GET /rsvp/{token} public route."""

    def test_accept_route_returns_200(self, client, db, lead):
        """Accept route returns 200 with success page."""
        accept_token, _ = generate_rsvp_tokens(db, lead)
        response = client.get(f"/rsvp/{accept_token}")
        assert response.status_code == 200
        assert "Confirmed" in response.text

    def test_decline_route_returns_200(self, client, db, lead):
        """Decline route returns 200 with decline page."""
        _, decline_token = generate_rsvp_tokens(db, lead)
        response = client.get(f"/rsvp/{decline_token}")
        assert response.status_code == 200
        assert "Declined" in response.text

    def test_invalid_token_returns_404(self, client):
        """Invalid token returns 404."""
        fake_token = secrets.token_urlsafe(32)
        response = client.get(f"/rsvp/{fake_token}")
        assert response.status_code == 404
        assert "Invalid" in response.text

    def test_consumed_token_returns_200(self, client, db, lead):
        """Consumed token returns 200 with 'already used' page."""
        accept_token, _ = generate_rsvp_tokens(db, lead)
        client.get(f"/rsvp/{accept_token}")  # First use
        response = client.get(f"/rsvp/{accept_token}")  # Second use
        assert response.status_code == 200
        assert "Already" in response.text

    def test_expired_token_returns_410(self, client, db, lead):
        """Expired token returns 410 Gone."""
        accept_token, _ = generate_rsvp_tokens(db, lead)

        # Manually expire the token
        rsvp_token = db.query(RSVPToken).filter(
            RSVPToken.token_hash == _hash_token(accept_token)
        ).first()
        rsvp_token.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()

        response = client.get(f"/rsvp/{accept_token}")
        assert response.status_code == 410
        assert "expired" in response.text.lower()

    def test_accept_updates_lead_status(self, client, db, lead):
        """Clicking accept link changes lead status to ACCEPTED."""
        accept_token, _ = generate_rsvp_tokens(db, lead)
        client.get(f"/rsvp/{accept_token}")

        db.refresh(lead)
        assert lead.status == LeadStatus.ACCEPTED

    def test_decline_updates_lead_status(self, client, db, lead):
        """Clicking decline link changes lead status to DECLINED."""
        _, decline_token = generate_rsvp_tokens(db, lead)
        client.get(f"/rsvp/{decline_token}")

        db.refresh(lead)
        assert lead.status == LeadStatus.DECLINED


# ══════════════════════════════════════════════════════════════════════════════
# E. Email Template RSVP Button Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestEmailTemplateRSVPButtons:
    """Tests for RSVP buttons in confirmation email templates."""

    def test_html_includes_rsvp_buttons_when_urls_provided(self, db, lead):
        """HTML email includes Accept/Decline buttons when RSVP URLs are provided."""
        from app.services.email_templates import build_confirmation_html
        from zoneinfo import ZoneInfo

        html = build_confirmation_html(
            lead,
            meet_link="https://meet.google.com/abc-defg-hij",
            ai_paragraph="Looking forward to our call!",
            tz=ZoneInfo("America/Chicago"),
            rsvp_accept_url="http://localhost:8000/rsvp/accept_token_123",
            rsvp_decline_url="http://localhost:8000/rsvp/decline_token_456",
        )
        assert "Accept" in html
        assert "Decline" in html
        assert "rsvp/accept_token_123" in html
        assert "rsvp/decline_token_456" in html

    def test_html_excludes_rsvp_buttons_when_urls_not_provided(self, db, lead):
        """HTML email does NOT include RSVP buttons when URLs are not provided."""
        from app.services.email_templates import build_confirmation_html
        from zoneinfo import ZoneInfo

        html = build_confirmation_html(
            lead,
            meet_link="https://meet.google.com/abc-defg-hij",
            ai_paragraph="Looking forward to our call!",
            tz=ZoneInfo("America/Chicago"),
        )
        # Should not contain RSVP-specific link patterns
        assert "rsvp/" not in html
        # But should still have the Meet button
        assert "Join Meeting" in html

    def test_text_includes_rsvp_links_when_urls_provided(self, db, lead):
        """Plain-text email includes RSVP links when URLs are provided."""
        from app.services.email_templates import build_confirmation_text
        from zoneinfo import ZoneInfo

        text = build_confirmation_text(
            lead,
            meet_link="https://meet.google.com/abc-defg-hij",
            ai_paragraph="Looking forward to our call!",
            tz=ZoneInfo("America/Chicago"),
            rsvp_accept_url="http://localhost:8000/rsvp/accept_token_123",
            rsvp_decline_url="http://localhost:8000/rsvp/decline_token_456",
        )
        assert "Accept: http://localhost:8000/rsvp/accept_token_123" in text
        assert "Decline: http://localhost:8000/rsvp/decline_token_456" in text

    def test_text_excludes_rsvp_links_when_urls_not_provided(self, db, lead):
        """Plain-text email does NOT include RSVP links when URLs are not provided."""
        from app.services.email_templates import build_confirmation_text
        from zoneinfo import ZoneInfo

        text = build_confirmation_text(
            lead,
            meet_link="https://meet.google.com/abc-defg-hij",
            ai_paragraph="Looking forward to our call!",
            tz=ZoneInfo("America/Chicago"),
        )
        assert "rsvp" not in text.lower()


# ══════════════════════════════════════════════════════════════════════════════
# F. Cross-Lead Isolation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestCrossLeadIsolation:
    """Tests for token isolation between leads."""

    def test_token_only_works_for_its_lead(self, db, org):
        """A token for lead A cannot be used to change lead B's status."""
        lead_a = _make_lead(db, org.id, name="Lead A", email="a@test.com")
        lead_b = _make_lead(db, org.id, name="Lead B", email="b@test.com")

        accept_token_a, _ = generate_rsvp_tokens(db, lead_a)
        validate_and_process_rsvp(db, accept_token_a)

        # Lead A should be ACCEPTED
        db.refresh(lead_a)
        assert lead_a.status == LeadStatus.ACCEPTED

        # Lead B should still be SCHEDULED
        db.refresh(lead_b)
        assert lead_b.status == LeadStatus.SCHEDULED

    def test_different_leads_get_different_tokens(self, db, org):
        """Different leads get different tokens."""
        lead_a = _make_lead(db, org.id, name="Lead A", email="a@test.com")
        lead_b = _make_lead(db, org.id, name="Lead B", email="b@test.com")

        accept_a, _ = generate_rsvp_tokens(db, lead_a)
        accept_b, _ = generate_rsvp_tokens(db, lead_b)

        assert accept_a != accept_b

        # Token A should only work for lead A
        result = validate_and_process_rsvp(db, accept_a)
        assert result.lead_name == "Lead A"

        # Token B should only work for lead B
        result = validate_and_process_rsvp(db, accept_b)
        assert result.lead_name == "Lead B"


# ══════════════════════════════════════════════════════════════════════════════
# G. Concurrency Safety Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestConcurrencySafety:
    """Tests for concurrent RSVP processing safety."""

    def test_double_click_same_token(self, db, lead):
        """Two rapid clicks on the same token are idempotent."""
        accept_token, _ = generate_rsvp_tokens(db, lead)

        result1 = validate_and_process_rsvp(db, accept_token)
        result2 = validate_and_process_rsvp(db, accept_token)

        assert result1.success is True
        assert result2.already_used is True

        db.refresh(lead)
        assert lead.status == LeadStatus.ACCEPTED
        # Should have exactly 1 rsvp_accepted event
        events = db.query(EventLog).filter(
            EventLog.lead_id == lead.id,
            EventLog.event_type == "rsvp_accepted",
        ).all()
        assert len(events) == 1
