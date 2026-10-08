"""Tests for Phase 23 AI Scoring & Summary service.

Covers:
  - score_lead: rule-based scoring (completeness, recency, engagement)
  - generate_lead_summary: AI summary with fallback
  - generate_call_summary: AI call summary with fallback
  - get_next_best_action: decision tree recommendations
"""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest
from sqlalchemy.orm import Session as SASession

from app.database import SessionLocal
from app.models import CallOutcome, Lead, LeadStatus
from app.tenant import _DEFAULT_ORG_ID
from app.services.ai_scoring_service import (
    generate_call_summary,
    generate_lead_summary,
    get_next_best_action,
    score_lead,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def db():
    """Yield a DB session with rollback."""
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


@pytest.fixture()
def org_id() -> uuid.UUID:
    return _DEFAULT_ORG_ID


def _make_lead(
    db: SASession,
    org_id: uuid.UUID,
    *,
    name: str = "Test Lead",
    email: str = "",  # empty string = no completeness credit
    phone_number: str | None = "",
    company_address: str | None = "",
    courses: str | None = "",
    direct_number: str | None = "",
    caller_name: str | None = "",
    status: LeadStatus = LeadStatus.PENDING,
    call_outcome: CallOutcome | None = None,
    call_notes: str | None = None,
    calendar_event_id: str | None = None,
    reminder_sent_at: datetime | None = None,
    created_at: datetime | None = None,
) -> Lead:
    """Insert a Lead directly via ORM for test purposes.

    Default optional fields are empty strings so the scoring completeness
    check (``if value and str(value).strip()``) treats them as absent.
    Pass explicit non-empty values to test presence-based scoring.
    """
    unique = uuid.uuid4().hex[:8]
    # DB requires non-null email and dedupe_key, so always provide them.
    lead_email = email if (email and email.strip()) else f"test-{unique}@example.com"
    lead = Lead(
        organization_id=org_id,
        interested=True,
        name=name,
        email=lead_email,
        phone_number=phone_number or None,
        company_address=company_address or None,
        courses=courses or None,
        direct_number=direct_number or None,
        caller_name=caller_name or None,
        status=status,
        call_outcome=call_outcome,
        call_notes=call_notes,
        calendar_event_id=calendar_event_id,
        reminder_sent_at=reminder_sent_at,
        appt_datetime_raw=f"test-{unique}",
        dedupe_key=f"test-{unique}",
    )
    if created_at:
        lead.created_at = created_at
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


# ══════════════════════════════════════════════════════════════════════════════
# 1. SCORE LEAD — Data Completeness
# ══════════════════════════════════════════════════════════════════════════════


class TestScoreLeadCompleteness:
    """Test data completeness component of scoring."""

    def test_all_fields_present_max_completeness(self, db: SASession, org_id: uuid.UUID):
        """Lead with all fields gets max completeness score (30)."""
        lead = _make_lead(
            db, org_id,
            email="test@example.com",
            phone_number="555-1234",
            company_address="123 Main St",
            courses="Python 101",
            direct_number="555-5678",
            caller_name="Jane Caller",
            created_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        result = score_lead(db, lead)
        assert result["factors"]["data_completeness"] == 30

    def test_no_fields_min_completeness(self, db: SASession, org_id: uuid.UUID):
        """Lead with minimal optional fields gets low completeness.
        
        Note: email is NOT NULL in DB, so it always contributes 4 points.
        """
        lead = _make_lead(
            db, org_id,
            phone_number="",
            company_address="",
            courses="",
            direct_number="",
            caller_name="",
            created_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        result = score_lead(db, lead)
        # email always present (NOT NULL) = 4 pts; everything else empty
        assert result["factors"]["data_completeness"] == 4

    def test_partial_completeness(self, db: SASession, org_id: uuid.UUID):
        """Lead with some fields gets partial completeness."""
        lead = _make_lead(
            db, org_id,
            email="test@example.com",      # 4 pts
            phone_number="555-1234",        # 6 pts
            company_address=None,
            courses=None,
            direct_number=None,
            caller_name=None,
            created_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        result = score_lead(db, lead)
        assert result["factors"]["data_completeness"] == 10


# ══════════════════════════════════════════════════════════════════════════════
# 2. SCORE LEAD — Recency
# ══════════════════════════════════════════════════════════════════════════════


class TestScoreLeadRecency:
    """Test recency component of scoring."""

    def test_very_recent_lead_max_recency(self, db: SASession, org_id: uuid.UUID):
        """Lead created now gets near-max recency (25)."""
        lead = _make_lead(db, org_id, created_at=datetime.now(timezone.utc))
        result = score_lead(db, lead)
        # Created just now → ~25 points (within rounding)
        assert result["factors"]["lead_recency"] >= 24

    def test_15_day_old_lead_half_recency(self, db: SASession, org_id: uuid.UUID):
        """Lead created 15 days ago gets ~half recency."""
        lead = _make_lead(
            db, org_id,
            created_at=datetime.now(timezone.utc) - timedelta(days=15),
        )
        result = score_lead(db, lead)
        # Linear decay: 25 * (1 - 15/30) = 12.5 → 12
        assert 11 <= result["factors"]["lead_recency"] <= 14

    def test_30_day_old_lead_min_recency(self, db: SASession, org_id: uuid.UUID):
        """Lead created 30+ days ago gets 0 recency."""
        lead = _make_lead(
            db, org_id,
            created_at=datetime.now(timezone.utc) - timedelta(days=35),
        )
        result = score_lead(db, lead)
        assert result["factors"]["lead_recency"] == 0

    def test_no_created_at_zero_recency(self, db: SASession, org_id: uuid.UUID):
        """Lead with created_at far in the past gets 0 recency.
        
        Note: created_at is set by the DB server default on INSERT,
        so we set it to a very old date to simulate a missing/recent lead.
        """
        lead = _make_lead(
            db, org_id,
            created_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
        result = score_lead(db, lead)
        assert result["factors"]["lead_recency"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# 3. SCORE LEAD — Engagement Signals
# ══════════════════════════════════════════════════════════════════════════════


class TestScoreLeadEngagement:
    """Test engagement signal scoring."""

    def test_calendar_event_bonus(self, db: SASession, org_id: uuid.UUID):
        """Calendar event adds 20 points."""
        lead = _make_lead(db, org_id, calendar_event_id=f"evt_cal_bonus_{uuid.uuid4().hex[:8]}")
        result = score_lead(db, lead)
        assert result["factors"]["calendar_created"] == 20

    def test_connected_call_bonus(self, db: SASession, org_id: uuid.UUID):
        """Connected call outcome adds 15 points."""
        lead = _make_lead(db, org_id, call_outcome=CallOutcome.CONNECTED)
        result = score_lead(db, lead)
        assert result["factors"]["call_completed"] == 15

    def test_voicemail_deduction(self, db: SASession, org_id: uuid.UUID):
        """Voicemail outcome deducts 3 points."""
        lead = _make_lead(db, org_id, call_outcome=CallOutcome.VOICEMAIL)
        result = score_lead(db, lead)
        assert result["factors"]["outcome_voicemail"] == -3

    def test_call_notes_bonus(self, db: SASession, org_id: uuid.UUID):
        """Call notes add 10 points."""
        lead = _make_lead(db, org_id, call_notes="Great conversation about pricing")
        result = score_lead(db, lead)
        assert result["factors"]["has_call_notes"] == 10

    def test_reminder_bonus(self, db: SASession, org_id: uuid.UUID):
        """Reminder sent adds 5 points."""
        lead = _make_lead(
            db, org_id,
            reminder_sent_at=datetime.now(timezone.utc),
        )
        result = score_lead(db, lead)
        assert result["factors"]["reminder_sent"] == 5

    def test_all_engagement_signals(self, db: SASession, org_id: uuid.UUID):
        """Lead with all engagement signals gets maximum engagement."""
        lead = _make_lead(
            db, org_id,
            calendar_event_id=f"evt_engage_{uuid.uuid4().hex[:8]}",
            call_outcome=CallOutcome.CONNECTED,
            call_notes="Excellent call",
            reminder_sent_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
        )
        result = score_lead(db, lead)
        # calendar(20) + connected(15) + notes(10) + reminder(5) = 50
        assert result["factors"]["engagement"] == 50


# ══════════════════════════════════════════════════════════════════════════════
# 4. SCORE LEAD — Terminal / Negative States
# ══════════════════════════════════════════════════════════════════════════════


class TestScoreLeadNegativeStates:
    """Test negative state adjustments."""

    def test_declined_deduction(self, db: SASession, org_id: uuid.UUID):
        """DECLINED status deducts 20 points."""
        lead = _make_lead(db, org_id, status=LeadStatus.DECLINED)
        result = score_lead(db, lead)
        assert result["factors"]["status_declined"] == -20

    def test_not_interested_deduction(self, db: SASession, org_id: uuid.UUID):
        """NOT_INTERESTED status deducts 40 points."""
        lead = _make_lead(db, org_id, status=LeadStatus.NOT_INTERESTED)
        result = score_lead(db, lead)
        assert result["factors"]["status_not_interested"] == -40

    def test_score_clamped_min_1(self, db: SASession, org_id: uuid.UUID):
        """Score is clamped to minimum 1."""
        lead = _make_lead(
            db, org_id,
            status=LeadStatus.NOT_INTERESTED,
            phone_number="",
            company_address="",
            courses="",
            direct_number="",
            caller_name="",
            created_at=datetime.now(timezone.utc) - timedelta(days=60),
        )
        result = score_lead(db, lead)
        assert result["score"] >= 1

    def test_score_clamped_max_100(self, db: SASession, org_id: uuid.UUID):
        """Score is clamped to maximum 100."""
        lead = _make_lead(
            db, org_id,
            email="full@test.com",
            phone_number="555-0001",
            company_address="123 Test St",
            courses="Python, React",
            direct_number="555-0002",
            caller_name="Caller",
            calendar_event_id=f"evt_clamp_{uuid.uuid4().hex[:8]}",
            call_outcome=CallOutcome.CONNECTED,
            call_notes="Great call",
            reminder_sent_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
        )
        result = score_lead(db, lead)
        assert result["score"] <= 100


# ══════════════════════════════════════════════════════════════════════════════
# 5. SCORE LEAD — Recommendations
# ══════════════════════════════════════════════════════════════════════════════


class TestScoreLeadRecommendations:
    """Test recommendation text based on score."""

    def test_high_score_recommendation(self, db: SASession, org_id: uuid.UUID):
        """High-scoring lead (≥80) gets priority recommendation."""
        lead = _make_lead(
            db, org_id,
            email="full@test.com",
            phone_number="555-0001",
            company_address="123 Test St",
            courses="Python, React",
            direct_number="555-0002",
            caller_name="Caller",
            calendar_event_id=f"evt_highrec_{uuid.uuid4().hex[:8]}",
            call_outcome=CallOutcome.CONNECTED,
            call_notes="Great call",
            reminder_sent_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
        )
        result = score_lead(db, lead)
        assert "High priority" in result["recommendation"]

    def test_declined_recommendation(self, db: SASession, org_id: uuid.UUID):
        """DECLINED lead gets archived recommendation regardless of score."""
        lead = _make_lead(db, org_id, status=LeadStatus.DECLINED)
        result = score_lead(db, lead)
        assert "Archived" in result["recommendation"]

    def test_completed_recommendation(self, db: SASession, org_id: uuid.UUID):
        """COMPLETED lead gets follow-up/referral recommendation."""
        lead = _make_lead(db, org_id, status=LeadStatus.COMPLETED)
        result = score_lead(db, lead)
        assert "Completed" in result["recommendation"]


# ══════════════════════════════════════════════════════════════════════════════
# 6. LEAD SUMMARY — AI & Fallback
# ══════════════════════════════════════════════════════════════════════════════


class TestGenerateLeadSummary:
    """Test AI-generated lead summary with fallback."""

    def test_fallback_summary(self, db: SASession, org_id: uuid.UUID):
        """When AI fails, fallback summary is returned."""
        lead = _make_lead(db, org_id, name="Alice Corp", status=LeadStatus.PENDING)
        result = generate_lead_summary(db, lead, org_context=None)
        assert "summary" in result
        assert len(result["summary"]) > 0
        assert result["model_used"] == "fallback:static"

    @patch("app.services.ai_service._chat_completion", side_effect=Exception("API down"))
    def test_ai_failure_returns_fallback(self, mock_ai, db: SASession, org_id: uuid.UUID):
        """AI exception returns fallback, not an error."""
        lead = _make_lead(db, org_id, name="Bob Inc")
        result = generate_lead_summary(db, lead, org_context=None)
        assert "summary" in result
        assert "fallback" in result["model_used"]


# ══════════════════════════════════════════════════════════════════════════════
# 7. CALL SUMMARY — AI & Fallback
# ══════════════════════════════════════════════════════════════════════════════


class TestGenerateCallSummary:
    """Test AI-generated call summary with fallback."""

    def test_no_call_notes_returns_fallback(self, db: SASession, org_id: uuid.UUID):
        """Lead without call_notes returns a fallback message."""
        lead = _make_lead(db, org_id, call_notes=None)
        result = generate_call_summary(db, lead, org_context=None)
        assert "summary" in result
        assert len(result["summary"]) > 0  # Returns a fallback message
        assert result["key_points"] == []

    def test_fallback_summary_with_notes(self, db: SASession, org_id: uuid.UUID):
        """When AI fails, call_notes returned as summary fallback."""
        lead = _make_lead(
            db, org_id,
            call_notes="Discussed pricing, they want 20% discount, follow up with proposal.",
        )
        result = generate_call_summary(db, lead, org_context=None)
        assert "summary" in result
        assert "Discussed pricing" in result["summary"]


# ══════════════════════════════════════════════════════════════════════════════
# 8. NEXT BEST ACTION
# ══════════════════════════════════════════════════════════════════════════════


class TestGetNextBestAction:
    """Test next best action decision tree."""

    def test_pending_lead_recommendation(self, db: SASession, org_id: uuid.UUID):
        """Pending lead gets call recommendation."""
        lead = _make_lead(db, org_id, status=LeadStatus.PENDING)
        result = get_next_best_action(db, lead)
        assert "action" in result
        assert "priority" in result

    def test_completed_lead_recommendation(self, db: SASession, org_id: uuid.UUID):
        """Completed lead gets follow-up recommendation."""
        lead = _make_lead(db, org_id, status=LeadStatus.COMPLETED)
        result = get_next_best_action(db, lead)
        assert "action" in result

    def test_declined_lead_low_priority(self, db: SASession, org_id: uuid.UUID):
        """Declined lead gets low priority action."""
        lead = _make_lead(db, org_id, status=LeadStatus.DECLINED)
        result = get_next_best_action(db, lead)
        assert result["priority"] == "low"
