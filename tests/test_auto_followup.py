"""Tests for Phase 23 Auto Follow-Up service.

Covers:
  - get_followup_templates: template lookup for each call outcome
  - create_post_call_followups: follow-up creation, priority, due dates
"""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest
from sqlalchemy.orm import Session as SASession

from app.database import SessionLocal
from app.models import (
    CallOutcome,
    FollowUp,
    FollowUpPriority,
    FollowUpStatus,
    Lead,
    LeadStatus,
)
from app.models_multi_tenant import Organization, OrganizationStatus, User, UserRole, UserStatus
from app.services.auto_followup_service import (
    create_post_call_followups,
    get_followup_templates,
)
from app.services.crypto import generate_key
from app.tenant import _DEFAULT_ORG_ID
from tests.test_auth import _create_org_and_user


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
def org_and_user(db):
    """Create an org with an owner user for FK compliance."""
    return _create_org_and_user(db, email=f"auto-{uuid.uuid4().hex[:8]}@test.com")


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
    status: LeadStatus = LeadStatus.PENDING,
    assigned_to: uuid.UUID | None = None,
) -> Lead:
    """Insert a Lead directly via ORM."""
    unique = uuid.uuid4().hex[:8]
    lead = Lead(
        organization_id=org_id,
        interested=True,
        name=name,
        email=f"test-{unique}@example.com",
        appt_datetime_raw=f"test-{unique}",
        dedupe_key=f"test-{unique}",
        status=status,
    )
    if assigned_to:
        lead.assigned_to = assigned_to
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


# ══════════════════════════════════════════════════════════════════════════════
# 1. FOLLOWUP TEMPLATES
# ══════════════════════════════════════════════════════════════════════════════


class TestFollowupTemplates:
    """Test template lookup for each call outcome."""

    def test_connected_template(self):
        """Connected outcome returns a proposal follow-up template."""
        templates = get_followup_templates("connected")
        assert len(templates) == 1
        assert "proposal" in templates[0]["title"].lower()
        assert templates[0]["priority"] == FollowUpPriority.HIGH
        assert templates[0]["due_days"] == 2

    def test_completed_template(self):
        """Completed outcome returns a proposal follow-up template."""
        templates = get_followup_templates("completed")
        assert len(templates) == 1
        assert templates[0]["priority"] == FollowUpPriority.HIGH

    def test_voicemail_template(self):
        """Voicemail returns a retry template with 1-day due."""
        templates = get_followup_templates("voicemail")
        assert len(templates) == 1
        assert "retry" in templates[0]["title"].lower()
        assert templates[0]["priority"] == FollowUpPriority.MEDIUM
        assert templates[0]["due_days"] == 1

    def test_no_answer_template(self):
        """No answer returns a retry template."""
        templates = get_followup_templates("no_answer")
        assert len(templates) == 1
        assert templates[0]["due_days"] == 1

    def test_busy_template(self):
        """Busy returns a retry template with 3-day due."""
        templates = get_followup_templates("busy")
        assert len(templates) == 1
        assert templates[0]["due_days"] == 3
        assert templates[0]["priority"] == FollowUpPriority.LOW

    def test_rescheduled_template(self):
        """Rescheduled returns a confirm template."""
        templates = get_followup_templates("rescheduled")
        assert len(templates) == 1
        assert templates[0]["priority"] == FollowUpPriority.HIGH

    def test_wrong_number_template(self):
        """Wrong number returns a verify template with 7-day due."""
        templates = get_followup_templates("wrong_number")
        assert len(templates) == 1
        assert templates[0]["due_days"] == 7

    def test_no_show_template(self):
        """No show returns a reschedule template."""
        templates = get_followup_templates("no_show")
        assert len(templates) == 1
        assert templates[0]["due_days"] == 1

    def test_not_interested_no_template(self):
        """Not-interested returns empty list (no follow-up)."""
        templates = get_followup_templates("not_interested")
        assert templates == []

    def test_cancelled_no_template(self):
        """Cancelled returns empty list (no follow-up)."""
        templates = get_followup_templates("cancelled")
        assert templates == []

    def test_unknown_outcome_no_template(self):
        """Unknown outcome returns empty list."""
        templates = get_followup_templates("some_future_outcome")
        assert templates == []

    def test_enum_input(self):
        """CallOutcome enum input works the same as string."""
        templates = get_followup_templates(CallOutcome.CONNECTED)
        assert len(templates) == 1

    def test_case_insensitive(self):
        """String matching is case-insensitive."""
        templates = get_followup_templates("CONNECTED")
        assert len(templates) == 1


# ══════════════════════════════════════════════════════════════════════════════
# 2. CREATE POST-CALL FOLLOWUPS
# ══════════════════════════════════════════════════════════════════════════════


class TestCreatePostCallFollowups:
    """Test auto follow-up creation after call outcomes."""

    def test_connected_creates_followup(self, db: SASession, org_id: uuid.UUID):
        """Connected call creates a high-priority follow-up."""
        lead = _make_lead(db, org_id, name="Alice")
        ids = create_post_call_followups(db, lead, "connected", org_id)
        assert len(ids) == 1

        fu = db.query(FollowUp).filter(FollowUp.id == ids[0]).first()
        assert fu is not None
        assert fu.title == "Send proposal/follow-up email"
        assert fu.priority == FollowUpPriority.HIGH
        assert fu.status == FollowUpStatus.PENDING
        assert fu.lead_id == lead.id
        assert fu.organization_id == org_id
        assert fu.due_at is not None

    def test_voicemail_creates_followup(self, db: SASession, org_id: uuid.UUID):
        """Voicemail creates a medium-priority follow-up."""
        lead = _make_lead(db, org_id, name="Bob")
        ids = create_post_call_followups(db, lead, "voicemail", org_id)
        assert len(ids) == 1

        fu = db.query(FollowUp).filter(FollowUp.id == ids[0]).first()
        assert fu.priority == FollowUpPriority.MEDIUM

    def test_not_interested_creates_nothing(self, db: SASession, org_id: uuid.UUID):
        """Not-interested creates no follow-ups."""
        lead = _make_lead(db, org_id, name="Charlie")
        ids = create_post_call_followups(db, lead, "not_interested", org_id)
        assert ids == []

    def test_cancelled_creates_nothing(self, db: SASession, org_id: uuid.UUID):
        """Cancelled creates no follow-ups."""
        lead = _make_lead(db, org_id, name="Dave")
        ids = create_post_call_followups(db, lead, "cancelled", org_id)
        assert ids == []

    def test_followup_assigned_to_lead_assignee(self, db: SASession, org_id: uuid.UUID, user_id: uuid.UUID):
        """Follow-up is assigned to the lead's assigned_to user."""
        lead = _make_lead(db, org_id, name="Eve", assigned_to=user_id)
        ids = create_post_call_followups(db, lead, "connected", org_id)
        fu = db.query(FollowUp).filter(FollowUp.id == ids[0]).first()
        assert fu.assigned_to == user_id

    def test_followup_due_date_in_future(self, db: SASession, org_id: uuid.UUID):
        """Follow-up due date is in the future."""
        lead = _make_lead(db, org_id, name="Frank")
        ids = create_post_call_followups(db, lead, "connected", org_id)

        fu = db.query(FollowUp).filter(FollowUp.id == ids[0]).first()
        assert fu.due_at > datetime.now(timezone.utc)

    def test_enum_input(self, db: SASession, org_id: uuid.UUID):
        """CallOutcome enum works as input."""
        lead = _make_lead(db, org_id, name="Grace")
        ids = create_post_call_followups(db, lead, CallOutcome.VOICEMAIL, org_id)
        assert len(ids) == 1

    def test_busy_creates_low_priority(self, db: SASession, org_id: uuid.UUID):
        """Busy outcome creates a low-priority follow-up."""
        lead = _make_lead(db, org_id, name="Hank")
        ids = create_post_call_followups(db, lead, "busy", org_id)
        assert len(ids) == 1

        fu = db.query(FollowUp).filter(FollowUp.id == ids[0]).first()
        assert fu.priority == FollowUpPriority.LOW

    @patch("app.services.auto_followup_service.publish_event")
    def test_publishes_sse_event(self, mock_publish, db: SASession, org_id: uuid.UUID):
        """Each follow-up creation publishes an SSE event."""
        lead = _make_lead(db, org_id, name="Iris")
        create_post_call_followups(db, lead, "connected", org_id)
        assert mock_publish.call_count >= 1
        # Verify the event type is followup_created
        first_call = mock_publish.call_args_list[0]
        assert first_call[0][0] == "followup_created"
