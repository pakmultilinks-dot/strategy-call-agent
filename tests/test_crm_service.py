"""Tests for Phase 23 CRM Search & Stats service.

Covers:
  - search_leads: full-text search, filters, sorting, pagination
  - get_crm_stats: dashboard aggregate statistics
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session as SASession

from app.database import SessionLocal
from app.models import CallOutcome, Lead, LeadStatus
from app.models_multi_tenant import Organization, OrganizationStatus, User, UserRole, UserStatus
from app.services.crypto import generate_key
from app.services.crm_service import get_crm_stats, search_leads
from tests.test_auth import _create_org_and_user


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", generate_key())
    monkeypatch.setattr(settings, "jwt_secret_key", "test-secret-for-crm-service-32char!!")


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
    """Create a fresh org for each test to avoid cross-test data contamination."""
    return _create_org_and_user(db, email=f"crm-{uuid.uuid4().hex[:8]}@test.com")


@pytest.fixture()
def org_id(org_and_user) -> uuid.UUID:
    org, _ = org_and_user
    return org.id


def _make_lead(
    db: SASession,
    org_id: uuid.UUID,
    *,
    name: str = "Test Lead",
    email: str | None = None,
    phone_number: str | None = "555-1234",
    company_address: str | None = "123 Main St",
    courses: str | None = "Python 101",
    direct_number: str | None = None,
    status: LeadStatus = LeadStatus.PENDING,
    call_outcome: CallOutcome | None = None,
    call_notes: str | None = None,
    assigned_to: uuid.UUID | None = None,
    calendar_event_id: str | None = None,
    created_at: datetime | None = None,
    appt_datetime_utc: datetime | None = None,
) -> Lead:
    """Insert a Lead directly via ORM for test purposes."""
    # Generate unique email and dedupe_key for each lead
    unique = uuid.uuid4().hex[:8]
    lead_email = email or f"test-{unique}@example.com"
    lead = Lead(
        organization_id=org_id,
        interested=True,
        name=name,
        email=lead_email,
        phone_number=phone_number,
        company_address=company_address,
        courses=courses,
        direct_number=direct_number,
        status=status,
        call_outcome=call_outcome,
        call_notes=call_notes,
        assigned_to=assigned_to,
        calendar_event_id=calendar_event_id,
        appt_datetime_raw=f"test-{unique}",
        dedupe_key=f"test-{unique}",
    )
    if created_at:
        lead.created_at = created_at
    if appt_datetime_utc:
        lead.appt_datetime_utc = appt_datetime_utc
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


# ══════════════════════════════════════════════════════════════════════════════
# 1. SEARCH LEADS — Full-text
# ══════════════════════════════════════════════════════════════════════════════


class TestSearchLeadsFullText:
    """Test full-text search across lead fields."""

    def test_search_by_name(self, db: SASession, org_id: uuid.UUID):
        """Search by name returns matching leads."""
        _make_lead(db, org_id, name="Alice Johnson")
        _make_lead(db, org_id, name="Bob Smith")

        result = search_leads(db, org_id, search_query="Alice")
        assert result["total"] == 1
        assert result["leads"][0]["name"] == "Alice Johnson"

    def test_search_by_email(self, db: SASession, org_id: uuid.UUID):
        """Search by email finds the correct lead."""
        _make_lead(db, org_id, name="L1", email="alice@corp.com")
        _make_lead(db, org_id, name="L2", email="bob@corp.com")

        result = search_leads(db, org_id, search_query="alice@corp")
        assert result["total"] == 1

    def test_search_by_company(self, db: SASession, org_id: uuid.UUID):
        """Search by company address finds matching leads."""
        _make_lead(db, org_id, name="L1", company_address="Acme Inc, Dallas TX")

        result = search_leads(db, org_id, search_query="Acme")
        assert result["total"] == 1

    def test_search_by_phone(self, db: SASession, org_id: uuid.UUID):
        """Search by phone number."""
        _make_lead(db, org_id, name="L1", phone_number="555-9999")
        _make_lead(db, org_id, name="L2", phone_number="555-0000")

        result = search_leads(db, org_id, search_query="9999")
        assert result["total"] == 1

    def test_search_by_courses(self, db: SASession, org_id: uuid.UUID):
        """Search by courses field."""
        _make_lead(db, org_id, name="L1", courses="Advanced React")
        _make_lead(db, org_id, name="L2", courses="Docker Fundamentals")

        result = search_leads(db, org_id, search_query="React")
        assert result["total"] == 1

    def test_search_case_insensitive(self, db: SASession, org_id: uuid.UUID):
        """Search is case-insensitive."""
        _make_lead(db, org_id, name="Charlie Brown")

        result = search_leads(db, org_id, search_query="charlie")
        assert result["total"] == 1

    def test_search_no_results(self, db: SASession, org_id: uuid.UUID):
        """Search with no matches returns empty list."""
        _make_lead(db, org_id, name="Alice")

        result = search_leads(db, org_id, search_query="ZZZZNOTFOUND")
        assert result["total"] == 0
        assert result["leads"] == []

    def test_search_empty_query_returns_all(self, db: SASession, org_id: uuid.UUID):
        """Empty or None search query returns all leads."""
        _make_lead(db, org_id, name="L1")
        _make_lead(db, org_id, name="L2")

        result = search_leads(db, org_id, search_query=None)
        assert result["total"] == 2

    def test_search_whitespace_query_returns_all(self, db: SASession, org_id: uuid.UUID):
        """Whitespace-only search query returns all leads."""
        _make_lead(db, org_id, name="L1")

        result = search_leads(db, org_id, search_query="   ")
        assert result["total"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# 2. SEARCH LEADS — Filters
# ══════════════════════════════════════════════════════════════════════════════


class TestSearchLeadsFilters:
    """Test advanced filtering on search_leads."""

    def test_filter_by_status(self, db: SASession, org_id: uuid.UUID):
        """Filter by single status."""
        _make_lead(db, org_id, name="L1", status=LeadStatus.PENDING)
        _make_lead(db, org_id, name="L2", status=LeadStatus.COMPLETED)

        result = search_leads(db, org_id, filters={"status": LeadStatus.PENDING.value})
        assert result["total"] == 1
        assert result["leads"][0]["name"] == "L1"

    def test_filter_by_status_in(self, db: SASession, org_id: uuid.UUID):
        """Filter by multiple statuses."""
        _make_lead(db, org_id, name="L1", status=LeadStatus.PENDING)
        _make_lead(db, org_id, name="L2", status=LeadStatus.COMPLETED)
        _make_lead(db, org_id, name="L3", status=LeadStatus.DECLINED)

        result = search_leads(
            db, org_id,
            filters={"status_in": [LeadStatus.PENDING.value, LeadStatus.COMPLETED.value]},
        )
        assert result["total"] == 2

    def test_filter_by_call_outcome(self, db: SASession, org_id: uuid.UUID):
        """Filter by call outcome."""
        _make_lead(db, org_id, name="L1", call_outcome=CallOutcome.CONNECTED)
        _make_lead(db, org_id, name="L2", call_outcome=CallOutcome.VOICEMAIL)

        result = search_leads(db, org_id, filters={"call_outcome": "connected"})
        assert result["total"] == 1

    def test_filter_by_created_after(self, db: SASession, org_id: uuid.UUID):
        """Filter by created_after."""
        _make_lead(db, org_id, name="Old", created_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
        _make_lead(db, org_id, name="New", created_at=datetime(2025, 6, 1, tzinfo=timezone.utc))

        result = search_leads(
            db, org_id,
            filters={"created_after": datetime(2025, 1, 1, tzinfo=timezone.utc)},
        )
        assert result["total"] == 1
        assert result["leads"][0]["name"] == "New"

    def test_filter_has_calendar_event(self, db: SASession, org_id: uuid.UUID):
        """Filter by has_calendar_event."""
        _make_lead(db, org_id, name="WithCal", calendar_event_id="evt_has_cal_unique")
        _make_lead(db, org_id, name="NoCal", calendar_event_id=None)

        result = search_leads(db, org_id, filters={"has_calendar_event": True})
        assert result["total"] == 1
        assert result["leads"][0]["name"] == "WithCal"

    def test_filter_no_calendar_event(self, db: SASession, org_id: uuid.UUID):
        """Filter has_calendar_event=False."""
        _make_lead(db, org_id, name="WithCal", calendar_event_id="evt_no_cal_unique")
        _make_lead(db, org_id, name="NoCal", calendar_event_id=None)

        result = search_leads(db, org_id, filters={"has_calendar_event": False})
        assert result["total"] == 1
        assert result["leads"][0]["name"] == "NoCal"

    def test_combined_search_and_filter(self, db: SASession, org_id: uuid.UUID):
        """Search query + filter together."""
        _make_lead(db, org_id, name="Alice Corp", status=LeadStatus.PENDING)
        _make_lead(db, org_id, name="Alice Corp", status=LeadStatus.COMPLETED)

        result = search_leads(
            db, org_id,
            search_query="Alice",
            filters={"status": LeadStatus.PENDING.value},
        )
        assert result["total"] == 1
        assert result["leads"][0]["status"] == "pending"


# ══════════════════════════════════════════════════════════════════════════════
# 3. SEARCH LEADS — Sorting & Pagination
# ══════════════════════════════════════════════════════════════════════════════


class TestSearchLeadsSortPagination:
    """Test sorting and pagination."""

    def test_sort_by_name_asc(self, db: SASession, org_id: uuid.UUID):
        """Sort ascending by name."""
        _make_lead(db, org_id, name="Charlie")
        _make_lead(db, org_id, name="Alice")
        _make_lead(db, org_id, name="Bob")

        result = search_leads(db, org_id, sort_by="name", sort_dir="asc")
        names = [l["name"] for l in result["leads"]]
        assert names == ["Alice", "Bob", "Charlie"]

    def test_sort_by_name_desc(self, db: SASession, org_id: uuid.UUID):
        """Sort descending by name."""
        _make_lead(db, org_id, name="Charlie")
        _make_lead(db, org_id, name="Alice")
        _make_lead(db, org_id, name="Bob")

        result = search_leads(db, org_id, sort_by="name", sort_dir="desc")
        names = [l["name"] for l in result["leads"]]
        assert names == ["Charlie", "Bob", "Alice"]

    def test_sort_invalid_column_falls_back(self, db: SASession, org_id: uuid.UUID):
        """Invalid sort column falls back to created_at."""
        _make_lead(db, org_id, name="L1")
        _make_lead(db, org_id, name="L2")

        # Should not raise, falls back to created_at
        result = search_leads(db, org_id, sort_by="nonexistent_column", sort_dir="asc")
        assert result["total"] == 2

    def test_pagination_limit(self, db: SASession, org_id: uuid.UUID):
        """Limit parameter restricts result count."""
        for i in range(5):
            _make_lead(db, org_id, name=f"Lead {i}")

        result = search_leads(db, org_id, limit=2)
        assert len(result["leads"]) == 2
        assert result["total"] == 5
        assert result["limit"] == 2

    def test_pagination_offset(self, db: SASession, org_id: uuid.UUID):
        """Offset skips results."""
        for i in range(5):
            _make_lead(db, org_id, name=f"Lead {i}")

        result = search_leads(db, org_id, limit=2, offset=2)
        assert len(result["leads"]) == 2
        assert result["offset"] == 2

    def test_pagination_clamp_limit(self, db: SASession, org_id: uuid.UUID):
        """Limit is clamped to max 1000 and min 1."""
        _make_lead(db, org_id, name="L1")

        # Limit of 0 should be clamped to 1
        result = search_leads(db, org_id, limit=0)
        assert result["limit"] == 1

        # Limit of 9999 should be clamped to 1000
        result = search_leads(db, org_id, limit=9999)
        assert result["limit"] == 1000


# ══════════════════════════════════════════════════════════════════════════════
# 4. SEARCH LEADS — Tenant Isolation
# ══════════════════════════════════════════════════════════════════════════════


class TestSearchLeadsTenantIsolation:
    """Search results are scoped to organization."""

    def test_only_returns_org_leads(self, db: SASession, org_and_user):
        """Leads from other orgs are not returned."""
        org, _ = org_and_user
        other, _ = _create_org_and_user(db, email=f"other-{uuid.uuid4().hex[:8]}@test.com")
        _make_lead(db, org.id, name="My Lead")
        _make_lead(db, other.id, name="Other Lead")

        result = search_leads(db, org.id, search_query="Lead")
        assert result["total"] == 1
        assert result["leads"][0]["name"] == "My Lead"


# ══════════════════════════════════════════════════════════════════════════════
# 5. CRM STATS
# ══════════════════════════════════════════════════════════════════════════════


class TestCrmStats:
    """Dashboard aggregate statistics."""

    def test_empty_org_stats(self, db: SASession, org_id: uuid.UUID):
        """Stats for org with no leads."""
        result = get_crm_stats(db, org_id)
        assert result["total_leads"] == 0
        assert result["leads_this_month"] == 0
        assert result["conversion_rate"] == 0.0

    def test_total_leads(self, db: SASession, org_id: uuid.UUID):
        """total_leads counts all leads in the org."""
        _make_lead(db, org_id, name="L1")
        _make_lead(db, org_id, name="L2")
        _make_lead(db, org_id, name="L3")

        result = get_crm_stats(db, org_id)
        assert result["total_leads"] == 3

    def test_leads_by_status(self, db: SASession, org_id: uuid.UUID):
        """leads_by_status groups by status."""
        _make_lead(db, org_id, name="L1", status=LeadStatus.PENDING)
        _make_lead(db, org_id, name="L2", status=LeadStatus.PENDING)
        _make_lead(db, org_id, name="L3", status=LeadStatus.COMPLETED)

        result = get_crm_stats(db, org_id)
        by_status = result["leads_by_status"]
        assert by_status.get("pending") == 2
        assert by_status.get("completed") == 1

    def test_conversion_rate(self, db: SASession, org_id: uuid.UUID):
        """conversion_rate is percentage of COMPLETED leads."""
        _make_lead(db, org_id, name="L1", status=LeadStatus.COMPLETED)
        _make_lead(db, org_id, name="L2", status=LeadStatus.COMPLETED)
        _make_lead(db, org_id, name="L3", status=LeadStatus.PENDING)
        _make_lead(db, org_id, name="L4", status=LeadStatus.DECLINED)

        result = get_crm_stats(db, org_id)
        # 2 out of 4 = 50%
        assert result["conversion_rate"] == 50.0

    def test_tenant_isolation(self, db: SASession, org_and_user):
        """Stats only count leads from the user's organization."""
        org, _ = org_and_user
        other, _ = _create_org_and_user(db, email=f"other-stats-{uuid.uuid4().hex[:8]}@test.com")
        _make_lead(db, org.id, name="My Lead")
        _make_lead(db, other.id, name="Other Lead")

        result = get_crm_stats(db, org.id)
        assert result["total_leads"] == 1
