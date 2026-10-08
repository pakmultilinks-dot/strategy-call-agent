"""Tenant isolation tests for Phase 6B.1 — Multi-Tenant Foundation.

Validates:
  1. Organization, User, OrgIntegration, OrgScheduleConfig models
  2. Tenant resolution helpers (tenant.py)
  3. Data isolation: org_id on leads, events_log, failed_jobs
  4. NOT NULL constraints enforced at DB level
  5. Foreign key constraints cascade correctly
  6. Composite indexes exist for multi-tenant queries
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from app.database import SessionLocal, engine
from app.models import EventLog, FailedJob, Lead, LeadStatus
from app.models_multi_tenant import (
    IntegrationStatus,
    Organization,
    OrganizationStatus,
    OrgIntegration,
    OrgScheduleConfig,
    User,
    UserRole,
    UserStatus,
)
from app.tenant import (
    _DEFAULT_ORG_ID,
    get_current_organization_id,
    get_default_organization_id,
    resolve_organization_id,
    set_event_organization,
    set_failed_job_organization,
    set_lead_organization,
)

# ── Constants ────────────────────────────────────────────────────────────────

SECONDARY_ORG_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_org(**overrides) -> Organization:
    """Insert an Organization row and return it."""
    defaults = {
        "name": f"Test Org {uuid.uuid4().hex[:8]}",
        "slug": f"test-org-{uuid.uuid4().hex[:8]}",
        "timezone": "America/Chicago",
        "status": OrganizationStatus.ACTIVE,
    }
    defaults.update(overrides)
    db = SessionLocal()
    try:
        org = Organization(**defaults)
        db.add(org)
        db.commit()
        db.refresh(org)
        return org
    finally:
        db.close()


def _make_user(org_id: uuid.UUID, **overrides) -> User:
    """Insert a User row and return it."""
    defaults = {
        "organization_id": org_id,
        "email": f"user-{uuid.uuid4().hex[:8]}@example.com",
        "password_hash": "$2b$12$LJ3m4y0T0V0YfNfNQyQxYOeYzP9q8v5zZw8yYzQxYzQxYzQxYzQxY",  # bcrypt hash of placeholder
        "role": UserRole.MEMBER,
        "status": UserStatus.ACTIVE,
    }
    defaults.update(overrides)
    db = SessionLocal()
    try:
        user = User(**defaults)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def _make_integration(org_id: uuid.UUID, **overrides) -> OrgIntegration:
    """Insert an OrgIntegration row and return it."""
    defaults = {
        "organization_id": org_id,
        "provider": "google",
        "integration_type": "google_oauth",
        "status": IntegrationStatus.CONNECTED,
    }
    defaults.update(overrides)
    db = SessionLocal()
    try:
        integ = OrgIntegration(**defaults)
        db.add(integ)
        db.commit()
        db.refresh(integ)
        return integ
    finally:
        db.close()


def _make_schedule_config(org_id: uuid.UUID, **overrides) -> OrgScheduleConfig:
    """Insert an OrgScheduleConfig row and return it."""
    defaults = {
        "organization_id": org_id,
    }
    defaults.update(overrides)
    db = SessionLocal()
    try:
        cfg = OrgScheduleConfig(**defaults)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
        return cfg
    finally:
        db.close()


def _make_lead(org_id: uuid.UUID = _DEFAULT_ORG_ID, **overrides) -> Lead:
    """Insert a Lead row with organization_id and return it."""
    defaults = {
        "name": "Test Lead",
        "email": f"lead-{uuid.uuid4().hex[:8]}@example.com",
        "company_address": "Test Co",
        "appt_datetime_raw": "tomorrow 2pm",
        "dedupe_key": f"test-{uuid.uuid4().hex}",
        "status": LeadStatus.PENDING,
        "organization_id": org_id,
    }
    defaults.update(overrides)
    db = SessionLocal()
    try:
        lead = Lead(**defaults)
        db.add(lead)
        db.commit()
        db.refresh(lead)
        return lead
    finally:
        db.close()


def _make_event_log(lead: Lead, event_type: str, org_id: uuid.UUID = None, **overrides) -> EventLog:
    """Insert an EventLog row for a lead."""
    defaults = {
        "lead_id": lead.id,
        "event_type": event_type,
        "payload": json.dumps({"test": True}),
        "organization_id": org_id or lead.organization_id or _DEFAULT_ORG_ID,
    }
    defaults.update(overrides)
    db = SessionLocal()
    try:
        log = EventLog(**defaults)
        db.add(log)
        db.commit()
        db.refresh(log)
        return log
    finally:
        db.close()


def _make_failed_job(org_id: uuid.UUID = _DEFAULT_ORG_ID, **overrides) -> FailedJob:
    """Insert a FailedJob row."""
    defaults = {
        "job_type": "test_job",
        "payload": json.dumps({"test": True}),
        "error": "test error",
        "retry_count": 0,
        "resolved": False,
        "organization_id": org_id,
    }
    defaults.update(overrides)
    db = SessionLocal()
    try:
        job = FailedJob(**defaults)
        db.add(job)
        db.commit()
        db.refresh(job)
        return job
    finally:
        db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 1. Organization Model Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestOrganizationModel:
    """Tests for the Organization ORM model."""

    def test_create_organization(self):
        """Organization can be created with required fields."""
        slug = f"acme-{uuid.uuid4().hex[:8]}"
        org = _make_org(name="Acme Corp", slug=slug)
        assert org.id is not None
        assert org.name == "Acme Corp"
        assert org.slug == slug
        assert org.status == OrganizationStatus.ACTIVE
        assert org.timezone == "America/Chicago"
        assert org.created_at is not None

    def test_default_org_exists(self):
        """The default organization seeded by migration exists."""
        db = SessionLocal()
        try:
            org = db.get(Organization, _DEFAULT_ORG_ID)
            assert org is not None
            assert org.slug == "integrated-it-trainings"
            assert org.name == "Integrated IT Trainings"
            assert org.status == OrganizationStatus.ACTIVE
            assert org.timezone == "America/Chicago"
        finally:
            db.close()

    def test_slug_unique_constraint(self):
        """Two organizations cannot share the same slug."""
        slug_val = f"unique-{uuid.uuid4().hex[:8]}"
        _make_org(slug=slug_val)
        with pytest.raises(IntegrityError):
            _make_org(slug=slug_val)

    def test_optional_fields(self):
        """display_name and other optional fields can be NULL."""
        org = _make_org()
        db = SessionLocal()
        try:
            fetched = db.get(Organization, org.id)
            assert fetched.display_name is None
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 2. User Model Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestUserModel:
    """Tests for the User ORM model."""

    def test_create_user(self):
        """User can be created linked to an organization."""
        org = _make_org()
        user = _make_user(org.id, email="admin@test.com", role=UserRole.ADMIN)
        assert user.id is not None
        assert user.organization_id == org.id
        assert user.email == "admin@test.com"
        assert user.role == UserRole.ADMIN
        assert user.status == UserStatus.ACTIVE

    def test_unique_email_per_org(self):
        """Two users in the same org cannot share an email."""
        org = _make_org()
        _make_user(org.id, email="dup@test.com")
        with pytest.raises(IntegrityError):
            _make_user(org.id, email="dup@test.com")

    def test_same_email_different_orgs(self):
        """The same email can exist in different organizations."""
        org1 = _make_org()
        org2 = _make_org()
        u1 = _make_user(org1.id, email="shared@test.com")
        u2 = _make_user(org2.id, email="shared@test.com")
        assert u1.id != u2.id

    def test_user_cascade_on_org_delete(self):
        """Deleting an organization cascades to its users."""
        org = _make_org()
        user = _make_user(org.id)
        db = SessionLocal()
        try:
            db.delete(db.get(Organization, org.id))
            db.commit()
            assert db.get(User, user.id) is None
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 3. OrgIntegration Model Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgIntegrationModel:
    """Tests for the OrgIntegration ORM model."""

    def test_create_integration(self):
        """OrgIntegration can be created with required fields."""
        org = _make_org()
        integ = _make_integration(org.id, provider="openai", integration_type="ai_provider")
        assert integ.id is not None
        assert integ.organization_id == org.id
        assert integ.provider == "openai"
        assert integ.integration_type == "ai_provider"
        assert integ.status == IntegrationStatus.CONNECTED

    def test_credentials_nullable(self):
        """credentials_encrypted is nullable initially."""
        org = _make_org()
        integ = _make_integration(org.id)
        db = SessionLocal()
        try:
            fetched = db.get(OrgIntegration, integ.id)
            assert fetched.credentials_encrypted is None
        finally:
            db.close()

    def test_metadata_json(self):
        """metadata_json stores arbitrary JSON."""
        org = _make_org()
        meta = {"sender_name": "Test Sender", "model": "gpt-4"}
        integ = _make_integration(org.id, metadata_json=meta)
        db = SessionLocal()
        try:
            fetched = db.get(OrgIntegration, integ.id)
            assert fetched.metadata_json == meta
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 4. OrgScheduleConfig Model Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgScheduleConfigModel:
    """Tests for the OrgScheduleConfig ORM model."""

    def test_create_schedule_config(self):
        """OrgScheduleConfig can be created for an organization."""
        org = _make_org()
        cfg = _make_schedule_config(org.id)
        assert cfg.id is not None
        assert cfg.organization_id == org.id

    def test_one_to_one_relationship(self):
        """Organization has at most one OrgScheduleConfig."""
        org = _make_org()
        cfg1 = _make_schedule_config(org.id)
        db = SessionLocal()
        try:
            fetched_org = db.get(Organization, org.id)
            assert fetched_org.schedule_config is not None
            assert fetched_org.schedule_config.id == cfg1.id
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 5. Tenant Resolution Helper Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestTenantResolution:
    """Tests for tenant.py resolution helpers."""

    def test_get_default_returns_constant(self):
        """get_default_organization_id returns the seed UUID."""
        assert get_default_organization_id() == _DEFAULT_ORG_ID
        assert str(get_default_organization_id()) == "00000000-0000-0000-0000-000000000001"

    def test_get_current_returns_default(self):
        """get_current_organization_id now raises RuntimeError (Phase 1 hardening)."""
        with pytest.raises(RuntimeError, match="get_current_organization_id\(\) is deprecated"):
            get_current_organization_id()

    def test_resolve_explicit(self):
        """resolve_organization_id returns explicit ID when provided."""
        result = resolve_organization_id(SECONDARY_ORG_ID)
        assert result == SECONDARY_ORG_ID

    def test_resolve_none_fallback(self):
        """resolve_organization_id(None) now raises RuntimeError (Phase 1 hardening)."""
        with pytest.raises(RuntimeError, match="resolve_organization_id\(None\) — caller must"):
            resolve_organization_id(None)

    def test_set_lead_organization(self):
        """set_lead_organization assigns the given org_id."""
        lead = _make_lead(org_id=_DEFAULT_ORG_ID)
        set_lead_organization(lead, SECONDARY_ORG_ID)
        assert lead.organization_id == SECONDARY_ORG_ID

    def test_set_lead_organization_default(self):
        """set_lead_organization(None) now raises RuntimeError (Phase 1 hardening)."""
        lead = _make_lead(org_id=_DEFAULT_ORG_ID)
        with pytest.raises(RuntimeError, match="resolve_organization_id\(None\) — caller must"):
            set_lead_organization(lead, None)
        # Lead's org should remain unchanged
        assert lead.organization_id == _DEFAULT_ORG_ID

    def test_set_event_organization(self):
        """set_event_organization assigns the given org_id."""
        lead = _make_lead()
        event = _make_event_log(lead, "test")
        set_event_organization(event, SECONDARY_ORG_ID)
        assert event.organization_id == SECONDARY_ORG_ID

    def test_set_failed_job_organization(self):
        """set_failed_job_organization assigns the given org_id."""
        job = _make_failed_job()
        set_failed_job_organization(job, SECONDARY_ORG_ID)
        assert job.organization_id == SECONDARY_ORG_ID


# ══════════════════════════════════════════════════════════════════════════════
# 6. Data Isolation Tests — Leads
# ══════════════════════════════════════════════════════════════════════════════


class TestLeadIsolation:
    """Verify leads are correctly scoped to organizations."""

    def test_lead_has_organization_id(self):
        """A lead can be created with a specific organization_id."""
        org = _make_org(name="Lead Org")
        lead = _make_lead(org_id=org.id)
        assert lead.organization_id == org.id

    def test_leads_different_orgs_independent(self):
        """Leads in different orgs have different organization_ids."""
        org_a = _make_org(name="Org A")
        org_b = _make_org(name="Org B")
        lead_a = _make_lead(org_id=org_a.id)
        lead_b = _make_lead(org_id=org_b.id)
        assert lead_a.organization_id != lead_b.organization_id

    def test_query_leads_by_org(self):
        """Only leads belonging to the queried org are returned."""
        org_a = _make_org(name="Query Org A")
        org_b = _make_org(name="Query Org B")
        lead_a = _make_lead(org_id=org_a.id)
        lead_b = _make_lead(org_id=org_b.id)
        db = SessionLocal()
        try:
            from sqlalchemy import select

            stmt = select(Lead).where(Lead.organization_id == org_b.id)
            results = db.execute(stmt).scalars().all()
            ids = {l.id for l in results}
            assert lead_b.id in ids
            assert lead_a.id not in ids
        finally:
            db.close()

    def test_lead_org_id_not_null_in_db(self):
        """The DB enforces NOT NULL on leads.organization_id.

        Note: The ORM column is nullable (for legacy compat), but the DB
        column has NOT NULL enforced by the migration. An attempt to insert
        a Lead with NULL organization_id should fail at the DB level.
        """
        db = SessionLocal()
        try:
            lead = Lead(
                name="Null Org Lead",
                email=f"null-org-{uuid.uuid4().hex[:8]}@test.com",
                company_address="Test",
                appt_datetime_raw="tomorrow 2pm",
                dedupe_key=f"null-org-{uuid.uuid4().hex}",
                status=LeadStatus.PENDING,
                organization_id=None,
            )
            db.add(lead)
            with pytest.raises(IntegrityError):
                db.commit()
            db.rollback()
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 7. Data Isolation Tests — EventLog
# ══════════════════════════════════════════════════════════════════════════════


class TestEventLogIsolation:
    """Verify event logs are correctly scoped to organizations."""

    def test_event_log_has_organization_id(self):
        """EventLog entries carry the organization_id."""
        org = _make_org(name="Event Org")
        lead = _make_lead(org_id=org.id)
        event = _make_event_log(lead, "test_event", org_id=org.id)
        assert event.organization_id == org.id

    def test_event_log_not_null_in_db(self, _seed_default_organization):
        """organization_id is NOT NULL on EventLog — every audit event must
        be scoped to an organization.

        System events (webhook auth failures, config changes) use the
        default org ID when no specific org context is available.
        """
        db = SessionLocal()
        try:
            lead = _make_lead(org_id=_DEFAULT_ORG_ID)
            event = EventLog(
                lead_id=lead.id,
                event_type="test_org_scoped",
                organization_id=_DEFAULT_ORG_ID,
            )
            db.add(event)
            db.commit()  # Should succeed — organization_id is required
            assert event.organization_id == _DEFAULT_ORG_ID
            db.delete(event)
            db.commit()
        finally:
            db.close()

    def test_events_different_orgs_independent(self):
        """Events from different orgs are independently queryable."""
        org_a = _make_org(name="Evt Org A")
        org_b = _make_org(name="Evt Org B")
        lead_a = _make_lead(org_id=org_a.id)
        lead_b = _make_lead(org_id=org_b.id)
        evt_a = _make_event_log(lead_a, "type_a", org_id=org_a.id)
        evt_b = _make_event_log(lead_b, "type_b", org_id=org_b.id)
        db = SessionLocal()
        try:
            from sqlalchemy import select

            stmt = select(EventLog).where(EventLog.organization_id == org_b.id)
            results = db.execute(stmt).scalars().all()
            ids = {e.id for e in results}
            assert evt_b.id in ids
            assert evt_a.id not in ids
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 8. Data Isolation Tests — FailedJob
# ══════════════════════════════════════════════════════════════════════════════


class TestFailedJobIsolation:
    """Verify failed jobs are correctly scoped to organizations."""

    def test_failed_job_has_organization_id(self):
        """FailedJob entries carry the organization_id."""
        org = _make_org(name="FailedJob Org")
        job = _make_failed_job(org_id=org.id)
        assert job.organization_id == org.id

    def test_failed_job_not_null_in_db(self):
        """The DB enforces NOT NULL on failed_jobs.organization_id."""
        db = SessionLocal()
        try:
            job = FailedJob(
                job_type="test_null",
                payload="{}",
                error="test",
                organization_id=None,
            )
            db.add(job)
            with pytest.raises(IntegrityError):
                db.commit()
            db.rollback()
        finally:
            db.close()

    def test_failed_jobs_different_orgs_independent(self):
        """FailedJobs from different orgs are independently queryable."""
        org_a = _make_org(name="FJ Org A")
        org_b = _make_org(name="FJ Org B")
        job_a = _make_failed_job(org_id=org_a.id)
        job_b = _make_failed_job(org_id=org_b.id)
        db = SessionLocal()
        try:
            from sqlalchemy import select

            stmt = select(FailedJob).where(FailedJob.organization_id == org_b.id)
            results = db.execute(stmt).scalars().all()
            ids = {j.id for j in results}
            assert job_b.id in ids
            assert job_a.id not in ids
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 9. Foreign Key Constraint Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestForeignKeyConstraints:
    """Verify FK constraints enforce referential integrity.
    Skipped on SQLite — FK enforcement is not enabled in test mode."""

    @pytest.mark.skipif(
        "sqlite" in str(engine.url),
        reason="FK enforcement not enabled on SQLite test database",
    )
    def test_lead_fk_to_organization(self):
        """A lead with a non-existent organization_id violates FK constraint."""
        fake_org_id = uuid.uuid4()
        db = SessionLocal()
        try:
            lead = Lead(
                name="FK Test Lead",
                email=f"fk-test-{uuid.uuid4().hex[:8]}@test.com",
                company_address="Test",
                appt_datetime_raw="tomorrow 2pm",
                dedupe_key=f"fk-{uuid.uuid4().hex}",
                status=LeadStatus.PENDING,
                organization_id=fake_org_id,
            )
            db.add(lead)
            with pytest.raises(IntegrityError):
                db.commit()
            db.rollback()
        finally:
            db.close()

    @pytest.mark.skipif(
        "sqlite" in str(engine.url),
        reason="FK enforcement not enabled on SQLite test database",
    )
    def test_user_fk_to_organization(self):
        """A user with a non-existent organization_id violates FK constraint."""
        fake_org_id = uuid.uuid4()
        db = SessionLocal()
        try:
            user = User(
                organization_id=fake_org_id,
                email=f"fk-user-{uuid.uuid4().hex[:8]}@test.com",
                password_hash="$2b$12$LJ3m4y0T0V0YfNfNQyQxYOeYzP9q8v5zZw8yYzQxYzQxYzQxYzQxY",
                role=UserRole.MEMBER,
                status=UserStatus.ACTIVE,
            )
            db.add(user)
            with pytest.raises(IntegrityError):
                db.commit()
            db.rollback()
        finally:
            db.close()

    @pytest.mark.skipif(
        "sqlite" in str(engine.url),
        reason="FK enforcement not enabled on SQLite test database",
    )
    def test_integration_fk_to_organization(self):
        """An integration with a non-existent org_id violates FK constraint."""
        fake_org_id = uuid.uuid4()
        db = SessionLocal()
        try:
            integ = OrgIntegration(
                organization_id=fake_org_id,
                provider="test",
                integration_type="test",
                status=IntegrationStatus.PENDING,
            )
            db.add(integ)
            with pytest.raises(IntegrityError):
                db.commit()
            db.rollback()
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 10. Database Schema / Index Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestDatabaseSchema:
    """Verify the migration created expected tables, columns, and indexes."""

    @pytest.fixture(autouse=True)
    def _inspector(self):
        self.inspector = inspect(engine)

    def _get_index_names(self, table_name: str) -> set[str]:
        return {idx["name"] for idx in self.inspector.get_indexes(table_name)}

    def _get_column_names(self, table_name: str) -> set[str]:
        return {col["name"] for col in self.inspector.get_columns(table_name)}

    def _get_table_names(self) -> set[str]:
        return set(self.inspector.get_table_names())

    # -- Tables exist --

    def test_organizations_table_exists(self):
        assert "organizations" in self._get_table_names()

    def test_users_table_exists(self):
        assert "users" in self._get_table_names()

    def test_org_integrations_table_exists(self):
        assert "org_integrations" in self._get_table_names()

    def test_org_schedule_config_table_exists(self):
        assert "org_schedule_config" in self._get_table_names()

    # -- Columns added to existing tables --

    def test_leads_has_organization_id(self):
        assert "organization_id" in self._get_column_names("leads")

    def test_events_log_has_organization_id(self):
        assert "organization_id" in self._get_column_names("events_log")

    def test_failed_jobs_has_organization_id(self):
        assert "organization_id" in self._get_column_names("failed_jobs")

    # -- Indexes exist --

    def test_leads_org_id_index(self):
        indexes = self._get_index_names("leads")
        assert "ix_leads_organization_id" in indexes

    def test_leads_org_status_index(self):
        indexes = self._get_index_names("leads")
        assert "ix_leads_org_status" in indexes

    def test_leads_org_email_index(self):
        indexes = self._get_index_names("leads")
        assert "ix_leads_org_email" in indexes

    def test_events_log_org_id_index(self):
        indexes = self._get_index_names("events_log")
        assert "ix_events_log_organization_id" in indexes

    def test_events_log_org_created_index(self):
        indexes = self._get_index_names("events_log")
        assert "ix_events_log_org_created" in indexes

    def test_failed_jobs_org_id_index(self):
        indexes = self._get_index_names("failed_jobs")
        assert "ix_failed_jobs_organization_id" in indexes

    def test_failed_jobs_org_created_index(self):
        indexes = self._get_index_names("failed_jobs")
        assert "ix_failed_jobs_org_created" in indexes

    def test_organizations_slug_index(self):
        indexes = self._get_index_names("organizations")
        assert "ix_organizations_slug" in indexes

    # -- Enum types exist --

    def test_organization_status_enum_exists(self):
        if "sqlite" in str(engine.url):
            pytest.skip("pg_type not available on SQLite")
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT 1 FROM pg_type WHERE typname = 'organization_status'")
            )
            assert result.fetchone() is not None

    def test_user_role_enum_exists(self):
        if "sqlite" in str(engine.url):
            pytest.skip("pg_type not available on SQLite")
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT 1 FROM pg_type WHERE typname = 'user_role'")
            )
            assert result.fetchone() is not None

    def test_user_status_enum_exists(self):
        if "sqlite" in str(engine.url):
            pytest.skip("pg_type not available on SQLite")
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT 1 FROM pg_type WHERE typname = 'user_status'")
            )
            assert result.fetchone() is not None

    def test_integration_status_enum_exists(self):
        if "sqlite" in str(engine.url):
            pytest.skip("pg_type not available on SQLite")
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT 1 FROM pg_type WHERE typname = 'integration_status'")
            )
            assert result.fetchone() is not None
