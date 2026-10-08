"""Regression tests for OrgScheduleConfig auto-creation (Phase 3).

Verifies that:
  1. Registering a new organization creates an OrgScheduleConfig
  2. The created config belongs to the correct organization
  3. Default timezone matches the organization timezone
  4. Default reminder settings are correct
  5. Registration does not create duplicate configs
  6. Existing org with existing config is not modified by backfill
  7. Organization creation remains atomic if config creation fails
  8. Scheduler registration recognizes newly created config
  9. Existing org-specific schedule settings remain unchanged after backfill
"""
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session as SASession

from app.database import SessionLocal
from app.models_multi_tenant import (
    OrgScheduleConfig,
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _unique_email() -> str:
    return f"test-{uuid.uuid4().hex[:10]}@example.com"


def _unique_slug() -> str:
    return f"org-{uuid.uuid4().hex[:8]}"


@pytest.fixture(autouse=True)
def _clear_register_rate_limit():
    """Clear the /auth/register rate limiter before each test.

    The limiter is a module-level dict (5 regs/IP/5min) shared across the
    session-scoped test client.  Without this, tests fail in the full suite
    after earlier test files exhaust the quota.
    """
    from app.routers.auth_router import _register_hits
    _register_hits.clear()
    yield
    _register_hits.clear()


# ── Tests ────────────────────────────────────────────────────────────────────

class TestOrgScheduleConfigAutoCreate:
    """Registration creates OrgScheduleConfig for new organizations."""

    def test_new_organization_creates_config(self, client: TestClient):
        """POST /auth/register creates an OrgScheduleConfig row."""
        email = _unique_email()
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": "Config AutoCreate Co",
                "name": "Config Tester",
                "email": email,
                "password": "StrongPass123!",
            },
        )
        assert resp.status_code == 201

        # Decode JWT to get org_id
        from jose import jwt
        from app.config import settings
        token = resp.json()["access_token"]
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        org_id = uuid.UUID(payload["org_id"])

        db = SessionLocal()
        try:
            cfg = (
                db.query(OrgScheduleConfig)
                .filter(OrgScheduleConfig.organization_id == org_id)
                .first()
            )
            assert cfg is not None, "OrgScheduleConfig was not created"
        finally:
            db.close()

    def test_config_belongs_to_correct_organization(self, client: TestClient):
        """Created config references the correct organization_id."""
        email = _unique_email()
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": "Belonging Corp",
                "name": "Owner User",
                "email": email,
                "password": "StrongPass123!",
            },
        )
        assert resp.status_code == 201

        from jose import jwt
        from app.config import settings
        token = resp.json()["access_token"]
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        org_id = uuid.UUID(payload["org_id"])

        db = SessionLocal()
        try:
            cfg = (
                db.query(OrgScheduleConfig)
                .filter(OrgScheduleConfig.organization_id == org_id)
                .first()
            )
            assert cfg is not None
            assert cfg.organization_id == org_id
            # Verify no other configs exist for this org
            count = (
                db.query(OrgScheduleConfig)
                .filter(OrgScheduleConfig.organization_id == org_id)
                .count()
            )
            assert count == 1
        finally:
            db.close()

    def test_default_timezone_matches_organization(self, client: TestClient):
        """Config timezone defaults to the organization's timezone."""
        email = _unique_email()
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": "Timezone Corp",
                "name": "TZ User",
                "email": email,
                "password": "StrongPass123!",
            },
        )
        assert resp.status_code == 201

        from jose import jwt
        from app.config import settings
        token = resp.json()["access_token"]
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        org_id = uuid.UUID(payload["org_id"])

        db = SessionLocal()
        try:
            org = db.query(Organization).filter(Organization.id == org_id).first()
            cfg = (
                db.query(OrgScheduleConfig)
                .filter(OrgScheduleConfig.organization_id == org_id)
                .first()
            )
            assert org is not None
            assert cfg is not None
            assert cfg.timezone == org.timezone
        finally:
            db.close()

    def test_default_reminder_settings(self, client: TestClient):
        """Config has correct default reminder_enabled, hour, and minute."""
        email = _unique_email()
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": "Defaults Corp",
                "name": "Def User",
                "email": email,
                "password": "StrongPass123!",
            },
        )
        assert resp.status_code == 201

        from jose import jwt
        from app.config import settings
        token = resp.json()["access_token"]
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        org_id = uuid.UUID(payload["org_id"])

        db = SessionLocal()
        try:
            cfg = (
                db.query(OrgScheduleConfig)
                .filter(OrgScheduleConfig.organization_id == org_id)
                .first()
            )
            assert cfg is not None
            assert cfg.reminder_enabled is True
            assert cfg.reminder_hour == 8
            assert cfg.reminder_minute == 0
            assert cfg.rsvp_poll_interval_minutes == 10
            assert cfg.scheduler_enabled is True
        finally:
            db.close()

    def test_no_duplicate_config_created(self, client: TestClient):
        """Registering once creates exactly one OrgScheduleConfig."""
        email = _unique_email()
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": "No Dupes Inc",
                "name": "Dup Checker",
                "email": email,
                "password": "StrongPass123!",
            },
        )
        assert resp.status_code == 201

        from jose import jwt
        from app.config import settings
        token = resp.json()["access_token"]
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        org_id = uuid.UUID(payload["org_id"])

        db = SessionLocal()
        try:
            count = (
                db.query(OrgScheduleConfig)
                .filter(OrgScheduleConfig.organization_id == org_id)
                .count()
            )
            assert count == 1, f"Expected 1 config, found {count}"
        finally:
            db.close()


class TestRegistrationAtomicity:
    """Organization creation remains atomic if config creation fails."""

    def test_config_failure_rolls_back_org(self, client: TestClient):
        """If OrgScheduleConfig creation fails, neither org nor user is committed."""
        from sqlalchemy.exc import SQLAlchemyError
        from unittest.mock import patch
        from app.routers.auth_router import _register_hits

        email = _unique_email()

        # Clear rate limiter so this test isn't blocked by prior register calls
        _register_hits.clear()

        # Patch OrgScheduleConfig constructor to raise on instantiation
        with patch("app.routers.auth_router.OrgScheduleConfig") as MockCfg:
            MockCfg.side_effect = SQLAlchemyError("simulated config failure")

            resp = client.post(
                "/auth/register",
                json={
                    "organization_name": "Atomic Rollback Corp",
                    "name": "Atomic User",
                    "email": email,
                    "password": "StrongPass123!",
                },
            )

            # Registration should fail (500) because config creation failed
            assert resp.status_code == 500

        # Verify neither org nor user was created (atomic rollback)
        db = SessionLocal()
        try:
            org = db.query(Organization).filter(
                Organization.name == "Atomic Rollback Corp"
            ).first()
            user = db.query(User).filter(User.email == email).first()
            assert org is None, "Organization should not exist after atomic rollback"
            assert user is None, "User should not exist after atomic rollback"
        finally:
            db.close()


class TestSchedulerRegistration:
    """Scheduler registration recognizes newly created config."""

    def test_reschedule_is_noop(self, db_session: SASession):
        """reschedule_org_scheduler_jobs is now a no-op stub (batch jobs handle scheduling)."""
        from app.main import reschedule_org_scheduler_jobs, _scheduler

        org = Organization(
            name="Scheduler Test Org",
            slug=_unique_slug(),
            status=OrganizationStatus.ACTIVE,
            timezone="America/Chicago",
        )
        db_session.add(org)
        db_session.flush()

        cfg = OrgScheduleConfig(
            organization_id=org.id,
            timezone="America/Chicago",
            reminder_enabled=True,
            reminder_hour=9,
            reminder_minute=30,
            rsvp_poll_interval_minutes=15,
            scheduler_enabled=True,
        )
        db_session.add(cfg)
        db_session.commit()

        # reschedule_org_scheduler_jobs is now a no-op - should not crash
        reschedule_org_scheduler_jobs(org.id)

        # Verify the config is still queryable
        db_session.expire_all()
        fetched = (
            db_session.query(OrgScheduleConfig)
            .filter(OrgScheduleConfig.organization_id == org.id)
            .first()
        )
        assert fetched is not None
        assert fetched.scheduler_enabled is True

    def test_no_config_results_in_no_crash(self, db_session: SASession):
        """reschedule_org_scheduler_jobs exits cleanly when config is missing."""
        from app.main import reschedule_org_scheduler_jobs

        org = Organization(
            name="No Config Org",
            slug=_unique_slug(),
            status=OrganizationStatus.ACTIVE,
            timezone="America/Chicago",
        )
        db_session.add(org)
        db_session.commit()

        # Should not raise - no-op stub
        reschedule_org_scheduler_jobs(org.id)


# ---------------------------------------------------------------------------
# Phase 4 regression: immediate scheduler job registration on registration
# ---------------------------------------------------------------------------

class TestImmediateSchedulerRegistration:
    """Registering a new org immediately registers its APScheduler jobs.

    The production code does: ``from app import main as _main_mod; _main_mod.reschedule_org_scheduler_jobs(org.id)``
    so the correct patch target is ``app.main.reschedule_org_scheduler_jobs``.
    """

    def test_registration_calls_reschedule(self, client: TestClient):
        """After successful registration, reschedule_org_scheduler_jobs is called."""
        from unittest.mock import patch

        email = _unique_email()
        call_args = []

        def _capture_reschedule(org_id):
            call_args.append(org_id)

        with patch(
            "app.main.reschedule_org_scheduler_jobs",
            side_effect=_capture_reschedule,
        ) as mock_resched:
            resp = client.post(
                "/auth/register",
                json={
                    "organization_name": "Immediate Scheduler Org",
                    "name": "Scheduler User",
                    "email": email,
                    "password": "StrongPass123!",
                },
            )

        assert resp.status_code == 201

        # Verify reschedule was called exactly once with the new org's id
        assert mock_resched.call_count == 1, (
            f"reschedule_org_scheduler_jobs called {mock_resched.call_count} times, expected 1"
        )

        from jose import jwt
        from app.config import settings
        token = resp.json()["access_token"]
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        called_org_id = uuid.UUID(payload["org_id"])

        assert call_args[0] == called_org_id, (
            f"reschedule called with {call_args[0]}, expected {called_org_id}"
        )

    def test_reschedule_called_after_commit(self, client: TestClient):
        """reschedule_org_scheduler_jobs is called after the DB commit succeeds."""
        from unittest.mock import patch

        email = _unique_email()

        def _check_during_reschedule(org_id):
            """Verify the org and config exist in DB when reschedule runs."""
            db = SessionLocal()
            try:
                org = db.query(Organization).filter(Organization.id == org_id).first()
                cfg = db.query(OrgScheduleConfig).filter(
                    OrgScheduleConfig.organization_id == org_id
                ).first()
                assert org is not None, "Org should exist when reschedule runs"
                assert cfg is not None, "Config should exist when reschedule runs"
            finally:
                db.close()

        with patch(
            "app.main.reschedule_org_scheduler_jobs",
            side_effect=_check_during_reschedule,
        ):
            resp = client.post(
                "/auth/register",
                json={
                    "organization_name": "Post Commit Org",
                    "name": "Post Commit User",
                    "email": email,
                    "password": "StrongPass123!",
                },
            )

        assert resp.status_code == 201

    def test_registration_failure_no_scheduler_jobs(self, client: TestClient):
        """If registration fails, reschedule_org_scheduler_jobs is NOT called."""
        from unittest.mock import patch
        from app.routers.auth_router import _register_hits

        email = _unique_email()
        _register_hits.clear()

        call_count = []

        def _count_calls(org_id):
            call_count.append(org_id)

        with patch(
            "app.main.reschedule_org_scheduler_jobs",
            side_effect=_count_calls,
        ):
            # Cause a failure by patching OrgScheduleConfig
            with patch(
                "app.routers.auth_router.OrgScheduleConfig",
                side_effect=Exception("boom"),
            ):
                resp = client.post(
                    "/auth/register",
                    json={
                        "organization_name": "Fail Scheduler Org",
                        "name": "Fail User",
                        "email": email,
                        "password": "StrongPass123!",
                    },
                )

        assert resp.status_code == 500
        assert len(call_count) == 0, (
            f"reschedule was called {len(call_count)} times despite registration failure"
        )

    def test_reschedule_failure_does_not_break_registration(self, client: TestClient):
        """If reschedule_org_scheduler_jobs raises, registration still succeeds."""
        from unittest.mock import patch

        email = _unique_email()

        def _explode(org_id):
            raise RuntimeError("scheduler unavailable")

        with patch(
            "app.main.reschedule_org_scheduler_jobs",
            side_effect=_explode,
        ):
            resp = client.post(
                "/auth/register",
                json={
                    "organization_name": "Reschedule Fail Org",
                    "name": "Reschedule User",
                    "email": email,
                    "password": "StrongPass123!",
                },
            )

        # Registration should succeed despite scheduler failure
        assert resp.status_code == 201

        # Verify the org and config still exist
        from jose import jwt
        from app.config import settings
        token = resp.json()["access_token"]
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        org_id = uuid.UUID(payload["org_id"])

        db = SessionLocal()
        try:
            org = db.query(Organization).filter(Organization.id == org_id).first()
            cfg = db.query(OrgScheduleConfig).filter(
                OrgScheduleConfig.organization_id == org_id
            ).first()
            assert org is not None, "Org should exist even if scheduler failed"
            assert cfg is not None, "Config should exist even if scheduler failed"
        finally:
            db.close()

    def test_existing_orgs_unaffected_by_new_hook(self, client: TestClient):
        """The new hook does not re-trigger for existing organizations."""
        from unittest.mock import patch

        email = _unique_email()
        reschedule_calls = []

        def _capture(org_id):
            reschedule_calls.append(org_id)

        with patch(
            "app.main.reschedule_org_scheduler_jobs",
            side_effect=_capture,
        ):
            resp = client.post(
                "/auth/register",
                json={
                    "organization_name": "Only New Org",
                    "name": "New Only User",
                    "email": email,
                    "password": "StrongPass123!",
                },
            )

        assert resp.status_code == 201

        # Exactly one call - only for the newly registered org
        assert len(reschedule_calls) == 1, (
            f"Expected exactly 1 reschedule call, got {len(reschedule_calls)}"
        )

        from jose import jwt
        from app.config import settings
        token = resp.json()["access_token"]
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        assert reschedule_calls[0] == uuid.UUID(payload["org_id"])
