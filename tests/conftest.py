"""Shared test fixtures for the strategy-call-agent test suite."""
import base64

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session as SASession

from sqlalchemy import select as sa_select

from app.config import settings
from app.database import SessionLocal, engine
from app.main import app
from app.models import Base, EventLog, FailedJob, FollowUp, Lead
from app.models_multi_tenant import Organization, OrganizationStatus
from app.tenant import _DEFAULT_ORG_ID


# ---------------------------------------------------------------------------
# Default Organization seed
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _seed_default_organization():
    """Ensure the default organization row exists before any test runs.

    The application's tenant module resolves all requests to
    ``_DEFAULT_ORG_ID`` (00000000-0000-0000-0000-000000000001) until
    authentication is implemented.  Without this row every INSERT that
    includes an ``organization_id`` FK would fail with an IntegrityError.

    Phase 23: Cleans up stale leads from prior test runs so they
    don't interfere with assertions.
    """
    Base.metadata.create_all(bind=engine)
    session: SASession = SessionLocal()
    try:
        existing = session.query(Organization).filter_by(id=_DEFAULT_ORG_ID).first()
        if existing is None:
            default_org = Organization(
                id=_DEFAULT_ORG_ID,
                name="Integrated IT Trainings",
                slug="integrated-it-trainings",
                display_name="Integrated IT Trainings",
                status=OrganizationStatus.ACTIVE,
                timezone="America/Chicago",
            )
            session.add(default_org)
            session.commit()
        else:
            changed = False
            if existing.slug != "integrated-it-trainings":
                existing.slug = "integrated-it-trainings"
                existing.name = "Integrated IT Trainings"
                changed = True
            if changed:
                session.commit()
        # Clean up stale leads from prior test runs that would
        # cause cross-run assertion failures. Must delete
        # follow_ups and event_log entries first due to FK constraints.
        from sqlalchemy import select
        stale_leads_stmt = select(Lead.id).filter(
            Lead.organization_id == _DEFAULT_ORG_ID,
        )
        session.query(FollowUp).filter(
            FollowUp.lead_id.in_(stale_leads_stmt),
        ).delete(synchronize_session="fetch")
        session.query(EventLog).filter(
            EventLog.lead_id.in_(stale_leads_stmt),
        ).delete(synchronize_session="fetch")
        stale_count = session.query(Lead).filter(
            Lead.organization_id == _DEFAULT_ORG_ID,
        ).delete()
        # Clean up stale FailedJob records from prior test runs so they
        # don't cause cross-run assertion failures (e.g. calendar tests
        # that query by job_type without event_id filtering).
        stale_fj = session.query(FailedJob).filter(
            FailedJob.organization_id == _DEFAULT_ORG_ID,
        ).delete()
        if stale_count or stale_fj:
            session.commit()
    finally:
        session.close()

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

_AUTH_HEADER = {
    "Authorization": "Basic "
    + base64.b64encode(
        f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
    ).decode()
}


@pytest.fixture(autouse=True)
def _enable_dev_webhook_mode():
    """Disable webhook secret enforcement in tests (dev mode).

    The org-scoped webhook endpoint requires Bearer auth when either the
    org or global ``WEBHOOK_SECRET`` is set.  In tests we create orgs
    without a webhook_secret; patching the global to "" activates the
    endpoint's "dev mode" (no auth required).  Tests that specifically
    test webhook auth override this with their own ``patch.object``.
    """
    from unittest.mock import patch
    with patch.object(settings, "webhook_secret", ""):
        yield


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Reset the in-memory rate limiter between tests to avoid cross-test
    interference. The RateLimitMiddleware stores hits per IP in a dict —
    without resetting, the shared test client IP (127.0.0.1) accumulates
    hits across the entire session."""
    from app.middleware import RateLimitMiddleware
    # The middleware instance is wrapped in Starlette's middleware stack.
    # Clear the class-level hit tracking to reset between tests.
    if hasattr(RateLimitMiddleware, "_global_hits"):
        RateLimitMiddleware._global_hits.clear()
    # Phase 10B: Also reset login brute-force rate limiter
    from app.routers.auth_router import _login_failures
    _login_failures.clear()
    yield


@pytest.fixture()
def auth_headers():
    """Return valid HTTP Basic auth headers for dashboard endpoints."""
    return _AUTH_HEADER.copy()


@pytest.fixture()
def bad_auth_headers():
    """Return invalid auth headers (401 expected)."""
    return {
        "Authorization": "Basic "
        + base64.b64encode(b"wrong_user:wrong_pass").decode()
    }


@pytest.fixture(scope="session")
def client():
    """Create a TestClient that shares the lifespan (creates tables, seeds config)."""
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db_session():
    """Yield a DB session that rolls back after the test for isolation."""
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()
