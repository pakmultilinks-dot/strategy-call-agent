"""Regression tests for Problem #5 — Per-Org Scheduler Jobs (REMOVED).

Per-org scheduler jobs (913 orgs × 2 jobs = 1826) were removed for
performance. The system-level batch jobs (rsvp_poll + daily_reminder)
now handle all organizations in a single pass.

These tests verify:
  1. reschedule_org_scheduler_jobs() is now a no-op stub
  2. The stub does not crash on any input
  3. Router integration still calls the stub
"""
import uuid
import logging
from unittest.mock import patch, MagicMock

import pytest

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tests — reschedule_org_scheduler_jobs (now a no-op)
# ---------------------------------------------------------------------------


class TestRescheduleOrgSchedulerJobs:
    """Unit tests for the reschedule_org_scheduler_jobs() no-op stub."""

    def test_is_noop(self):
        """reschedule_org_scheduler_jobs should be a no-op (does not create jobs)."""
        from app.main import reschedule_org_scheduler_jobs

        org_id = uuid.uuid4()
        with patch("app.main._scheduler", None):
            reschedule_org_scheduler_jobs(org_id)

    def test_noop_with_real_scheduler(self):
        """Stub does not interact with the scheduler even when it's running."""
        from app.main import reschedule_org_scheduler_jobs

        org_id = uuid.uuid4()
        mock_scheduler = MagicMock()
        with patch("app.main._scheduler", mock_scheduler):
            reschedule_org_scheduler_jobs(org_id)

        # Should NOT have called get_job, add_job, or remove_job
        mock_scheduler.get_job.assert_not_called()
        mock_scheduler.add_job.assert_not_called()
        mock_scheduler.remove_job.assert_not_called()

    def test_noop_when_scheduler_is_none(self):
        """If _scheduler is None (dev/test without scheduler), function is a no-op."""
        from app.main import reschedule_org_scheduler_jobs

        org_id = uuid.uuid4()
        with patch("app.main._scheduler", None):
            reschedule_org_scheduler_jobs(org_id)

    def test_accepts_various_inputs(self):
        """Stub accepts any UUID without error."""
        from app.main import reschedule_org_scheduler_jobs

        for _ in range(5):
            reschedule_org_scheduler_jobs(uuid.uuid4())


# ---------------------------------------------------------------------------
# Tests — Router integration (source-level)
# ---------------------------------------------------------------------------


class TestRouterCallsReschedule:
    """Verify the router still has the reschedule call (as a no-op)."""

    def test_update_settings_triggers_reschedule(self):
        """After PATCH /organization/settings, reschedule should be called."""
        import inspect
        from app.routers.organization_router import update_organization_settings

        source = inspect.getsource(update_organization_settings)
        assert "reschedule_org_scheduler_jobs" in source

    def test_import_is_lazy(self):
        """The import of reschedule_org_scheduler_jobs should be inside function body."""
        import inspect
        from app.routers.organization_router import update_organization_settings

        source = inspect.getsource(update_organization_settings)
        assert "from app.main import" in source
        assert "try:" in source


class TestLifespanStartupRegistration:
    """Verify lifespan() no longer calls _register_startup_org_jobs."""

    def test_lifespan_does_not_call_startup_registration(self):
        """lifespan() should NOT call _register_startup_org_jobs (removed for perf)."""
        import inspect
        from app.main import lifespan

        source = inspect.getsource(lifespan)
        assert "_register_startup_org_jobs" not in source
