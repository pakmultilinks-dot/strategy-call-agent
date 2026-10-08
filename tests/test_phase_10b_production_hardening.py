"""Phase 10B - Production Hardening Regression Tests.

Targeted tests for each P0/P1 fix implemented in Phase 10B to ensure
the fixes work correctly and don't regress.
"""
import asyncio
import json
import time
import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.config import settings


# ══════════════════════════════════════════════════════════════════════════════
# 1. SSE Memory Leak Fix (unsubscribe on disconnect)
# ══════════════════════════════════════════════════════════════════════════════


class TestSSEUnsubscribe:
    """Verify that event_stream properly unsubscribes on disconnect."""

    def test_unsubscribe_called_on_generator_close(self):
        """event_stream should call unsubscribe when the generator is closed."""
        from app import events

        with events._lock:
            events._subscribers.clear()

        queue = events.subscribe()
        with events._lock:
            assert len(events._subscribers) == 1

        # Create the generator and immediately close it (simulates disconnect)
        async def close_gen():
            gen = events.event_stream(queue)
            # Prime the generator
            await gen.__anext__()
            # Close it - triggers GeneratorExit, which hits the finally block
            await gen.aclose()

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(close_gen())
        finally:
            loop.close()

        # After close, unsubscribe should have removed the queue
        with events._lock:
            remaining = len(events._subscribers)
        assert remaining == 0, f"Expected 0 subscribers after close, got {remaining}"

    def test_subscribe_returns_queue(self):
        """subscribe() should return an asyncio.Queue."""
        from app import events

        with events._lock:
            events._subscribers.clear()

        queue = events.subscribe()
        assert isinstance(queue, asyncio.Queue)

        # Cleanup
        events.unsubscribe(queue)

    def test_unsubscribe_removes_queue(self):
        """unsubscribe() should remove the queue from the subscriber list."""
        from app import events

        with events._lock:
            events._subscribers.clear()

        queue = events.subscribe()
        with events._lock:
            assert len(events._subscribers) == 1

        events.unsubscribe(queue)
        with events._lock:
            assert len(events._subscribers) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 2. SSE Tenant Isolation (publish_event org filtering)
# ══════════════════════════════════════════════════════════════════════════════


class TestSSETenantIsolation:
    """Verify that publish_event respects organization_id filtering."""

    def test_publish_with_org_id_filters_subscribers(self):
        """Events with org_id should only reach matching subscribers."""
        from app import events

        with events._lock:
            events._subscribers.clear()

        org_a = uuid.UUID("11111111-1111-1111-1111-111111111111")
        org_b = uuid.UUID("22222222-2222-2222-2222-222222222222")

        queue_a = events.subscribe(organization_id=org_a)
        queue_b = events.subscribe(organization_id=org_b)
        queue_admin = events.subscribe(organization_id=None)  # platform admin

        try:
            # Publish event for org_a
            events.publish_event("test.event", {"msg": "hello"}, organization_id=org_a)

            # queue_a should receive it
            assert not queue_a.empty()
            msg_a = queue_a.get_nowait()
            data_a = json.loads(msg_a)
            assert data_a["type"] == "test.event"
            assert data_a["org_id"] == str(org_a)

            # queue_b should NOT receive it (different org)
            assert queue_b.empty(), "queue_b should not receive events for org_a"

            # queue_admin should receive it (admin sees all)
            assert not queue_admin.empty()
            msg_admin = queue_admin.get_nowait()
            data_admin = json.loads(msg_admin)
            assert data_admin["type"] == "test.event"
        finally:
            events.unsubscribe(queue_a)
            events.unsubscribe(queue_b)
            events.unsubscribe(queue_admin)

    def test_publish_without_org_id_broadcasts_to_all(self):
        """Events without org_id should ONLY reach admin (org_id=None) subscribers.

        Tenant isolation fix: platform events must not leak to
        organization-specific subscribers.  Only subscribers with no org
        filter (platform admin) receive org-less events.
        """
        from app import events

        with events._lock:
            events._subscribers.clear()

        org_a = uuid.UUID("11111111-1111-1111-1111-111111111111")

        queue_a = events.subscribe(organization_id=org_a)
        queue_admin = events.subscribe(organization_id=None)

        try:
            # Publish event without org_id (platform event)
            events.publish_event("broadcast.event", {"msg": "all"})

            # Only admin receives it; org-specific subscriber does NOT
            # (prevents cross-tenant event leakage).
            assert queue_a.empty()
            assert not queue_admin.empty()
        finally:
            events.unsubscribe(queue_a)
            events.unsubscribe(queue_admin)

    def test_subscribe_with_org_id(self):
        """subscribe() with organization_id should store the org filter."""
        from app import events

        with events._lock:
            events._subscribers.clear()

        org_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
        queue = events.subscribe(organization_id=org_id)

        # Verify the subscriber tuple contains the org_id
        with events._lock:
            found = False
            for q, sub_org_id in events._subscribers:
                if q is queue:
                    assert sub_org_id == org_id
                    found = True
                    break
        assert found, "Subscriber not found in _subscribers list"

        events.unsubscribe(queue)


# ══════════════════════════════════════════════════════════════════════════════
# 3. Login Brute-Force Protection
# ══════════════════════════════════════════════════════════════════════════════


class TestLoginBruteForceProtection:
    """Verify that login rate limiting works correctly."""

    def test_rate_limit_allows_normal_attempts(self):
        """Normal login attempts should not be rate-limited."""
        from app.routers.auth_router import _check_login_rate_limit, _login_failures

        _login_failures.clear()
        email = "test@example.com"
        # Should not raise for a fresh email
        _check_login_rate_limit(email)

    def test_rate_limit_blocks_after_max_attempts(self):
        """After _LOGIN_MAX_ATTEMPTS failures, should raise 429."""
        from app.routers.auth_router import (
            _check_login_rate_limit,
            _record_login_failure,
            _login_failures,
            _LOGIN_MAX_ATTEMPTS,
        )

        _login_failures.clear()
        email = "bruteforce@example.com"

        # Record max failures
        for _ in range(_LOGIN_MAX_ATTEMPTS):
            _record_login_failure(email)

        # Next check should raise 429
        with pytest.raises(HTTPException) as exc_info:
            _check_login_rate_limit(email)
        assert exc_info.value.status_code == 429

        # Cleanup
        _login_failures.clear()

    def test_rate_limit_resets_on_success(self):
        """After a successful login, the rate limit counter should be cleared."""
        from app.routers.auth_router import (
            _check_login_rate_limit,
            _record_login_failure,
            _reset_login_rate_limit,
            _login_failures,
            _LOGIN_MAX_ATTEMPTS,
        )

        _login_failures.clear()
        email = "reset@example.com"

        # Record some failures
        for _ in range(_LOGIN_MAX_ATTEMPTS - 1):
            _record_login_failure(email)

        # Verify failures are recorded
        assert len(_login_failures[email]) == _LOGIN_MAX_ATTEMPTS - 1

        # Reset (simulating successful login)
        _reset_login_rate_limit(email)

        # Should be able to try again without 429
        _check_login_rate_limit(email)
        # The failures list should be empty (or key removed)
        assert len(_login_failures.get(email, [])) == 0

        # Cleanup
        _login_failures.clear()

    def test_rate_limit_is_per_email(self):
        """Rate limiting should be per-email, not global."""
        from app.routers.auth_router import (
            _check_login_rate_limit,
            _record_login_failure,
            _login_failures,
            _LOGIN_MAX_ATTEMPTS,
        )

        _login_failures.clear()

        # Max out one email
        for _ in range(_LOGIN_MAX_ATTEMPTS):
            _record_login_failure("blocked@example.com")

        # Another email should still work
        _check_login_rate_limit("other@example.com")

        # Cleanup
        _login_failures.clear()


# ══════════════════════════════════════════════════════════════════════════════
# 4. Secret Masking (new behavior)
# ══════════════════════════════════════════════════════════════════════════════


class TestSecretMaskingProduction:
    """Verify the new masking behavior reveals only the last 4 characters."""

    def test_16_char_secret_shows_only_last_4(self):
        """A 16-char secret should show 12 asterisks + last 4 chars."""
        from app.routers.webhook_config_router import _mask_secret

        secret = "abcdefghijklmnop"
        result = _mask_secret(secret)
        assert result == "************mnop"
        # Ensure first 4 chars are NOT visible
        assert "abcd" not in result

    def test_first_chars_never_exposed(self):
        """No matter the length, the first characters should never be visible."""
        from app.routers.webhook_config_router import _mask_secret

        for secret in ["abcdefghij", "abcdefghijklmnop", "a" * 100]:
            result = _mask_secret(secret)
            # First char should be masked
            assert result[0] == "*"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Email Null Guard
# ══════════════════════════════════════════════════════════════════════════════


class TestEmailNullGuard:
    """Verify that sending an email with None/to-empty raises ValueError."""

    def test_send_email_raises_on_none_recipient(self):
        """send_email should raise ValueError when 'to' is None."""
        from app.services.email_service import EmailService

        # We don't need a real service - just verify the guard logic
        svc = object.__new__(EmailService)
        with pytest.raises(ValueError, match="recipient address"):
            svc.send_email(None, "Subject", "Body", MagicMock())

    def test_send_email_raises_on_empty_recipient(self):
        """send_email should raise ValueError when 'to' is empty string."""
        from app.services.email_service import EmailService

        svc = object.__new__(EmailService)
        with pytest.raises(ValueError, match="recipient address"):
            svc.send_email("", "Subject", "Body", MagicMock())


# ══════════════════════════════════════════════════════════════════════════════
# 6. Mark Completed Meetings - previous_status fix
# ══════════════════════════════════════════════════════════════════════════════


class TestMarkCompletedMeetingsPreviousStatus:
    """Verify that _mark_completed_meetings logs the ORIGINAL status."""

    def test_previous_status_captured_before_update(self):
        """previous_status in the event log should be the status BEFORE setting COMPLETED."""
        # This is a code review test - the fix ensures previous_status is captured
        # BEFORE lead.status is changed to COMPLETED. The test verifies the code
        # structure by checking that the old status value is used.
        import inspect
        from app.main import _mark_completed_meetings

        source = inspect.getsource(_mark_completed_meetings)
        # The fix: previous_status should be captured BEFORE status assignment
        # Look for the pattern: previous_status = lead.status.value (before assignment)
        lines = source.split("\n")
        found_capture = False
        found_assignment = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if "previous_status = lead.status.value" in stripped:
                found_capture = True
            if "lead.status = LeadStatus.COMPLETED" in stripped:
                if found_capture:
                    found_assignment = True
                    break
                # If we find the assignment BEFORE the capture, the bug still exists
                assert False, "lead.status is assigned BEFORE previous_status is captured"

        assert found_capture, "previous_status capture not found in source"
        assert found_assignment, "lead.status = LeadStatus.COMPLETED not found after capture"
