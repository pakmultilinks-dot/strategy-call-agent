"""Phase 28 P1-B: Rate limiting expansion tests.

Tests for the shared rate_limit service and per-endpoint rate limiting
added to CRM AI endpoints, billing state changes, and webhook secret rotation.

Coverage:
- Shared rate_limit service: sliding window, 429, reset, concurrent keys
- CRM AI endpoints: score, summary, call-summary, next-action rate-limited per-org
- Billing: upgrade, downgrade rate-limited per-org
- Webhook config: rotate-secret rate-limited per-org

NOTE: CRM endpoints use _auth_context (supports Basic + JWT) but rate limiting
only fires when ctx.org_id is set (JWT Bearer). Billing/webhook endpoints use
require_role → get_current_user → JWT Bearer only. So all integration tests
here create a real user + JWT to get org-scoped auth.
"""
import time
import uuid as _uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.config import settings
from app.database import SessionLocal
from app.models_multi_tenant import (
    Organization,
    User,
    UserRole,
    UserStatus,
)
from app.tenant import _DEFAULT_ORG_ID


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_jwt(user: User) -> str:
    """Create a valid JWT for the given user using app.auth."""
    from app.auth import create_access_token
    return create_access_token(
        user_id=user.id,
        organization_id=user.organization_id,
        role=user.role.value,
        expires_delta=timedelta(hours=1),
    )


def _make_user(role: UserRole = UserRole.OWNER) -> User:
    """Create a fresh test user in the default org with the given role."""
    from app.auth import hash_password

    db = SessionLocal()
    try:
        # Always create a fresh user to guarantee the correct role
        user = User(
            organization_id=_DEFAULT_ORG_ID,
            email=f"rate-limit-test-{_uuid.uuid4().hex[:8]}@example.com",
            password_hash=hash_password("TestPassword123!"),
            full_name="Rate Limit Test User",
            role=role,
            status=UserStatus.ACTIVE,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def _jwt_headers(user: User) -> dict:
    """Return Authorization headers with a valid JWT Bearer token."""
    return {"Authorization": f"Bearer {_make_jwt(user)}"}


# ---------------------------------------------------------------------------
# TestSharedRateLimiter — tests for app/services/rate_limit.py
# ---------------------------------------------------------------------------


class TestSharedRateLimiter:
    """Tests for the shared sliding-window rate limiter."""

    def setup_method(self):
        """Clear global state between tests."""
        from app.services.rate_limit import _clear_all_hits
        _clear_all_hits()

    def test_allows_within_limit(self):
        """Requests within the limit should pass without raising."""
        from app.services.rate_limit import check_rate_limit

        for _ in range(9):
            check_rate_limit(key="test:org1", max_attempts=10, window_seconds=60)

    def test_blocks_at_limit(self):
        """Reaching the limit should raise HTTPException 429."""
        from app.services.rate_limit import check_rate_limit

        for _ in range(10):
            check_rate_limit(key="test:org1", max_attempts=10, window_seconds=60)

        with pytest.raises(HTTPException) as exc_info:
            check_rate_limit(key="test:org1", max_attempts=10, window_seconds=60)
        assert exc_info.value.status_code == 429

    def test_different_keys_are_independent(self):
        """Different keys have independent counters."""
        from app.services.rate_limit import check_rate_limit

        # Exhaust key1
        for _ in range(10):
            check_rate_limit(key="test:org1", max_attempts=10, window_seconds=60)

        # key2 should still be fine
        check_rate_limit(key="test:org2", max_attempts=10, window_seconds=60)

        # key1 should be blocked
        with pytest.raises(HTTPException) as exc_info:
            check_rate_limit(key="test:org1", max_attempts=10, window_seconds=60)
        assert exc_info.value.status_code == 429

    def test_reset_clears_counter(self):
        """reset_rate_limit should clear the counter for a key."""
        from app.services.rate_limit import check_rate_limit, reset_rate_limit

        for _ in range(10):
            check_rate_limit(key="test:org1", max_attempts=10, window_seconds=60)

        reset_rate_limit("test:org1")
        # Should pass again after reset
        check_rate_limit(key="test:org1", max_attempts=10, window_seconds=60)

    def test_window_expiry_allows_new_requests(self):
        """After the window expires, new requests should be allowed."""
        from app.services.rate_limit import check_rate_limit

        # Use a very short window
        for _ in range(10):
            check_rate_limit(key="test:expire", max_attempts=10, window_seconds=1)

        # Wait for the window to expire
        time.sleep(1.1)

        # Should pass now
        check_rate_limit(key="test:expire", max_attempts=10, window_seconds=1)

    def test_clear_all_hits(self):
        """_clear_all_hits should clear all rate limit state."""
        from app.services.rate_limit import check_rate_limit, _clear_all_hits

        for _ in range(10):
            check_rate_limit(key="test:org1", max_attempts=10, window_seconds=60)

        _clear_all_hits()
        # Should pass again after clearing all
        check_rate_limit(key="test:org1", max_attempts=10, window_seconds=60)


# ---------------------------------------------------------------------------
# TestCRMRateLimiting — tests for per-org rate limiting on AI endpoints
# ---------------------------------------------------------------------------


class TestCRMRateLimiting:
    """Tests that CRM AI endpoints enforce per-org rate limits."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        """Clear rate-limit state and create a test user."""
        from app.services.rate_limit import _clear_all_hits
        _clear_all_hits()
        self.user = _make_user(UserRole.MEMBER)
        self.headers = _jwt_headers(self.user)

    def test_next_action_rate_limited(self, client):
        """GET /crm/leads/{id}/next-action should be 429 when rate-limited.

        This endpoint has no feature gate so it's the cleanest to test.
        Rate limit fires before the DB lead lookup, so a nonexistent lead
        still gets 429 when the limit is exhausted.
        """
        from app.services.rate_limit import _hits

        # Pre-fill the rate limiter to exhaust the 30/min limit
        org_key = f"ai_score:{_DEFAULT_ORG_ID}"
        now = time.monotonic()
        _hits[org_key] = [now] * 30

        dummy_lead = str(_uuid.uuid4())
        resp = client.get(
            f"/crm/leads/{dummy_lead}/next-action",
            headers=self.headers,
        )
        assert resp.status_code == 429, (
            f"Expected 429 when rate limit exhausted, got {resp.status_code}: "
            f"{resp.text}"
        )

    def test_ai_score_rate_limited(self, client):
        """GET /crm/leads/{id}/score should be 429 when rate-limited."""
        from app.services.rate_limit import _hits

        org_key = f"ai_score:{_DEFAULT_ORG_ID}"
        now = time.monotonic()
        _hits[org_key] = [now] * 30

        dummy_lead = str(_uuid.uuid4())
        resp = client.get(
            f"/crm/leads/{dummy_lead}/score",
            headers=self.headers,
        )
        # Rate limit fires before feature check, so 429 regardless of plan
        assert resp.status_code == 429


# ---------------------------------------------------------------------------
# TestBillingRateLimiting — tests for per-org rate limiting on plan changes
# ---------------------------------------------------------------------------


class TestBillingRateLimiting:
    """Tests that billing endpoints enforce per-org rate limits."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        """Clear rate-limit state and create a test user."""
        from app.services.rate_limit import _clear_all_hits
        _clear_all_hits()
        self.user = _make_user(UserRole.OWNER)
        self.headers = _jwt_headers(self.user)

    def test_downgrade_rate_limited(self, client):
        """POST /billing/downgrade should be 429 when rate-limited."""
        pytest.skip("Billing endpoints removed")

    def test_upgrade_rate_limited(self, client):
        """POST /billing/upgrade should be 429 when rate-limited."""
        pytest.skip("Billing endpoints removed")


# ---------------------------------------------------------------------------
# TestWebhookRotationRateLimiting — tests for per-org rate limiting
# ---------------------------------------------------------------------------


class TestWebhookRotationRateLimiting:
    """Tests that webhook secret rotation is rate-limited per org."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        """Clear rate-limit state and create a test user."""
        from app.services.rate_limit import _clear_all_hits
        _clear_all_hits()
        self.user = _make_user(UserRole.OWNER)
        self.headers = _jwt_headers(self.user)

    def test_rotate_secret_rate_limited(self, client):
        """POST /organization/webhook/rotate-secret should be 429 when rate-limited."""
        from app.services.rate_limit import _hits

        org_key = f"webhook_rotate:{_DEFAULT_ORG_ID}"
        now = time.monotonic()
        _hits[org_key] = [now] * 5

        resp = client.post(
            "/organization/webhook/rotate-secret",
            headers=self.headers,
        )
        assert resp.status_code == 429, (
            f"Expected 429 when rate limit exhausted, got {resp.status_code}: "
            f"{resp.text}"
        )
