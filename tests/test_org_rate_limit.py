"""Tests for OrgRateLimitMiddleware (per-organization API rate limiting).

Phase 32: Per-org rate limiter prevents a single org from hammering the API.
"""
from __future__ import annotations

import time
import uuid
from unittest.mock import patch, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware import OrgRateLimitMiddleware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_test_app(rate_limit: int = 5) -> FastAPI:
    """Create a minimal FastAPI app with OrgRateLimitMiddleware."""
    app = FastAPI()
    app.add_middleware(OrgRateLimitMiddleware, requests_per_minute=rate_limit)

    @app.get("/dashboard/api/overview")
    def overview():
        return {"ok": True}

    @app.post("/auth/login")
    def login():
        """Public path — should NOT be rate-limited."""
        return {"ok": True}

    @app.post("/webhooks/test-org/form-submission")
    def webhook():
        """Webhook path — should NOT be rate-limited."""
        return {"ok": True}

    return app


def _fake_jwt(org_id: str | None = None) -> str:
    """Create a fake JWT with the given org_id (no real signing)."""
    if org_id is None:
        org_id = str(uuid.uuid4())
    # Use jose to create a valid-enough JWT for rate limiting
    from jose import jwt as _jwt
    return _jwt.encode(
        {"org_id": org_id, "sub": str(uuid.uuid4()), "role": "member"},
        "test-secret",
        algorithm="HS256",
    )


# ---------------------------------------------------------------------------
# Test Classes
# ---------------------------------------------------------------------------

class TestOrgRateLimitBypass:
    """Verify that public paths are NOT rate-limited."""

    def test_login_not_rate_limited(self):
        """POST /auth/login should bypass per-org rate limiting."""
        app = _make_test_app(rate_limit=2)
        client = TestClient(app)
        token = _fake_jwt()

        for _ in range(10):
            resp = client.post(
                "/auth/login",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 200

    def test_webhook_not_rate_limited(self):
        """Webhook paths should bypass per-org rate limiting."""
        app = _make_test_app(rate_limit=2)
        client = TestClient(app)

        for _ in range(10):
            resp = client.post("/webhooks/test-org/form-submission")
        assert resp.status_code == 200

    def test_no_auth_not_rate_limited(self):
        """Requests without Authorization header should bypass rate limiting."""
        app = _make_test_app(rate_limit=2)
        client = TestClient(app)

        for _ in range(10):
            resp = client.get("/dashboard/api/overview")
        assert resp.status_code == 200


class TestOrgRateLimitEnforcement:
    """Verify that per-org rate limiting is enforced."""

    def test_rate_limit_exceeded_returns_429(self):
        """Exceeding the per-org rate limit should return 429."""
        app = _make_test_app(rate_limit=3)
        client = TestClient(app)
        org_id = str(uuid.uuid4())
        token = _fake_jwt(org_id)

        for _ in range(3):
            resp = client.get(
                "/dashboard/api/overview",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200

        # 4th request should be rate-limited
        resp = client.get(
            "/dashboard/api/overview",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 429
        assert "rate limit" in resp.json()["detail"].lower()

    def test_rate_limit_includes_retry_after(self):
        """Rate-limited response should include Retry-After header."""
        app = _make_test_app(rate_limit=1)
        client = TestClient(app)
        token = _fake_jwt()

        # First request succeeds
        client.get(
            "/dashboard/api/overview",
            headers={"Authorization": f"Bearer {token}"},
        )
        # Second request is rate-limited
        resp = client.get(
            "/dashboard/api/overview",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers

    def test_different_orgs_have_separate_limits(self):
        """Different orgs should have independent rate limit counters."""
        app = _make_test_app(rate_limit=2)
        client = TestClient(app)
        org1_token = _fake_jwt(str(uuid.uuid4()))
        org2_token = _fake_jwt(str(uuid.uuid4()))

        # Org 1 uses up its limit
        for _ in range(2):
            resp = client.get(
                "/dashboard/api/overview",
                headers={"Authorization": f"Bearer {org1_token}"},
            )
            assert resp.status_code == 200

        # Org 1 is now rate-limited
        resp = client.get(
            "/dashboard/api/overview",
            headers={"Authorization": f"Bearer {org1_token}"},
        )
        assert resp.status_code == 429

        # Org 2 should still be able to make requests
        resp = client.get(
            "/dashboard/api/overview",
            headers={"Authorization": f"Bearer {org2_token}"},
        )
        assert resp.status_code == 200

    def test_malformed_token_bypasses_rate_limit(self):
        """Malformed tokens should bypass rate limiting (auth handles rejection)."""
        app = _make_test_app(rate_limit=2)
        client = TestClient(app)

        for _ in range(10):
            resp = client.get(
                "/dashboard/api/overview",
                headers={"Authorization": "Bearer not-a-real-jwt"},
            )
        assert resp.status_code == 200


class TestOrgRateLimitCleanup:
    """Verify memory cleanup works correctly."""

    def test_class_level_hits_shared(self):
        """Hits should be shared across instances (class-level tracking)."""
        OrgRateLimitMiddleware._global_hits.clear()
        app = _make_test_app(rate_limit=100)
        client = TestClient(app)
        token = _fake_jwt()

        resp = client.get(
            "/dashboard/api/overview",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert len(OrgRateLimitMiddleware._global_hits) >= 1
        # Cleanup
        OrgRateLimitMiddleware._global_hits.clear()

    def test_extract_org_id_valid(self):
        """Valid JWT should return org_id."""
        org_id = str(uuid.uuid4())
        token = _fake_jwt(org_id)
        result = OrgRateLimitMiddleware._extract_org_id(token)
        assert result == org_id

    def test_extract_org_id_invalid(self):
        """Invalid token should return None."""
        result = OrgRateLimitMiddleware._extract_org_id("not-a-jwt")
        assert result is None
