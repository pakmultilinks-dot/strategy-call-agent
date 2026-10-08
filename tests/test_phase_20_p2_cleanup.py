"""Phase 20 — Production Hardening Tests.

Tests for P2-A (register rate limit), P2-B (dead code removal),
P2-C (consolidated _safe_user_info), P2-D (test collection fix).
"""
import importlib
import inspect
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import LeadStatus
from app.models_multi_tenant import Organization, OrganizationStatus
from app.tenant import (
    _DEFAULT_ORG_ID,
    set_lead_organization,
)
from tests.conftest import _seed_default_organization


# ─────────────────────────────────────────────────────────────────────────────
# P2-A: Registration rate limiting
# ─────────────────────────────────────────────────────────────────────────────

class TestRegisterRateLimit:
    """Verify /auth/register has per-IP rate limiting."""

    def test_register_works_normally(self, client: TestClient, db_session: Session):
        """First registration within window should succeed."""
        payload = {
            "email": f"rate-{uuid.uuid4().hex[:8]}@example.com",
            "password": "Str0ng!Pass#2026",
            "organization_name": f"Rate Test {uuid.uuid4().hex[:6]}",
            "name": "Rate Test User",
        }
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code in (201, 409), f"Unexpected: {resp.status_code} {resp.text}"

    def test_register_rate_limit_enforced(self, client: TestClient, db_session: Session):
        """After exceeding max attempts, registration returns 429."""
        from app.routers.auth_router import _register_hits, _REGISTER_WINDOW_SECONDS
        import time

        # Seed the rate limiter to be at the limit
        ip_key = "testclient"  # TestClient's default IP
        now = time.monotonic()
        _register_hits[ip_key] = [now - 1] * 5  # Already at max

        payload = {
            "email": f"limited-{uuid.uuid4().hex[:8]}@example.com",
            "password": "Str0ng!Pass#2026",
            "organization_name": f"Limited Org {uuid.uuid4().hex[:6]}",
            "name": "Limited User",
        }
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 429
        assert "Too many" in resp.json()["detail"]

        # Clean up
        _register_hits.pop(ip_key, None)


# ─────────────────────────────────────────────────────────────────────────────
# P2-B: verify_lead_org_access removed
# ─────────────────────────────────────────────────────────────────────────────

class TestDeadCodeRemoval:
    """Verify that dead code was properly removed."""

    def test_verify_lead_org_access_removed(self):
        """verify_lead_org_access should no longer exist in app.tenant."""
        import app.tenant as tenant_mod
        assert not hasattr(tenant_mod, "verify_lead_org_access"), (
            "verify_lead_org_access should have been removed from app.tenant"
        )

    def test_set_lead_organization_still_exists(self):
        """set_lead_organization should still be available."""
        assert callable(set_lead_organization)


# ─────────────────────────────────────────────────────────────────────────────
# P2-C: Consolidated build_safe_user_info
# ─────────────────────────────────────────────────────────────────────────────

class TestConsolidatedHelper:
    """Verify _safe_user_info was consolidated to build_safe_user_info."""

    def test_build_safe_user_info_exists(self):
        """build_safe_user_info should be importable from schemas_auth."""
        from app.schemas_auth import build_safe_user_info
        assert callable(build_safe_user_info)

    def test_auth_router_uses_shared_helper(self):
        """auth_router should not define its own _safe_user_info."""
        import app.routers.auth_router as auth_mod
        # The local _safe_user_info function should no longer exist
        source = inspect.getsource(auth_mod)
        assert "def _safe_user_info(" not in source, (
            "auth_router still defines local _safe_user_info"
        )

    def test_organization_router_uses_shared_helper(self):
        """organization_router should not define its own _safe_user_info."""
        import app.routers.organization_router as org_mod
        source = inspect.getsource(org_mod)
        assert "def _safe_user_info(" not in source, (
            "organization_router still defines local _safe_user_info"
        )


# ─────────────────────────────────────────────────────────────────────────────
# P2-D: test_clean_db_install.py collection fix
# ─────────────────────────────────────────────────────────────────────────────

class TestCollectionFix:
    """Verify disposable scripts were cleaned up in Phase 51."""

    def test_script_renamed(self):
        """scripts/clean_db_install.py removed in Phase 51 cleanup."""
        from pathlib import Path
        scripts_dir = Path("scripts")
        assert not (scripts_dir / "test_clean_db_install.py").exists(), (
            "scripts/test_clean_db_install.py should not exist"
        )
