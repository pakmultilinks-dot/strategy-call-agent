"""Phase 6: Billing / Subscription / Plan-Based Feature Gating — REMOVED.

Regression tests verifying that billing, subscription, plan, and
feature-gating logic have been completely removed.  All features are
unconditionally available to every organization regardless of plan.

Covers:
  1. Organization model defaults — new orgs get plan="business"
  2. Settings — no Stripe/payment provider fields exist
  3. payment_provider.py — module deleted
  4. Pipeline — leads processed without billing gate for any plan
  5. Routers — no feature-gating checks in CRM or followup endpoints

Total: 12 tests
"""
from __future__ import annotations

import importlib
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal, engine
from app.main import app
from app.models import Base, Lead, FollowUp, EventLog
from app.models_multi_tenant import Organization, OrganizationStatus
from app.tenant import _DEFAULT_ORG_ID


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def client():
    """TestClient with lifespan support."""
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db_session():
    """Yield a database session, rolling back after the test."""
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


# ══════════════════════════════════════════════════════════════════════════════
# 1. Organization Model Defaults
# ══════════════════════════════════════════════════════════════════════════════

class TestOrgModelDefaults:
    """New organizations must default to plan='business' (fully enabled)."""

    def test_new_org_defaults_to_business_plan(self):
        """Inserting an Organization without specifying plan → plan='business'."""
        session = SessionLocal()
        try:
            slug = f"regression-test-{uuid.uuid4().hex[:8]}"
            org = Organization(
                name="Regression Test Org",
                slug=slug,
                display_name="Regression Test Org",
                status=OrganizationStatus.ACTIVE,
            )
            session.add(org)
            session.commit()
            session.refresh(org)
            assert org.plan == "business", (
                f"Organization.plan default should be 'business', got '{org.plan}'"
            )
        finally:
            # Clean up
            session.query(Organization).filter(
                Organization.name == "Regression Test Org"
            ).delete()
            session.commit()
            session.close()

    def test_default_org_seed_has_business_plan(self):
        """The default org fixture sets plan to 'business'."""
        session = SessionLocal()
        try:
            org = session.query(Organization).filter_by(id=_DEFAULT_ORG_ID).first()
            assert org is not None, "Default org must exist"
            assert org.plan == "business", (
                f"Default org plan should be 'business', got '{org.plan}'"
            )
        finally:
            session.close()


# ══════════════════════════════════════════════════════════════════════════════
# 2. Settings — No Stripe / Payment Provider Fields
# ══════════════════════════════════════════════════════════════════════════════

class TestSettingsNoBilling:
    """Settings class must not contain Stripe or payment provider fields."""

    def test_no_payment_provider_field(self):
        """Settings should not have a 'payment_provider' attribute."""
        assert not hasattr(settings, "payment_provider"), (
            "settings.payment_provider should be removed"
        )

    def test_no_stripe_secret_key(self):
        """Settings should not have a 'stripe_secret_key' attribute."""
        assert not hasattr(settings, "stripe_secret_key"), (
            "settings.stripe_secret_key should be removed"
        )

    def test_no_stripe_webhook_secret(self):
        """Settings should not have a 'stripe_webhook_secret' attribute."""
        assert not hasattr(settings, "stripe_webhook_secret"), (
            "settings.stripe_webhook_secret should be removed"
        )

    def test_no_stripe_price_fields(self):
        """Settings should not have any stripe_price_* attributes."""
        for attr in ("stripe_price_free", "stripe_price_starter",
                      "stripe_price_pro", "stripe_price_business"):
            assert not hasattr(settings, attr), (
                f"settings.{attr} should be removed"
            )


# ══════════════════════════════════════════════════════════════════════════════
# 3. payment_provider.py Deleted
# ══════════════════════════════════════════════════════════════════════════════

class TestPaymentProviderDeleted:
    """The payment_provider.py service file must no longer exist."""

    def test_module_not_importable(self):
        """app.services.payment_provider must not be importable."""
        # Remove from sys.modules cache if present
        sys.modules.pop("app.services.payment_provider", None)
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("app.services.payment_provider")


# ══════════════════════════════════════════════════════════════════════════════
# 4. Pipeline — No Billing Gate
# ══════════════════════════════════════════════════════════════════════════════

class TestPipelineNoBillingGate:
    """Form submission pipeline must not check plan or billing status."""

    def test_webhook_processes_lead_regardless_of_plan(self, client):
        """POST /webhooks/form-submission succeeds for any plan tier."""
        # Create a fresh org with plan explicitly set to 'free'
        session = SessionLocal()
        try:
            test_org = Organization(
                name="Free Plan Regression",
                slug=f"free-regression-{uuid.uuid4().hex[:8]}",
                display_name="Free Plan Regression",
                status=OrganizationStatus.ACTIVE,
                timezone="America/Chicago",
                plan="free",
            )
            session.add(test_org)
            session.commit()
            test_org_id = str(test_org.id)
        finally:
            session.close()

        payload = {
            "name": "Free Plan Test Lead",
            "email": f"free-test-{uuid.uuid4().hex[:8]}@example.com",
            "phone": "+15551234567",
            "interested": "Yes",
            "appt_datetime": "2026-12-31 14:00",
            "organization_id": test_org_id,
        }
        resp = client.post(
            "/webhooks/form-submission",
            json=payload,
            headers={"Authorization": f"Bearer {settings.webhook_secret}"}
            if settings.webhook_secret
            else {},
        )
        # Pipeline should NOT return 403 (billing gate) — it should accept the lead
        assert resp.status_code != 403, (
            f"Pipeline must not gate on plan. Got 403: {resp.text}"
        )
        # 200/201 = accepted, 422 = validation (both acceptable — no billing gate)
        assert resp.status_code in (200, 201, 422), (
            f"Expected 200/201/422, got {resp.status_code}: {resp.text}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 5. Routers — No Feature-Gating Checks
# ══════════════════════════════════════════════════════════════════════════════

class TestRoutersNoFeatureGating:
    """CRM and followup routers must not contain billing/plan feature gates."""

    def test_crm_router_source_no_plan_check(self):
        """crm_router.py must not contain plan-based access checks."""
        import app.routers.crm_router as crm
        source = open(crm.__file__).read()
        # Check for common billing-gate patterns that should NOT exist
        forbidden_patterns = [
            "has_ai_scoring",
            "has_follow_up",
            'require_feature',
            'has_feature',
            'plan == "free"',
            "plan == 'free'",
            'plan != "business"',
        ]
        for pattern in forbidden_patterns:
            assert pattern not in source, (
                f"crm_router.py still contains billing gate pattern: '{pattern}'"
            )

    def test_followup_router_source_no_plan_check(self):
        """followup_router.py must not contain plan-based access checks."""
        import app.routers.followup_router as fu
        source = open(fu.__file__).read()
        forbidden_patterns = [
            "has_follow_up_automation",
            "has_ai_scoring",
            'require_feature',
            'has_feature',
            'plan == "free"',
            "plan == 'free'",
            'plan != "business"',
        ]
        for pattern in forbidden_patterns:
            assert pattern not in source, (
                f"followup_router.py still contains billing gate pattern: '{pattern}'"
            )

    def test_crm_scoring_endpoint_no_plan_gate(self, client):
        """CRM /crm/leads/{id}/score returns 404 (not 403) for unknown lead."""
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/crm/leads/{fake_id}/score")
        # Should be 404 (not found) or 401 (no auth) — never 403 (forbidden/plan gate)
        assert resp.status_code != 403, (
            f"CRM scoring must not gate on plan. Got 403: {resp.text}"
        )

    def test_followup_create_no_plan_gate(self, client):
        """Follow-up creation returns 400/401 (not 403) when lead is missing."""
        fake_id = str(uuid.uuid4())
        resp = client.post(
            "/followups/",
            json={
                "lead_id": fake_id,
                "title": "Regression test",
                "due_at": "2026-12-31T23:59:59Z",
            },
        )
        # Should be 400 (bad request) or 401 (no auth) — never 403 (forbidden/plan gate)
        assert resp.status_code != 403, (
            f"Followup create must not gate on plan. Got 403: {resp.text}"
        )
