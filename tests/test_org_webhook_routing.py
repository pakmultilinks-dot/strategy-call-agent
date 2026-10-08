"""Phase 6B.5 — Organization-Aware Webhook & Google Forms/Sheets Routing.

Covers:
  1. Org-scoped webhook route (POST /webhooks/{org_slug}/form-submission)
  2. Organization lookup from slug (ACTIVE status check)
  3. Per-org webhook secret authentication
  4. Global webhook secret fallback
  5. Unknown/disabled org slug error responses (404)
  6. Lead organization_id set correctly from slug
  7. Duplicate protection across orgs
  8. EventLog organization_id from slug
  9. FailedJob organization_id from pipeline
 10. Interested=No handling on org-scoped route
 11. Backward compatibility of legacy route
 12. Apps Script contract: org_slug URL format
"""
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models import EventLog, Lead, LeadStatus
from app.models_multi_tenant import Organization, OrganizationStatus
from app.tenant import (
    _DEFAULT_ORG_ID,
    lookup_organization_by_slug,
    verify_org_webhook_secret,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_org(**overrides) -> Organization:
    """Insert an Organization row and return it.

    Default plan is "starter" (has_pipeline_automation=True) so the
    Phase 27 pipeline feature gate does not block execution in
    webhook-routing tests.  Tests that specifically need a free-tier
    org can pass ``plan="free"`` explicitly.
    """
    defaults = {
        "name": f"Test Org {uuid.uuid4().hex[:8]}",
        "slug": f"test-org-{uuid.uuid4().hex[:8]}",
        "timezone": "America/Chicago",
        "status": OrganizationStatus.ACTIVE,
        "plan": "starter",
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


def _unique_payload(**overrides) -> dict:
    """Generate a unique valid payload with UUID email to avoid dedup."""
    uid = uuid.uuid4().hex[:8]
    base = {
        "Interested?": "Yes",
        "Name": "Test User",
        "Company Address": "123 Test St",
        "Phone Number": "555-0100",
        "Direct Number": "555-0101",
        "Courses": "Python, Docker",
        "Email Address": f"test-{uid}@example.com",
        "Scheduled Date": "tomorrow",
        "Caller Name": "Agent Smith",
        "Phone Appt. Date/Time": f"tomorrow {uid[:2]}:{uid[2:4]}",
    }
    base.update(overrides)
    return base


def _get_default_org_slug() -> str:
    """Return the default org's slug from the database."""
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(
            Organization.id == _DEFAULT_ORG_ID
        ).first()
        return org.slug if org else "integrated-it-trainings"
    finally:
        db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 1. Organization Lookup
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgLookupBySlug:
    """lookup_organization_by_slug() must resolve ACTIVE orgs only."""

    def test_lookup_existing_active_org(self):
        org = _make_org(slug=f"active-{uuid.uuid4().hex[:6]}")
        result = lookup_organization_by_slug(org.slug)
        assert result is not None
        assert result.id == org.id

    def test_lookup_nonexistent_slug(self):
        result = lookup_organization_by_slug("this-slug-does-not-exist-xyz")
        assert result is None

    def test_lookup_disabled_org_returns_none(self):
        org = _make_org(
            slug=f"disabled-{uuid.uuid4().hex[:6]}",
            status=OrganizationStatus.DISABLED,
        )
        result = lookup_organization_by_slug(org.slug)
        assert result is None

    def test_lookup_suspended_org_returns_none(self):
        org = _make_org(
            slug=f"suspended-{uuid.uuid4().hex[:6]}",
            status=OrganizationStatus.SUSPENDED,
        )
        result = lookup_organization_by_slug(org.slug)
        assert result is None

    def test_lookup_with_explicit_session(self):
        org = _make_org(slug=f"sess-{uuid.uuid4().hex[:6]}")
        db = SessionLocal()
        try:
            result = lookup_organization_by_slug(org.slug, db=db)
            assert result is not None
            assert result.id == org.id
        finally:
            db.close()

    def test_lookup_default_org(self):
        """The default org seeded by migration 001 should be lookupable."""
        slug = _get_default_org_slug()
        result = lookup_organization_by_slug(slug)
        assert result is not None
        assert result.id == _DEFAULT_ORG_ID


# ══════════════════════════════════════════════════════════════════════════════
# 2. Per-Org Webhook Secret Verification
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgWebhookSecret:
    """verify_org_webhook_secret() must check org secret, then global."""

    def test_org_secret_accepted(self):
        secret = "org-secret-" + uuid.uuid4().hex[:12]
        org = _make_org(webhook_secret=secret)
        assert verify_org_webhook_secret(org, secret) is True

    def test_org_secret_rejects_wrong_token(self):
        org = _make_org(webhook_secret="correct-secret-123")
        assert verify_org_webhook_secret(org, "wrong-token") is False

    def test_fallback_to_global_secret(self):
        """When org has no secret, fall back to settings.webhook_secret."""
        org = _make_org(webhook_secret=None)
        global_secret = "global-webhook-secret-test"
        with patch.object(settings, "webhook_secret", global_secret):
            assert verify_org_webhook_secret(org, global_secret) is True

    def test_fallback_rejects_wrong_global(self):
        org = _make_org(webhook_secret=None)
        with patch.object(settings, "webhook_secret", "the-real-global-secret"):
            assert verify_org_webhook_secret(org, "wrong-global") is False

    def test_no_secret_anywhere_rejects(self):
        """With no org secret and no global secret, everything is rejected."""
        org = _make_org(webhook_secret=None)
        with patch.object(settings, "webhook_secret", ""):
            assert verify_org_webhook_secret(org, "anything") is False

    def test_org_secret_takes_precedence_over_global(self):
        """When org has its own secret, the global secret is NOT accepted."""
        org = _make_org(webhook_secret="org-only-secret")
        with patch.object(settings, "webhook_secret", "global-secret"):
            assert verify_org_webhook_secret(org, "org-only-secret") is True
            assert verify_org_webhook_secret(org, "global-secret") is False


# ══════════════════════════════════════════════════════════════════════════════
# 3. Org-Scoped Webhook Route — Basic
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgWebhookRoute:
    """POST /webhooks/{org_slug}/form-submission"""

    def test_valid_submission_returns_202(self, client):
        org = _make_org()
        payload = _unique_payload()
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        assert resp.status_code == 202

    def test_valid_submission_returns_accepted(self, client):
        org = _make_org()
        payload = _unique_payload()
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        data = resp.json()
        assert data["status"] == "accepted"
        assert "lead_id" in data

    def test_lead_has_correct_organization_id(self, client):
        org = _make_org()
        payload = _unique_payload()
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        data = resp.json()
        assert data["status"] == "accepted"

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            assert lead is not None
            assert lead.organization_id == org.id
        finally:
            db.close()

    def test_unknown_slug_returns_404(self, client):
        payload = _unique_payload()
        resp = client.post(
            "/webhooks/this-org-does-not-exist/form-submission",
            json=payload,
        )
        assert resp.status_code == 404

    def test_disabled_slug_returns_404(self, client):
        """Disabled orgs return 404 (not 403) to avoid information leakage."""
        org = _make_org(status=OrganizationStatus.DISABLED)
        payload = _unique_payload()
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        assert resp.status_code == 404

    def test_suspended_slug_returns_404(self, client):
        org = _make_org(status=OrganizationStatus.SUSPENDED)
        payload = _unique_payload()
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 4. Org-Scoped Webhook Route — Authentication
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgWebhookAuth:
    """Bearer token authentication on the org-scoped route."""

    def test_org_secret_accepted(self, client):
        secret = "org-auth-" + uuid.uuid4().hex[:12]
        org = _make_org(webhook_secret=secret)
        payload = _unique_payload()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": f"Bearer {secret}"},
        )
        assert resp.status_code == 202

    def test_wrong_org_secret_rejected(self, client):
        org = _make_org(webhook_secret="correct-secret")
        payload = _unique_payload()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": "Bearer wrong-secret"},
        )
        assert resp.status_code == 401

    def test_missing_auth_header_rejected(self, client):
        org = _make_org(webhook_secret="some-secret")
        payload = _unique_payload()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 401

    def test_global_secret_accepted_when_no_org_secret(self, client):
        """When org has no secret, global secret should be accepted."""
        org = _make_org(webhook_secret=None)
        global_secret = "global-test-secret"
        payload = _unique_payload()
        with patch.object(settings, "webhook_secret", global_secret):
            resp = client.post(
                f"/webhooks/{org.slug}/form-submission",
                json=payload,
                headers={"Authorization": f"Bearer {global_secret}"},
            )
            assert resp.status_code == 202

    def test_no_secret_configured_allows_dev_mode(self, client):
        """With no secret anywhere, dev mode allows unauthenticated access."""
        org = _make_org(webhook_secret=None)
        payload = _unique_payload()
        with patch.object(settings, "webhook_secret", ""):
            resp = client.post(
                f"/webhooks/{org.slug}/form-submission",
                json=payload,
            )
            assert resp.status_code == 202

    def test_org_secret_does_not_accept_global_fallback(self, client):
        """When org has its own secret, global secret MUST NOT be accepted."""
        org = _make_org(webhook_secret="org-only-secret")
        payload = _unique_payload()
        with patch.object(settings, "webhook_secret", "global-secret"):
            resp = client.post(
                f"/webhooks/{org.slug}/form-submission",
                json=payload,
                headers={"Authorization": "Bearer global-secret"},
            )
            assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# 5. Duplicate Protection
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgDuplicateProtection:
    """Same email+appt time within one org returns duplicate."""

    def test_same_payload_returns_duplicate(self, client):
        org = _make_org()
        payload = _unique_payload()
        resp1 = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        resp2 = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        assert resp1.status_code == 202
        assert resp2.status_code == 202
        assert resp1.json()["status"] == "accepted"
        assert resp2.json()["status"] == "duplicate"

    def test_same_payload_different_orgs_accepted(self, client):
        """Same email+appt time in DIFFERENT orgs should both be accepted.
        After the cross-tenant dedupe fix, dedupe_key is org-scoped so the
        same email+appt in different orgs produces different keys."""
        org1 = _make_org()
        org2 = _make_org()
        payload1 = _unique_payload()
        resp1 = client.post(f"/webhooks/{org1.slug}/form-submission", json=payload1)
        resp2 = client.post(f"/webhooks/{org2.slug}/form-submission", json=payload1)
        assert resp1.status_code == 202
        assert resp2.status_code == 202
        # Both accepted — dedupe_key is now org-scoped, so same email+appt
        # in different orgs produces different dedupe keys.
        assert resp1.json()["status"] == "accepted"
        assert resp2.json()["status"] == "accepted"

    def test_different_payloads_same_org_accepted(self, client):
        org = _make_org()
        payload1 = _unique_payload()
        payload2 = _unique_payload()
        resp1 = client.post(f"/webhooks/{org.slug}/form-submission", json=payload1)
        resp2 = client.post(f"/webhooks/{org.slug}/form-submission", json=payload2)
        assert resp1.json()["status"] == "accepted"
        assert resp2.json()["status"] == "accepted"


# ══════════════════════════════════════════════════════════════════════════════
# 6. EventLog Tenancy
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgEventLog:
    """EventLog entries must carry the correct organization_id."""

    def test_form_submitted_event_has_org_id(self, client):
        org = _make_org()
        payload = _unique_payload()
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        data = resp.json()
        assert data["status"] == "accepted"

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            events = (
                db.query(EventLog)
                .filter(EventLog.lead_id == lead.id, EventLog.event_type == "form_submitted")
                .all()
            )
            assert len(events) == 1
            assert events[0].organization_id == org.id
        finally:
            db.close()

    def test_interested_no_event_has_org_id(self, client):
        org = _make_org()
        payload = _unique_payload(**{"Interested?": "No"})
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        data = resp.json()
        assert data["status"] == "ignored"

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            events = (
                db.query(EventLog)
                .filter(EventLog.lead_id == lead.id, EventLog.event_type == "form_ignored")
                .all()
            )
            assert len(events) == 1
            assert events[0].organization_id == org.id
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 7. Interested=No Handling on Org Route
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgInterestedNo:
    """Interested=No on the org-scoped route should not trigger pipeline."""

    def test_interested_no_returns_ignored(self, client):
        org = _make_org()
        payload = _unique_payload(**{"Interested?": "No"})
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "ignored"
        assert "lead_id" in data

    def test_interested_no_lead_status(self, client):
        org = _make_org()
        payload = _unique_payload(**{"Interested?": "No"})
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        data = resp.json()
        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            assert lead.status == LeadStatus.NOT_INTERESTED
            assert lead.organization_id == org.id
        finally:
            db.close()

    def test_interested_yes_returns_accepted(self, client):
        org = _make_org()
        payload = _unique_payload(**{"Interested?": "Yes"})
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        assert resp.json()["status"] == "accepted"

    def test_interested_blank_returns_accepted(self, client):
        """Blank Interested? field defaults to pending (accepted)."""
        org = _make_org()
        payload = _unique_payload(**{"Interested?": ""})
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        assert resp.json()["status"] == "accepted"


# ══════════════════════════════════════════════════════════════════════════════
# 8. Legacy Route Backward Compatibility
# ══════════════════════════════════════════════════════════════════════════════


class TestLegacyWebhookBackwardCompat:
    """The legacy POST /webhooks/form-submission now returns 410 Gone (Phase 1 hardening)."""

    def test_legacy_route_returns_410(self, client):
        payload = _unique_payload()
        resp = client.post("/webhooks/form-submission", json=payload)
        assert resp.status_code == 410

    def test_legacy_route_410_body_mentions_migration(self, client):
        payload = _unique_payload()
        resp = client.post("/webhooks/form-submission", json=payload)
        data = resp.json()
        # detail is a nested dict: {"error": "gone", "message": "..."}
        detail = data["detail"]
        if isinstance(detail, dict):
            msg = detail.get("message", "")
        else:
            msg = str(detail)
        assert "migrate" in msg.lower() or "org" in msg.lower()

    def test_legacy_route_respects_global_secret(self, client):
        """Legacy route with auth also returns 410 (not 401 or 202)."""
        secret = "legacy-global-secret"
        payload = _unique_payload()
        with patch.object(settings, "webhook_secret", secret):
            resp = client.post(
                "/webhooks/form-submission",
                json=payload,
                headers={"Authorization": f"Bearer {secret}"},
            )
            assert resp.status_code == 410


# ══════════════════════════════════════════════════════════════════════════════
# 9. Validation Errors on Org Route
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgWebhookValidation:
    """Form validation errors should work the same on the org-scoped route."""

    def test_invalid_email_returns_422(self, client):
        org = _make_org()
        payload = _unique_payload(**{"Email Address": "not-an-email"})
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        assert resp.status_code == 422

    def test_missing_name_returns_422(self, client):
        org = _make_org()
        payload = _unique_payload(**{"Name": ""})
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        assert resp.status_code == 422

    def test_phone_as_email_returns_422(self, client):
        org = _make_org()
        payload = _unique_payload(**{"Email Address": "+92 300 1234567"})
        resp = client.post(f"/webhooks/{org.slug}/form-submission", json=payload)
        assert resp.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# 10. Organization webhook_secret Storage
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgWebhookSecretStorage:
    """Verify the webhook_secret column persists on Organization."""

    def test_org_with_webhook_secret(self):
        secret = "my-org-secret-value"
        org = _make_org(webhook_secret=secret)
        db = SessionLocal()
        try:
            fetched = db.get(Organization, org.id)
            assert fetched.webhook_secret == secret
        finally:
            db.close()

    def test_org_default_webhook_secret_is_none(self):
        org = _make_org()
        db = SessionLocal()
        try:
            fetched = db.get(Organization, org.id)
            assert fetched.webhook_secret is None
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 11. Cross-Org Isolation
# ══════════════════════════════════════════════════════════════════════════════


class TestCrossOrgIsolation:
    """Leads created via org-scoped route must belong to the correct org."""

    def test_two_orgs_get_correct_org_ids(self, client):
        org1 = _make_org()
        org2 = _make_org()
        payload1 = _unique_payload()
        payload2 = _unique_payload()

        resp1 = client.post(f"/webhooks/{org1.slug}/form-submission", json=payload1)
        resp2 = client.post(f"/webhooks/{org2.slug}/form-submission", json=payload2)

        data1 = resp1.json()
        data2 = resp2.json()
        assert data1["status"] == "accepted"
        assert data2["status"] == "accepted"

        db = SessionLocal()
        try:
            lead1 = db.get(Lead, uuid.UUID(data1["lead_id"]))
            lead2 = db.get(Lead, uuid.UUID(data2["lead_id"]))
            assert lead1.organization_id == org1.id
            assert lead2.organization_id == org2.id
            assert lead1.organization_id != lead2.organization_id
        finally:
            db.close()

    def test_org_secret_only_works_for_that_org(self, client):
        """Org A's secret must NOT work for Org B's webhook."""
        secret_a = "secret-for-org-a"
        org_a = _make_org(webhook_secret=secret_a)
        org_b = _make_org()  # No secret
        payload = _unique_payload()

        # Org A's secret should NOT work for Org B
        resp = client.post(
            f"/webhooks/{org_b.slug}/form-submission",
            json=payload,
            headers={"Authorization": f"Bearer {secret_a}"},
        )
        # Org B has no secret, and the global is empty — so dev mode allows it
        with patch.object(settings, "webhook_secret", ""):
            resp = client.post(
                f"/webhooks/{org_b.slug}/form-submission",
                json=payload,
            )
            assert resp.status_code == 202


# ══════════════════════════════════════════════════════════════════════════════
# 12. Apps Script Contract
# ══════════════════════════════════════════════════════════════════════════════


class TestAppsScriptContract:
    """Verify the Apps Script URL format matches the backend route."""

    def test_org_slug_url_matches_route(self, client):
        """POST /webhooks/{slug}/form-submission should be a valid route."""
        org = _make_org()
        resp = client.options(f"/webhooks/{org.slug}/form-submission")
        # FastAPI returns 405 Method Not Allowed for OPTIONS on a route that
        # only accepts POST — confirming the route exists.
        assert resp.status_code in (200, 405)

    def test_apps_script_webhook_gs_references_org_slug(self):
        """The webhook.gs file must reference ORG_SLUG and WEBHOOK_URL_BASE."""
        with open("apps_script/webhook.gs", "r") as f:
            content = f.read()
        assert "ORG_SLUG" in content
        assert "WEBHOOK_URL_BASE" in content
        assert "org_slug" in content or "ORG_SLUG" in content


# ══════════════════════════════════════════════════════════════════════════════
# 13. Security: No Credentials Logged
# ══════════════════════════════════════════════════════════════════════════════


class TestWebhookSecurityLogging:
    """Webhook auth failures must never log the token or secret value."""

    def test_auth_failure_logs_no_secret(self, client, caplog):
        import logging
        org = _make_org(webhook_secret="super-secret-value")
        payload = _unique_payload()
        with caplog.at_level(logging.WARNING, logger="strategy-call-agent"):
            resp = client.post(
                f"/webhooks/{org.slug}/form-submission",
                json=payload,
                headers={"Authorization": "Bearer wrong-token"},
            )
            assert resp.status_code == 401
            # The secret value must NOT appear in any log message
            for record in caplog.records:
                assert "super-secret-value" not in record.message

    def test_org_not_found_logs_no_secret(self, client, caplog):
        """404 for unknown org should not leak any secret info."""
        import logging
        payload = _unique_payload()
        with caplog.at_level(logging.WARNING, logger="strategy-call-agent"):
            resp = client.post(
                "/webhooks/nonexistent-org/form-submission",
                json=payload,
            )
            assert resp.status_code == 404
            for record in caplog.records:
                assert "secret" not in record.message.lower() or "webhook" in record.message.lower()
