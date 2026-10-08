"""Phase 1, Problem 1 — Verify the real Google Form submission path.

End-to-end tests proving that the production Google Form → Apps Script →
Webhook → Lead ingestion path works correctly.

Every test uses a realistic payload matching the EXACT format that
webhook.gs produces when triggered by a Google Form submission.

Production flow:
  Google Form
  → Apps Script (onFormSubmit reads Sheet headers, builds JSON)
  → POST /webhooks/{org_slug}/form-submission (Bearer auth)
  → Organization resolution (slug → ACTIVE org)
  → Payload normalization (form labels → canonical fields via mapping)
  → Lead creation (correct org_id, all fields populated)
  → EventLog audit trail
"""
import json
import uuid
from unittest.mock import patch

import pytest
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models import EventLog, Lead, LeadStatus
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_org(**overrides) -> Organization:
    """Insert an Organization row and return it.

    Default plan is 'starter' (has_pipeline_automation=True) so the
    Phase 27 pipeline feature gate does not block execution.
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


def _realistic_appsscript_payload(**overrides) -> dict:
    """Generate a realistic payload matching what webhook.gs actually sends.

    Source: apps_script/webhook.gs → onFormSubmit() handler.

    The Apps Script reads spreadsheet headers from Row 1 (dynamically),
    skips the auto-added 'Timestamp' column, and maps each header to its
    value as a String. It also attaches 'form_identifier' from Script
    Properties when configured.

    This payload uses the DEFAULT IT Training form labels, which map 1:1
    to the Pydantic aliases in FormSubmission (app/schemas.py) and the
    DEFAULT_FORM_FIELD_MAPPING (app/models_multi_tenant.py).
    """
    uid = uuid.uuid4().hex[:8]
    base = {
        "Interested?": "Yes",
        "Name": f"Realistic Lead {uid}",
        "Company Address": f"{uid} Innovation Blvd, Suite 100",
        "Phone Number": "+1-555-0100",
        "Direct Number": "+1-555-0101",
        "Courses": "AI Strategy Workshop, Digital Transformation",
        "Email Address": f"realistic-{uid}@example.com",
        "Scheduled Date": "2026-09-15",
        "Caller Name": "Sarah Johnson",
        "Phone Appt. Date/Time": "September 15, 2026 at 2:00 PM",
        "form_identifier": "strategy-call",
    }
    base.update(overrides)
    return base


# ══════════════════════════════════════════════════════════════════════════════
# 1. Realistic Apps Script Payload — Full Field Verification
# ══════════════════════════════════════════════════════════════════════════════


class TestRealisticAppsScriptPayload:
    """Send a realistic payload matching what webhook.gs actually produces.

    Proves: Apps Script payload → webhook → Lead with all fields correct.
    """

    def test_full_path_creates_lead_with_all_fields(self, client):
        """Complete chain: realistic payload → webhook → Lead with ALL fields.

        This is the primary proof that the real submission path works.
        Uses every standard IT Training form field.
        """
        org = _make_org()
        payload = _realistic_appsscript_payload()

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"
        assert "lead_id" in data
        assert len(data["lead_id"]) == 36  # UUID format

        # Verify EVERY field in the database
        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            assert lead is not None, "Lead must be persisted in database"

            # Core Google Form fields — mapped from question labels
            assert lead.name == payload["Name"]
            assert lead.email == payload["Email Address"]
            assert lead.phone_number == payload["Phone Number"]
            assert lead.direct_number == payload["Direct Number"]
            assert lead.courses == payload["Courses"]
            assert lead.company_address == payload["Company Address"]
            assert lead.caller_name == payload["Caller Name"]

            # Interested field — normalized to lowercase
            assert lead.interested == "yes"

            # Appointment datetime — raw string preserved
            assert lead.appt_datetime_raw == payload["Phone Appt. Date/Time"]

            # Organization — MUST match the slug's org (multi-tenant)
            assert lead.organization_id == org.id

            # Status — Initially PENDING, but the background pipeline runs
            # synchronously in TestClient and may change status to ERROR
            # (since Google credentials aren't configured in test mode).
            # The important assertion is that the Lead WAS created with
            # the correct fields and org_id — pipeline failure is expected.
            assert lead.status in (LeadStatus.PENDING, LeadStatus.ERROR)

            # Dedupe key — composite of email + appt time
            assert lead.dedupe_key is not None
            assert "|" in lead.dedupe_key
            assert lead.email.lower() in lead.dedupe_key.lower()
        finally:
            db.close()

    def test_form_identifier_silently_ignored(self, client):
        """Apps Script sends 'form_identifier' — FormSubmission ignores it.

        The form_identifier field is NOT part of FormSubmission schema.
        Pydantic v2 default extra='ignore' drops it silently.
        """
        org = _make_org()
        payload = _realistic_appsscript_payload()
        assert "form_identifier" in payload  # confirm it's present

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 202

    def test_all_values_are_strings(self, client):
        """Apps Script converts all values to String(). Backend handles this.

        Phone numbers, dates, names — all arrive as strings.
        """
        org = _make_org()
        payload = _realistic_appsscript_payload(
            **{"Phone Number": "1234567890", "Direct Number": "0987654321"}
        )

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 202
        data = resp.json()

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            assert lead.phone_number == "1234567890"
            assert lead.direct_number == "0987654321"
        finally:
            db.close()

    def test_optional_fields_can_be_empty(self, client):
        """Empty optional fields are accepted (not required by FormSubmission)."""
        org = _make_org()
        payload = _realistic_appsscript_payload(
            **{
                "Company Address": "",
                "Direct Number": "",
                "Courses": "",
                "Caller Name": "",
                "Scheduled Date": "",
            }
        )

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 202
        data = resp.json()

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            # Required fields present
            assert lead.name
            assert lead.email
            assert lead.appt_datetime_raw
            # Optional fields are None or empty
            assert lead.company_address in (None, "")
            assert lead.direct_number in (None, "")
            assert lead.courses in (None, "")
            assert lead.caller_name in (None, "")
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 2. Organization Resolution — Definitive Cross-Tenant Proof
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgResolution:
    """Prove that org identification from URL slug is correct and tamper-proof.

    The org is resolved exclusively from the URL path segment
    (/webhooks/{org_slug}/form-submission). The payload never carries
    an org identifier — it comes from the Apps Script Script Properties
    (ORG_SLUG).
    """

    def test_org_a_submission_creates_lead_for_org_a(self, client):
        """Submission to Org A's slug → Lead belongs to Org A, NOT Org B."""
        org_a = _make_org()
        org_b = _make_org()

        payload = _realistic_appsscript_payload()
        resp = client.post(
            f"/webhooks/{org_a.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 202
        lead_id = resp.json()["lead_id"]

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(lead_id))
            assert lead is not None
            assert lead.organization_id == org_a.id
            assert lead.organization_id != org_b.id
        finally:
            db.close()

    def test_org_b_submission_creates_lead_for_org_b(self, client):
        """Submission to Org B's slug → Lead belongs to Org B."""
        org_a = _make_org()
        org_b = _make_org()

        payload = _realistic_appsscript_payload()
        resp = client.post(
            f"/webhooks/{org_b.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 202
        lead_id = resp.json()["lead_id"]

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(lead_id))
            assert lead.organization_id == org_b.id
            assert lead.organization_id != org_a.id
        finally:
            db.close()

    def test_cross_org_isolation_both_leads_correct(self, client):
        """Two orgs each get their own lead — no cross-contamination."""
        org_a = _make_org()
        org_b = _make_org()

        payload_a = _realistic_appsscript_payload()
        payload_b = _realistic_appsscript_payload()

        resp_a = client.post(
            f"/webhooks/{org_a.slug}/form-submission", json=payload_a,
        )
        resp_b = client.post(
            f"/webhooks/{org_b.slug}/form-submission", json=payload_b,
        )

        assert resp_a.json()["status"] == "accepted"
        assert resp_b.json()["status"] == "accepted"

        db = SessionLocal()
        try:
            lead_a = db.get(Lead, uuid.UUID(resp_a.json()["lead_id"]))
            lead_b = db.get(Lead, uuid.UUID(resp_b.json()["lead_id"]))

            assert lead_a.organization_id == org_a.id
            assert lead_b.organization_id == org_b.id
            assert lead_a.organization_id != lead_b.organization_id
            assert lead_a.email != lead_b.email  # different UUID emails
        finally:
            db.close()

    def test_unknown_slug_returns_404(self, client):
        """Non-existent org slug → 404, no lead created anywhere."""
        payload = _realistic_appsscript_payload()
        resp = client.post(
            "/webhooks/this-slug-does-not-exist/form-submission",
            json=payload,
        )
        assert resp.status_code == 404

    def test_disabled_org_returns_404(self, client):
        """Disabled org → 404 (not 403, to avoid info leakage)."""
        org = _make_org(status=OrganizationStatus.DISABLED)
        payload = _realistic_appsscript_payload()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 404

    def test_suspended_org_returns_404(self, client):
        """Suspended org → 404."""
        org = _make_org(status=OrganizationStatus.SUSPENDED)
        payload = _realistic_appsscript_payload()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 404

    def test_no_fallback_to_default_org(self, client):
        """Org-scoped webhook NEVER falls back to _DEFAULT_ORG_ID."""
        from app.tenant import _DEFAULT_ORG_ID

        org = _make_org()
        payload = _realistic_appsscript_payload()

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 202
        lead_id = resp.json()["lead_id"]

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(lead_id))
            assert lead.organization_id == org.id
            assert lead.organization_id != _DEFAULT_ORG_ID
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 3. Webhook Authentication — Bearer Token
# ══════════════════════════════════════════════════════════════════════════════


class TestWebhookAuth:
    """Bearer token authentication on the org-scoped route.

    Org secret takes precedence over global. When org has its own
    secret, the global secret is NOT accepted (prevents cross-org auth).
    """

    def test_org_secret_accepted(self, client):
        """Valid org Bearer token → 202."""
        secret = "org-secret-" + uuid.uuid4().hex[:8]
        org = _make_org(webhook_secret=secret)
        payload = _realistic_appsscript_payload()

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": f"Bearer {secret}"},
        )
        assert resp.status_code == 202

    def test_wrong_org_secret_rejected(self, client):
        """Wrong Bearer token → 401."""
        org = _make_org(webhook_secret="correct-secret-value")
        payload = _realistic_appsscript_payload()

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401

    def test_missing_auth_when_secret_configured(self, client):
        """No auth header when org has a secret → 401."""
        org = _make_org(webhook_secret="required-secret")
        payload = _realistic_appsscript_payload()

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 401

    def test_org_secret_does_not_accept_global_fallback(self, client):
        """When org has its own secret, the global secret is NOT accepted."""
        org = _make_org(webhook_secret="org-only-secret")
        payload = _realistic_appsscript_payload()

        with patch.object(settings, "webhook_secret", "global-secret"):
            resp = client.post(
                f"/webhooks/{org.slug}/form-submission",
                json=payload,
                headers={"Authorization": "Bearer global-secret"},
            )
            assert resp.status_code == 401

    def test_global_secret_fallback_when_no_org_secret(self, client):
        """No org secret configured → global secret is accepted."""
        org = _make_org(webhook_secret=None)
        global_secret = "global-test-secret-" + uuid.uuid4().hex[:8]
        payload = _realistic_appsscript_payload()

        with patch.object(settings, "webhook_secret", global_secret):
            resp = client.post(
                f"/webhooks/{org.slug}/form-submission",
                json=payload,
                headers={"Authorization": f"Bearer {global_secret}"},
            )
            assert resp.status_code == 202

    def test_no_secret_anywhere_allows_dev_mode(self, client):
        """No secret anywhere → dev mode (unauthenticated access)."""
        org = _make_org(webhook_secret=None)
        payload = _realistic_appsscript_payload()

        with patch.object(settings, "webhook_secret", ""):
            resp = client.post(
                f"/webhooks/{org.slug}/form-submission",
                json=payload,
            )
            assert resp.status_code == 202


# ══════════════════════════════════════════════════════════════════════════════
# 4. Duplicate Submissions — Deduplication
# ══════════════════════════════════════════════════════════════════════════════


class TestDuplicateSubmissions:
    """Same email + same appointment time → deduplication.

    Dedupe key: normalized_email|normalized_appt_datetime_raw
    Enforced via unique constraint on leads.dedupe_key.
    """

    def test_same_payload_returns_duplicate(self, client):
        """Submitting identical payload twice → second is 'duplicate'."""
        org = _make_org()
        payload = _realistic_appsscript_payload()

        resp1 = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )
        resp2 = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )

        assert resp1.json()["status"] == "accepted"
        assert resp2.json()["status"] == "duplicate"
        assert resp1.status_code == 202
        assert resp2.status_code == 202

    def test_different_email_same_time_both_accepted(self, client):
        """Different email + same time → both accepted (different dedupe key)."""
        org = _make_org()
        payload1 = _realistic_appsscript_payload()
        payload2 = _realistic_appsscript_payload()

        resp1 = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload1,
        )
        resp2 = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload2,
        )

        assert resp1.json()["status"] == "accepted"
        assert resp2.json()["status"] == "accepted"

    def test_request_id_returned_on_duplicate(self, client):
        """Duplicate response includes request_id for idempotency tracking."""
        org = _make_org()
        payload = _realistic_appsscript_payload()
        request_id = str(uuid.uuid4())

        client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"X-Request-ID": request_id},
        )
        resp2 = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"X-Request-ID": request_id},
        )

        data2 = resp2.json()
        assert data2["status"] == "duplicate"
        assert data2.get("request_id") == request_id

    def test_request_id_returned_on_accepted(self, client):
        """Accepted response includes request_id when provided."""
        org = _make_org()
        payload = _realistic_appsscript_payload()
        request_id = str(uuid.uuid4())

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"X-Request-ID": request_id},
        )

        data = resp.json()
        assert data["status"] == "accepted"
        assert data.get("request_id") == request_id


# ══════════════════════════════════════════════════════════════════════════════
# 5. Interested=No Gating
# ══════════════════════════════════════════════════════════════════════════════


class TestInterestedNoGating:
    """Interested=No → lead created for observability but NOT in pipeline.

    The lead is recorded with status NOT_INTERESTED and a form_ignored
    event is logged. The pipeline background task is never started.
    """

    def test_interested_no_returns_ignored(self, client):
        """Interested? = No → status 'ignored'."""
        org = _make_org()
        payload = _realistic_appsscript_payload(**{"Interested?": "No"})

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )
        assert resp.status_code == 202
        assert resp.json()["status"] == "ignored"
        assert "lead_id" in resp.json()

    def test_interested_no_lead_status(self, client):
        """Interested? = No → Lead.status = NOT_INTERESTED."""
        org = _make_org()
        payload = _realistic_appsscript_payload(**{"Interested?": "No"})

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )
        lead_id = resp.json()["lead_id"]

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(lead_id))
            assert lead.status == LeadStatus.NOT_INTERESTED
            assert lead.organization_id == org.id
        finally:
            db.close()

    def test_interested_yes_returns_accepted(self, client):
        """Interested? = Yes → status 'accepted', enters pipeline."""
        org = _make_org()
        payload = _realistic_appsscript_payload(**{"Interested?": "Yes"})

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )
        assert resp.json()["status"] == "accepted"

    def test_interested_blank_returns_accepted(self, client):
        """Blank Interested? → defaults to pending (accepted)."""
        org = _make_org()
        payload = _realistic_appsscript_payload(**{"Interested?": ""})

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )
        assert resp.json()["status"] == "accepted"

    def test_interested_ambiguous_returns_422(self, client):
        """Ambiguous Interested? value → 422 validation error."""
        org = _make_org()
        payload = _realistic_appsscript_payload(**{"Interested?": "Maybe"})

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )
        assert resp.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# 6. Error Handling — Malformed Submissions
# ══════════════════════════════════════════════════════════════════════════════


class TestErrorHandling:
    """Malformed payloads must be rejected safely.

    The endpoint must not crash, create corrupted Leads, create Leads
    in a default organization, leak internal exceptions, or expose
    stack traces.
    """

    def test_empty_payload_returns_422(self, client):
        """Empty JSON {} → 422 (missing required fields: name, email, etc)."""
        org = _make_org()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json={},
        )
        assert resp.status_code == 422

    def test_malformed_json_returns_422(self, client):
        """Non-JSON body → 422 (Invalid JSON body)."""
        org = _make_org()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            content="this is not json at all {{{",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_missing_email_returns_422(self, client):
        """Missing Email Address → 422."""
        org = _make_org()
        payload = _realistic_appsscript_payload()
        del payload["Email Address"]

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 422

    def test_missing_name_returns_422(self, client):
        """Missing Name → 422."""
        org = _make_org()
        payload = _realistic_appsscript_payload()
        del payload["Name"]

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 422

    def test_missing_appt_datetime_returns_422(self, client):
        """Missing Phone Appt. Date/Time → 422."""
        org = _make_org()
        payload = _realistic_appsscript_payload()
        del payload["Phone Appt. Date/Time"]

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 422

    def test_invalid_email_returns_422(self, client):
        """Invalid email format → 422."""
        org = _make_org()
        payload = _realistic_appsscript_payload(
            **{"Email Address": "not-an-email"},
        )

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 422

    def test_phone_as_email_returns_422(self, client):
        """Phone number in email field → 422 with helpful error."""
        org = _make_org()
        payload = _realistic_appsscript_payload(
            **{"Email Address": "+92 300 1234567"},
        )

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 422

    def test_empty_name_returns_422(self, client):
        """Empty Name → 422."""
        org = _make_org()
        payload = _realistic_appsscript_payload(**{"Name": ""})

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 422

    def test_placeholder_email_returns_422(self, client):
        """Placeholder email (n/a, na, none, etc) → 422."""
        org = _make_org()
        payload = _realistic_appsscript_payload(**{"Email Address": "n/a"})

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 422

    def test_no_stack_trace_in_error_response(self, client):
        """422 response must not contain stack traces or internal details."""
        org = _make_org()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json={},
        )
        assert resp.status_code == 422
        body = resp.text.lower()
        assert "traceback" not in body
        assert "stack trace" not in body

    def test_no_lead_created_on_validation_failure(self, client):
        """Failed validation → no Lead row created in the database."""
        org = _make_org()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json={"garbage": "data"},
        )
        assert resp.status_code == 422

        # Confirm no Lead was created for this org
        db = SessionLocal()
        try:
            count = db.query(Lead).filter(
                Lead.organization_id == org.id,
            ).count()
            assert count == 0
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 7. EventLog Audit Trail
# ══════════════════════════════════════════════════════════════════════════════


class TestEventLogAuditTrail:
    """Every webhook submission must be logged for audit trail.

    Events: form_submitted (accepted), form_ignored (interested=no).
    Each event carries the correct organization_id.
    """

    def test_form_submitted_event_logged(self, client):
        """Accepted submission → form_submitted event with org_id."""
        org = _make_org()
        payload = _realistic_appsscript_payload()

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )
        lead_id = resp.json()["lead_id"]

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(lead_id))
            events = (
                db.query(EventLog)
                .filter(
                    EventLog.lead_id == lead.id,
                    EventLog.event_type == "form_submitted",
                )
                .all()
            )
            assert len(events) == 1
            assert events[0].organization_id == org.id
        finally:
            db.close()

    def test_interested_no_event_logged(self, client):
        """Ignored submission → form_ignored event with org_id."""
        org = _make_org()
        payload = _realistic_appsscript_payload(**{"Interested?": "No"})

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )
        lead_id = resp.json()["lead_id"]

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(lead_id))
            events = (
                db.query(EventLog)
                .filter(
                    EventLog.lead_id == lead.id,
                    EventLog.event_type == "form_ignored",
                )
                .all()
            )
            assert len(events) == 1
            assert events[0].organization_id == org.id
        finally:
            db.close()

    def test_event_payload_contains_dedupe_key(self, client):
        """form_submitted event includes dedupe_key for tracing."""
        org = _make_org()
        payload = _realistic_appsscript_payload()

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission", json=payload,
        )
        lead_id = resp.json()["lead_id"]

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(lead_id))
            event = (
                db.query(EventLog)
                .filter(
                    EventLog.lead_id == lead.id,
                    EventLog.event_type == "form_submitted",
                )
                .first()
            )
            assert event is not None
            payload_data = json.loads(event.payload)
            assert "dedupe_key" in payload_data
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 8. Legacy Endpoint — 410 Gone
# ══════════════════════════════════════════════════════════════════════════════


class TestLegacyEndpoint:
    """Legacy /webhooks/form-submission returns 410 Gone (Phase 1 hardening).

    Apps Script must use POST /webhooks/{org_slug}/form-submission.
    """

    def test_legacy_returns_410(self, client):
        """POST /webhooks/form-submission → 410 Gone."""
        payload = _realistic_appsscript_payload()
        resp = client.post("/webhooks/form-submission", json=payload)
        assert resp.status_code == 410

    def test_legacy_with_auth_still_410(self, client):
        """Even with valid auth, legacy endpoint → 410 (not 401 or 202)."""
        secret = "legacy-secret-value"
        payload = _realistic_appsscript_payload()

        with patch.object(settings, "webhook_secret", secret):
            resp = client.post(
                "/webhooks/form-submission",
                json=payload,
                headers={"Authorization": f"Bearer {secret}"},
            )
            assert resp.status_code == 410

    def test_legacy_410_body_mentions_migration(self, client):
        """410 response body tells caller to migrate to org-scoped route."""
        payload = _realistic_appsscript_payload()
        resp = client.post("/webhooks/form-submission", json=payload)
        data = resp.json()
        detail = data.get("detail", "")
        if isinstance(detail, dict):
            msg = detail.get("message", "")
        else:
            msg = str(detail)
        assert "migrate" in msg.lower() or "org" in msg.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 9. Apps Script Contract Verification
# ══════════════════════════════════════════════════════════════════════════════


class TestAppsScriptContract:
    """Verify that the backend implements what Apps Script expects.

    The Apps Script (webhook.gs) sends:
    - POST /webhooks/{org_slug}/form-submission
    - Content-Type: application/json
    - Authorization: Bearer {WEBHOOK_SECRET}
    - X-Request-ID: {UUID}
    - X-Webhook-Source: apps-script
    - Body: JSON with form question labels as keys
    """

    def test_org_slug_url_matches_route(self, client):
        """POST /webhooks/{slug}/form-submission is a valid route."""
        org = _make_org()
        payload = _realistic_appsscript_payload()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        # Should not be 404 (route exists)
        assert resp.status_code != 404 or "not found" not in resp.text.lower()

    def test_apps_script_source_header_accepted(self, client):
        """X-Webhook-Source: apps-script header is accepted."""
        org = _make_org()
        payload = _realistic_appsscript_payload()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"X-Webhook-Source": "apps-script"},
        )
        assert resp.status_code == 202

    def test_request_id_header_tracked(self, client):
        """X-Request-ID header is tracked in response."""
        org = _make_org()
        payload = _realistic_appsscript_payload()
        request_id = str(uuid.uuid4())

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"X-Request-ID": request_id},
        )
        assert resp.status_code == 202
        assert resp.json().get("request_id") == request_id

    def test_content_type_json_accepted(self, client):
        """Content-Type: application/json is accepted."""
        org = _make_org()
        payload = _realistic_appsscript_payload()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 202
