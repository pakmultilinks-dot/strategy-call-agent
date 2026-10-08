"""Step 2A — Focused tests for Google Form / Sheet flexibility.

Verifies that organizations can use different Google Forms / Sheet
column structures without breaking the ingestion pipeline.

Tests:
  1. Existing IT Training form labels continue to work
  2. Different headers (non-default labels) work with custom mapping
  3. Reordered columns work
  4. Extra columns are handled gracefully
  5. Missing optional fields do not break ingestion
  6. Organization-specific mappings are isolated
  7. Unknown/unmapped labels are ignored without crashing
  8. Existing webhook endpoint compatibility
  9. Security — no credentials exposed
 10. Regression — existing tests still pass
"""
import uuid

import pytest
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Lead
from app.models_multi_tenant import (
    DEFAULT_FORM_FIELD_MAPPING,
    OrgFormFieldMapping,
    Organization,
    OrganizationStatus,
    REQUIRED_LEAD_FIELDS,
    VALID_LEAD_FIELDS,
    User,
    UserRole,
    UserStatus,
)
from app.schemas import FormSubmission
from app.services.field_mapping_resolver import (
    invalidate_mapping_cache,
    load_field_mapping,
    map_payload_to_fields,
    validate_mapping_config,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_org(**overrides) -> Organization:
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


def _seed_custom_mapping(org_id, mapping_dict):
    """Seed a custom mapping {form_label: lead_field} for an org."""
    db = SessionLocal()
    try:
        for i, (label, field) in enumerate(mapping_dict.items()):
            db.add(OrgFormFieldMapping(
                organization_id=org_id,
                form_label=label,
                lead_field=field,
                is_required=field in REQUIRED_LEAD_FIELDS,
                display_order=i,
            ))
        db.commit()
    finally:
        db.close()
    invalidate_mapping_cache(org_id)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Existing IT Training form labels — backward compatibility
# ══════════════════════════════════════════════════════════════════════════════


class TestExistingFormat:
    """Test 1: The default IT Training form labels continue to work."""

    def test_default_payload_via_from_webhook_payload(self):
        """Default labels with default mapping produce a valid FormSubmission."""
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Interested?": "Yes",
            "Name": "Jane Doe",
            "Company Address": "123 Main St",
            "Phone Number": "555-0001",
            "Direct Number": "555-0002",
            "Courses": "Python, Docker",
            "Email Address": f"jane-{uid}@example.com",
            "Scheduled Date": "next week",
            "Caller Name": "Agent Smith",
            "Phone Appt. Date/Time": "next Tuesday 10:00 AM",
            "Scheduled Date and Time": "next Tuesday 10:00 AM",
            "Date": "next Tuesday",
            "Time": "10:00 AM",
        }
        sub = FormSubmission.from_webhook_payload(payload, DEFAULT_FORM_FIELD_MAPPING)
        assert sub.name == "Jane Doe"
        assert sub.email == f"jane-{uid}@example.com"
        assert sub.appt_datetime_raw == "next Tuesday 10:00 AM"
        assert sub.interested == "yes"
        assert sub.company_address == "123 Main St"
        assert sub.phone_number == "555-0001"
        assert sub.courses == "Python, Docker"

    def test_default_payload_via_legacy_aliases(self):
        """Default labels with empty mapping fall back to Pydantic aliases."""
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Interested?": "Yes",
            "Name": "Legacy User",
            "Email Address": f"legacy-{uid}@example.com",
            "Phone Appt. Date/Time": "tomorrow 2pm",
        }
        sub = FormSubmission.from_webhook_payload(payload, {})
        assert sub.name == "Legacy User"
        assert sub.email == f"legacy-{uid}@example.com"
        assert sub.appt_datetime_raw == "tomorrow 2pm"

    def test_minimum_required_fields(self):
        """Only name, email, appt_datetime_raw are required."""
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Name": "Min User",
            "Email Address": f"min-{uid}@example.com",
            "Phone Appt. Date/Time": "tomorrow 3pm",
        }
        sub = FormSubmission.from_webhook_payload(payload, DEFAULT_FORM_FIELD_MAPPING)
        assert sub.name == "Min User"
        assert sub.email == f"min-{uid}@example.com"
        assert sub.appt_datetime_raw == "tomorrow 3pm"
        # Optional fields should be None
        assert sub.company_address is None
        assert sub.phone_number is None
        assert sub.courses is None


# ══════════════════════════════════════════════════════════════════════════════
# 2. Different headers — non-default form labels with custom mapping
# ══════════════════════════════════════════════════════════════════════════════


class TestDifferentHeaders:
    """Test 2: Forms with completely different question names work via mapping."""

    def test_full_name_contact_email_whatsapp(self):
        """Organization using 'Full Name', 'Contact Email', 'WhatsApp' etc."""
        uid = uuid.uuid4().hex[:8]
        custom_mapping = {
            "Full Name": "name",
            "Contact Email": "email",
            "WhatsApp": "phone_number",
            "Business Name": "company_address",
            "Service Required": "courses",
            "Preferred Date": "appt_datetime_raw",
            "Interested": "interested",
        }
        payload = {
            "Full Name": "Ahmed Khan",
            "Contact Email": f"ahmed-{uid}@example.com",
            "WhatsApp": "+92-300-1234567",
            "Business Name": "Khan Trading Co.",
            "Service Required": "Export Consulting",
            "Preferred Date": "Friday 2pm",
            "Interested": "Yes",
        }
        sub = FormSubmission.from_webhook_payload(payload, custom_mapping)
        assert sub.name == "Ahmed Khan"
        assert sub.email == f"ahmed-{uid}@example.com"
        assert sub.appt_datetime_raw == "Friday 2pm"
        assert sub.phone_number == "+92-300-1234567"
        assert sub.company_address == "Khan Trading Co."
        assert sub.courses == "Export Consulting"

    def test_applicant_name_email_mobile(self):
        """Another org uses 'Applicant Name', 'Email', 'Mobile Number'."""
        uid = uuid.uuid4().hex[:8]
        custom_mapping = {
            "Applicant Name": "name",
            "Email": "email",
            "Mobile Number": "phone_number",
            "Organization": "company_address",
            "Requirements": "courses",
            "Date and Time": "appt_datetime_raw",
        }
        payload = {
            "Applicant Name": "Maria Garcia",
            "Email": f"maria-{uid}@example.com",
            "Mobile Number": "+34-612-345678",
            "Organization": "Garcia SL",
            "Requirements": "Digital Marketing",
            "Date and Time": "Wednesday 11am",
        }
        sub = FormSubmission.from_webhook_payload(payload, custom_mapping)
        assert sub.name == "Maria Garcia"
        assert sub.email == f"maria-{uid}@example.com"
        assert sub.appt_datetime_raw == "Wednesday 11am"
        assert sub.phone_number == "+34-612-345678"
        assert sub.company_address == "Garcia SL"

    def test_customer_email_mobile_minimal(self):
        """Minimal form with only 'Customer', 'Email Address', 'Mobile'."""
        uid = uuid.uuid4().hex[:8]
        custom_mapping = {
            "Customer": "name",
            "Email Address": "email",
            "Mobile": "phone_number",
            "Appointment": "appt_datetime_raw",
        }
        payload = {
            "Customer": "John Smith",
            "Email Address": f"john-{uid}@example.com",
            "Mobile": "555-9999",
            "Appointment": "next Monday 9am",
        }
        sub = FormSubmission.from_webhook_payload(payload, custom_mapping)
        assert sub.name == "John Smith"
        assert sub.email == f"john-{uid}@example.com"
        assert sub.appt_datetime_raw == "next Monday 9am"
        assert sub.phone_number == "555-9999"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Reordered columns — column order must not matter
# ══════════════════════════════════════════════════════════════════════════════


class TestReorderedColumns:
    """Test 3: Column order in the payload should not affect the result."""

    def test_reversed_order(self):
        """Payload keys in reverse order produce the same FormSubmission."""
        uid = uuid.uuid4().hex[:8]
        custom_mapping = {
            "Full Name": "name",
            "Contact Email": "email",
            "Appointment": "appt_datetime_raw",
        }
        # Normal order
        payload_normal = {
            "Full Name": "Alice",
            "Contact Email": f"alice-{uid}@example.com",
            "Appointment": "tomorrow 10am",
        }
        # Reversed order
        payload_reversed = {
            "Appointment": "tomorrow 10am",
            "Contact Email": f"alice-{uid}@example.com",
            "Full Name": "Alice",
        }
        sub_normal = FormSubmission.from_webhook_payload(payload_normal, custom_mapping)
        sub_reversed = FormSubmission.from_webhook_payload(payload_reversed, custom_mapping)
        assert sub_normal.name == sub_reversed.name
        assert sub_normal.email == sub_reversed.email
        assert sub_normal.appt_datetime_raw == sub_reversed.appt_datetime_raw

    def test_shuffled_order_with_extra_fields(self):
        """Shuffled order with extra unmapped fields still works."""
        uid = uuid.uuid4().hex[:8]
        custom_mapping = {
            "Name": "name",
            "Email": "email",
            "Date": "appt_datetime_raw",
        }
        payload = {
            "Notes": "referred by friend",
            "Date": "Friday 3pm",
            "Budget": "$5000",
            "Name": "Bob",
            "Email": f"bob-{uid}@example.com",
        }
        sub = FormSubmission.from_webhook_payload(payload, custom_mapping)
        assert sub.name == "Bob"
        assert sub.email == f"bob-{uid}@example.com"
        assert sub.appt_datetime_raw == "Friday 3pm"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Extra columns — additional Sheet columns do not break ingestion
# ══════════════════════════════════════════════════════════════════════════════


class TestExtraColumns:
    """Test 4: Extra Sheet columns are ignored gracefully."""

    def test_extra_columns_ignored(self):
        """Payload with extra unmapped fields still produces valid submission."""
        uid = uuid.uuid4().hex[:8]
        custom_mapping = {
            "Full Name": "name",
            "Email": "email",
            "Appointment": "appt_datetime_raw",
        }
        payload = {
            "Full Name": "Carlos",
            "Email": f"carlos-{uid}@example.com",
            "Appointment": "next week",
            "Budget": "$10,000",
            "Country": "Brazil",
            "Preferred Language": "Portuguese",
            "How did you hear about us?": "Google",
            "Notes": "VIP client",
        }
        sub = FormSubmission.from_webhook_payload(payload, custom_mapping)
        assert sub.name == "Carlos"
        assert sub.email == f"carlos-{uid}@example.com"
        assert sub.appt_datetime_raw == "next week"

    def test_many_extra_columns(self):
        """Payload with 10+ extra columns still works."""
        uid = uuid.uuid4().hex[:8]
        custom_mapping = {
            "Name": "name",
            "Email": "email",
            "DateTime": "appt_datetime_raw",
        }
        payload = {
            "Name": "Dave",
            "Email": f"dave-{uid}@example.com",
            "DateTime": "tomorrow",
        }
        # Add 15 extra columns
        for i in range(15):
            payload[f"Extra Field {i}"] = f"value_{i}"

        sub = FormSubmission.from_webhook_payload(payload, custom_mapping)
        assert sub.name == "Dave"
        assert sub.email == f"dave-{uid}@example.com"
        assert sub.appt_datetime_raw == "tomorrow"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Missing optional fields — do not break ingestion
# ══════════════════════════════════════════════════════════════════════════════


class TestMissingOptionalFields:
    """Test 5: Missing optional columns do not break ingestion."""

    def test_only_required_fields_mapped(self):
        """Mapping with only name, email, appt_datetime_raw — no optionals."""
        uid = uuid.uuid4().hex[:8]
        custom_mapping = {
            "Full Name": "name",
            "Contact Email": "email",
            "Preferred Date": "appt_datetime_raw",
        }
        payload = {
            "Full Name": "Eve",
            "Contact Email": f"eve-{uid}@example.com",
            "Preferred Date": "Thursday 1pm",
        }
        sub = FormSubmission.from_webhook_payload(payload, custom_mapping)
        assert sub.name == "Eve"
        assert sub.email == f"eve-{uid}@example.com"
        assert sub.appt_datetime_raw == "Thursday 1pm"
        # Optional fields should be None
        assert sub.company_address is None
        assert sub.phone_number is None
        assert sub.direct_number is None
        assert sub.courses is None
        assert sub.caller_name is None
        assert sub.scheduled_date is None
        assert sub.interested is None

    def test_partial_optional_fields(self):
        """Some optional fields present, others absent."""
        uid = uuid.uuid4().hex[:8]
        custom_mapping = {
            "Name": "name",
            "Email": "email",
            "Date": "appt_datetime_raw",
            "Phone": "phone_number",
        }
        payload = {
            "Name": "Frank",
            "Email": f"frank-{uid}@example.com",
            "Date": "Monday 9am",
            "Phone": "555-1234",
            # No company, no courses, etc.
        }
        sub = FormSubmission.from_webhook_payload(payload, custom_mapping)
        assert sub.name == "Frank"
        assert sub.phone_number == "555-1234"
        assert sub.company_address is None
        assert sub.courses is None


# ══════════════════════════════════════════════════════════════════════════════
# 6. Organization-specific mappings — isolation
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgIsolation:
    """Test 6: Org A mapping must not affect Org B."""

    def test_different_orgs_different_mappings(self):
        """Two orgs with different mappings produce different translations."""
        org_a = _make_org()
        org_b = _make_org()

        mapping_a = {"Full Name": "name", "Contact": "email", "When": "appt_datetime_raw"}
        mapping_b = {"Applicant": "name", "Email": "email", "Date": "appt_datetime_raw"}

        _seed_custom_mapping(org_a.id, mapping_a)
        _seed_custom_mapping(org_b.id, mapping_b)

        # Load and verify independence
        db = SessionLocal()
        try:
            m_a = load_field_mapping(db, org_a.id)
            m_b = load_field_mapping(db, org_b.id)
            assert m_a == mapping_a
            assert m_b == mapping_b
        finally:
            db.close()

    def test_org_a_payload_rejected_by_org_b_mapping(self):
        """Org A's form labels don't work with Org B's mapping."""
        uid = uuid.uuid4().hex[:8]
        mapping_a = {"Full Name": "name", "Contact": "email", "When": "appt_datetime_raw"}
        mapping_b = {"Applicant": "name", "Email": "email", "Date": "appt_datetime_raw"}

        payload_a = {
            "Full Name": "Test User",
            "Contact": f"test-{uid}@example.com",
            "When": "tomorrow",
        }
        # Using Org A's payload with Org B's mapping — none of Org A's
        # labels match Org B's mapping, so required fields are missing.
        # Pydantic should reject the submission.
        with pytest.raises(Exception):  # ValidationError
            FormSubmission.from_webhook_payload(payload_a, mapping_b)

    def test_deleting_one_org_mapping_does_not_affect_other(self):
        """Deleting Org A's mapping doesn't change Org B's."""
        org_a = _make_org()
        org_b = _make_org()

        mapping_a = {"Name": "name", "Email": "email", "Date": "appt_datetime_raw"}
        mapping_b = {"Full Name": "name", "Contact": "email", "When": "appt_datetime_raw"}

        _seed_custom_mapping(org_a.id, mapping_a)
        _seed_custom_mapping(org_b.id, mapping_b)

        # Delete Org A's mapping
        db = SessionLocal()
        try:
            db.query(OrgFormFieldMapping).filter(
                OrgFormFieldMapping.organization_id == org_a.id
            ).delete()
            db.commit()
        finally:
            db.close()
        invalidate_mapping_cache(org_a.id)

        # Org B's mapping should be unaffected
        db = SessionLocal()
        try:
            m_a = load_field_mapping(db, org_a.id)
            m_b = load_field_mapping(db, org_b.id)
            assert m_a == DEFAULT_FORM_FIELD_MAPPING  # Fallback to default
            assert m_b == mapping_b
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 7. Unknown/unmapped labels — must not crash
# ══════════════════════════════════════════════════════════════════════════════


class TestUnknownLabels:
    """Test 7: Unknown labels are ignored without crashing."""

    def test_all_unknown_labels(self):
        """Payload where no labels match the mapping — Pydantic rejects it."""
        uid = uuid.uuid4().hex[:8]
        custom_mapping = {
            "Name": "name",
            "Email": "email",
            "Date": "appt_datetime_raw",
        }
        payload = {
            "Field A": "value1",
            "Field B": "value2",
            "Field C": "value3",
        }
        # None of the payload labels are in the mapping — required fields missing
        with pytest.raises(Exception):  # ValidationError
            FormSubmission.from_webhook_payload(payload, custom_mapping)

    def test_mixed_known_and_unknown_labels(self):
        """Some labels match, some don't — only matching ones are mapped."""
        uid = uuid.uuid4().hex[:8]
        custom_mapping = {
            "Name": "name",
            "Email": "email",
            "Date": "appt_datetime_raw",
        }
        payload = {
            "Name": "Grace",
            "Email": f"grace-{uid}@example.com",
            "Date": "tomorrow 2pm",
            "Unknown Field": "should be ignored",
            "Another Unknown": "also ignored",
        }
        sub = FormSubmission.from_webhook_payload(payload, custom_mapping)
        assert sub.name == "Grace"
        assert sub.email == f"grace-{uid}@example.com"
        assert sub.appt_datetime_raw == "tomorrow 2pm"


# ══════════════════════════════════════════════════════════════════════════════
# 8. Existing webhook endpoint compatibility
# ══════════════════════════════════════════════════════════════════════════════


class TestWebhookCompatibility:
    """Test 8: The existing webhook endpoint continues to work."""

    def test_org_scoped_webhook_with_default_labels(self, client):
        """Org-scoped webhook with IT Training labels still works."""
        from app.config import settings
        org = _make_org(webhook_secret="test-secret-123")
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Interested?": "Yes",
            "Name": "Webhook Test User",
            "Email Address": f"wh-{uid}@example.com",
            "Phone Appt. Date/Time": "tomorrow 3pm",
        }
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": "Bearer test-secret-123"},
        )
        assert resp.status_code == 202
        assert resp.json()["status"] in ("accepted", "duplicate")

    def test_org_scoped_webhook_with_custom_labels(self, client):
        """Org-scoped webhook with custom labels and custom mapping works."""
        org = _make_org(webhook_secret="test-secret-456")
        custom_mapping = {
            "Full Name": "name",
            "Contact Email": "email",
            "Appointment": "appt_datetime_raw",
        }
        _seed_custom_mapping(org.id, custom_mapping)
        invalidate_mapping_cache(org.id)

        uid = uuid.uuid4().hex[:8]
        payload = {
            "Full Name": "Custom User",
            "Contact Email": f"custom-{uid}@example.com",
            "Appointment": "next Friday 2pm",
        }
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": "Bearer test-secret-456"},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] in ("accepted", "duplicate")

        # Verify the Lead was created with correct canonical fields
        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            assert lead is not None
            assert lead.name == "Custom User"
            assert lead.email == f"custom-{uid}@example.com"
            assert lead.organization_id == org.id
        finally:
            db.close()

    def test_legacy_webhook_returns_410(self, client):
        """Legacy /webhooks/form-submission returns 410 Gone (Phase 1 hardening)."""
        resp = client.post(
            "/webhooks/form-submission",
            json={
                "Name": "Legacy",
                "Email Address": "a@b.com",
                "Phone Appt. Date/Time": "tomorrow",
            },
        )
        assert resp.status_code == 410


# ══════════════════════════════════════════════════════════════════════════════
# 9. Security — no credentials exposed
# ══════════════════════════════════════════════════════════════════════════════


class TestSecurity:
    """Test 9: No sensitive credentials or unauthorized data are introduced."""

    def test_webhook_rejects_invalid_secret(self, client):
        """Invalid bearer token is rejected when webhook_secret is enforced."""
        from unittest.mock import patch
        from app.config import settings
        org = _make_org(webhook_secret="real-secret-789")
        with patch.object(settings, "webhook_secret", "real-secret-789"):
            resp = client.post(
                f"/webhooks/{org.slug}/form-submission",
                json={"Name": "Test", "Email Address": "a@b.com", "Phone Appt. Date/Time": "now"},
                headers={"Authorization": "Bearer wrong-secret"},
            )
            assert resp.status_code == 401

    def test_webhook_rejects_no_auth(self, client):
        """Missing authorization header is rejected when webhook_secret is enforced."""
        from unittest.mock import patch
        from app.config import settings
        org = _make_org(webhook_secret="some-secret")
        with patch.object(settings, "webhook_secret", "some-secret"):
            resp = client.post(
                f"/webhooks/{org.slug}/form-submission",
                json={"Name": "Test"},
            )
            assert resp.status_code == 401

    def test_mapping_not_leaked_across_orgs(self):
        """Org A cannot see Org B's custom mapping via the API."""
        from fastapi.testclient import TestClient
        from app.main import app
        from app.models_multi_tenant import User as UserModel, UserRole as UserRoleEnum, UserStatus as UserStatusEnum
        from app.auth import hash_password
        from jose import jwt as jose_jwt

        org_a = _make_org()
        org_b = _make_org()

        mapping_a = {"Custom A": "name", "Email A": "email", "Date A": "appt_datetime_raw"}
        mapping_b = {"Custom B": "name", "Email B": "email", "Date B": "appt_datetime_raw"}

        _seed_custom_mapping(org_a.id, mapping_a)
        _seed_custom_mapping(org_b.id, mapping_b)

        # Create users for each org
        db = SessionLocal()
        try:
            user_a = UserModel(
                organization_id=org_a.id,
                email=f"user-a-{uuid.uuid4().hex[:8]}@example.com",
                password_hash=hash_password("TestPass123!"),
                full_name="User A",
                role=UserRoleEnum.OWNER,
                status=UserStatusEnum.ACTIVE,
            )
            db.add(user_a)
            db.commit()
            db.refresh(user_a)
        finally:
            db.close()

        # Create JWT for Org A user
        jwt_payload = {
            "sub": str(user_a.id),
            "org_id": str(org_a.id),
            "role": "owner",
            "exp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc) + __import__("datetime").timedelta(hours=1),
            "iat": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            "jti": str(uuid.uuid4()),
        }
        from app.config import settings
        token = jose_jwt.encode(jwt_payload, settings.jwt_secret_key, algorithm="HS256")

        client = TestClient(app)
        resp = client.get(
            "/dashboard/api/form-field-mappings",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Org A should see its own mapping, not Org B's
        returned_labels = {m["form_label"] for m in data["mappings"]}
        assert "Custom A" in returned_labels
        assert "Custom B" not in returned_labels


# ══════════════════════════════════════════════════════════════════════════════
# 10. map_payload_to_fields consistency
# ══════════════════════════════════════════════════════════════════════════════


class TestMapPayloadConsistency:
    """Verify map_payload_to_fields and from_webhook_payload agree."""

    def test_same_result_for_custom_mapping(self):
        """map_payload_to_fields and from_webhook_payload produce same canonical fields."""
        uid = uuid.uuid4().hex[:8]
        custom_mapping = {
            "Full Name": "name",
            "Contact Email": "email",
            "Appointment": "appt_datetime_raw",
            "Phone": "phone_number",
        }
        payload = {
            "Full Name": "Test",
            "Contact Email": f"test-{uid}@example.com",
            "Appointment": "tomorrow",
            "Phone": "555-1234",
            "Extra Field": "ignored",
        }
        mapped = map_payload_to_fields(payload, custom_mapping)
        assert mapped == {
            "name": "Test",
            "email": f"test-{uid}@example.com",
            "appt_datetime_raw": "tomorrow",
            "phone_number": "555-1234",
        }

    def test_validate_rejects_invalid_lead_field(self):
        """Mapping with invalid lead_field is rejected."""
        errors = validate_mapping_config([
            {"form_label": "Name", "lead_field": "nonexistent_field"},
        ])
        assert len(errors) > 0
        assert "nonexistent_field" in errors[0]

    def test_validate_rejects_missing_required(self):
        """Mapping missing required fields is rejected."""
        errors = validate_mapping_config([
            {"form_label": "Name", "lead_field": "name"},
            {"form_label": "Email", "lead_field": "email"},
            # Missing appt_datetime_raw
        ])
        assert len(errors) > 0
        assert any("appt_datetime_raw" in e for e in errors)

    def test_validate_accepts_valid_config(self):
        """Valid mapping configuration passes validation."""
        errors = validate_mapping_config([
            {"form_label": "Full Name", "lead_field": "name"},
            {"form_label": "Contact Email", "lead_field": "email"},
            {"form_label": "Appointment Date", "lead_field": "appt_datetime_raw"},
            {"form_label": "Phone", "lead_field": "phone_number"},
        ])
        assert errors == []


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2B — End-to-end webhook-level flexibility tests
# ══════════════════════════════════════════════════════════════════════════════
#
# The tests above verify the schema/mapping layer in isolation.
# The tests below verify the COMPLETE webhook ingestion path:
#
#   Raw payload → webhook endpoint → field mapping → Lead creation
#
# These correspond to the spec's TEST A–G requirements at the HTTP level.


class TestStep2B_WebhookEndToEnd:
    """Step 2B: End-to-end webhook tests proving flexible Sheet ingestion."""

    # ── TEST B (Org C scenario from spec) ────────────────────────────────

    def test_org_c_client_name_email_whatsapp(self, client):
        """Org C: 'Client Name', 'Email', 'WhatsApp', 'Preferred Appointment',
        'Program', 'Location' → canonical Lead fields via webhook."""
        org = _make_org(webhook_secret="org-c-secret")
        uid = uuid.uuid4().hex[:8]
        mapping_c = {
            "Client Name": "name",
            "Email": "email",
            "WhatsApp": "phone_number",
            "Preferred Appointment": "appt_datetime_raw",
            "Program": "courses",
            "Location": "company_address",
        }
        _seed_custom_mapping(org.id, mapping_c)
        invalidate_mapping_cache(org.id)

        # Simulate Apps Script payload (all Sheet columns except Timestamp)
        payload = {
            "Client Name": "Fatima Al-Rashid",
            "Email": f"fatima-{uid}@example.com",
            "WhatsApp": "+971-50-1234567",
            "Preferred Appointment": "Sunday 4pm",
            "Program": "AI Strategy Workshop",
            "Location": "Dubai, UAE",
        }
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": "Bearer org-c-secret"},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] in ("accepted", "duplicate")

        # Verify the Lead was created with correct canonical fields
        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            assert lead is not None
            assert lead.name == "Fatima Al-Rashid"
            assert lead.email == f"fatima-{uid}@example.com"
            assert lead.phone_number == "+971-50-1234567"
            assert lead.appt_datetime_raw == "Sunday 4pm"
            assert lead.courses == "AI Strategy Workshop"
            assert lead.company_address == "Dubai, UAE"
            assert lead.organization_id == org.id
        finally:
            db.close()

    # ── TEST D — Extra columns in webhook payload ────────────────────────

    def test_webhook_extra_columns_ignored(self, client):
        """Webhook with extra unmapped columns still creates Lead correctly."""
        org = _make_org(webhook_secret="extra-col-secret")
        uid = uuid.uuid4().hex[:8]
        mapping = {
            "Full Name": "name",
            "Contact Email": "email",
            "Appointment": "appt_datetime_raw",
        }
        _seed_custom_mapping(org.id, mapping)
        invalidate_mapping_cache(org.id)

        # Simulate Apps Script payload with many extra Sheet columns
        payload = {
            "Full Name": "Extra Test",
            "Contact Email": f"extra-{uid}@example.com",
            "Appointment": "tomorrow 2pm",
            "Budget": "$10,000",
            "How did you hear about us?": "Google",
            "Notes": "VIP client",
            "Country": "Brazil",
            "Language": "Portuguese",
            "Random Internal Field": "value",
        }
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": "Bearer extra-col-secret"},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] in ("accepted", "duplicate")

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            assert lead.name == "Extra Test"
            assert lead.email == f"extra-{uid}@example.com"
            assert lead.appt_datetime_raw == "tomorrow 2pm"
        finally:
            db.close()

    # ── TEST E — Unmapped labels via webhook (no matching mapping) ───────

    def test_webhook_completely_unmapped_labels_returns_422(self, client):
        """Webhook with labels that don't match the mapping returns 422."""
        org = _make_org(webhook_secret="unmapped-secret")
        mapping = {
            "Name": "name",
            "Email": "email",
            "Date": "appt_datetime_raw",
        }
        _seed_custom_mapping(org.id, mapping)
        invalidate_mapping_cache(org.id)

        # Payload has NO labels matching the mapping
        payload = {
            "Customer": "Unknown User",
            "Contact": "unknown@example.com",
            "Mobile": "555-0000",
        }
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": "Bearer unmapped-secret"},
        )
        assert resp.status_code == 422

    # ── TEST F — Cross-org webhook isolation ─────────────────────────────

    def test_cross_org_webhook_isolation(self, client):
        """Org A's payload cannot produce a valid Lead via Org B's mapping."""
        org_a = _make_org(webhook_secret="org-a-iso")
        org_b = _make_org(webhook_secret="org-b-iso")
        uid = uuid.uuid4().hex[:8]

        mapping_a = {"Customer Name": "name", "Contact": "email", "When": "appt_datetime_raw"}
        mapping_b = {"Applicant": "name", "Personal Email": "email", "Date": "appt_datetime_raw"}

        _seed_custom_mapping(org_a.id, mapping_a)
        _seed_custom_mapping(org_b.id, mapping_b)
        invalidate_mapping_cache(org_a.id)
        invalidate_mapping_cache(org_b.id)

        # Send Org A's payload to Org A → should succeed
        payload_a = {
            "Customer Name": "Org A User",
            "Contact": f"orga-{uid}@example.com",
            "When": "Monday 9am",
        }
        resp_a = client.post(
            f"/webhooks/{org_a.slug}/form-submission",
            json=payload_a,
            headers={"Authorization": "Bearer org-a-iso"},
        )
        assert resp_a.status_code == 202

        # Send same payload to Org B → should fail (labels don't match Org B's mapping)
        resp_b = client.post(
            f"/webhooks/{org_b.slug}/form-submission",
            json=payload_a,
            headers={"Authorization": "Bearer org-b-iso"},
        )
        assert resp_b.status_code == 422

        # Send Org B's payload to Org B → should succeed
        payload_b = {
            "Applicant": "Org B User",
            "Personal Email": f"orgb-{uid}@example.com",
            "Date": "Tuesday 3pm",
        }
        resp_b_ok = client.post(
            f"/webhooks/{org_b.slug}/form-submission",
            json=payload_b,
            headers={"Authorization": "Bearer org-b-iso"},
        )
        assert resp_b_ok.status_code == 202

        # Verify both Leads have correct organization_ids
        db = SessionLocal()
        try:
            lead_a = db.get(Lead, uuid.UUID(resp_a.json()["lead_id"]))
            lead_b = db.get(Lead, uuid.UUID(resp_b_ok.json()["lead_id"]))
            assert lead_a.organization_id == org_a.id
            assert lead_b.organization_id == org_b.id
            assert lead_a.name == "Org A User"
            assert lead_b.name == "Org B User"
        finally:
            db.close()

    # ── TEST A — Existing IT Training form via webhook ───────────────────

    def test_webhook_default_org_no_mapping_uses_default(self, client):
        """Org with no custom mapping uses DEFAULT_FORM_FIELD_MAPPING."""
        org = _make_org(webhook_secret="default-sec")
        uid = uuid.uuid4().hex[:8]
        # No custom mapping seeded — load_field_mapping returns DEFAULT
        payload = {
            "Name": "Default Org User",
            "Email Address": f"def-{uid}@example.com",
            "Phone Appt. Date/Time": "Wednesday 10am",
        }
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": "Bearer default-sec"},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] in ("accepted", "duplicate")

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            assert lead.name == "Default Org User"
            assert lead.email == f"def-{uid}@example.com"
            assert lead.appt_datetime_raw == "Wednesday 10am"
        finally:
            db.close()

    # ── TEST C — Column order independence via webhook ───────────────────

    def test_webhook_column_order_irrelevant(self, client):
        """Different key order in the same payload produces the same Lead."""
        uid1 = uuid.uuid4().hex[:8]
        uid2 = uuid.uuid4().hex[:8]
        org = _make_org(webhook_secret="order-sec")
        mapping = {"Name": "name", "Email": "email", "Date": "appt_datetime_raw"}
        _seed_custom_mapping(org.id, mapping)
        invalidate_mapping_cache(org.id)

        # Same data, different key ordering — use unique emails to avoid dedupe
        payload_a = {"Name": "Alice", "Email": f"alice-{uid1}@example.com", "Date": "tomorrow"}
        payload_b = {"Date": "Tuesday 3pm", "Email": f"alice-{uid2}@example.com", "Name": "Alice"}

        resp1 = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload_a,
            headers={"Authorization": "Bearer order-sec"},
        )
        resp2 = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload_b,
            headers={"Authorization": "Bearer order-sec"},
        )
        assert resp1.status_code == 202
        assert resp2.status_code == 202

        db = SessionLocal()
        try:
            lead1 = db.get(Lead, uuid.UUID(resp1.json()["lead_id"]))
            lead2 = db.get(Lead, uuid.UUID(resp2.json()["lead_id"]))
            # Both leads have same name, different emails (due to dedupe)
            assert lead1.name == lead2.name == "Alice"
            # Both have their respective emails mapped correctly
            assert lead1.email == f"alice-{uid1}@example.com"
            assert lead2.email == f"alice-{uid2}@example.com"
            # Both have their respective appointment times mapped
            assert lead1.appt_datetime_raw == "tomorrow"
            assert lead2.appt_datetime_raw == "Tuesday 3pm"
        finally:
            db.close()
