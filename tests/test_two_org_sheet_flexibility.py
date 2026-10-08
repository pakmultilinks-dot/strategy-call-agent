"""Real-world verification: Two organizations with different Sheet structures.

Proves that Organization A and Organization B can use completely different
Google Sheet column/header structures simultaneously, with no production-code
changes between them.

This test exercises the ACTUAL webhook ingestion path:
  Simulated Apps Script payload (external Sheet labels)
  → POST /webhooks/{org_slug}/form-submission
  → organization resolution
  → organization-specific field mapping load
  → map_payload_to_fields (label translation)
  → FormSubmission.from_webhook_payload (Pydantic validation)
  → Lead creation with canonical fields
"""
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Lead
from app.models_multi_tenant import (
    DEFAULT_FORM_FIELD_MAPPING,
    OrgFormFieldMapping,
    Organization,
    OrganizationStatus,
    REQUIRED_LEAD_FIELDS,
    User,
    UserRole,
    UserStatus,
)
from app.services.field_mapping_resolver import (
    invalidate_mapping_cache,
    load_field_mapping,
    map_payload_to_fields,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_org(**overrides) -> Organization:
    """Create a fresh organization for testing."""
    defaults = {
        "name": f"Flex Test Org {uuid.uuid4().hex[:8]}",
        "slug": f"flex-test-{uuid.uuid4().hex[:8]}",
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


def _submit_payload(client, org, payload, secret):
    """Simulate Apps Script sending a payload to the org's webhook."""
    return client.post(
        f"/webhooks/{org.slug}/form-submission",
        json=payload,
        headers={"Authorization": f"Bearer {secret}"},
    )


def _verify_lead(db, lead_id, expected_name, expected_email, expected_appt,
                 expected_org_id, expected_company=None, expected_phone=None):
    """Verify a Lead was created with the correct canonical fields."""
    lead = db.get(Lead, uuid.UUID(lead_id))
    assert lead is not None, f"Lead {lead_id} not found"
    assert lead.name == expected_name, f"name: {lead.name!r} != {expected_name!r}"
    assert lead.email == expected_email, f"email: {lead.email!r} != {expected_email!r}"
    assert lead.appt_datetime_raw == expected_appt, f"appt: {lead.appt_datetime_raw!r} != {expected_appt!r}"
    assert lead.organization_id == expected_org_id, (
        f"org_id: {lead.organization_id} != {expected_org_id}"
    )
    if expected_company is not None:
        assert lead.company_address == expected_company, (
            f"company_address: {lead.company_address!r} != {expected_company!r}"
        )
    if expected_phone is not None:
        assert lead.phone_number == expected_phone, (
            f"phone_number: {lead.phone_number!r} != {expected_phone!r}"
        )
    return lead


# ══════════════════════════════════════════════════════════════════════════════
# STEPS 2-4: Two organizations, different Sheet structures, simultaneous use
# ══════════════════════════════════════════════════════════════════════════════


class TestTwoOrgDifferentSheetStructures:
    """Organization A and B use completely different Sheet headers simultaneously."""

    def test_org_a_default_headers_leads_created(self, client):
        """STEP 2-4: Org A uses IT Training default headers → Lead created."""
        uid = uuid.uuid4().hex[:8]
        org_a = _make_org(name="IT Training Co", slug=f"it-training-{uid}", webhook_secret="org-a-secret")

        # Org A mapping: default IT Training labels
        mapping_a = {
            "Name": "name",
            "Email Address": "email",
            "Phone Appt. Date/Time": "appt_datetime_raw",
            "Company Address": "company_address",
            "Interested?": "interested",
        }
        _seed_custom_mapping(org_a.id, mapping_a)

        # Simulate Apps Script reading Org A's Sheet headers and sending them
        payload_a = {
            "Name": "Ahmad Khan",
            "Email Address": f"ahmad-{uid}@example.com",
            "Phone Appt. Date/Time": "Friday 3pm",
            "Company Address": "123 Main Street, Lahore",
            "Interested?": "Yes",
        }

        resp = _submit_payload(client, org_a, payload_a, "org-a-secret")
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] in ("accepted", "duplicate")

        db = SessionLocal()
        try:
            _verify_lead(
                db, data["lead_id"],
                expected_name="Ahmad Khan",
                expected_email=f"ahmad-{uid}@example.com",
                expected_appt="Friday 3pm",
                expected_org_id=org_a.id,
                expected_company="123 Main Street, Lahore",
            )
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            assert lead.interested == "yes"
        finally:
            db.close()

    def test_org_b_completely_different_headers(self, client):
        """STEP 2-4: Org B uses totally different headers → Lead created with canonical fields."""
        uid = uuid.uuid4().hex[:8]
        org_b = _make_org(name="Global Consulting", slug=f"global-consulting-{uid}", webhook_secret="org-b-secret")

        # Org B mapping: completely different labels
        mapping_b = {
            "Full Name": "name",
            "Work Email": "email",
            "Appointment": "appt_datetime_raw",
            "Business Name": "company_address",
            "Phone": "phone_number",
        }
        _seed_custom_mapping(org_b.id, mapping_b)

        # Simulate Apps Script reading Org B's DIFFERENT Sheet headers
        payload_b = {
            "Full Name": "Fatima Al-Rashid",
            "Work Email": f"fatima-{uid}@example.com",
            "Appointment": "Sunday 4pm",
            "Business Name": "Al-Rashid Trading LLC",
            "Phone": "+971-50-123-4567",
        }

        resp = _submit_payload(client, org_b, payload_b, "org-b-secret")
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] in ("accepted", "duplicate")

        db = SessionLocal()
        try:
            _verify_lead(
                db, data["lead_id"],
                expected_name="Fatima Al-Rashid",
                expected_email=f"fatima-{uid}@example.com",
                expected_appt="Sunday 4pm",
                expected_org_id=org_b.id,
                expected_company="Al-Rashid Trading LLC",
                expected_phone="+971-50-123-4567",
            )
        finally:
            db.close()

    def test_simultaneous_different_structures(self, client):
        """STEP 4: Both orgs submit simultaneously — correct mapping applied to each."""
        uid = uuid.uuid4().hex[:8]
        org_a = _make_org(name="Org A Simultaneous", slug=f"sim-org-a-{uid}", webhook_secret="sim-a-secret")
        org_b = _make_org(name="Org B Simultaneous", slug=f"sim-org-b-{uid}", webhook_secret="sim-b-secret")

        mapping_a = {
            "Name": "name",
            "Email Address": "email",
            "Phone Appt. Date/Time": "appt_datetime_raw",
            "Company Address": "company_address",
        }
        mapping_b = {
            "Full Name": "name",
            "Work Email": "email",
            "Appointment": "appt_datetime_raw",
            "Business Name": "company_address",
            "Phone": "phone_number",
        }
        _seed_custom_mapping(org_a.id, mapping_a)
        _seed_custom_mapping(org_b.id, mapping_b)

        # Submit Org A payload
        payload_a = {
            "Name": "Alice Johnson",
            "Email Address": f"alice-{uid}@example.com",
            "Phone Appt. Date/Time": "Monday 10am",
            "Company Address": "456 Oak Ave, New York",
        }
        resp_a = _submit_payload(client, org_a, payload_a, "sim-a-secret")
        assert resp_a.status_code == 202

        # Submit Org B payload (completely different headers)
        payload_b = {
            "Full Name": "Bob Martinez",
            "Work Email": f"bob-{uid}@example.com",
            "Appointment": "Tuesday 2pm",
            "Business Name": "Martinez Consulting",
            "Phone": "+1-555-9876",
        }
        resp_b = _submit_payload(client, org_b, payload_b, "sim-b-secret")
        assert resp_b.status_code == 202

        # Verify both leads exist with correct org assignment and canonical fields
        db = SessionLocal()
        try:
            lead_a = db.get(Lead, uuid.UUID(resp_a.json()["lead_id"]))
            lead_b = db.get(Lead, uuid.UUID(resp_b.json()["lead_id"]))

            # Org A lead
            assert lead_a.name == "Alice Johnson"
            assert lead_a.email == f"alice-{uid}@example.com"
            assert lead_a.appt_datetime_raw == "Monday 10am"
            assert lead_a.company_address == "456 Oak Ave, New York"
            assert lead_a.organization_id == org_a.id
            assert lead_a.phone_number is None  # Org A mapping doesn't include phone

            # Org B lead
            assert lead_b.name == "Bob Martinez"
            assert lead_b.email == f"bob-{uid}@example.com"
            assert lead_b.appt_datetime_raw == "Tuesday 2pm"
            assert lead_b.company_address == "Martinez Consulting"
            assert lead_b.phone_number == "+1-555-9876"
            assert lead_b.organization_id == org_b.id
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5: Mapping change in Org A does NOT affect Org B
# ══════════════════════════════════════════════════════════════════════════════


class TestMappingIndependence:
    """Changing Org A's mapping must not affect Org B."""

    def test_changing_org_a_mapping_does_not_affect_org_b(self, client):
        """STEP 5: Org A changes its mapping — Org B's mapping stays the same."""
        uid = uuid.uuid4().hex[:8]
        org_a = _make_org(name="Org A Indep", slug=f"indep-a-{uid}", webhook_secret="indep-a")
        org_b = _make_org(name="Org B Indep", slug=f"indep-b-{uid}", webhook_secret="indep-b")

        # Initial mappings
        mapping_a_v1 = {
            "Name": "name",
            "Email Address": "email",
            "Phone Appt. Date/Time": "appt_datetime_raw",
            "Company Address": "company_address",
        }
        mapping_b = {
            "Full Name": "name",
            "Work Email": "email",
            "Appointment": "appt_datetime_raw",
            "Business Name": "company_address",
            "Phone": "phone_number",
        }
        _seed_custom_mapping(org_a.id, mapping_a_v1)
        _seed_custom_mapping(org_b.id, mapping_b)

        # Submit to Org B with v1 mapping — should work
        payload_b_v1 = {
            "Full Name": "Before Change",
            "Work Email": f"before-{uid}@test.com",
            "Appointment": "Wednesday 9am",
            "Business Name": "Before LLC",
            "Phone": "+1-000-0001",
        }
        resp1 = _submit_payload(client, org_b, payload_b_v1, "indep-b")
        assert resp1.status_code == 202

        # Now CHANGE Org A's mapping (Org B's mapping should be unaffected)
        db = SessionLocal()
        try:
            db.query(OrgFormFieldMapping).filter(
                OrgFormFieldMapping.organization_id == org_a.id
            ).delete()
            db.commit()
        finally:
            db.close()
        invalidate_mapping_cache(org_a.id)

        # Seed Org A's NEW mapping — "Company Address" replaced with "Office Location"
        mapping_a_v2 = {
            "Name": "name",
            "Email Address": "email",
            "Phone Appt. Date/Time": "appt_datetime_raw",
            "Office Location": "company_address",  # Changed label
        }
        _seed_custom_mapping(org_a.id, mapping_a_v2)

        # Verify Org B's mapping is STILL the original
        db = SessionLocal()
        try:
            m_b = load_field_mapping(db, org_b.id)
            assert m_b == mapping_b, "Org B mapping was altered by Org A change!"
        finally:
            db.close()

        # Submit to Org B with same payload — should still work identically
        payload_b_v2 = {
            "Full Name": "After Change",
            "Work Email": f"after-{uid}@test.com",
            "Appointment": "Thursday 11am",
            "Business Name": "After LLC",
            "Phone": "+1-000-0002",
        }
        resp2 = _submit_payload(client, org_b, payload_b_v2, "indep-b")
        assert resp2.status_code == 202

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(resp2.json()["lead_id"]))
            assert lead.name == "After Change"
            assert lead.company_address == "After LLC"  # Still mapped via "Business Name"
            assert lead.organization_id == org_b.id
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# STEP 6: Third organization with completely different structure
# ══════════════════════════════════════════════════════════════════════════════


class TestThirdOrgDifferentStructure:
    """A third org with a third distinct Sheet structure."""

    def test_org_c_applicant_email_meeting(self, client):
        """STEP 6: Org C uses Applicant/Email/Meeting Date/Phone Number/Organization."""
        uid = uuid.uuid4().hex[:8]
        org_c = _make_org(name="Org C Academy", slug=f"academy-{uid}", webhook_secret="org-c-secret")

        mapping_c = {
            "Applicant": "name",
            "Email": "email",
            "Meeting Date": "appt_datetime_raw",
            "Phone Number": "phone_number",
            "Organization": "company_address",
        }
        _seed_custom_mapping(org_c.id, mapping_c)

        payload_c = {
            "Applicant": "Carlos Rivera",
            "Email": f"carlos-{uid}@example.com",
            "Meeting Date": "Saturday 11am",
            "Phone Number": "+52-55-1234-5678",
            "Organization": "Rivera Academy",
        }

        resp = _submit_payload(client, org_c, payload_c, "org-c-secret")
        assert resp.status_code == 202

        db = SessionLocal()
        try:
            _verify_lead(
                db, resp.json()["lead_id"],
                expected_name="Carlos Rivera",
                expected_email=f"carlos-{uid}@example.com",
                expected_appt="Saturday 11am",
                expected_org_id=org_c.id,
                expected_company="Rivera Academy",
                expected_phone="+52-55-1234-5678",
            )
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# STEP 7: Column order independence
# ══════════════════════════════════════════════════════════════════════════════


class TestColumnOrderIndependence:
    """Payload key order must not affect the result."""

    def test_reversed_order_same_lead(self, client):
        """STEP 7: Same Org B data in reversed column order → identical Lead."""
        uid = uuid.uuid4().hex[:8]
        org = _make_org(name="Org Order Test", slug=f"order-{uid}", webhook_secret="order-secret")

        mapping = {
            "Full Name": "name",
            "Work Email": "email",
            "Appointment": "appt_datetime_raw",
            "Business Name": "company_address",
            "Phone": "phone_number",
        }
        _seed_custom_mapping(org.id, mapping)

        # Normal order
        payload_normal = {
            "Full Name": "Diana Prince",
            "Work Email": f"diana-{uid}@example.com",
            "Appointment": "Friday 1pm",
            "Business Name": "Themyscira Inc",
            "Phone": "+1-555-0001",
        }
        resp1 = _submit_payload(client, org, payload_normal, "order-secret")
        assert resp1.status_code == 202

        # Reversed order — use unique email to avoid dedupe
        payload_reversed = {
            "Phone": "+1-555-0002",
            "Business Name": "Themyscira Inc",
            "Appointment": "Friday 1pm",
            "Full Name": "Diana Prince",
            "Work Email": f"diana2-{uid}@example.com",
        }
        resp2 = _submit_payload(client, org, payload_reversed, "order-secret")
        assert resp2.status_code == 202

        db = SessionLocal()
        try:
            lead1 = db.get(Lead, uuid.UUID(resp1.json()["lead_id"]))
            lead2 = db.get(Lead, uuid.UUID(resp2.json()["lead_id"]))

            # Both leads must have identical canonical field values (except
            # phone, which intentionally differs to prove mapping works in
            # both orderings)
            assert lead1.name == lead2.name == "Diana Prince"
            assert lead1.appt_datetime_raw == lead2.appt_datetime_raw == "Friday 1pm"
            assert lead1.company_address == lead2.company_address == "Themyscira Inc"
            assert lead1.phone_number == "+1-555-0001"
            assert lead2.phone_number == "+1-555-0002"
            assert lead1.organization_id == lead2.organization_id == org.id
        finally:
            db.close()

    def test_shuffled_with_extra_fields(self, client):
        """STEP 7+8: Shuffled order with extra unmapped columns still works."""
        uid = uuid.uuid4().hex[:8]
        org = _make_org(name="Org Shuffle", slug=f"shuffle-{uid}", webhook_secret="shuffle-secret")

        mapping = {
            "Full Name": "name",
            "Work Email": "email",
            "Appointment": "appt_datetime_raw",
        }
        _seed_custom_mapping(org.id, mapping)

        # Payload with shuffled order AND extra columns
        payload = {
            "Internal Notes": "do not use",
            "Appointment": "next Tuesday",
            "Budget": "$50,000",
            "Full Name": "Shuffle Test",
            "Work Email": f"shuffle-{uid}@example.com",
            "Random Column": "should be ignored",
        }

        resp = _submit_payload(client, org, payload, "shuffle-secret")
        assert resp.status_code == 202

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(resp.json()["lead_id"]))
            assert lead.name == "Shuffle Test"
            assert lead.email == f"shuffle-{uid}@example.com"
            assert lead.appt_datetime_raw == "next Tuesday"
            assert lead.company_address is None  # Not in mapping
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# STEP 8: Unknown Sheet columns are safely ignored
# ══════════════════════════════════════════════════════════════════════════════


class TestUnknownColumnsSafe:
    """Extra unknown Sheet columns must not break or corrupt ingestion."""

    def test_many_unknown_columns_ignored(self, client):
        """STEP 8: Payload with 5 extra unmapped columns still creates correct Lead."""
        uid = uuid.uuid4().hex[:8]
        org = _make_org(name="Org Unknown Cols", slug=f"unknown-{uid}", webhook_secret="unknown-secret")

        mapping = {
            "Full Name": "name",
            "Work Email": "email",
            "Appointment": "appt_datetime_raw",
        }
        _seed_custom_mapping(org.id, mapping)

        payload = {
            "Full Name": "Extra Test User",
            "Work Email": f"extra-{uid}@example.com",
            "Appointment": "Monday 3pm",
            "How did you hear about us?": "Google Search",
            "Marketing Consent": "Yes",
            "IP Address": "192.168.1.1",
            "Browser": "Chrome 120",
            "Internal Score": "42",
        }

        resp = _submit_payload(client, org, payload, "unknown-secret")
        assert resp.status_code == 202

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(resp.json()["lead_id"]))
            assert lead.name == "Extra Test User"
            assert lead.email == f"extra-{uid}@example.com"
            assert lead.appt_datetime_raw == "Monday 3pm"
            # Extra columns must NOT corrupt any field
            assert lead.company_address is None
            assert lead.phone_number is None
            assert lead.courses is None
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# STEP 9: Missing required fields → rejection
# ══════════════════════════════════════════════════════════════════════════════


class TestMissingRequiredFields:
    """Missing required canonical fields must be rejected — validation not weakened."""

    def test_missing_email_rejected(self, client):
        """STEP 9: Payload with no email-mapped field → 422."""
        uid = uuid.uuid4().hex[:8]
        org = _make_org(name="Org Missing Email", slug=f"missing-{uid}", webhook_secret="missing-secret")

        # Mapping includes name and appt but NOT email
        mapping = {
            "Full Name": "name",
            "Appointment": "appt_datetime_raw",
            "Phone": "phone_number",
        }
        _seed_custom_mapping(org.id, mapping)

        payload = {
            "Full Name": "No Email Person",
            "Appointment": "Wednesday 2pm",
            "Phone": "+1-555-0000",
            # NO email field in the payload
        }

        resp = _submit_payload(client, org, payload, "missing-secret")
        assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"

    def test_missing_all_required_rejected(self, client):
        """STEP 9: Payload matching NO required fields → 422."""
        uid = uuid.uuid4().hex[:8]
        org = _make_org(name="Org Missing All", slug=f"missingall-{uid}", webhook_secret="missingall-secret")

        mapping = {
            "Full Name": "name",
            "Work Email": "email",
            "Appointment": "appt_datetime_raw",
            "Phone": "phone_number",
        }
        _seed_custom_mapping(org.id, mapping)

        # Payload has none of the required fields — all labels are unmapped
        payload = {
            "Random Field": "value1",
            "Another Random": "value2",
        }

        resp = _submit_payload(client, org, payload, "missingall-secret")
        assert resp.status_code == 422

    def test_empty_email_rejected(self, client):
        """STEP 9: Empty email value → 422 (validation not weakened)."""
        uid = uuid.uuid4().hex[:8]
        org = _make_org(name="Org Empty Email", slug=f"empty-{uid}", webhook_secret="empty-secret")

        mapping = {
            "Name": "name",
            "Email": "email",
            "Date": "appt_datetime_raw",
        }
        _seed_custom_mapping(org.id, mapping)

        payload = {
            "Name": "Empty Email Person",
            "Email": "",  # Empty email
            "Date": "Thursday 10am",
        }

        resp = _submit_payload(client, org, payload, "empty-secret")
        assert resp.status_code == 422
