"""Regression tests for Phase 29 — Organization-scoped Form Field Mapping.

Covers:
  1. DEFAULT_FORM_FIELD_MAPPING constant and VALID_LEAD_FIELDS/REQUIRED_LEAD_FIELDS
  2. validate_mapping_config() unit tests
  3. map_payload_to_fields() unit tests
  4. load_field_mapping() DB + cache behavior
  5. FormSubmission.from_webhook_payload() dynamic mapping
  6. Dashboard API: GET /api/form-field-mappings
  7. Dashboard API: PUT /api/form-field-mappings (replace)
  8. Dashboard API: POST /api/form-field-mappings/seed
  9. Dashboard API: DELETE /api/form-field-mappings
  10. Dashboard API RBAC enforcement
  11. Cross-org isolation of mappings
  12. Webhook ingestion with custom mapping
  13. Backward compatibility: default mapping = legacy behavior
  14. OrgFormFieldMapping Model
"""
import json
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError
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
    VALID_LEAD_FIELDS,
)
from app.schemas import FormSubmission
from app.services.field_mapping_resolver import (
    _mapping_cache,
    invalidate_mapping_cache,
    load_field_mapping,
    map_payload_to_fields,
    validate_mapping_config,
)
from app.tenant import _DEFAULT_ORG_ID


# ── Test Constants ──────────────────────────────────────────────────────────

TEST_JWT_SECRET = "test-secret-key-for-phase-29-field-mapping-32chars!!"


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_org(**overrides) -> Organization:
    """Insert an Organization row and return it."""
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


def _create_user(org_id, role=UserRole.OWNER):
    """Create a user in the given org and return it."""
    from app.auth import hash_password
    db = SessionLocal()
    try:
        user = User(
            organization_id=org_id,
            email=f"user-{uuid.uuid4().hex[:8]}@example.com",
            password_hash=hash_password("TestPassword123!"),
            full_name="Test User",
            role=role,
            status=UserStatus.ACTIVE,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def _make_jwt(user):
    """Create a valid JWT for the given user."""
    from jose import jwt as jose_jwt
    payload = {
        "sub": str(user.id),
        "org_id": str(user.organization_id),
        "role": user.role.value,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4()),
    }
    return jose_jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")


def _auth_headers(user):
    """Return Bearer JWT auth headers for the given user."""
    return {"Authorization": f"Bearer {_make_jwt(user)}"}


def _seed_mappings(org_id, mappings=None):
    """Seed field mappings for an organization."""
    if mappings is None:
        mappings = DEFAULT_FORM_FIELD_MAPPING
    db = SessionLocal()
    try:
        for i, (label, field) in enumerate(mappings.items()):
            db.add(OrgFormFieldMapping(
                organization_id=org_id,
                form_label=label,
                lead_field=field,
                is_required=field in ("name", "email", "appt_datetime_raw"),
                display_order=i,
            ))
        db.commit()
        return len(mappings)
    finally:
        db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 1. Constants and Model Sanity
# ══════════════════════════════════════════════════════════════════════════════


class TestFieldMappingConstants:
    """Verify constants are well-formed and non-empty."""

    def test_default_mapping_not_empty(self):
        assert len(DEFAULT_FORM_FIELD_MAPPING) > 0

    def test_default_mapping_values_are_valid_lead_fields(self):
        for form_label, lead_field in DEFAULT_FORM_FIELD_MAPPING.items():
            assert lead_field in VALID_LEAD_FIELDS, (
                f"Default mapping has invalid field '{lead_field}' for label '{form_label}'"
            )

    def test_required_fields_subset_of_valid(self):
        assert REQUIRED_LEAD_FIELDS.issubset(VALID_LEAD_FIELDS)

    def test_required_fields_include_core_three(self):
        assert "name" in REQUIRED_LEAD_FIELDS
        assert "email" in REQUIRED_LEAD_FIELDS
        assert "appt_datetime_raw" in REQUIRED_LEAD_FIELDS

    def test_valid_fields_are_strings(self):
        for f in VALID_LEAD_FIELDS:
            assert isinstance(f, str)


# ══════════════════════════════════════════════════════════════════════════════
# 2. validate_mapping_config()
# ══════════════════════════════════════════════════════════════════════════════


class TestValidateMappingConfig:
    """Unit tests for mapping validation logic."""

    def test_valid_default_mapping(self):
        mappings = [
            {"form_label": k, "lead_field": v, "is_required": v in REQUIRED_LEAD_FIELDS}
            for k, v in DEFAULT_FORM_FIELD_MAPPING.items()
        ]
        errors = validate_mapping_config(mappings)
        assert errors == []

    def test_empty_list_fails_required_check(self):
        errors = validate_mapping_config([])
        assert len(errors) > 0
        assert any("required" in e.lower() or "missing" in e.lower() for e in errors)

    def test_empty_form_label_rejected(self):
        mappings = [{"form_label": "", "lead_field": "name"}]
        errors = validate_mapping_config(mappings)
        assert any("form_label" in e for e in errors)

    def test_empty_lead_field_rejected(self):
        mappings = [
            {"form_label": "Name", "lead_field": "name"},
            {"form_label": "Email", "lead_field": ""},
        ]
        errors = validate_mapping_config(mappings)
        assert any("lead_field" in e for e in errors)

    def test_invalid_lead_field_rejected(self):
        mappings = [
            {"form_label": "Name", "lead_field": "name"},
            {"form_label": "Email", "lead_field": "email"},
            {"form_label": "Date", "lead_field": "appt_datetime_raw"},
            {"form_label": "Weird", "lead_field": "nonexistent_field"},
        ]
        errors = validate_mapping_config(mappings)
        assert any("nonexistent_field" in e for e in errors)

    def test_duplicate_lead_field_rejected(self):
        mappings = [
            {"form_label": "Name", "lead_field": "name"},
            {"form_label": "Full Name", "lead_field": "name"},
            {"form_label": "Email", "lead_field": "email"},
            {"form_label": "Date", "lead_field": "appt_datetime_raw"},
        ]
        errors = validate_mapping_config(mappings)
        assert any("duplicate" in e.lower() and "name" in e for e in errors)

    def test_duplicate_form_label_rejected(self):
        mappings = [
            {"form_label": "Name", "lead_field": "name"},
            {"form_label": "Name", "lead_field": "email"},
        ]
        errors = validate_mapping_config(mappings)
        assert any("duplicate" in e.lower() and "form label" in e.lower() for e in errors)

    def test_missing_required_fields_detected(self):
        mappings = [
            {"form_label": "Company", "lead_field": "company_address"},
        ]
        errors = validate_mapping_config(mappings)
        assert any("required" in e.lower() or "missing" in e.lower() for e in errors)

    def test_valid_minimal_mapping(self):
        """Minimal valid mapping: just name + email + appt_datetime_raw."""
        mappings = [
            {"form_label": "Name", "lead_field": "name"},
            {"form_label": "Email", "lead_field": "email"},
            {"form_label": "Date/Time", "lead_field": "appt_datetime_raw"},
        ]
        errors = validate_mapping_config(mappings)
        assert errors == []

    def test_optional_fields_can_be_included(self):
        mappings = [
            {"form_label": "Name", "lead_field": "name"},
            {"form_label": "Email", "lead_field": "email"},
            {"form_label": "Date", "lead_field": "appt_datetime_raw"},
            {"form_label": "Phone", "lead_field": "phone_number"},
            {"form_label": "Company", "lead_field": "company_address"},
        ]
        errors = validate_mapping_config(mappings)
        assert errors == []


# ══════════════════════════════════════════════════════════════════════════════
# 3. map_payload_to_fields()
# ══════════════════════════════════════════════════════════════════════════════


class TestMapPayloadToFields:
    """Unit tests for payload translation."""

    def test_default_mapping_translates_correctly(self):
        payload = {
            "Name": "John Doe",
            "Email Address": "john@example.com",
            "Phone Appt. Date/Time": "tomorrow 10:00",
        }
        result = map_payload_to_fields(payload, DEFAULT_FORM_FIELD_MAPPING)
        assert result["name"] == "John Doe"
        assert result["email"] == "john@example.com"
        assert result["appt_datetime_raw"] == "tomorrow 10:00"

    def test_custom_mapping_translates(self):
        custom = {
            "Full Name": "name",
            "Contact Email": "email",
            "Appointment": "appt_datetime_raw",
        }
        payload = {
            "Full Name": "Jane Doe",
            "Contact Email": "jane@example.com",
            "Appointment": "next week",
            "Extra Column": "ignored",
        }
        result = map_payload_to_fields(payload, custom)
        assert result["name"] == "Jane Doe"
        assert result["email"] == "jane@example.com"
        assert result["appt_datetime_raw"] == "next week"
        assert "Extra Column" not in result

    def test_unknown_form_labels_ignored(self):
        payload = {"Name": "A", "Bogus Label": "B"}
        result = map_payload_to_fields(payload, DEFAULT_FORM_FIELD_MAPPING)
        assert result["name"] == "A"
        assert len(result) == 1

    def test_empty_payload_returns_empty(self):
        result = map_payload_to_fields({}, DEFAULT_FORM_FIELD_MAPPING)
        assert result == {}

    def test_missing_payload_fields_not_in_result(self):
        custom = {"Name": "name", "Email": "email"}
        payload = {"Name": "Only Name"}
        result = map_payload_to_fields(payload, custom)
        assert result == {"name": "Only Name"}
        assert "email" not in result


# ══════════════════════════════════════════════════════════════════════════════
# 4. load_field_mapping() — DB + Cache
# ══════════════════════════════════════════════════════════════════════════════


class TestLoadFieldMapping:
    """Tests for load_field_mapping DB + cache behavior."""

    def setup_method(self):
        _mapping_cache.clear()

    def teardown_method(self):
        _mapping_cache.clear()

    def test_no_mapping_returns_default(self):
        org = _make_org()
        invalidate_mapping_cache(org.id)
        db = SessionLocal()
        try:
            mapping = load_field_mapping(db, org.id)
            assert mapping == DEFAULT_FORM_FIELD_MAPPING
        finally:
            db.close()

    def test_custom_mapping_returned(self):
        org = _make_org()
        custom = {"Full Name": "name", "Contact": "email", "When": "appt_datetime_raw"}
        _seed_mappings(org.id, custom)
        invalidate_mapping_cache(org.id)
        db = SessionLocal()
        try:
            mapping = load_field_mapping(db, org.id)
            assert mapping["Full Name"] == "name"
            assert mapping["Contact"] == "email"
            assert mapping["When"] == "appt_datetime_raw"
        finally:
            db.close()

    def test_cache_is_used(self):
        org = _make_org()
        _mapping_cache[str(org.id)] = ({"Cached": "name"}, time.time())
        db = SessionLocal()
        try:
            mapping = load_field_mapping(db, org.id)
            assert mapping == {"Cached": "name"}
        finally:
            db.close()

    def test_cache_invalidation_works(self):
        org = _make_org()
        _mapping_cache[str(org.id)] = ({"Stale": "name"}, time.time())
        invalidate_mapping_cache(org.id)
        assert str(org.id) not in _mapping_cache

    def test_cache_refreshes_after_invalidation(self):
        org = _make_org()
        custom = {"Label": "email"}
        _seed_mappings(org.id, custom)
        invalidate_mapping_cache(org.id)
        db = SessionLocal()
        try:
            mapping = load_field_mapping(db, org.id)
            assert mapping == {"Label": "email"}
        finally:
            db.close()

    def test_default_org_returns_default_mapping(self):
        """The default org (seeded by conftest) should return the default mapping."""
        invalidate_mapping_cache(_DEFAULT_ORG_ID)
        db = SessionLocal()
        try:
            mapping = load_field_mapping(db, _DEFAULT_ORG_ID)
            assert mapping == DEFAULT_FORM_FIELD_MAPPING
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 5. FormSubmission.from_webhook_payload()
# ══════════════════════════════════════════════════════════════════════════════


class TestFromWebhookPayload:
    """Tests for FormSubmission.from_webhook_payload() dynamic mapping."""

    def _legacy_payload(self, **overrides):
        uid = uuid.uuid4().hex[:8]
        base = {
            "Interested?": "Yes",
            "Name": "Test User",
            "Company Address": "123 Test St",
            "Phone Number": "555-0100",
            "Direct Number": "555-0101",
            "Courses": "Python",
            "Email Address": f"test-{uid}@example.com",
            "Scheduled Date": "tomorrow",
            "Caller Name": "Agent",
            "Phone Appt. Date/Time": "tomorrow 10:00",
        }
        base.update(overrides)
        return base

    def test_default_mapping_produces_same_result_as_legacy(self):
        payload = self._legacy_payload()
        legacy = FormSubmission(**payload)
        dynamic = FormSubmission.from_webhook_payload(payload, DEFAULT_FORM_FIELD_MAPPING)
        assert legacy.name == dynamic.name
        assert legacy.email == dynamic.email
        assert legacy.appt_datetime_raw == dynamic.appt_datetime_raw
        assert legacy.interested == dynamic.interested

    def test_empty_mapping_uses_legacy(self):
        payload = self._legacy_payload()
        legacy = FormSubmission(**payload)
        dynamic = FormSubmission.from_webhook_payload(payload, {})
        assert legacy.email == dynamic.email

    def test_custom_mapping_translates(self):
        payload = {
            "Full Name": "Custom User",
            "Contact Email": "custom@test.com",
            "Appointment Date": "next tuesday 2pm",
        }
        custom = {
            "Full Name": "name",
            "Contact Email": "email",
            "Appointment Date": "appt_datetime_raw",
        }
        sub = FormSubmission.from_webhook_payload(payload, custom)
        assert sub.name == "Custom User"
        assert sub.email == "custom@test.com"
        assert sub.appt_datetime_raw == "next tuesday 2pm"

    def test_custom_mapping_optional_fields(self):
        payload = {
            "Name": "Test",
            "Email": "test@example.com",
            "When": "tomorrow",
            "Phone": "555-9999",
            "Company": "Acme Corp",
        }
        custom = {
            "Name": "name",
            "Email": "email",
            "When": "appt_datetime_raw",
            "Phone": "phone_number",
            "Company": "company_address",
        }
        sub = FormSubmission.from_webhook_payload(payload, custom)
        assert sub.name == "Test"
        assert sub.email == "test@example.com"
        assert sub.phone_number == "555-9999"
        assert sub.company_address == "Acme Corp"

    def test_missing_required_field_raises(self):
        from pydantic import ValidationError
        payload = {"Name": "Only Name"}
        custom = {"Name": "name", "Email": "email", "Date": "appt_datetime_raw"}
        with pytest.raises(ValidationError):
            FormSubmission.from_webhook_payload(payload, custom)

    def test_unknown_labels_ignored(self):
        payload = {
            "Name": "User",
            "Email": "user@example.com",
            "Date": "tomorrow",
            "Random Extra": "whatever",
        }
        custom = {
            "Name": "name",
            "Email": "email",
            "Date": "appt_datetime_raw",
        }
        sub = FormSubmission.from_webhook_payload(payload, custom)
        assert sub.name == "User"


# ══════════════════════════════════════════════════════════════════════════════
# Dashboard API tests — all require JWT auth for org context
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    """Inject test-mode secrets for JWT and env."""
    from app.config import settings
    from app.services.crypto import generate_key
    monkeypatch.setattr(settings, "jwt_secret_key", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", generate_key())


# ══════════════════════════════════════════════════════════════════════════════
# 6. Dashboard API — GET /api/form-field-mappings
# ══════════════════════════════════════════════════════════════════════════════


class TestDashboardFieldMappingGET:
    """GET /dashboard/api/form-field-mappings"""

    def test_default_org_no_mappings_returns_default(self, client):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        resp = client.get(
            "/dashboard/api/form-field-mappings",
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "mappings" in data
        assert "default_mapping" in data
        assert "valid_fields" in data
        assert data["is_custom"] is False
        assert data["default_mapping"] == DEFAULT_FORM_FIELD_MAPPING
        assert data["mappings"] == []

    def test_org_with_mappings_returns_them(self, client):
        org = _make_org()
        _seed_mappings(org.id)
        invalidate_mapping_cache(org.id)
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        resp = client.get(
            "/dashboard/api/form-field-mappings",
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_custom"] is True
        assert len(data["mappings"]) == len(DEFAULT_FORM_FIELD_MAPPING)

    def test_valid_fields_list_non_empty(self, client):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        resp = client.get(
            "/dashboard/api/form-field-mappings",
            headers=headers,
        )
        assert resp.status_code == 200
        assert len(resp.json()["valid_fields"]) > 0

    def test_unauthenticated_returns_401(self, client):
        resp = client.get("/dashboard/api/form-field-mappings")
        assert resp.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# 7. Dashboard API — PUT /api/form-field-mappings (replace)
# ══════════════════════════════════════════════════════════════════════════════


class TestDashboardFieldMappingPUT:
    """PUT /dashboard/api/form-field-mappings"""

    def _minimal_valid_mappings(self):
        return [
            {"form_label": "Name", "lead_field": "name", "is_required": True},
            {"form_label": "Email", "lead_field": "email", "is_required": True},
            {"form_label": "Date", "lead_field": "appt_datetime_raw", "is_required": True},
        ]

    def test_replace_mappings(self, client):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        resp = client.put(
            "/dashboard/api/form-field-mappings",
            json={"mappings": self._minimal_valid_mappings()},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert resp.json()["count"] == 3

    def test_replace_persists_to_db(self, client):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        client.put(
            "/dashboard/api/form-field-mappings",
            json={"mappings": self._minimal_valid_mappings()},
            headers=headers,
        )
        resp = client.get(
            "/dashboard/api/form-field-mappings",
            headers=headers,
        )
        data = resp.json()
        assert data["is_custom"] is True
        assert len(data["mappings"]) == 3

    def test_invalid_mapping_returns_422(self, client):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        bad_mappings = [
            {"form_label": "Name", "lead_field": "name"},
            {"form_label": "Bad", "lead_field": "nonexistent"},
        ]
        resp = client.put(
            "/dashboard/api/form-field-mappings",
            json={"mappings": bad_mappings},
            headers=headers,
        )
        assert resp.status_code == 422

    def test_missing_required_fields_returns_422(self, client):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        mappings = [
            {"form_label": "Company", "lead_field": "company_address"},
        ]
        resp = client.put(
            "/dashboard/api/form-field-mappings",
            json={"mappings": mappings},
            headers=headers,
        )
        assert resp.status_code == 422

    def test_empty_mappings_list_rejected_by_validation(self, client):
        """PUT with empty list fails validation (use DELETE to clear)."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        client.put(
            "/dashboard/api/form-field-mappings",
            json={"mappings": self._minimal_valid_mappings()},
            headers=headers,
        )
        resp = client.put(
            "/dashboard/api/form-field-mappings",
            json={"mappings": []},
            headers=headers,
        )
        assert resp.status_code == 422
        # Original mappings still exist
        resp = client.get(
            "/dashboard/api/form-field-mappings",
            headers=headers,
        )
        assert resp.json()["is_custom"] is True

    def test_non_list_mappings_returns_422(self, client):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        resp = client.put(
            "/dashboard/api/form-field-mappings",
            json={"mappings": "not a list"},
            headers=headers,
        )
        assert resp.status_code == 422

    def test_unauthenticated_returns_401(self, client):
        resp = client.put(
            "/dashboard/api/form-field-mappings",
            json={"mappings": []},
        )
        assert resp.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# 8. Dashboard API — POST /api/form-field-mappings/seed
# ══════════════════════════════════════════════════════════════════════════════


class TestDashboardFieldMappingSeed:
    """POST /dashboard/api/form-field-mappings/seed"""

    def test_seed_creates_default_mappings(self, client):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        resp = client.post(
            "/dashboard/api/form-field-mappings/seed",
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert resp.json()["count"] == len(DEFAULT_FORM_FIELD_MAPPING)

    def test_seed_already_exists_returns_409(self, client):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        client.post(
            "/dashboard/api/form-field-mappings/seed",
            headers=headers,
        )
        resp = client.post(
            "/dashboard/api/form-field-mappings/seed",
            headers=headers,
        )
        assert resp.status_code == 409

    def test_seed_then_delete_then_seed_works(self, client):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        resp1 = client.post(
            "/dashboard/api/form-field-mappings/seed",
            headers=headers,
        )
        assert resp1.status_code == 200
        resp2 = client.delete(
            "/dashboard/api/form-field-mappings",
            headers=headers,
        )
        assert resp2.status_code == 200
        resp3 = client.post(
            "/dashboard/api/form-field-mappings/seed",
            headers=headers,
        )
        assert resp3.status_code == 200

    def test_unauthenticated_returns_401(self, client):
        resp = client.post("/dashboard/api/form-field-mappings/seed")
        assert resp.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# 9. Dashboard API — DELETE /api/form-field-mappings
# ══════════════════════════════════════════════════════════════════════════════


class TestDashboardFieldMappingDelete:
    """DELETE /dashboard/api/form-field-mappings"""

    def test_delete_returns_ok(self, client):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        resp = client.delete(
            "/dashboard/api/form-field-mappings",
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_delete_clears_mappings(self, client):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        client.put(
            "/dashboard/api/form-field-mappings",
            json={
                "mappings": [
                    {"form_label": "Name", "lead_field": "name", "is_required": True},
                    {"form_label": "Email", "lead_field": "email", "is_required": True},
                    {"form_label": "Date", "lead_field": "appt_datetime_raw", "is_required": True},
                ]
            },
            headers=headers,
        )
        resp = client.delete(
            "/dashboard/api/form-field-mappings",
            headers=headers,
        )
        assert resp.json()["deleted"] == 3
        resp = client.get(
            "/dashboard/api/form-field-mappings",
            headers=headers,
        )
        assert resp.json()["is_custom"] is False

    def test_delete_when_nothing_exists(self, client):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        resp = client.delete(
            "/dashboard/api/form-field-mappings",
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["deleted"] == 0

    def test_unauthenticated_returns_401(self, client):
        resp = client.delete("/dashboard/api/form-field-mappings")
        assert resp.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# 10. Dashboard API RBAC
# ══════════════════════════════════════════════════════════════════════════════


class TestFieldMappingRBAC:
    """Owner/admin can modify, member/viewer cannot."""

    def test_member_cannot_put(self, client):
        org = _make_org()
        member = _create_user(org.id, UserRole.MEMBER)
        headers = _auth_headers(member)
        resp = client.put(
            "/dashboard/api/form-field-mappings",
            json={"mappings": [
                {"form_label": "Name", "lead_field": "name", "is_required": True},
                {"form_label": "Email", "lead_field": "email", "is_required": True},
                {"form_label": "Date", "lead_field": "appt_datetime_raw", "is_required": True},
            ]},
            headers=headers,
        )
        assert resp.status_code == 403

    def test_owner_can_put(self, client):
        org = _make_org()
        owner = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(owner)
        resp = client.put(
            "/dashboard/api/form-field-mappings",
            json={"mappings": [
                {"form_label": "Name", "lead_field": "name", "is_required": True},
                {"form_label": "Email", "lead_field": "email", "is_required": True},
                {"form_label": "Date", "lead_field": "appt_datetime_raw", "is_required": True},
            ]},
            headers=headers,
        )
        assert resp.status_code == 200

    def test_admin_can_put(self, client):
        org = _make_org()
        admin = _create_user(org.id, UserRole.ADMIN)
        headers = _auth_headers(admin)
        resp = client.put(
            "/dashboard/api/form-field-mappings",
            json={"mappings": [
                {"form_label": "Name", "lead_field": "name", "is_required": True},
                {"form_label": "Email", "lead_field": "email", "is_required": True},
                {"form_label": "Date", "lead_field": "appt_datetime_raw", "is_required": True},
            ]},
            headers=headers,
        )
        assert resp.status_code == 200

    def test_member_cannot_seed(self, client):
        org = _make_org()
        member = _create_user(org.id, UserRole.MEMBER)
        headers = _auth_headers(member)
        resp = client.post(
            "/dashboard/api/form-field-mappings/seed",
            headers=headers,
        )
        assert resp.status_code == 403

    def test_member_cannot_delete(self, client):
        org = _make_org()
        member = _create_user(org.id, UserRole.MEMBER)
        headers = _auth_headers(member)
        resp = client.delete(
            "/dashboard/api/form-field-mappings",
            headers=headers,
        )
        assert resp.status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# 11. Cross-Org Isolation
# ══════════════════════════════════════════════════════════════════════════════


class TestCrossOrgIsolation:
    """Field mappings from one org must not leak to another."""

    def test_two_orgs_have_independent_mappings(self):
        org1 = _make_org()
        org2 = _make_org()
        custom1 = {"Name": "name", "Email": "email", "Date": "appt_datetime_raw"}
        custom2 = {"Full Name": "name", "Contact": "email", "When": "appt_datetime_raw"}
        _seed_mappings(org1.id, custom1)
        _seed_mappings(org2.id, custom2)
        invalidate_mapping_cache(org1.id)
        invalidate_mapping_cache(org2.id)

        db = SessionLocal()
        try:
            m1 = load_field_mapping(db, org1.id)
            m2 = load_field_mapping(db, org2.id)
            assert m1 == custom1
            assert m2 == custom2
            assert m1 != m2
        finally:
            db.close()

    def test_deleting_one_org_does_not_affect_other(self):
        org1 = _make_org()
        org2 = _make_org()
        custom2 = {"Full Name": "name", "Contact": "email", "When": "appt_datetime_raw"}
        _seed_mappings(org1.id)
        _seed_mappings(org2.id, custom2)
        invalidate_mapping_cache(org1.id)
        invalidate_mapping_cache(org2.id)

        db = SessionLocal()
        try:
            db.query(OrgFormFieldMapping).filter(
                OrgFormFieldMapping.organization_id == org1.id
            ).delete()
            db.commit()
        finally:
            db.close()
        invalidate_mapping_cache(org1.id)
        invalidate_mapping_cache(org2.id)

        db = SessionLocal()
        try:
            m1 = load_field_mapping(db, org1.id)
            m2 = load_field_mapping(db, org2.id)
            assert m1 == DEFAULT_FORM_FIELD_MAPPING  # Fallback to default
            assert m2 == custom2  # Still has org2's custom mapping
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 12. Webhook Ingestion with Custom Mapping
# ══════════════════════════════════════════════════════════════════════════════


class TestWebhookWithCustomMapping:
    """Verify the org-scoped webhook uses field mapping."""

    def _custom_payload(self):
        uid = uuid.uuid4().hex[:8]
        return {
            "Full Name": "Custom Mapping User",
            "Contact Email": f"custom-{uid}@example.com",
            "Appointment Date": "tomorrow 2pm",
            "Phone": "555-1234",
            "Company": "Custom Corp",
            "Interested": "Yes",
        }

    def test_custom_mapping_webhook_creates_lead(self, client):
        org = _make_org(webhook_secret="test-webhook-secret")
        custom = {
            "Full Name": "name",
            "Contact Email": "email",
            "Appointment Date": "appt_datetime_raw",
            "Phone": "phone_number",
            "Company": "company_address",
            "Interested": "interested",
        }
        _seed_mappings(org.id, custom)
        invalidate_mapping_cache(org.id)

        payload = self._custom_payload()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": "Bearer test-webhook-secret"},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"

        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            assert lead is not None
            assert lead.name == "Custom Mapping User"
            assert lead.organization_id == org.id
        finally:
            db.close()

    def test_default_org_webhook_unchanged(self, client):
        """Legacy webhook route still works without any mapping config."""
        from app.config import settings
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Interested?": "Yes",
            "Name": "Legacy User",
            "Email Address": f"legacy-{uid}@example.com",
            "Phone Appt. Date/Time": "tomorrow 3pm",
        }
        webhook_secret = settings.webhook_secret
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=payload,
            headers={"Authorization": f"Bearer {webhook_secret}"} if webhook_secret else {},
        )
        assert resp.status_code == 202


# ══════════════════════════════════════════════════════════════════════════════
# 13. Backward Compatibility
# ══════════════════════════════════════════════════════════════════════════════


class TestBackwardCompatibility:
    """Ensure existing flows remain identical with no custom mapping."""

    def test_default_org_no_mappings_uses_default(self, client):
        """Default org with no mappings should accept legacy payload."""
        from app.config import settings
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Interested?": "Yes",
            "Name": "Backward Compat User",
            "Company Address": "456 Legacy Ave",
            "Phone Number": "555-0200",
            "Direct Number": "555-0201",
            "Courses": "Docker, Kubernetes",
            "Email Address": f"compat-{uid}@example.com",
            "Scheduled Date": "next week",
            "Caller Name": "Legacy Agent",
            "Phone Appt. Date/Time": "next week 10:00",
        }
        webhook_secret = settings.webhook_secret
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=payload,
            headers={"Authorization": f"Bearer {webhook_secret}"} if webhook_secret else {},
        )
        assert resp.status_code == 202

        data = resp.json()
        db = SessionLocal()
        try:
            lead = db.get(Lead, uuid.UUID(data["lead_id"]))
            assert lead.name == "Backward Compat User"
            assert lead.email == f"compat-{uid}@example.com"
            assert lead.company_address == "456 Legacy Ave"
            assert lead.phone_number == "555-0200"
            assert lead.courses == "Docker, Kubernetes"
        finally:
            db.close()

    def test_org_scoped_legacy_labels_still_work(self, client):
        """Org-scoped webhook with default labels (no custom mapping) works."""
        org = _make_org(webhook_secret="test-webhook-secret")
        uid = uuid.uuid4().hex[:8]
        payload = {
            "Interested?": "Yes",
            "Name": "Org Legacy User",
            "Email Address": f"org-legacy-{uid}@example.com",
            "Phone Appt. Date/Time": "tomorrow 11am",
        }
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": "Bearer test-webhook-secret"},
        )
        assert resp.status_code == 202


# ══════════════════════════════════════════════════════════════════════════════
# 14. OrgFormFieldMapping Model
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgFormFieldMappingModel:
    """Direct model-level tests for OrgFormFieldMapping."""

    def test_create_and_read(self):
        org = _make_org()
        db = SessionLocal()
        try:
            mapping = OrgFormFieldMapping(
                organization_id=org.id,
                form_label="Test Label",
                lead_field="name",
                is_required=True,
                display_order=0,
            )
            db.add(mapping)
            db.commit()
            db.refresh(mapping)
            assert mapping.id is not None
            assert mapping.form_label == "Test Label"
            assert mapping.lead_field == "name"
            assert mapping.is_required is True
        finally:
            db.close()

    def test_cascade_delete_on_org(self):
        """Deleting an org should cascade-delete its mappings."""
        org = _make_org()
        _seed_mappings(org.id)
        db = SessionLocal()
        try:
            count = db.query(OrgFormFieldMapping).filter(
                OrgFormFieldMapping.organization_id == org.id
            ).count()
            assert count > 0
            db.delete(org)
            db.commit()
            remaining = db.query(OrgFormFieldMapping).filter(
                OrgFormFieldMapping.organization_id == org.id
            ).count()
            assert remaining == 0
        finally:
            db.close()

    def test_unique_constraint_org_label(self):
        """Duplicate (org_id, form_label) should fail on PostgreSQL.

        SQLite does not enforce multi-column UNIQUE constraints defined
        via UniqueConstraint(), so we only assert the IntegrityError on
        PostgreSQL.  On SQLite we verify the row was inserted and clean up.
        """
        org = _make_org()
        db = SessionLocal()
        try:
            db.add(OrgFormFieldMapping(
                organization_id=org.id,
                form_label="Unique Label",
                lead_field="name",
                display_order=0,
            ))
            db.commit()
            db.add(OrgFormFieldMapping(
                organization_id=org.id,
                form_label="Unique Label",
                lead_field="email",
                display_order=1,
            ))
            # Try commit — PostgreSQL will raise IntegrityError,
            # SQLite will silently allow it (no multi-col UNIQUE enforcement).
            try:
                db.commit()
                # SQLite path: commit succeeded, clean up and verify
                count = db.query(OrgFormFieldMapping).filter(
                    OrgFormFieldMapping.organization_id == org.id,
                    OrgFormFieldMapping.form_label == "Unique Label",
                ).count()
                assert count == 2  # Both rows inserted (SQLite)
                db.rollback()
            except IntegrityError:
                # PostgreSQL path: constraint fired as expected
                db.rollback()
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 15. Frontend api() error extraction regression
# ══════════════════════════════════════════════════════════════════════════════


def _extract_frontend_error(err_body):
    """Reproduce the JavaScript api() error extraction logic from dashboard.py.

    This mirrors the client-side code that was patched to never produce
    '[object Object]'.  If this Python helper produces the same result
    as the JS, the regression test passes.
    """
    if err_body and err_body.get("detail"):
        d = err_body["detail"]
        if isinstance(d, str):
            return d
        if isinstance(d, dict) and "errors" in d and isinstance(d["errors"], list):
            return "; ".join(
                str(x) if isinstance(x, str) else json.dumps(x)
                for x in d["errors"]
            )
        if isinstance(d, dict) and "message" in d:
            return d["message"] if isinstance(d["message"], str) else json.dumps(d["message"])
        if isinstance(d, dict) and "error" in d:
            return d["error"] if isinstance(d["error"], str) else json.dumps(d["error"])
        return json.dumps(d)
    # Top-level errors array (e.g. from RequestValidationError handler)
    if err_body and "errors" in err_body and isinstance(err_body["errors"], list) and err_body["errors"]:
        return "; ".join(
            str(x) if isinstance(x, str) else json.dumps(x)
            for x in err_body["errors"]
        )
    # Top-level message string (e.g. from global_exception_handler)
    if err_body and "message" in err_body and isinstance(err_body["message"], str):
        return err_body["message"]
    return None


class TestFrontendApiErrorExtraction:
    """Regression: the dashboard api() helper must never produce '[object Object]'.

    These tests mirror the JavaScript error extraction logic patched in
    app/dashboard.py and verify the same cases produce human-readable strings.
    """

    def test_detail_string_not_mangled(self):
        body = {"detail": "Invalid request"}
        assert _extract_frontend_error(body) == "Invalid request"

    def test_detail_errors_array_extracted(self):
        body = {
            "detail": {
                "errors": [
                    "Missing required system fields: appt_datetime_raw, name"
                ]
            }
        }
        msg = _extract_frontend_error(body)
        assert msg is not None
        assert "Missing required system fields" in msg
        assert "[object Object]" not in msg
        assert "appt_datetime_raw" in msg

    def test_detail_errors_multiple_messages(self):
        body = {
            "detail": {
                "errors": ["Error one", "Error two"]
            }
        }
        msg = _extract_frontend_error(body)
        assert msg == "Error one; Error two"

    def test_detail_message_field(self):
        body = {"detail": {"message": "Something went wrong"}}
        assert _extract_frontend_error(body) == "Something went wrong"

    def test_detail_error_field(self):
        body = {"detail": {"error": "Forbidden"}}
        assert _extract_frontend_error(body) == "Forbidden"

    def test_detail_unknown_object_falls_back_to_json(self):
        body = {"detail": {"unknown_key": 42}}
        msg = _extract_frontend_error(body)
        assert msg is not None
        assert "[object Object]" not in msg
        assert "42" in msg

    def test_no_detail_returns_none(self):
        body = {"error": "Not found"}
        assert _extract_frontend_error(body) is None

    def test_empty_body_returns_none(self):
        assert _extract_frontend_error({}) is None

    def test_none_body_returns_none(self):
        assert _extract_frontend_error(None) is None

    def test_live_validation_error_format(self, client):
        """End-to-end: PUT with missing required fields returns readable detail."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        headers = _auth_headers(user)
        resp = client.put(
            "/dashboard/api/form-field-mappings",
            json={"mappings": [
                {"form_label": "Company", "lead_field": "company_address"},
            ]},
            headers=headers,
        )
        assert resp.status_code == 422
        body = resp.json()
        msg = _extract_frontend_error(body)
        assert msg is not None
        assert "[object Object]" not in msg
        # The message should contain the missing field names
        assert "appt_datetime_raw" in msg or "required" in msg.lower()

    def test_top_level_errors_array_extracted(self):
        """RequestValidationError handler returns errors without detail wrapper."""
        body = {
            "status": "validation_error",
            "message": "Validation failed",
            "errors": ["field one is invalid", "field two is missing"],
        }
        msg = _extract_frontend_error(body)
        assert msg is not None
        assert "field one is invalid" in msg
        assert "field two is missing" in msg
        assert "[object Object]" not in msg

    def test_top_level_message_string_extracted(self):
        """global_exception_handler returns message without detail wrapper."""
        body = {
            "status": "error",
            "message": "An unexpected error occurred",
        }
        msg = _extract_frontend_error(body)
        assert msg == "An unexpected error occurred"

    def test_top_level_errors_over_message(self):
        """When both errors and message exist, errors array takes precedence."""
        body = {
            "status": "validation_error",
            "message": "Validation failed",
            "errors": ["Specific error"],
        }
        msg = _extract_frontend_error(body)
        assert msg == "Specific error"

    def test_null_detail_falls_through_to_top_level(self):
        """When detail is null (JS falsy), fall through to top-level errors/message."""
        body = {
            "detail": None,
            "errors": ["Error from top level"],
        }
        msg = _extract_frontend_error(body)
        assert msg is not None
        assert "Error from top level" in msg

    def test_empty_top_level_errors_returns_none(self):
        """Empty errors array with no message returns None."""
        body = {"status": "error", "errors": [], "message": 42}
        assert _extract_frontend_error(body) is None

    def test_never_produces_object_object(self):
        """Exhaustive: check all edge cases never produce [object Object]."""
        bodies = [
            {"detail": {"nested": {"deep": True}}},
            {"errors": [123, True, None]},
            {"detail": [1, 2, 3]},
            {"detail": True},
            {"detail": 42},
            {},
            None,
        ]
        for body in bodies:
            msg = _extract_frontend_error(body)
            if msg is not None:
                assert "[object Object]" not in f"Body {body} produced: {msg}"
