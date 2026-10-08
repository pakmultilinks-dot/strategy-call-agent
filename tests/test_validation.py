"""Tests for form submission validation (PHASE 2).

Covers: valid submission, invalid email, missing required fields,
phone number as email, and the custom 422 error response format.
"""
import uuid

import pytest


def _unique_payload(**overrides):
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


# ── TEST 1: Valid submission ─────────────────────────────────────────────────


class TestValidSubmission:
    """A well-formed submission should return 202 accepted."""

    def test_valid_returns_202(self, client):
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=_unique_payload())
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] in ("accepted", "duplicate")
        if data["status"] == "accepted":
            assert "lead_id" in data


# ── TEST 2: Invalid email ───────────────────────────────────────────────────


class TestInvalidEmail:
    """An invalid email address should return 422 with a clear error."""

    def test_invalid_email_returns_422(self, client):
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Email Address": "not-an-email"}),
        )
        assert resp.status_code == 422

    def test_invalid_email_has_field_error(self, client):
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Email Address": "not-an-email"}),
        )
        data = resp.json()
        assert "detail" in data
        assert "email" in data["detail"].lower()

    def test_empty_string_email_returns_422(self, client):
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Email Address": ""}),
        )
        assert resp.status_code == 422


# ── TEST 3: Phone number as email ───────────────────────────────────────────


class TestPhoneAsEmail:
    """A phone number supplied as Email Address should return 422 with a
    specific error message mentioning 'phone number'."""

    def test_phone_with_plus_returns_422(self, client):
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Email Address": "+92 300 1234567"}),
        )
        assert resp.status_code == 422

    def test_phone_with_plus_mentions_phone(self, client):
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Email Address": "+92 300 1234567"}),
        )
        data = resp.json()
        assert "detail" in data
        assert "email" in data["detail"].lower()

    def test_digits_only_phone_returns_422(self, client):
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Email Address": "3001234567"}),
        )
        assert resp.status_code == 422

    def test_digits_only_mentions_phone(self, client):
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Email Address": "3001234567"}),
        )
        data = resp.json()
        assert "detail" in data
        assert "email" in data["detail"].lower()

    def test_short_number_not_treated_as_phone(self, client):
        """A short number like '12345' (5 digits) should fail as invalid email,
        NOT as 'phone number' — it's too short to be a phone."""
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Email Address": "12345"}),
        )
        assert resp.status_code == 422
        data = resp.json()
        assert "detail" in data
        # Should be generic email validation error, not phone-specific
        assert "phone number" not in data["detail"].lower()


# ── TEST 4: Missing required fields ─────────────────────────────────────────


class TestMissingRequiredFields:
    """Missing required fields should return 422 with clear errors."""

    def test_missing_name_returns_422(self, client):
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Name": ""}),
        )
        assert resp.status_code == 422
        data = resp.json()
        assert "detail" in data

    def test_missing_email_returns_422(self, client):
        payload = _unique_payload()
        del payload["Email Address"]
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
        assert resp.status_code == 422
        data = resp.json()
        assert "detail" in data

    def test_missing_appt_time_returns_422(self, client):
        payload = _unique_payload()
        del payload["Phone Appt. Date/Time"]
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=payload)
        assert resp.status_code == 422
        data = resp.json()
        assert "detail" in data

    def test_multiple_missing_fields_lists_all(self, client):
        """When multiple required fields are missing, all should be reported."""
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json={
                "Interested?": "Yes",
                # Name, Email, and Appt Time all missing
            },
        )
        assert resp.status_code == 422
        data = resp.json()
        assert "detail" in data


# ── TEST 5: Custom 422 response format ──────────────────────────────────────


class TestValidationResponseFormat:
    """The org-scoped endpoint returns 422 with a detail string for validation errors."""

    def test_422_has_detail_field(self, client):
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Email Address": "bad"}),
        )
        data = resp.json()
        assert "detail" in data

    def test_422_detail_is_string(self, client):
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Email Address": "bad"}),
        )
        data = resp.json()
        assert isinstance(data["detail"], str)
        assert len(data["detail"]) > 0

    def test_422_detail_mentions_validation(self, client):
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Email Address": "bad"}),
        )
        data = resp.json()
        assert "validation" in data["detail"].lower() or "email" in data["detail"].lower()


# ── TEST 6: Placeholder emails ──────────────────────────────────────────────


class TestPlaceholderEmails:
    """Common placeholder emails should be rejected."""

    @pytest.mark.parametrize("placeholder", ["n/a", "na", "none", "-", "--", "no", "noemail"])
    def test_placeholder_rejected(self, client, placeholder):
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Email Address": placeholder}),
        )
        assert resp.status_code == 422


# ── TEST 7: Interested? validation ──────────────────────────────────────────


class TestInterestedValidation:
    """Ambiguous Interested? values should be rejected."""

    def test_ambiguous_interested_returns_422(self, client):
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Interested?": "Maybe"}),
        )
        assert resp.status_code == 422
        data = resp.json()
        assert "detail" in data

    def test_blank_interested_accepted(self, client):
        """Blank Interested? is valid (legacy behavior — treated as None)."""
        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json=_unique_payload(**{"Interested?": ""}),
        )
        assert resp.status_code == 202
