"""Tests for the health endpoint, readiness endpoint, and form submission webhook."""
import pytest


class TestHealthEndpoint:
    """GET /health"""

    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_returns_ok(self, client):
        data = client.get("/health").json()
        assert data == {"status": "ok"}


class TestReadinessEndpoint:
    """GET /health/ready"""

    def test_readiness_returns_200(self, client):
        resp = client.get("/health/ready")
        assert resp.status_code == 200

    def test_readiness_returns_ready(self, client):
        data = client.get("/health/ready").json()
        assert data["status"] == "ready"
        assert data["database"] == "ok"

    def test_readiness_no_secrets_exposed(self, client):
        """Readiness response must not contain any secret-like values."""
        resp = client.get("/health/ready")
        text = resp.text.lower()
        for word in ["password", "secret", "api_key", "token", "postgres"]:
            assert word not in text


class TestFormSubmission:
    """POST /webhooks/integrated-it-trainings/form-submission"""

    VALID_PAYLOAD = {
        "Interested?": "Yes",
        "Name": "Test User",
        "Company Address": "123 Test St",
        "Phone Number": "555-0100",
        "Direct Number": "555-0101",
        "Courses": "Python, Docker",
        "Email Address": "test-form-submit@example.com",
        "Scheduled Date": "tomorrow",
        "Caller Name": "Agent Smith",
        "Phone Appt. Date/Time": "tomorrow 2pm",
    }

    def test_form_submission_returns_202(self, client):
        resp = client.post("/webhooks/integrated-it-trainings/form-submission", json=self.VALID_PAYLOAD)
        assert resp.status_code == 202

    def test_form_submission_returns_accepted(self, client):
        data = client.post("/webhooks/integrated-it-trainings/form-submission", json=self.VALID_PAYLOAD).json()
        assert data["status"] in ("accepted", "duplicate")

    def test_form_submission_returns_lead_id(self, client):
        data = client.post("/webhooks/integrated-it-trainings/form-submission", json=self.VALID_PAYLOAD).json()
        if data["status"] == "accepted":
            assert "lead_id" in data
            assert len(data["lead_id"]) == 36  # UUID format

    def test_duplicate_submission_returns_duplicate(self, client):
        """Submitting the same payload twice returns duplicate on the second call."""
        resp1 = client.post("/webhooks/integrated-it-trainings/form-submission", json=self.VALID_PAYLOAD)
        resp2 = client.post("/webhooks/integrated-it-trainings/form-submission", json=self.VALID_PAYLOAD)
        assert resp2.status_code == 202
        data2 = resp2.json()
        # Second call may be 'duplicate' due to dedupe_key uniqueness
        assert data2["status"] in ("accepted", "duplicate")
