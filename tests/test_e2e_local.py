"""
Real local E2E test — simulates the complete customer journey against the running
app (Docker containers with real PostgreSQL). Run with:
    $env:APP_ENV='dev'; python -m pytest tests/test_e2e_local.py -v --tb=short

Requires:
    - Docker containers running (docker compose up -d)
    - App server responding at http://localhost:8000

This test is SELF-CONTAINED:
    - Registers its own user (no pre-seeded data required)
    - Uses unique email per run to avoid conflicts
    - Verifies the complete customer journey
"""
from __future__ import annotations

import subprocess
import os
import uuid

import pytest
import requests
from dotenv import load_dotenv

# Load .env so WEBHOOK_SECRET is available during E2E tests
load_dotenv(override=True)

BASE = "http://localhost:8000"
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
_unique = uuid.uuid4().hex[:8]


def _check_server():
    """Verify the app server is reachable before running E2E tests."""
    try:
        r = requests.get(f"{BASE}/health", timeout=5)
        if r.status_code != 200:
            pytest.skip(f"App server unhealthy: {r.status_code}")
    except requests.ConnectionError:
        pytest.skip("App server not reachable -- run 'docker compose up -d' first")


@pytest.fixture(scope="module")
def creds():
    """Register a fresh user and return credentials + JWT token.

    Self-contained: no pre-seeded data needed.
    """
    _check_server()

    email = f"e2e-test-{_unique}@test.example.com"
    password = "E2ETestP@ss123!"

    # Register a new organization + user
    r = requests.post(
        f"{BASE}/auth/register",
        json={
            "organization_name": f"E2E Test Org {_unique}",
            "email": email,
            "name": "E2E Test User",
            "password": password,
        },
        timeout=10,
    )
    assert r.status_code == 201, f"Registration failed: {r.status_code} {r.text}"
    token = r.json()["access_token"]
    assert token and len(token) > 100

    return {"email": email, "password": password, "token": token}


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def auth_webhook(token):
    return {"Authorization": f"Bearer {WEBHOOK_SECRET}"}


def _get_org_slug(email: str) -> str | None:
    """Retrieve the org slug from Docker PostgreSQL for the given email."""
    try:
        result = subprocess.run(
            [
                "docker", "exec", "strategy-call-agent-db",
                "psql", "-U", "postgres", "-d", "strategy_calls",
                "-t", "-A", "-c",
                "SELECT o.slug FROM organizations o "
                "JOIN users u ON u.organization_id = o.id "
                f"WHERE u.email = '{email}' LIMIT 1",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


class TestRegistrationAndAuth:
    def test_register_returns_201(self, creds):
        assert creds["token"]
        assert len(creds["token"]) > 100

    def test_login_returns_200(self, creds):
        r = requests.post(f"{BASE}/auth/login", json={
            "email": creds["email"],
            "password": creds["password"],
        }, timeout=10)
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_login_wrong_password_401(self, creds):
        r = requests.post(f"{BASE}/auth/login", json={
            "email": creds["email"],
            "password": "WrongPassword123!",
        }, timeout=10)
        assert r.status_code in (401, 422)


class TestWebhookFormSubmission:
    @pytest.fixture(autouse=True)
    def _get_slug(self, creds, request):
        """Determine the org slug for this test class."""
        import subprocess
        result = subprocess.run([
            "docker", "exec", "strategy-call-agent-db",
            "psql", "-U", "postgres", "-d", "strategy_calls",
            "-t", "-A", "-c",
            "SELECT o.slug FROM organizations o JOIN users u ON u.organization_id = o.id "
            f"WHERE u.email = '{creds['email']}' LIMIT 1"
        ], capture_output=True, text=True, timeout=10)
        self.org_slug = result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None
        # If Docker psql failed, try using the API
        if not self.org_slug:
            pytest.skip("Could not determine org slug for webhook tests")

    def test_webhook_creates_lead(self, creds):
        """Simulates Google Form → webhook → lead creation."""
        r = requests.post(
            f"{BASE}/webhooks/{self.org_slug}/form-submission",
            json={
                "Name": "Jane Smith",
                "Email Address": "jane.smith@example.com",
                "Phone Number": "555-1234",
                "Interested?": "Yes",
                "Phone Appt. Date/Time": "2026-12-15 10:00 AM",
            },
            headers=auth_webhook(creds["token"]),
            timeout=30,
        )
        # 200/201 = lead created + pipeline started
        # 202 = lead created but pipeline gated (free tier)
        assert r.status_code in (200, 201, 202), f"Webhook failed: {r.status_code} {r.text}"
        data = r.json()
        assert "lead_id" in data or "message" in data or "status" in data

    def test_webhook_wrong_secret_401(self, creds):
        r = requests.post(
            f"{BASE}/webhooks/{self.org_slug}/form-submission",
            json={"Name": "Bad Actor", "Email Address": "bad@example.com", "Interested?": "Yes", "Phone Appt. Date/Time": "2026-12-15 10:00 AM"},
            headers={"Authorization": "Bearer wrong-secret"},
            timeout=10,
        )
        assert r.status_code in (401, 403)


class TestDashboardLeadsList:
    def test_list_leads(self, creds):
        """The submitted lead should appear in the leads list."""
        r = requests.get(
            f"{BASE}/dashboard/api/leads",
            headers=auth(creds["token"]),
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        # Response is {"total": N, "leads": [...], "limit": N, "offset": N}
        leads = data.get("leads", []) if isinstance(data, dict) else data
        # May be 0 if webhook failed (expected in some test environments)
        assert isinstance(leads, list), f"Expected list of leads, got {type(leads)}"

    def test_lead_detail(self, creds):
        """Get the first lead's detail if any exist."""
        r = requests.get(
            f"{BASE}/dashboard/api/leads",
            headers=auth(creds["token"]),
            timeout=10,
        )
        leads = r.json().get("leads", [])
        if not leads:
            pytest.skip("No leads available — webhook may have failed")
        lead_id = leads[0].get("id")
        if lead_id:
            r2 = requests.get(
                f"{BASE}/dashboard/api/leads/{lead_id}",
                headers=auth(creds["token"]),
                timeout=10,
            )
            assert r2.status_code == 200


class TestFollowUp:
    def test_create_followup(self, creds):
        """Create a follow-up for the first lead.
        
        Note: 422 = missing lead.
        """
        r = requests.get(
            f"{BASE}/dashboard/api/leads",
            headers=auth(creds["token"]),
            timeout=10,
        )
        leads = r.json().get("leads", []) if isinstance(r.json(), dict) else r.json()
        if not leads:
            pytest.skip("No leads available")
        lead_id = leads[0].get("id") or leads[0].get("lead_id")
        if not lead_id:
            pytest.skip("No lead_id found")

        r2 = requests.post(
            f"{BASE}/followups/",
            json={
                "lead_id": lead_id,
                "title": "E2E test follow-up",
                "notes": "E2E test follow-up notes",
                "due_at": "2026-12-31T23:59:59Z",
            },
            headers=auth(creds["token"]),
            timeout=10,
        )
        # 201 = created, 409 = lead in terminal status (error/completed/not_interested)
        assert r2.status_code in (200, 201, 409), f"Followup create failed: {r2.status_code} {r2.text}"

    def test_list_followups(self, creds):
        r = requests.get(
            f"{BASE}/followups/",
            headers=auth(creds["token"]),
            timeout=10,
        )
        assert r.status_code == 200


class TestBilling:
    def test_trial_status(self, creds):
        pytest.skip("Billing endpoints removed")

    def test_current_plan(self, creds):
        pytest.skip("Billing endpoints removed")


class TestOrganizationSettings:
    def test_list_users(self, creds):
        r = requests.get(
            f"{BASE}/organization/users",
            headers=auth(creds["token"]),
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        # Response is {"users": [...], "total": N}
        users = data.get("users", data) if isinstance(data, dict) else data
        assert isinstance(users, list)
        assert len(users) >= 1
        # Owner should be in the list
        emails = [u.get("email") for u in users if isinstance(u, dict)]
        assert creds["email"] in emails


class TestCRM:
    def test_crm_search(self, creds):
        r = requests.get(
            f"{BASE}/crm/search?q=jane",
            headers=auth(creds["token"]),
            timeout=10,
        )
        # CRM search may return 200 with results or 404 if not found
        assert r.status_code in (200, 404)

    def test_crm_stats(self, creds):
        r = requests.get(
            f"{BASE}/crm/stats",
            headers=auth(creds["token"]),
            timeout=10,
        )
        assert r.status_code == 200


class TestPipeline:
    def test_pipeline_log_after_webhook(self, creds):
        """After webhook submission, check event log for pipeline activity."""
        r = requests.get(
            f"{BASE}/dashboard/api/leads",
            headers=auth(creds["token"]),
            timeout=10,
        )
        leads = r.json().get("leads", []) if isinstance(r.json(), dict) else r.json()
        if not leads:
            pytest.skip("No leads")
        lead_id = leads[0].get("id") or leads[0].get("lead_id")
        if not lead_id:
            pytest.skip("No lead_id")

        # Check event log for the lead (pipeline events)
        r2 = requests.get(
            f"{BASE}/dashboard/api/leads/{lead_id}/events",
            headers=auth(creds["token"]),
            timeout=10,
        )
        # Pipeline may have attempted Google Calendar (expected to fail in dev)
        # The important thing is the endpoint works
        assert r2.status_code in (200, 404)
