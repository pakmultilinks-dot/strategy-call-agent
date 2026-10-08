"""Worldwide timezone selector tests (Phase 5).

Validates:
1. Backend IANA timezone validation via OrganizationSettingsUpdate schema.
2. Existing timezone values remain valid.
3. Global worldwide timezones are accepted.
4. Invalid timezones are rejected.
5. Both onboarding and org-settings dropdowns contain identical options.
6. Dropdown includes major worldwide regions.
7. Existing organization settings save/load behavior still works.
"""
import json
import re
import uuid

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.schemas_auth import OrganizationSettingsUpdate


# ---------------------------------------------------------------------------
# 1. Backend validation — accepted timezones
# ---------------------------------------------------------------------------

class TestTimezoneValidation:
    """Prove the schema accepts/rejects the correct IANA identifiers."""

    @pytest.mark.parametrize("tz", [
        # Original US timezones (must not break existing orgs)
        "America/Chicago",
        "America/New_York",
        "America/Denver",
        "America/Los_Angeles",
        "America/Anchorage",
        "Pacific/Honolulu",
        "UTC",
        "Europe/London",
        "Europe/Paris",
        "Asia/Tokyo",
        # New worldwide timezones
        "Asia/Karachi",
        "Asia/Kolkata",
        "Europe/Berlin",
        "Australia/Sydney",
        "Pacific/Auckland",
        "America/Toronto",
        "America/Vancouver",
        "America/Mexico_City",
        "America/Sao_Paulo",
        "America/Argentina/Buenos_Aires",
        "Europe/Dublin",
        "Europe/Madrid",
        "Europe/Rome",
        "Europe/Amsterdam",
        "Europe/Zurich",
        "Europe/Stockholm",
        "Europe/Warsaw",
        "Europe/Athens",
        "Europe/Helsinki",
        "Europe/Istanbul",
        "Europe/Moscow",
        "Africa/Cairo",
        "Africa/Johannesburg",
        "Africa/Lagos",
        "Africa/Nairobi",
        "Africa/Casablanca",
        "Asia/Dubai",
        "Asia/Riyadh",
        "Asia/Qatar",
        "Asia/Kuwait",
        "Asia/Bahrain",
        "Asia/Muscat",
        "Asia/Jerusalem",
        "Asia/Dhaka",
        "Asia/Colombo",
        "Asia/Kathmandu",
        "Asia/Shanghai",
        "Asia/Hong_Kong",
        "Asia/Taipei",
        "Asia/Seoul",
        "Asia/Singapore",
        "Asia/Bangkok",
        "Asia/Jakarta",
        "Asia/Manila",
        "Australia/Perth",
        "Australia/Adelaide",
        "Australia/Darwin",
        "Australia/Brisbane",
        "Australia/Melbourne",
    ])
    def test_valid_timezone_accepted(self, tz):
        """Every valid IANA timezone must be accepted."""
        result = OrganizationSettingsUpdate(timezone=tz)
        assert result.timezone == tz

    def test_none_timezone_accepted(self):
        """None (omitted) timezone must be accepted."""
        result = OrganizationSettingsUpdate(timezone=None)
        assert result.timezone is None

    @pytest.mark.parametrize("bad_tz", [
        "Not/A/Real_Timezone",
        "Fake/Zone",
        "CST",
        "PST",
        "GMT+5",
        "",
        " America/Chicago ",  # leading/trailing whitespace
    ])
    def test_invalid_timezone_rejected(self, bad_tz):
        """Invalid or ambiguous timezone strings must be rejected."""
        with pytest.raises(ValidationError, match="not a valid IANA timezone"):
            OrganizationSettingsUpdate(timezone=bad_tz)


# ---------------------------------------------------------------------------
# 2. Frontend dropdown consistency
# ---------------------------------------------------------------------------

def _extract_option_values(html: str, select_id: str) -> list[str]:
    """Extract <option value="..."> from a <select> with the given id."""
    pattern = rf'<select\s+id="{select_id}"[^>]*>(.*?)</select>'
    match = re.search(pattern, html, re.DOTALL)
    assert match, f"<select id=\"{select_id}\"> not found in HTML"
    return re.findall(r'<option\s+value="([^"]+)"', match.group(1))


class TestDashboardDropdownConsistency:
    """Both onboarding and org-settings dropdowns must have identical options."""

    @pytest.fixture(autouse=True)
    def _load_dashboard(self, client: TestClient):
        """Fetch dashboard HTML and extract both timezone selects."""
        resp = client.get("/dashboard", follow_redirects=True)
        assert resp.status_code == 200
        self.html = resp.text

    def test_onboarding_dropdown_exists(self):
        opts = _extract_option_values(self.html, "onboard-timezone")
        assert len(opts) > 10, "Onboarding dropdown should have many options"

    def test_org_settings_dropdown_exists(self):
        opts = _extract_option_values(self.html, "os-timezone")
        assert len(opts) > 10, "Org settings dropdown should have many options"

    def test_both_dropdowns_identical(self):
        onboard = _extract_option_values(self.html, "onboard-timezone")
        settings = _extract_option_values(self.html, "os-timezone")
        assert onboard == settings, (
            "Onboarding and org-settings timezone dropdowns must be identical.\n"
            f"Onboarding only: {set(onboard) - set(settings)}\n"
            f"Settings only: {set(settings) - set(onboard)}"
        )

    def test_dropdown_includes_americas(self):
        opts = _extract_option_values(self.html, "os-timezone")
        for tz in ["America/Chicago", "America/New_York", "America/Los_Angeles",
                    "America/Toronto", "America/Sao_Paulo"]:
            assert tz in opts, f"Missing Americas timezone: {tz}"

    def test_dropdown_includes_europe(self):
        opts = _extract_option_values(self.html, "os-timezone")
        for tz in ["Europe/London", "Europe/Paris", "Europe/Berlin", "Europe/Moscow"]:
            assert tz in opts, f"Missing Europe timezone: {tz}"

    def test_dropdown_includes_africa_middle_east(self):
        opts = _extract_option_values(self.html, "os-timezone")
        for tz in ["Africa/Johannesburg", "Africa/Cairo", "Asia/Dubai", "Asia/Riyadh"]:
            assert tz in opts, f"Missing Africa/ME timezone: {tz}"

    def test_dropdown_includes_south_asia(self):
        opts = _extract_option_values(self.html, "os-timezone")
        for tz in ["Asia/Karachi", "Asia/Kolkata", "Asia/Dhaka"]:
            assert tz in opts, f"Missing South Asia timezone: {tz}"

    def test_dropdown_includes_east_southeast_asia(self):
        opts = _extract_option_values(self.html, "os-timezone")
        for tz in ["Asia/Shanghai", "Asia/Tokyo", "Asia/Seoul", "Asia/Singapore"]:
            assert tz in opts, f"Missing East/SE Asia timezone: {tz}"

    def test_dropdown_includes_oceania(self):
        opts = _extract_option_values(self.html, "os-timezone")
        for tz in ["Australia/Sydney", "Australia/Perth", "Pacific/Auckland", "Pacific/Honolulu"]:
            assert tz in opts, f"Missing Oceania timezone: {tz}"

    def test_dropdown_includes_utc(self):
        opts = _extract_option_values(self.html, "os-timezone")
        assert "UTC" in opts, "UTC must be in the timezone dropdown"

    def test_old_values_still_present(self):
        """All previously available timezone values must still exist."""
        opts = _extract_option_values(self.html, "os-timezone")
        for tz in [
            "America/Chicago", "America/New_York", "America/Denver",
            "America/Los_Angeles", "America/Anchorage", "Pacific/Honolulu",
            "UTC", "Europe/London", "Europe/Paris", "Asia/Tokyo",
        ]:
            assert tz in opts, f"Previously available timezone missing: {tz}"


# ---------------------------------------------------------------------------
# 3. Integration — settings save/load with new timezone
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _set_test_env(monkeypatch):
    """Inject test-mode secrets."""
    from app.config import settings
    monkeypatch.setattr(settings, "jwt_secret_key", "test-tz-secret-key-32chars!!!")


def _make_org_and_token(db):
    """Create an org + owner and return (org, auth_header)."""
    from app.auth import create_access_token, hash_password
    from app.models_multi_tenant import Organization, OrganizationStatus, User, UserRole, UserStatus

    org = Organization(
        name=f"TZ Test {uuid.uuid4().hex[:6]}",
        slug=f"tz-test-{uuid.uuid4().hex[:6]}",
        timezone="America/Chicago",
        status=OrganizationStatus.ACTIVE,
        plan="business",
    )
    db.add(org)
    db.flush()

    user = User(
        organization_id=org.id,
        email=f"tz-test-{uuid.uuid4().hex[:6]}@test.com",
        full_name="TZ Tester",
        password_hash=hash_password("StrongPass123!"),
        role=UserRole.OWNER,
        status=UserStatus.ACTIVE,
    )
    db.add(user)
    db.commit()

    token = create_access_token(
        user_id=user.id,
        organization_id=org.id,
        role=UserRole.OWNER.value,
    )
    return org, {"Authorization": f"Bearer {token}"}


@pytest.mark.usefixtures("_set_test_env")
class TestTimezoneSettingsIntegration:
    """Verify PATCH /organization/settings with worldwide timezones."""

    def test_save_and_load_asia_karachi(self, client: TestClient):
        """Organization can save Asia/Karachi and read it back."""
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            org, headers = _make_org_and_token(db)
        finally:
            db.close()

        # Save new timezone
        resp = client.patch(
            "/organization/settings",
            json={"timezone": "Asia/Karachi"},
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["timezone"] == "Asia/Karachi"

        # Read back
        resp = client.get("/organization/settings", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["timezone"] == "Asia/Karachi"

    def test_save_and_load_europe_berlin(self, client: TestClient):
        """Organization can save Europe/Berlin and read it back."""
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            org, headers = _make_org_and_token(db)
        finally:
            db.close()

        resp = client.patch(
            "/organization/settings",
            json={"timezone": "Europe/Berlin"},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["timezone"] == "Europe/Berlin"

    def test_save_and_load_pacific_auckland(self, client: TestClient):
        """Organization can save Pacific/Auckland and read it back."""
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            org, headers = _make_org_and_token(db)
        finally:
            db.close()

        resp = client.patch(
            "/organization/settings",
            json={"timezone": "Pacific/Auckland"},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["timezone"] == "Pacific/Auckland"

    def test_reject_invalid_timezone(self, client: TestClient):
        """PATCH must reject an invalid timezone with 422."""
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            org, headers = _make_org_and_token(db)
        finally:
            db.close()

        resp = client.patch(
            "/organization/settings",
            json={"timezone": "Not/A/Real_Timezone"},
            headers=headers,
        )
        assert resp.status_code == 422
        body = resp.json()
        # FastAPI validation error response contains errors referencing timezone
        errors_text = json.dumps(body).lower()
        assert "timezone" in errors_text

    def test_unchanged_timezone_on_partial_update(self, client: TestClient):
        """PATCH without timezone field should not alter the stored timezone."""
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            org, headers = _make_org_and_token(db)
        finally:
            db.close()

        # First set a known timezone
        client.patch(
            "/organization/settings",
            json={"timezone": "Asia/Tokyo"},
            headers=headers,
        )

        # Now update a different field only
        resp = client.patch(
            "/organization/settings",
            json={"sender_name": "Test Sender"},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["timezone"] == "Asia/Tokyo"
