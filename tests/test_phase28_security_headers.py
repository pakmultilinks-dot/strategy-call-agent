"""Phase 28 P1-C: Security Headers + Content-Security-Policy tests.

Validates that all security headers are present on every response,
that the CSP policy is correctly structured, and that environment-
sensitive headers (HSTS) are gated appropriately.

Headers tested:
- Content-Security-Policy (CSP)
- Referrer-Policy
- Permissions-Policy
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Strict-Transport-Security (HSTS, production only)
- Cache-Control: no-store (non-health endpoints)
"""
import base64

import pytest
from fastapi.testclient import TestClient

from app.config import settings


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def _auth():
    """Return valid HTTP Basic auth header for dashboard endpoints."""
    return {
        "Authorization": "Basic "
        + base64.b64encode(
            f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
        ).decode()
    }


# ---------------------------------------------------------------------------
# 1. CSP header present on all responses
# ---------------------------------------------------------------------------


class TestCSPPresent:
    """Content-Security-Policy header must appear on every response."""

    def test_csp_on_health(self, client):
        resp = client.get("/health")
        assert resp.headers.get("Content-Security-Policy"), (
            "CSP header missing on /health"
        )

    def test_csp_on_dashboard(self, client, _auth):
        resp = client.get("/dashboard", headers=_auth)
        assert resp.headers.get("Content-Security-Policy"), (
            "CSP header missing on /dashboard"
        )

    def test_csp_on_dashboard_api(self, client, _auth):
        resp = client.get("/dashboard/api/summary", headers=_auth)
        assert resp.headers.get("Content-Security-Policy"), (
            "CSP header missing on dashboard API"
        )

    def test_csp_on_webhook(self, client):
        resp = client.get("/webhooks/integrated-it-trainings/form-submission")
        # Webhook returns 405 for GET, but CSP should still be present
        assert resp.headers.get("Content-Security-Policy"), (
            "CSP header missing on webhook"
        )


# ---------------------------------------------------------------------------
# 2. CSP directive structure
# ---------------------------------------------------------------------------


class TestCSPDirectives:
    """CSP must contain all required directives with correct values."""

    def _get_csp(self, client):
        resp = client.get("/health")
        return resp.headers.get("Content-Security-Policy", "")

    def test_default_src_self(self, client):
        csp = self._get_csp(client)
        assert "default-src 'self'" in csp

    def test_script_src_self_unsafe_inline(self, client):
        """script-src allows 'self' and 'unsafe-inline' for dashboard inline JS."""
        csp = self._get_csp(client)
        assert "script-src 'self' 'unsafe-inline'" in csp

    def test_script_src_no_wildcard(self, client):
        """script-src must NOT use wildcard * (blocks external script injection)."""
        csp = self._get_csp(client)
        # Extract script-src directive value
        for part in csp.split(";"):
            part = part.strip()
            if part.startswith("script-src"):
                assert "*" not in part, (
                    f"script-src must not contain wildcard: {part}"
                )
                break

    def test_style_src_fontshare(self, client):
        """style-src must allow api.fontshare.com for external fonts CSS."""
        csp = self._get_csp(client)
        assert "api.fontshare.com" in csp

    def test_font_src_fontshare_cdn(self, client):
        """font-src must allow cdn.fontshare.com for font files."""
        csp = self._get_csp(client)
        for part in csp.split(";"):
            part = part.strip()
            if part.startswith("font-src"):
                assert "cdn.fontshare.com" in part, (
                    f"font-src must include cdn.fontshare.com: {part}"
                )
                break

    def test_img_src_data(self, client):
        """img-src must allow data: for inline SVG search icon."""
        csp = self._get_csp(client)
        for part in csp.split(";"):
            part = part.strip()
            if part.startswith("img-src"):
                assert "data:" in part
                break

    def test_connect_src_self_only(self, client):
        """connect-src must restrict to 'self' only (no external fetches)."""
        csp = self._get_csp(client)
        for part in csp.split(";"):
            part = part.strip()
            if part.startswith("connect-src"):
                assert part == "connect-src 'self'", (
                    f"connect-src should only be 'self': {part}"
                )
                break

    def test_no_event_source_src_directive(self, client):
        """event-source-src is NOT a valid CSP directive; SSE uses connect-src."""
        csp = self._get_csp(client)
        assert "event-source-src" not in csp, (
            f"event-source-src is invalid CSP and must be removed: {csp}"
        )

    def test_frame_ancestors_none(self, client):
        """frame-ancestors 'none' prevents all framing."""
        csp = self._get_csp(client)
        assert "frame-ancestors 'none'" in csp

    def test_base_uri_self(self, client):
        """base-uri 'self' prevents base tag hijacking."""
        csp = self._get_csp(client)
        assert "base-uri 'self'" in csp

    def test_form_action_self(self, client):
        """form-action 'self' prevents form submission to third parties."""
        csp = self._get_csp(client)
        assert "form-action 'self'" in csp

    def test_csp_directive_count(self, client):
        """CSP must contain at least 9 directives."""
        csp = self._get_csp(client)
        directives = [d.strip() for d in csp.split(";") if d.strip()]
        assert len(directives) >= 9, (
            f"CSP has only {len(directives)} directives, expected >= 9"
        )


# ---------------------------------------------------------------------------
# 3. Referrer-Policy
# ---------------------------------------------------------------------------


class TestReferrerPolicy:
    """Referrer-Policy must be present with a safe value."""

    def test_referrer_policy_on_health(self, client):
        resp = client.get("/health")
        assert resp.headers.get("Referrer-Policy"), (
            "Referrer-Policy missing on /health"
        )

    def test_referrer_policy_value(self, client):
        resp = client.get("/health")
        value = resp.headers.get("Referrer-Policy", "")
        # Must be one of the safe values
        safe_values = {
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url",
        }
        assert value in safe_values, f"Unsafe Referrer-Policy: {value}"
        # Our implementation uses strict-origin-when-cross-origin
        assert value == "strict-origin-when-cross-origin"

    def test_referrer_policy_on_dashboard(self, client, _auth):
        resp = client.get("/dashboard", headers=_auth)
        assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


# ---------------------------------------------------------------------------
# 4. Permissions-Policy
# ---------------------------------------------------------------------------


class TestPermissionsPolicy:
    """Permissions-Policy must disable unnecessary browser features."""

    def _get_permissions_policy(self, client):
        resp = client.get("/health")
        return resp.headers.get("Permissions-Policy", "")

    def test_permissions_policy_present(self, client):
        pp = self._get_permissions_policy(client)
        assert pp, "Permissions-Policy header missing"

    def test_camera_disabled(self, client):
        pp = self._get_permissions_policy(client)
        assert "camera=()" in pp

    def test_microphone_disabled(self, client):
        pp = self._get_permissions_policy(client)
        assert "microphone=()" in pp

    def test_geolocation_disabled(self, client):
        pp = self._get_permissions_policy(client)
        assert "geolocation=()" in pp

    def test_payment_disabled(self, client):
        pp = self._get_permissions_policy(client)
        assert "payment=()" in pp

    def test_usb_disabled(self, client):
        pp = self._get_permissions_policy(client)
        assert "usb=()" in pp

    def test_permissions_policy_on_dashboard(self, client, _auth):
        resp = client.get("/dashboard", headers=_auth)
        pp = resp.headers.get("Permissions-Policy", "")
        assert "camera=()" in pp
        assert "microphone=()" in pp


# ---------------------------------------------------------------------------
# 5. HSTS environment gating
# ---------------------------------------------------------------------------


class TestHSTSEnvironmentGating:
    """HSTS should only be present in production environment."""

    def test_hsts_absent_in_non_production(self, client):
        """In dev/test, HSTS must NOT be set (plain HTTP breaks with HSTS)."""
        resp = client.get("/health")
        if settings.app_env != "production":
            assert "Strict-Transport-Security" not in resp.headers, (
                f"HSTS should not be present in env={settings.app_env}"
            )

    def test_hsts_value_when_production(self, client):
        """In production, HSTS must be max-age=31536000."""
        if settings.app_env == "production":
            resp = client.get("/health")
            hsts = resp.headers.get("Strict-Transport-Security", "")
            assert hsts == "max-age=31536000", f"Unexpected HSTS: {hsts}"

    def test_hsts_not_on_health_in_dev(self, client):
        """Health endpoint should not have HSTS in non-production."""
        if settings.app_env != "production":
            resp = client.get("/health")
            assert "Strict-Transport-Security" not in resp.headers


# ---------------------------------------------------------------------------
# 6. Existing headers still present
# ---------------------------------------------------------------------------


class TestExistingHeaders:
    """Existing security headers must not be regressed by CSP additions."""

    def test_nosniff_on_health(self, client):
        resp = client.get("/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_frame_deny_on_health(self, client):
        resp = client.get("/health")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_nosniff_on_dashboard(self, client, _auth):
        resp = client.get("/dashboard", headers=_auth)
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_frame_deny_on_dashboard(self, client, _auth):
        resp = client.get("/dashboard", headers=_auth)
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_cache_control_no_store_on_dashboard(self, client, _auth):
        resp = client.get("/dashboard/api/summary", headers=_auth)
        assert resp.headers.get("Cache-Control") == "no-store"

    def test_cache_control_absent_on_health(self, client):
        """Health endpoint uses short public cache for lightweight probing."""
        resp = client.get("/health")
        assert resp.headers.get("Cache-Control") == "public, max-age=5"


# ---------------------------------------------------------------------------
# 7. CSP consistency across endpoints
# ---------------------------------------------------------------------------


class TestCSPConsistency:
    """CSP must be identical on all endpoints (same middleware, same policy)."""

    def test_csp_same_on_health_and_dashboard(self, client, _auth):
        health_csp = client.get("/health").headers.get("Content-Security-Policy")
        dash_csp = client.get("/dashboard", headers=_auth).headers.get(
            "Content-Security-Policy"
        )
        assert health_csp == dash_csp, "CSP differs between /health and /dashboard"

    def test_csp_same_on_webhook_and_api(self, client, _auth):
        webhook_csp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json={"test": True},
            headers={"Content-Type": "application/json"},
        ).headers.get("Content-Security-Policy")
        api_csp = client.get("/dashboard/api/summary", headers=_auth).headers.get(
            "Content-Security-Policy"
        )
        assert webhook_csp == api_csp, "CSP differs between webhook and API"


# ---------------------------------------------------------------------------
# 8. Security headers on 401/404 responses
# ---------------------------------------------------------------------------


class TestHeadersOnErrorResponses:
    """Security headers must be present even on error responses."""

    def test_csp_on_unauthorized(self, client):
        resp = client.get("/dashboard")
        # No auth → 401, but CSP should still be present
        assert resp.headers.get("Content-Security-Policy"), (
            "CSP missing on 401 response"
        )

    def test_nosniff_on_unauthorized(self, client):
        resp = client.get("/dashboard")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_referrer_policy_on_unauthorized(self, client):
        resp = client.get("/dashboard")
        assert resp.headers.get("Referrer-Policy"), (
            "Referrer-Policy missing on 401 response"
        )

    def test_permissions_policy_on_unauthorized(self, client):
        resp = client.get("/dashboard")
        assert resp.headers.get("Permissions-Policy"), (
            "Permissions-Policy missing on 401 response"
        )
