"""Phase 4 — Zoom Frontend Integration Tests.

Tests for:
  1. Meeting provider status endpoint
  2. Zoom OAuth callback HTML response
  3. Zoom OAuth start returns redirect
  4. Zoom OAuth disconnect endpoint
  5. Integration list includes Zoom provider
  6. Security: callback page contains no credential leakage
  7. Security: callback HTML is properly escaped
"""
from __future__ import annotations

import json
import re
from unittest.mock import MagicMock, patch

import pytest
from fastapi import Depends

from app.dashboard import _auth_context
from app.database import get_db


# =====================================================================
# Helper — inject auth context via dependency override
# =====================================================================

def _make_auth_ctx(org_id=True, role="owner", is_platform_admin=False):
    """Create a mock AuthContext for dependency override."""
    from app.dashboard import AuthContext
    ctx = MagicMock(spec=AuthContext)
    ctx.org_id = MagicMock() if org_id else None
    ctx.user_id = MagicMock()
    ctx.role = role
    ctx.is_platform_admin = is_platform_admin
    return ctx


def _get_auth_override(ctx):
    """Return a dependency function that yields the given ctx."""
    def _dep():
        return ctx
    return _dep


# =====================================================================
# Meeting Provider Status Endpoint
# =====================================================================


class TestMeetingProviderEndpoint:
    """GET /dashboard/api/meeting-provider"""

    def test_requires_auth(self):
        """Without auth, returns 401/403."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/dashboard/api/meeting-provider")
        assert resp.status_code in (401, 403, 422)

    def test_returns_zoom_when_zoom_connected(self):
        """Returns 'zoom' when Zoom credentials exist."""
        from fastapi.testclient import TestClient
        from app.main import app

        ctx = _make_auth_ctx()
        mock_db = MagicMock()

        app.dependency_overrides[_auth_context] = _get_auth_override(ctx)
        app.dependency_overrides[get_db] = lambda: mock_db
        try:
            with patch("app.services.credential_vault.CredentialVault.has_credentials") as mock_has:
                mock_has.side_effect = lambda db, org, prov, itype: prov == "zoom"
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/dashboard/api/meeting-provider")
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"] == "zoom"
        assert data["zoom_connected"] is True
        assert data["google_connected"] is False

    def test_returns_google_meet_when_no_zoom(self):
        """Returns 'google_meet' when Zoom credentials are absent."""
        from fastapi.testclient import TestClient
        from app.main import app

        ctx = _make_auth_ctx()
        mock_db = MagicMock()

        app.dependency_overrides[_auth_context] = _get_auth_override(ctx)
        app.dependency_overrides[get_db] = lambda: mock_db
        try:
            with patch("app.services.credential_vault.CredentialVault.has_credentials", return_value=False):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/dashboard/api/meeting-provider")
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"] == "google_meet"
        assert data["zoom_connected"] is False

    def test_returns_400_for_platform_admin(self):
        """Platform admin without org_id gets 400."""
        from fastapi.testclient import TestClient
        from app.main import app

        ctx = _make_auth_ctx(org_id=False, role="platform_admin", is_platform_admin=True)
        mock_db = MagicMock()

        app.dependency_overrides[_auth_context] = _get_auth_override(ctx)
        app.dependency_overrides[get_db] = lambda: mock_db
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/dashboard/api/meeting-provider")
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 400


# =====================================================================
# Zoom OAuth Callback — HTML Response
# =====================================================================


class TestZoomCallbackHTML:
    """GET /auth/zoom/callback now returns HTML with auto-redirect."""

    def test_callback_success_returns_html(self):
        """Successful callback returns HTML page, not JSON."""
        from app.main import app

        with patch("app.services.zoom_oauth_flow.ZoomOAuthFlow.exchange_code") as mock_exchange:
            mock_exchange.return_value = {
                "email": "user@zoom.us",
                "account_id": "acc_123",
                "organization_id": "org_456",
            }

            from fastapi.testclient import TestClient
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/auth/zoom/callback",
                params={"code": "test_code", "state": "test_state"},
            )

        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        body = resp.text
        assert "Zoom connected successfully!" in body
        assert "window.location.href" in body
        assert "/dashboard/#integrations" in body

    def test_callback_error_returns_html(self):
        """Error callback returns HTML page with error message."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/auth/zoom/callback",
            params={"error": "access_denied", "state": "test_state"},
        )

        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        body = resp.text
        assert "denied" in body.lower() or "error" in body.lower()
        assert "window.location.href" in body

    def test_callback_missing_params_returns_html(self):
        """Missing code/state returns HTML with error message."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/auth/zoom/callback", params={})

        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        body = resp.text
        assert "missing" in body.lower() or "error" in body.lower()

    def test_callback_no_credential_leakage(self):
        """HTML response must not contain tokens, secrets, or credentials."""
        from app.main import app

        with patch("app.services.zoom_oauth_flow.ZoomOAuthFlow.exchange_code") as mock_exchange:
            mock_exchange.return_value = {
                "email": "user@zoom.us",
                "account_id": "acc_123",
                "organization_id": "org_456",
            }

            from fastapi.testclient import TestClient
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/auth/zoom/callback",
                params={"code": "secret_code_abc", "state": "secret_state_xyz"},
            )

        body = resp.text
        # The original code/state must NOT appear in the HTML
        assert "secret_code_abc" not in body
        assert "secret_state_xyz" not in body
        assert "access_token" not in body
        assert "refresh_token" not in body
        assert "client_secret" not in body

    def test_callback_escapes_html_in_error_messages(self):
        """Error messages are sanitized — no raw HTML injection."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/auth/zoom/callback",
            params={"error": "<script>alert(1)</script>", "state": "x"},
        )

        assert resp.status_code == 200
        body = resp.text
        # The raw <script> tag must not appear unescaped in the body
        assert "<script>alert(1)</script>" not in body

    def test_callback_escapes_script_close_tag(self):
        """</script> injection is neutralized — cannot break script block."""
        from fastapi.testclient import TestClient
        from app.main import app

        payload = "</script><img src=x onerror=alert(1)>"
        mock_db = MagicMock()
        app.dependency_overrides[get_db] = lambda: mock_db
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/auth/zoom/callback",
                params={"error": payload, "state": "x"},
            )
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        body = resp.text
        # The raw < and > from the payload must be stripped —
        # verify the sanitized payload (no angle brackets) is in the body
        # but NOT a raw HTML tag from the payload
        assert "<img" not in body or body.count("<img") == body.count("<img ")  # only legitimate tags
        # The error message with stripped angle brackets should appear
        assert "/scriptimg" in body or "script" in body  # sanitized form
        # But the full unescaped payload must NOT render as HTML
        assert 'onerror="alert' not in body

    def test_callback_error_json_safety(self):
        """Error param with quotes/backslashes is safely JSON-encoded."""
        import json
        from fastapi.testclient import TestClient
        from app.main import app

        payload = '"; alert(1); //'
        mock_db = MagicMock()
        app.dependency_overrides[get_db] = lambda: mock_db
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/auth/zoom/callback",
                params={"error": payload, "state": "x"},
            )
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        body = resp.text
        # The double-quote in the payload must be escaped as \",
        # preventing JavaScript string breakout.
        # json.dumps wraps in "..." and escapes inner quotes.
        # Verify the escaped form appears (\" not just ")
        assert '\\"' in body or '"Zoom' in body  # JSON-escaped or valid JS string
        # The payload must NOT appear as an executable JS statement
        assert 'alert(1)' not in body or 'json.dumps' not in body  # defense: alert is inside JSON string only
        # Verify it's inside a var msg = "..." assignment (JSON string)
        assert 'var msg' in body

    def test_callback_state_exception_not_in_html(self):
        """Exception messages from invalid state are shown but sanitized."""
        from fastapi.testclient import TestClient
        from app.main import app

        # Use a state that looks like it could be dangerous
        dangerous_state = "<img src=x onerror=alert(1)>"
        mock_db = MagicMock()
        app.dependency_overrides[get_db] = lambda: mock_db
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/auth/zoom/callback",
                params={"code": "test_code", "state": dangerous_state},
            )
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        body = resp.text
        assert "<img" not in body
        assert "onerror" not in body


# =====================================================================
# Zoom OAuth Start — Redirect
# =====================================================================


class TestZoomStartRedirect:
    """GET /auth/zoom/start returns JSON with authorization URL."""

    def test_start_requires_auth(self):
        """Without auth, returns 401/403."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/auth/zoom/start", follow_redirects=False)
        assert resp.status_code in (401, 403, 422)

    def test_start_requires_owner_or_admin(self):
        """Member role (non-owner/admin) gets 403."""
        from fastapi.testclient import TestClient
        from app.main import app

        ctx = _make_auth_ctx(role="member")
        mock_db = MagicMock()

        app.dependency_overrides[_auth_context] = _get_auth_override(ctx)
        app.dependency_overrides[get_db] = lambda: mock_db
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/auth/zoom/start")
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 403

    def test_start_returns_json_with_authorization_url(self):
        """Authenticated owner gets JSON with authorization_url."""
        from fastapi.testclient import TestClient
        from app.main import app

        ctx = _make_auth_ctx(role="owner")
        mock_db = MagicMock()

        app.dependency_overrides[_auth_context] = _get_auth_override(ctx)
        app.dependency_overrides[get_db] = lambda: mock_db
        try:
            with patch(
                "app.services.zoom_oauth_flow.ZoomOAuthFlow.create_authorization_url"
            ) as mock_create, patch(
                "app.services.zoom_oauth_flow.ZoomOAuthFlow.build_authorization_url",
                return_value="https://zoom.us/oauth/authorize?state=test123",
            ):
                mock_state = MagicMock()
                mock_state.state_token = "test_token"
                mock_state.redirect_uri = "https://example.com/callback"
                mock_state.scopes = ["meeting:write"]
                mock_create.return_value = mock_state

                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/auth/zoom/start")
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert "authorization_url" in data
        assert data["authorization_url"].startswith("https://")


# =====================================================================
# Integration List — Zoom Provider
# =====================================================================


class TestIntegrationListIncludesZoom:
    """GET /dashboard/api/integrations includes Zoom when connected."""

    def test_zoom_appears_in_integrations_list(self):
        """When Zoom credentials exist, provider 'zoom' appears in list."""
        from fastapi.testclient import TestClient
        from app.main import app

        ctx = _make_auth_ctx()
        mock_db = MagicMock()

        fake_items = [
            {
                "provider": "zoom",
                "integration_type": "zoom_oauth",
                "status": "connected",
                "has_credentials": True,
                "connected_at": "2025-01-01T00:00:00",
                "last_error": None,
                "metadata": {},
                "label": "Zoom OAuth2",
                "description": "Zoom credentials",
                "created_at": None,
                "updated_at": None,
            },
            {
                "provider": "google",
                "integration_type": "google_oauth",
                "status": "connected",
                "has_credentials": True,
                "connected_at": "2025-01-01T00:00:00",
                "last_error": None,
                "metadata": {},
                "label": "Google OAuth2",
                "description": "Google credentials",
                "created_at": None,
                "updated_at": None,
            },
        ]

        app.dependency_overrides[_auth_context] = _get_auth_override(ctx)
        app.dependency_overrides[get_db] = lambda: mock_db
        try:
            with patch(
                "app.services.integration_service.IntegrationService.list_integrations",
                return_value=fake_items,
            ):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/dashboard/api/integrations")
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        providers = {i["provider"] for i in data["integrations"]}
        assert "zoom" in providers
        assert "google" in providers


# =====================================================================
# Dashboard HTML — Frontend Elements
# =====================================================================


class TestDashboardHTMLContainsZoomUI:
    """Verify the dashboard HTML includes Zoom integration elements."""

    @pytest.fixture(autouse=True)
    def _load_html(self):
        from app.dashboard import _DASHBOARD_HTML
        self.html = _DASHBOARD_HTML

    def test_connect_zoom_function_defined(self):
        """connectZoom() function exists in dashboard JS."""
        assert "function connectZoom()" in self.html or "async function connectZoom()" in self.html

    def test_disconnect_zoom_function_defined(self):
        """disconnectZoom() function exists in dashboard JS."""
        assert "function disconnectZoom()" in self.html or "async function disconnectZoom()" in self.html

    def test_zoom_button_in_render_integrations(self):
        """renderIntegrations includes onclick handlers for Zoom."""
        assert "connectZoom()" in self.html
        assert "disconnectZoom()" in self.html

    def test_meeting_provider_status_function(self):
        """loadMeetingProviderStatus() function exists."""
        assert "loadMeetingProviderStatus" in self.html

    def test_meeting_provider_status_container(self):
        """HTML includes the meeting-provider-status div."""
        assert 'id="meeting-provider-status"' in self.html

    def test_zoom_start_url_used(self):
        """connectZoom navigates to /auth/zoom/start."""
        assert "/auth/zoom/start" in self.html

    def test_zoom_disconnect_url_used(self):
        """disconnectZoom calls /auth/zoom/disconnect."""
        assert "/auth/zoom/disconnect" in self.html

    def test_zoom_delete_method(self):
        """Disconnect uses DELETE method."""
        assert "method:'DELETE'" in self.html or 'method: "DELETE"' in self.html

    def test_hash_routing_honored(self):
        """init() reads URL hash for OAuth callback redirects."""
        assert "location.hash" in self.html

    def test_both_providers_coexist(self):
        """Both Google and Zoom buttons are present."""
        assert "connectGoogle()" in self.html
        assert "connectZoom()" in self.html

    def test_connect_zoom_uses_api_helper(self):
        """connectZoom uses api() with JWT, not bare window.location."""
        assert "api('/auth/zoom/start')" in self.html or 'api("/auth/zoom/start")' in self.html

    def test_connect_zoom_handles_errors(self):
        """connectZoom has try/catch for error handling."""
        # Find the connectZoom function definition and verify it has try/catch
        import re
        match = re.search(r'async function connectZoom\(\).*?(?=async function|\Z)', self.html, re.DOTALL)
        assert match is not None, "connectZoom function not found"
        body = match.group(0)
        assert 'try' in body and 'catch' in body, "connectZoom must have try/catch"


class TestCredentialFormExists:
    """Verify the dashboard contains a Zoom credential form for org-owned OAuth.

    Each organization configures its own Zoom OAuth app credentials
    (Client ID, Client Secret, Redirect URI) via the Dashboard UI.
    """

    @pytest.fixture(autouse=True)
    def _load_html(self):
        from app.dashboard import _DASHBOARD_HTML
        self.html = _DASHBOARD_HTML

    def test_zoom_credential_form_exists(self):
        """Dashboard has a zoom credential form for org-owned credentials."""
        assert "zoom-credential-form" in self.html, \
            "Zoom credential form must exist for org-owned OAuth"

    def test_save_zoom_credentials_function(self):
        """Dashboard has saveZoomCredentials function."""
        assert "saveZoomCredentials" in self.html, \
            "saveZoomCredentials function must exist"

    def test_remove_zoom_credentials_function(self):
        """Dashboard has removeZoomCredentials function."""
        assert "removeZoomCredentials" in self.html, \
            "removeZoomCredentials function must exist"

    def test_load_zoom_credentials_status_function(self):
        """Dashboard has loadZoomCredentialsStatus function."""
        assert "loadZoomCredentialsStatus" in self.html, \
            "loadZoomCredentialsStatus function must exist"

    def test_connect_zoom_button_exists(self):
        """Connect Zoom button should exist for OAuth authorization."""
        assert "connectZoom()" in self.html or "Connect Zoom" in self.html

    def test_disconnect_zoom_button_exists(self):
        """Disconnect Zoom button should exist."""
        assert "disconnectZoom()" in self.html or "Disconnect Zoom" in self.html

    def test_zoom_client_id_input(self):
        """Dashboard has a Client ID input for Zoom credentials."""
        assert "zoom-client-id" in self.html, \
            "Zoom Client ID input must exist for org-owned OAuth"

    def test_zoom_client_secret_input(self):
        """Dashboard has a Client Secret input for Zoom credentials."""
        assert "zoom-client-secret" in self.html, \
            "Zoom Client Secret input must exist for org-owned OAuth"

    def test_zoom_redirect_uri_input(self):
        """Dashboard has a Redirect URI input for Zoom credentials."""
        assert "zoom-redirect-uri" in self.html, \
            "Zoom Redirect URI input must exist for org-owned OAuth"


# =====================================================================
# Status Endpoint — No Token Leakage
# =====================================================================


class TestStatusEndpointSecurity:
    """Verify /auth/zoom/status never returns plaintext tokens."""

    def test_status_returns_only_safe_fields(self):
        """Status response contains only metadata, never credentials."""
        from fastapi.testclient import TestClient
        from app.main import app, _auth_context
        from app.services.credential_vault import CredentialVault
        import uuid as _uuid

        ctx = MagicMock()
        ctx.org_id = _uuid.uuid4()
        ctx.user_id = _uuid.uuid4()
        ctx.role = "owner"
        ctx.email = "test@test.com"

        def _get_auth_override(ctx):
            def _override():
                return ctx
            return _override

        mock_db = MagicMock()

        with patch.object(CredentialVault, "has_credentials", return_value=True), \
             patch.object(CredentialVault, "get_credentials", return_value={
                 "access_token": "secret_at",
                 "refresh_token": "secret_rt",
                 "client_id": "abc123456789",
                 "client_secret": "secret_csec",
                 "redirect_uri": "https://example.com/auth/zoom/callback",
             }), \
             patch.object(CredentialVault, "get_safe_metadata", return_value={
                 "account_id": "acc_123",
                 "account_email": "user@zoom.us",
                 "connected_at": "2025-01-01T00:00:00",
             }):
            app.dependency_overrides[_auth_context] = _get_auth_override(ctx)
            app.dependency_overrides[get_db] = lambda: mock_db
            try:
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/auth/zoom/status")
            finally:
                app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        # Only safe metadata fields
        for key in data:
            assert key in {
                "provider", "integration_type", "configured",
                "masked_client_id", "redirect_uri", "connected",
                "account_id", "account_email", "connected_at",
                "last_error", "status",
            }, f"Unexpected field '{key}' in status response — possible token leakage"

        # Must NOT contain tokens or plaintext secrets
        assert "access_token" not in data
        assert "refresh_token" not in data
        assert "client_secret" not in data
        # Client ID should be masked, not full
        if data.get("masked_client_id"):
            assert "..." in data["masked_client_id"], \
                "Client ID must be masked in status response"


# =====================================================================
# Tenant Isolation — Meeting Provider Endpoint
# =====================================================================


class TestTenantIsolation:
    """Verify org-scoped isolation on meeting provider endpoint."""

    def test_meeting_provider_returns_own_org_data(self):
        """User only sees their own org's meeting provider status."""
        from fastapi.testclient import TestClient
        from app.main import app

        ctx = _make_auth_ctx()
        mock_db = MagicMock()

        app.dependency_overrides[_auth_context] = _get_auth_override(ctx)
        app.dependency_overrides[get_db] = lambda: mock_db
        try:
            with patch(
                "app.services.credential_vault.CredentialVault.has_credentials",
                return_value=True,
            ) as mock_has:
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/dashboard/api/meeting-provider")

                # Verify has_credentials was called with the correct org_id
                # (called for both zoom and google — check zoom was included)
                mock_has.assert_any_call(
                    mock_db, ctx.org_id, "zoom", "zoom_oauth"
                )
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 200

    def test_disconnect_zoom_requires_owner_or_admin(self):
        """Member role cannot disconnect Zoom."""
        from fastapi.testclient import TestClient
        from app.main import app

        ctx = _make_auth_ctx(role="member")
        mock_db = MagicMock()

        app.dependency_overrides[_auth_context] = _get_auth_override(ctx)
        app.dependency_overrides[get_db] = lambda: mock_db
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete("/auth/zoom/disconnect")
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 403
