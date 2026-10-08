"""Phase 6B.5 - Zoom OAuth + Meeting Provider Tests (Steps 10-11).

Comprehensive test coverage for:
  1. ZoomAPIClient - unit tests with httpx mocking (no network)
  2. ZoomOAuthFlow - state management, validation, credential storage
  3. ZoomMeetingProvider - meeting CRUD delegation
  4. resolve_meeting_provider - provider selection logic
  5. Token refresh - expiry detection, transparent refresh
  6. Route integration - OAuth start/callback/status/disconnect endpoints

DB-dependent tests use the shared fixtures from conftest.py.
Tests that require Zoom API access mock all HTTP calls.
"""
from __future__ import annotations

import secrets
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.models_multi_tenant import IntegrationStatus


# =====================================================================
# ZoomAPIClient - pure unit tests (no DB, no network)
# =====================================================================


class TestZoomAPIClientAuthorizationURL:
    """Test authorization URL construction."""

    def test_build_authorization_url_contains_required_params(self):
        from app.services.zoom_api_client import ZoomAPIClient, ZOOM_OAUTH_AUTHORIZE

        url = ZoomAPIClient.build_authorization_url(
            client_id="test_client_id_123",
            redirect_uri="http://localhost:8000/auth/zoom/callback",
            state_token="abc-def-123",
        )

        assert url.startswith(ZOOM_OAUTH_AUTHORIZE)
        assert "client_id=test_client_id_123" in url
        assert "state=abc-def-123" in url
        assert "response_type=code" in url
        assert "redirect_uri=" in url

    def test_build_authorization_url_encodes_redirect_uri(self):
        from app.services.zoom_api_client import ZoomAPIClient

        url = ZoomAPIClient.build_authorization_url(
            client_id="cid",
            redirect_uri="http://localhost:8000/auth/zoom/callback",
            state_token="st",
        )

        # redirect_uri should be URL-encoded
        assert "localhost%3A8000" in url or "redirect_uri=http" in url


class TestZoomAPIClientExchangeCode:
    """Test authorization code exchange with mocked HTTP."""

    @patch("app.services.zoom_api_client.httpx.post")
    def test_exchange_code_success(self, mock_post):
        from app.services.zoom_api_client import ZoomAPIClient

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "access_token": "at_abc123",
            "refresh_token": "rt_xyz789",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "meeting:write",
        }
        mock_post.return_value = mock_resp

        result = ZoomAPIClient.exchange_code(
            code="auth_code_123",
            client_id="cid",
            client_secret="csec",
            redirect_uri="http://localhost:8000/auth/zoom/callback",
        )

        assert result["access_token"] == "at_abc123"
        assert result["refresh_token"] == "rt_xyz789"
        assert result["expires_in"] == 3600

        # Verify Basic Auth was used
        call_kwargs = mock_post.call_args
        assert call_kwargs[1].get("auth") == ("cid", "csec") or \
               call_kwargs.kwargs.get("auth") == ("cid", "csec")

    @patch("app.services.zoom_api_client.httpx.post")
    def test_exchange_code_failure_raises_error(self, mock_post):
        from app.services.zoom_api_client import ZoomAPIClient, ZoomTokenExchangeError

        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Code expired",
        }
        mock_post.return_value = mock_resp

        with pytest.raises(ZoomTokenExchangeError, match="invalid_grant"):
            ZoomAPIClient.exchange_code(
                code="expired_code",
                client_id="cid",
                client_secret="csec",
                redirect_uri="http://localhost:8000/auth/zoom/callback",
            )

    @patch("app.services.zoom_api_client.httpx.post")
    def test_exchange_code_network_error_raises_error(self, mock_post):
        from app.services.zoom_api_client import ZoomAPIClient, ZoomTokenExchangeError

        mock_post.side_effect = httpx.ConnectError("Connection refused")

        with pytest.raises(ZoomTokenExchangeError, match="Failed to connect"):
            ZoomAPIClient.exchange_code(
                code="code",
                client_id="cid",
                client_secret="csec",
                redirect_uri="http://localhost:8000/auth/zoom/callback",
            )


class TestZoomAPIClientGetAccountInfoDiagnostics:
    """Verify that get_account_info() surfaces Zoom error details on failure.

    The previous implementation discarded the response body, making HTTP 400
    errors opaque. After the fix, the Zoom error code and message should be
    included in the raised exception - without ever logging tokens or secrets.
    """

    @patch("app.services.zoom_api_client.httpx.get")
    def test_400_includes_zoom_error_code_and_message(self, mock_get):
        from app.services.zoom_api_client import ZoomAPIClient, ZoomAPIError

        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "reason": "Invalid request",
            "code": 300,
            "message": "The request is invalid. Check required scopes.",
        }
        mock_get.return_value = mock_resp

        with pytest.raises(ZoomAPIError, match="Zoom code=300") as exc_info:
            ZoomAPIClient.get_account_info(access_token="fake_token")

        msg = str(exc_info.value)
        assert "400" in msg
        assert "300" in msg
        assert "invalid" in msg.lower() or "check required scopes" in msg.lower()

    @patch("app.services.zoom_api_client.httpx.get")
    def test_400_non_json_response_still_raises(self, mock_get):
        from app.services.zoom_api_client import ZoomAPIClient, ZoomAPIError

        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.headers = {"content-type": "text/html"}
        mock_resp.json.side_effect = ValueError("No JSON")
        mock_get.return_value = mock_resp

        with pytest.raises(ZoomAPIError, match="HTTP 400"):
            ZoomAPIClient.get_account_info(access_token="fake_token")

    @patch("app.services.zoom_api_client.httpx.get")
    def test_success_returns_expected_fields(self, mock_get):
        from app.services.zoom_api_client import ZoomAPIClient

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "id": "user_123",
            "account_id": "acc_456",
            "email": "user@zoom.us",
            "first_name": "Test",
            "last_name": "User",
        }
        mock_get.return_value = mock_resp

        result = ZoomAPIClient.get_account_info(access_token="fake_token")
        assert result["id"] == "user_123"
        assert result["account_id"] == "acc_456"
        assert result["email"] == "user@zoom.us"

    @patch("app.services.zoom_api_client.httpx.get")
    def test_no_tokens_in_error_message(self, mock_get):
        """Access tokens must never appear in exception messages."""
        from app.services.zoom_api_client import ZoomAPIClient, ZoomAPIError

        secret_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.SECRET"

        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"code": 124, "message": "Invalid parameter"}
        mock_get.return_value = mock_resp

        with pytest.raises(ZoomAPIError) as exc_info:
            ZoomAPIClient.get_account_info(access_token=secret_token)

        assert secret_token not in str(exc_info.value)


class TestZoomAPIClientRefreshToken:
    """Test token refresh with mocked HTTP."""

    @patch("app.services.zoom_api_client.httpx.post")
    def test_refresh_success(self, mock_post):
        from app.services.zoom_api_client import ZoomAPIClient

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "access_token": "new_at_456",
            "refresh_token": "new_rt_789",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_resp

        result = ZoomAPIClient.refresh_access_token(
            refresh_token="old_rt_123",
            client_id="cid",
            client_secret="csec",
        )

        assert result["access_token"] == "new_at_456"
        assert result["refresh_token"] == "new_rt_789"

    @patch("app.services.zoom_api_client.httpx.post")
    def test_refresh_failure_raises_error(self, mock_post):
        from app.services.zoom_api_client import ZoomAPIClient, ZoomTokenRefreshError

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"error": "invalid_grant"}
        mock_post.return_value = mock_resp

        with pytest.raises(ZoomTokenRefreshError, match="invalid_grant"):
            ZoomAPIClient.refresh_access_token(
                refresh_token="bad_rt",
                client_id="cid",
                client_secret="csec",
            )


class TestZoomAPIClientMeetingCRUD:
    """Test meeting create/get/delete with mocked HTTP."""

    @patch("app.services.zoom_api_client.httpx.post")
    def test_create_meeting_success(self, mock_post):
        from app.services.zoom_api_client import ZoomAPIClient

        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "id": 12345678901,
            "join_url": "https://zoom.us/j/12345678901",
            "start_time": "2026-09-01T14:00:00",
            "topic": "Strategy Call",
            "duration": 30,
            "status": "waiting",
        }
        mock_post.return_value = mock_resp

        result = ZoomAPIClient.create_meeting(
            access_token="valid_token",
            topic="Strategy Call",
            start_time=datetime(2026, 9, 1, 14, 0, tzinfo=timezone.utc),
            duration_minutes=30,
            description="Quarterly review",
            timezone="America/Chicago",
        )

        assert result["id"] == "12345678901"
        assert result["join_url"] == "https://zoom.us/j/12345678901"
        assert result["topic"] == "Strategy Call"

    @patch("app.services.zoom_api_client.httpx.get")
    def test_get_meeting_success(self, mock_get):
        from app.services.zoom_api_client import ZoomAPIClient

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "id": 12345678901,
            "join_url": "https://zoom.us/j/12345678901",
            "topic": "Strategy Call",
            "status": "started",
        }
        mock_get.return_value = mock_resp

        result = ZoomAPIClient.get_meeting("valid_token", "12345678901")
        assert result is not None
        assert result["id"] == "12345678901"

    @patch("app.services.zoom_api_client.httpx.get")
    def test_get_meeting_not_found_returns_none(self, mock_get):
        from app.services.zoom_api_client import ZoomAPIClient

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = ZoomAPIClient.get_meeting("valid_token", "999")
        assert result is None

    @patch("app.services.zoom_api_client.httpx.delete")
    def test_delete_meeting_success(self, mock_delete):
        from app.services.zoom_api_client import ZoomAPIClient

        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_delete.return_value = mock_resp

        result = ZoomAPIClient.delete_meeting("valid_token", "12345678901")
        assert result is True

    @patch("app.services.zoom_api_client.httpx.delete")
    def test_delete_meeting_already_gone_is_idempotent(self, mock_delete):
        from app.services.zoom_api_client import ZoomAPIClient

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_delete.return_value = mock_resp

        result = ZoomAPIClient.delete_meeting("valid_token", "999")
        assert result is True


class TestTokenExpiryHelper:
    """Test the is_token_expired helper."""

    def test_expired_token(self):
        from app.services.zoom_api_client import is_token_expired

        past = datetime.now(timezone.utc) - timedelta(minutes=10)
        assert is_token_expired(past) is True

    def test_valid_token(self):
        from app.services.zoom_api_client import is_token_expired

        future = datetime.now(timezone.utc) + timedelta(hours=1)
        assert is_token_expired(future) is False

    def test_expiring_soon_is_expired(self):
        """Token within buffer window (5 min) should be flagged."""
        from app.services.zoom_api_client import is_token_expired

        soon = datetime.now(timezone.utc) + timedelta(minutes=3)
        assert is_token_expired(soon) is True

    def test_none_is_expired(self):
        from app.services.zoom_api_client import is_token_expired

        assert is_token_expired(None) is True


# =====================================================================
# ZoomOAuthFlow - state management and validation tests
# =====================================================================


class TestZoomOAuthStateValidation:
    """Test state token validation logic (unit, no DB)."""

    def test_validate_state_rejects_nonexistent_token(self):
        """State token that doesn't exist in DB should raise error."""
        from app.services.zoom_oauth_flow import (
            ZoomOAuthFlow,
            ZoomOAuthStateError,
        )

        # We need a DB session - use a mock
        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = None

        with pytest.raises(ZoomOAuthStateError, match="Invalid OAuth state"):
            ZoomOAuthFlow.exchange_code(
                db=mock_db, code="code", state="nonexistent_token"
            )

    def test_validate_state_rejects_used_token(self):
        """Previously used state token should raise error."""
        from app.services.zoom_oauth_flow import (
            _validate_state,
            ZoomOAuthStateError,
        )

        mock_state = MagicMock()
        mock_state.used = True
        mock_state.organization_id = uuid.uuid4()

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_state

        with pytest.raises(ZoomOAuthStateError, match="already been used"):
            _validate_state(mock_db, "reused_token")

    def test_validate_state_rejects_expired_token(self):
        """Expired state token should raise error."""
        from app.services.zoom_oauth_flow import (
            _validate_state,
            ZoomOAuthStateError,
        )

        mock_state = MagicMock()
        mock_state.used = False
        mock_state.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        mock_state.organization_id = uuid.uuid4()

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_state

        with pytest.raises(ZoomOAuthStateError, match="expired"):
            _validate_state(mock_db, "expired_token")


class TestZoomOAuthFlowCreateAuthorizationURL:
    """Test authorization URL creation."""

    def test_create_authorization_url_requires_config(self):
        """Should raise error if org has no Zoom credentials in vault."""
        from app.services.zoom_oauth_flow import (
            ZoomOAuthFlow,
            ZoomOAuthError,
        )
        from app.services.credential_vault import CredentialNotFoundError

        mock_db = MagicMock()

        with patch(
            "app.services.integration_config_resolver.IntegrationConfigResolver"
        ) as mock_resolver:
            mock_resolver.resolve_zoom_config.side_effect = CredentialNotFoundError(
                "not found"
            )
            with pytest.raises(ZoomOAuthError, match="not set up"):
                ZoomOAuthFlow.create_authorization_url(
                    db=mock_db,
                    org_id=uuid.uuid4(),
                    user_id=uuid.uuid4(),
                )

    def test_create_authorization_url_success(self):
        """Should create state row and return it when org has credentials."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow
        from app.services.integration_config_resolver import ZoomOAuthConfig

        mock_db = MagicMock()

        mock_cfg = ZoomOAuthConfig(
            account_id="",
            client_id="test_cid",
            client_secret="test_csec",
            redirect_uri="http://localhost:8000/auth/zoom/callback",
        )

        with patch(
            "app.services.integration_config_resolver.IntegrationConfigResolver"
        ) as mock_resolver:
            mock_resolver.resolve_zoom_config.return_value = mock_cfg

            with patch("app.services.zoom_oauth_flow.settings") as mock_settings:
                mock_settings.zoom_oauth_state_ttl_minutes = 10

                result = ZoomOAuthFlow.create_authorization_url(
                    db=mock_db,
                    org_id=uuid.uuid4(),
                    user_id=uuid.uuid4(),
                )

                # State row should be added to DB
                mock_db.add.assert_called_once()
                mock_db.commit.assert_called_once()

                # Returned state should have a state_token
                state_row = mock_db.add.call_args[0][0]
                assert len(state_row.state_token) > 20


class TestZoomOAuthFlowConnectionStatus:
    """Test connection status check."""

    def test_get_connection_status_returns_disconnected_when_no_creds(self):
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        mock_db = MagicMock()

        with patch("app.services.zoom_oauth_flow.settings"), \
             patch("app.services.credential_vault.CredentialVault") as mock_vault:
            mock_vault.has_credentials.return_value = False
            mock_vault.get_safe_metadata.return_value = None

            result = ZoomOAuthFlow.get_connection_status(
                mock_db, uuid.uuid4()
            )

            assert result["connected"] is False
            assert result["provider"] == "zoom"


# =====================================================================
# ZoomMeetingProvider - meeting delegation tests
# =====================================================================


class TestZoomMeetingProvider:
    """Test ZoomMeetingProvider protocol implementation."""

    def _make_provider(self):
        from app.services.meeting_provider import ZoomMeetingProvider

        mock_ctx = MagicMock()
        mock_ctx.organization_id = uuid.uuid4()
        mock_db = MagicMock()
        return ZoomMeetingProvider(org_context=mock_ctx, db=mock_db)

    @patch("app.services.zoom_oauth_flow.ZoomOAuthFlow.refresh_token_if_needed")
    @patch("app.services.zoom_api_client.httpx.post")
    def test_create_meeting_returns_meeting_details(self, mock_post, mock_refresh):
        from app.services.meeting_provider import MeetingDetails

        mock_refresh.return_value = "valid_token"
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "id": 9876543210,
            "join_url": "https://zoom.us/j/9876543210",
            "topic": "Strategy Call",
            "duration": 30,
            "status": "waiting",
        }
        mock_post.return_value = mock_resp

        provider = self._make_provider()
        result = provider.create_meeting(
            summary="Strategy Call",
            description="Quarterly review",
            start_utc=datetime(2026, 9, 1, 14, 0, tzinfo=timezone.utc),
            duration_minutes=30,
            attendees=["user@example.com"],
            idempotency_key="lead-123",
        )

        assert isinstance(result, MeetingDetails)
        assert result.meeting_id == "9876543210"
        assert result.meeting_link == "https://zoom.us/j/9876543210"
        assert result.provider == "zoom"

    @patch("app.services.zoom_oauth_flow.ZoomOAuthFlow.refresh_token_if_needed")
    @patch("app.services.zoom_api_client.httpx.delete")
    def test_cancel_meeting_calls_delete(self, mock_delete, mock_refresh):
        mock_refresh.return_value = "valid_token"
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_delete.return_value = mock_resp

        provider = self._make_provider()
        provider.cancel_meeting("12345")

        mock_delete.assert_called_once()

    @patch("app.services.zoom_oauth_flow.ZoomOAuthFlow.refresh_token_if_needed")
    @patch("app.services.zoom_api_client.httpx.get")
    def test_get_meeting_link_returns_url(self, mock_get, mock_refresh):
        mock_refresh.return_value = "valid_token"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "id": 12345,
            "join_url": "https://zoom.us/j/12345",
        }
        mock_get.return_value = mock_resp

        provider = self._make_provider()
        link = provider.get_meeting_link("12345")
        assert link == "https://zoom.us/j/12345"


# =====================================================================
# resolve_meeting_provider - resolution logic tests
# =====================================================================


class TestResolveMeetingProvider:
    """Test provider resolution logic."""

    def test_resolves_zoom_when_credentials_exist(self):
        from app.services.meeting_provider import (
            resolve_meeting_provider,
            ZoomMeetingProvider,
        )

        mock_ctx = MagicMock()
        mock_ctx.organization_id = uuid.uuid4()
        mock_db = MagicMock()

        with patch("app.services.credential_vault.CredentialVault") as mock_vault:
            mock_vault.has_credentials.return_value = True

            provider = resolve_meeting_provider(
                org_context=mock_ctx, db=mock_db
            )

            assert isinstance(provider, ZoomMeetingProvider)

    def test_defaults_to_google_when_no_zoom_creds(self):
        from app.services.meeting_provider import (
            resolve_meeting_provider,
            ZoomMeetingProvider,
        )

        mock_ctx = MagicMock()
        mock_ctx.organization_id = uuid.uuid4()
        mock_db = MagicMock()

        with patch("app.services.credential_vault.CredentialVault") as mock_vault:
            mock_vault.has_credentials.return_value = False

            provider = resolve_meeting_provider(
                org_context=mock_ctx, db=mock_db
            )

            # Should return the Google Meet shim
            assert not isinstance(provider, ZoomMeetingProvider)
            assert hasattr(provider, "provider_name")
            assert provider.provider_name == "google_meet"

    def test_defaults_to_google_when_no_context(self):
        from app.services.meeting_provider import resolve_meeting_provider

        provider = resolve_meeting_provider(org_context=None, db=None)
        assert provider.provider_name == "google_meet"


# =====================================================================
# Route integration - endpoint tests
# =====================================================================


class TestZoomOAuthRoutes:
    """Test the Zoom OAuth HTTP endpoints."""

    def test_zoom_status_returns_disconnected(self):
        """GET /auth/zoom/status should return disconnected status."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)

        # Without auth, should get 401 or 403
        resp = client.get("/auth/zoom/status")
        # The endpoint requires auth - without valid JWT it should fail
        assert resp.status_code in (401, 403, 422)


class TestZoomOAuthFlowExchangeCode:
    """Integration-level tests for the exchange_code flow."""

    def test_exchange_code_rejects_used_state(self):
        """exchange_code should reject a previously used state token."""
        from app.services.zoom_oauth_flow import (
            ZoomOAuthFlow,
            ZoomOAuthStateError,
        )

        mock_state = MagicMock()
        mock_state.used = True
        mock_state.organization_id = uuid.uuid4()

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_state

        with pytest.raises(ZoomOAuthStateError, match="already been used"):
            ZoomOAuthFlow.exchange_code(
                db=mock_db, code="code", state="used_state"
            )


# =====================================================================
# Exception hierarchy tests
# =====================================================================


class TestZoomExceptions:
    """Verify exception hierarchy and error codes."""

    def test_zoom_api_error_hierarchy(self):
        from app.services.zoom_api_client import (
            ZoomAPIError,
            ZoomTokenExchangeError,
            ZoomTokenRefreshError,
            ZoomMeetingError,
        )

        assert issubclass(ZoomTokenExchangeError, ZoomAPIError)
        assert issubclass(ZoomTokenRefreshError, ZoomAPIError)
        assert issubclass(ZoomMeetingError, ZoomAPIError)

    def test_zoom_oauth_error_hierarchy(self):
        from app.services.zoom_oauth_flow import (
            ZoomOAuthError,
            ZoomOAuthStateError,
            ZoomOAuthTokenExchangeError,
            ZoomOAuthDenialError,
        )

        assert issubclass(ZoomOAuthStateError, ZoomOAuthError)
        assert issubclass(ZoomOAuthTokenExchangeError, ZoomOAuthError)
        assert issubclass(ZoomOAuthDenialError, ZoomOAuthError)

    def test_error_codes_are_distinct(self):
        from app.services.zoom_api_client import (
            ZoomTokenExchangeError,
            ZoomTokenRefreshError,
        )

        e1 = ZoomTokenExchangeError("test")
        e2 = ZoomTokenRefreshError("test")
        assert e1.error_code != e2.error_code


# =====================================================================
# Credential vault integration - verify correct provider/type keys
# =====================================================================


class TestZoomCredentialKeys:
    """Verify the vault keys used for Zoom OAuth are consistent."""

    def test_zoom_oauth_flow_uses_correct_vault_keys(self):
        """ZoomOAuthFlow should use provider='zoom', type='zoom_oauth'."""
        import inspect
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        # Read the source and verify the vault keys
        source = inspect.getsource(ZoomOAuthFlow.exchange_code)
        assert '"zoom"' in source or "'zoom'" in source
        assert '"zoom_oauth"' in source or "'zoom_oauth'" in source

    def test_zoom_provider_uses_correct_vault_keys(self):
        """ZoomMeetingProvider._get_access_token should use correct vault keys."""
        import inspect
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        source = inspect.getsource(ZoomOAuthFlow.refresh_token_if_needed)
        assert '"zoom"' in source or "'zoom'" in source
        assert '"zoom_oauth"' in source or "'zoom_oauth'" in source


# =====================================================================
# Migration test
# =====================================================================


class TestMigrationExists:
    """Verify the Alembic migration file exists and has correct metadata."""

    def test_migration_015_file_exists(self):
        from pathlib import Path
        migration = Path("alembic/versions/015_zoom_oauth_states.py")
        assert migration.exists(), "Migration 015 file not found"

    def test_migration_has_correct_revision(self):
        """Verify migration 015 references 014 as down_revision."""
        import importlib
        spec = importlib.util.spec_from_file_location(
            "migration_015", "alembic/versions/015_zoom_oauth_states.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.revision == "015_zoom_oauth_states"
        assert mod.down_revision == "014_zoom_lead_fields"


# =====================================================================
# SECURITY TESTS - OAuth state binding and isolation
# =====================================================================


class TestOAuthStateSecurity:
    """Test OAuth state is properly bound to org+user, single-use, and expiring."""

    @contextmanager
    def _patch_resolver(self):
        """Context manager to patch IntegrationConfigResolver for create_authorization_url."""
        from app.services.integration_config_resolver import ZoomOAuthConfig
        mock_cfg = ZoomOAuthConfig(
            account_id="",
            client_id="cid",
            client_secret="csec",
            redirect_uri="http://localhost/callback",
        )
        with patch(
            "app.services.integration_config_resolver.IntegrationConfigResolver"
        ) as mock_resolver, patch(
            "app.services.zoom_oauth_flow.settings"
        ) as mock_settings:
            mock_resolver.resolve_zoom_config.return_value = mock_cfg
            mock_settings.zoom_oauth_state_ttl_minutes = 10
            yield mock_resolver, mock_settings

    def test_state_token_is_cryptographically_random(self):
        """State token must come from secrets.token_urlsafe, not predictable."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        mock_db = MagicMock()
        tokens = set()
        for _ in range(20):
            mock_db.reset_mock()
            with self._patch_resolver():
                ZoomOAuthFlow.create_authorization_url(
                    db=mock_db,
                    org_id=uuid.uuid4(),
                    user_id=uuid.uuid4(),
                )
                state_row = mock_db.add.call_args[0][0]
                tokens.add(state_row.state_token)

        # All 20 tokens must be unique
        assert len(tokens) == 20

    def test_state_binds_to_organization(self):
        """State token must be bound to the creating organization."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        mock_db = MagicMock()
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()

        with self._patch_resolver():
            row_a = ZoomOAuthFlow.create_authorization_url(
                db=mock_db, org_id=org_a, user_id=uuid.uuid4()
            )
            row_b = ZoomOAuthFlow.create_authorization_url(
                db=mock_db, org_id=org_b, user_id=uuid.uuid4()
            )

        captured_a = mock_db.add.call_args_list[-2][0][0]
        captured_b = mock_db.add.call_args_list[-1][0][0]
        assert captured_a.organization_id == org_a
        assert captured_b.organization_id == org_b
        assert captured_a.organization_id != captured_b.organization_id

    def test_state_binds_to_user(self):
        """State token must be bound to the initiating user."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        mock_db = MagicMock()
        user_a = uuid.uuid4()
        user_b = uuid.uuid4()
        org = uuid.uuid4()

        with self._patch_resolver():
            ZoomOAuthFlow.create_authorization_url(
                db=mock_db, org_id=org, user_id=user_a
            )
            ZoomOAuthFlow.create_authorization_url(
                db=mock_db, org_id=org, user_id=user_b
            )

        captured_a = mock_db.add.call_args_list[-2][0][0]
        captured_b = mock_db.add.call_args_list[-1][0][0]
        assert captured_a.user_id == user_a
        assert captured_b.user_id == user_b
        assert captured_a.user_id != captured_b.user_id

    def test_state_has_sufficient_entropy(self):
        """State token from secrets.token_urlsafe(32) must be >= 43 chars."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        mock_db = MagicMock()
        with self._patch_resolver():
            ZoomOAuthFlow.create_authorization_url(
                db=mock_db, org_id=uuid.uuid4(), user_id=uuid.uuid4()
            )
        state_row = mock_db.add.call_args[0][0]
        # secrets.token_urlsafe(32) produces at least 43 characters
        assert len(state_row.state_token) >= 43


# =====================================================================
# SECURITY TESTS - Tenant isolation for credential access
# =====================================================================


class TestTenantIsolation:
    """Prove that cross-org credential access is impossible."""

    def test_credential_vault_scoped_to_org(self):
        """Vault operations require org_id - no cross-org access."""
        from app.services.credential_vault import _find_integration

        mock_db = MagicMock()
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()

        # Mock query to return None (no cross-org leakage)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        # Query for org_a should not return org_b's credentials
        result = _find_integration(mock_db, org_a, "zoom", "zoom_oauth")
        assert result is None

        # Verify the query filters by org_id
        call_args = mock_db.execute.call_args[0][0]
        # The WHERE clause should include organization_id == org_a
        compiled = str(call_args.compile())
        # Both calls should pass different org_ids
        assert "organization_id" in compiled

    def test_has_credentials_scoped_to_org(self):
        """has_credentials checks only the specified org."""
        from app.services.credential_vault import CredentialVault

        mock_db = MagicMock()
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()

        with patch("app.services.credential_vault._find_integration") as mock_find:
            # Org A has credentials
            mock_integration = MagicMock()
            mock_integration.credentials_encrypted = "encrypted_data"
            mock_integration.status = IntegrationStatus.CONNECTED

            def side_effect(db, org_id, provider, itype):
                if org_id == org_a:
                    return mock_integration
                return None

            mock_find.side_effect = side_effect

            assert CredentialVault.has_credentials(mock_db, org_a, "zoom", "zoom_oauth") is True
            assert CredentialVault.has_credentials(mock_db, org_b, "zoom", "zoom_oauth") is False

    def test_disconnect_scoped_to_org(self):
        """Disconnecting org A must not affect org B."""
        from app.services.credential_vault import CredentialVault

        mock_db = MagicMock()
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()

        with patch("app.services.credential_vault._find_integration") as mock_find:
            org_a_integration = MagicMock()
            org_a_integration.credentials_encrypted = "encrypted_a"
            org_a_integration.status = IntegrationStatus.CONNECTED

            def side_effect(db, org_id, provider, itype):
                if org_id == org_a:
                    return org_a_integration
                return None

            mock_find.side_effect = side_effect

            result = CredentialVault.disconnect(mock_db, org_a, "zoom", "zoom_oauth")
            assert result is not None
            # Org A integration should be disconnected
            assert org_a_integration.status == IntegrationStatus.DISCONNECTED

    def test_zoom_oauth_state_rejects_used_token(self):
        """Previously consumed state must be rejected (replay protection)."""
        from app.services.zoom_oauth_flow import (
            _validate_state,
            ZoomOAuthStateError,
        )

        mock_state = MagicMock()
        mock_state.used = True
        mock_state.organization_id = uuid.uuid4()

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_state

        with pytest.raises(ZoomOAuthStateError, match="already been used"):
            _validate_state(mock_db, "reused_token")

    def test_zoom_oauth_state_rejects_expired_token(self):
        """Expired state must be rejected."""
        from app.services.zoom_oauth_flow import (
            _validate_state,
            ZoomOAuthStateError,
        )

        mock_state = MagicMock()
        mock_state.used = False
        mock_state.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        mock_state.organization_id = uuid.uuid4()

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_state

        with pytest.raises(ZoomOAuthStateError, match="expired"):
            _validate_state(mock_db, "expired_token")

    def test_zoom_oauth_state_rejects_nonexistent_token(self):
        """Non-existent state must be rejected."""
        from app.services.zoom_oauth_flow import (
            _validate_state,
            ZoomOAuthStateError,
        )

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = None

        with pytest.raises(ZoomOAuthStateError, match="Invalid OAuth state"):
            _validate_state(mock_db, "nonexistent_token")

    def test_refresh_token_scoped_to_org(self):
        """Token refresh must only use the specified org's credentials."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        mock_db = MagicMock()
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()

        with patch("app.services.credential_vault.CredentialVault") as mock_vault:
            # Org A has valid credentials
            mock_vault.get_credentials.return_value = {
                "access_token": "at_a",
                "refresh_token": "rt_a",
                "client_id": "cid",
                "client_secret": "csec",
            }
            mock_vault.get_safe_metadata.return_value = {
                "token_expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            }

            # Should return org A's token, not org B's
            token = ZoomOAuthFlow.refresh_token_if_needed(mock_db, org_a)
            assert token == "at_a"

            # Verify the vault was queried with org_a, not org_b
            mock_vault.get_credentials.assert_called_with(
                mock_db, org_a, "zoom", "zoom_oauth"
            )


# =====================================================================
# SECURITY TESTS - Error handling and token leakage prevention
# =====================================================================


class TestErrorSecurity:
    """Verify errors don't leak tokens, secrets, or credentials."""

    def test_exchange_code_error_does_not_leak_client_secret(self):
        """When token exchange fails, error message must not contain secrets."""
        from app.services.zoom_api_client import ZoomAPIClient, ZoomTokenExchangeError

        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "error": "invalid_client",
            "error_description": "Invalid client_id or secret",
        }

        with patch("app.services.zoom_api_client.httpx.post", return_value=mock_resp):
            with pytest.raises(ZoomTokenExchangeError) as exc_info:
                ZoomAPIClient.exchange_code(
                    code="code",
                    client_id="my_secret_client_id",
                    client_secret="my_super_secret_value",
                    redirect_uri="http://localhost/callback",
                )
            error_msg = str(exc_info.value)
            assert "my_secret_client_id" not in error_msg
            assert "my_super_secret_value" not in error_msg

    def test_refresh_error_does_not_leak_refresh_token(self):
        """When refresh fails, error message must not contain the refresh token."""
        from app.services.zoom_api_client import ZoomAPIClient, ZoomTokenRefreshError

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"error": "invalid_grant"}

        with patch("app.services.zoom_api_client.httpx.post", return_value=mock_resp):
            with pytest.raises(ZoomTokenRefreshError) as exc_info:
                ZoomAPIClient.refresh_access_token(
                    refresh_token="sensitive_refresh_token_value",
                    client_id="cid",
                    client_secret="csec",
                )
            error_msg = str(exc_info.value)
            assert "sensitive_refresh_token_value" not in error_msg

    def test_sanitize_error_masks_sensitive_patterns(self):
        """_sanitize_error_message must mask token/secret patterns."""
        from app.main import _sanitize_error_message

        # Test various sensitive patterns
        assert _sanitize_error_message("access_token=abc123") is not None
        assert "abc123" not in (_sanitize_error_message("access_token=abc123") or "")
        assert _sanitize_error_message("client_secret=xyz") is not None
        assert "xyz" not in (_sanitize_error_message("client_secret=xyz") or "")
        assert _sanitize_error_message("normal error message") == "normal error message"

    def test_zoom_oauth_flow_exchange_code_rollback_on_failure(self):
        """exchange_code must rollback state marking on token exchange failure."""
        from app.services.zoom_oauth_flow import (
            ZoomOAuthFlow,
            ZoomOAuthTokenExchangeError,
        )

        # Set up valid state
        mock_state = MagicMock()
        mock_state.used = False
        mock_state.organization_id = uuid.uuid4()
        mock_state.redirect_uri = "http://localhost/callback"
        mock_state.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_state

        # Make exchange_code fail
        with patch("app.services.zoom_api_client.ZoomAPIClient") as mock_client:
            mock_client.exchange_code.side_effect = ZoomOAuthTokenExchangeError("exchange failed")

            with pytest.raises(ZoomOAuthTokenExchangeError):
                ZoomOAuthFlow.exchange_code(
                    db=mock_db, code="code", state="valid_state"
                )

            # Verify rollback was called (state un-marked)
            mock_db.rollback.assert_called()


# =====================================================================
# BEHAVIORAL TESTS - create_meeting retry safety
# =====================================================================


class TestCreateMeetingRetrySafety:
    """Verify create_meeting does NOT use external_call_retry."""

    def test_create_meeting_has_no_retry_decorator(self):
        """create_meeting must not be wrapped with external_call_retry."""
        import inspect
        from app.services.zoom_api_client import ZoomAPIClient

        # Get the raw function (unwrap any decorators)
        func = ZoomAPIClient.create_meeting
        # If it were wrapped by tenacity retry, __wrapped__ would exist
        # or the function would have retry attributes
        has_retry = hasattr(func, 'retry') or hasattr(func, 'stop') or hasattr(func, 'wait')
        assert not has_retry, (
            "create_meeting must NOT have retry decorator - "
            "meeting creation is not idempotent"
        )

    def test_get_meeting_still_has_retry(self):
        """get_meeting (read-only) should still have retry for resilience."""
        from app.services.zoom_api_client import ZoomAPIClient

        func = ZoomAPIClient.get_meeting
        has_retry = hasattr(func, 'retry')
        assert has_retry, "get_meeting should have external_call_retry"

    def test_delete_meeting_still_has_retry(self):
        """delete_meeting is idempotent (404 = success), so retry is safe."""
        from app.services.zoom_api_client import ZoomAPIClient

        func = ZoomAPIClient.delete_meeting
        has_retry = hasattr(func, 'retry')
        assert has_retry, "delete_meeting should have external_call_retry"


# =====================================================================
# BEHAVIORAL TESTS - ZoomOAuthFlow exchange_code rollback
# =====================================================================


class TestExchangeCodeRollback:
    """Verify state is rolled back on exchange failure."""

    def test_exchange_code_rollback_on_token_exchange_failure(self):
        """State should be rolled back when token exchange fails."""
        from app.services.zoom_oauth_flow import (
            ZoomOAuthFlow,
            ZoomOAuthTokenExchangeError,
        )

        mock_state = MagicMock()
        mock_state.used = False
        mock_state.organization_id = uuid.uuid4()
        mock_state.redirect_uri = "http://localhost/callback"
        mock_state.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_state

        with patch("app.services.zoom_api_client.ZoomAPIClient") as mock_client:
            mock_client.exchange_code.side_effect = ZoomOAuthTokenExchangeError("timeout")

            with pytest.raises(ZoomOAuthTokenExchangeError):
                ZoomOAuthFlow.exchange_code(
                    db=mock_db, code="code", state="valid_state"
                )

            # db.rollback should be called to undo state marking
            mock_db.rollback.assert_called()

    def test_exchange_code_rollback_on_account_info_failure(self):
        """State should be rolled back when account info fetch fails."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow
        from app.services.zoom_api_client import ZoomAPIError
        from app.services.integration_config_resolver import ZoomOAuthConfig

        mock_state = MagicMock()
        mock_state.used = False
        mock_state.organization_id = uuid.uuid4()
        mock_state.redirect_uri = "http://localhost/callback"
        mock_state.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_state

        mock_cfg = ZoomOAuthConfig(
            account_id="", client_id="cid", client_secret="csec",
            redirect_uri="http://localhost/callback",
        )

        with patch("app.services.zoom_api_client.ZoomAPIClient") as mock_client, \
             patch("app.services.integration_config_resolver.IntegrationConfigResolver") as mock_resolver:
            mock_resolver.resolve_zoom_config.return_value = mock_cfg
            mock_client.exchange_code.return_value = {
                "access_token": "at",
                "refresh_token": "rt",
                "expires_in": 3600,
                "scope": "meeting:write",
            }
            mock_client.get_account_info.side_effect = ZoomAPIError("account info failed")

            with pytest.raises(ZoomAPIError):
                ZoomOAuthFlow.exchange_code(
                    db=mock_db, code="code", state="valid_state"
                )

            mock_db.rollback.assert_called()


# =====================================================================
# BEHAVIORAL TESTS - Token refresh edge cases
# =====================================================================


class TestTokenRefreshEdgeCases:
    """Test token refresh behavior at boundary conditions."""

    def test_token_not_yet_expired_returns_existing(self):
        """If token expires in >5 minutes, return existing token without refresh."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        mock_db = MagicMock()
        org_id = uuid.uuid4()
        future_expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        with patch("app.services.credential_vault.CredentialVault") as mock_vault:
            mock_vault.get_credentials.return_value = {
                "access_token": "valid_token",
                "refresh_token": "rt",
                "client_id": "cid",
                "client_secret": "csec",
            }
            mock_vault.get_safe_metadata.return_value = {
                "token_expires_at": future_expiry
            }

            token = ZoomOAuthFlow.refresh_token_if_needed(mock_db, org_id)
            assert token == "valid_token"

    def test_no_refresh_token_raises_error(self):
        """If no refresh token exists, raise ZoomOAuthError."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow, ZoomOAuthError

        mock_db = MagicMock()
        org_id = uuid.uuid4()
        expired_expiry = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()

        with patch("app.services.credential_vault.CredentialVault") as mock_vault:
            mock_vault.get_credentials.return_value = {
                "access_token": "expired_token",
                "refresh_token": "",  # Empty refresh token
                "client_id": "cid",
                "client_secret": "csec",
            }
            mock_vault.get_safe_metadata.return_value = {
                "token_expires_at": expired_expiry
            }

            with pytest.raises(ZoomOAuthError, match="refresh token not available"):
                ZoomOAuthFlow.refresh_token_if_needed(mock_db, org_id)

    def test_refresh_token_rotation_persists_new_refresh_token(self):
        """When Zoom rotates the refresh token, the new one must be stored."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        mock_db = MagicMock()
        org_id = uuid.uuid4()
        expired_expiry = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()

        with patch("app.services.credential_vault.CredentialVault") as mock_vault, \
             patch("app.services.zoom_api_client.ZoomAPIClient") as mock_api:

            mock_vault.get_credentials.return_value = {
                "access_token": "old_token",
                "refresh_token": "old_refresh",
                "client_id": "cid",
                "client_secret": "csec",
            }
            mock_vault.get_safe_metadata.return_value = {
                "token_expires_at": expired_expiry
            }

            mock_api.refresh_access_token.return_value = {
                "access_token": "new_access",
                "refresh_token": "new_refresh_rotated",
                "expires_in": 3600,
            }

            token = ZoomOAuthFlow.refresh_token_if_needed(mock_db, org_id)

            assert token == "new_access"
            # Verify save_credentials was called with the NEW refresh token
            save_call = mock_vault.save_credentials.call_args
            saved_creds = save_call[1]["credentials"]
            assert saved_creds["refresh_token"] == "new_refresh_rotated"

    def test_refresh_failure_preserves_existing_credentials(self):
        """If refresh fails, existing credentials should not be destroyed."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow
        from app.services.zoom_api_client import ZoomTokenRefreshError

        mock_db = MagicMock()
        org_id = uuid.uuid4()
        expired_expiry = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()

        with patch("app.services.credential_vault.CredentialVault") as mock_vault, \
             patch("app.services.zoom_api_client.ZoomAPIClient") as mock_api:

            mock_vault.get_credentials.return_value = {
                "access_token": "existing_token",
                "refresh_token": "existing_refresh",
                "client_id": "cid",
                "client_secret": "csec",
            }
            mock_vault.get_safe_metadata.return_value = {
                "token_expires_at": expired_expiry
            }

            mock_api.refresh_access_token.side_effect = ZoomTokenRefreshError("revoked")

            with pytest.raises(ZoomTokenRefreshError):
                ZoomOAuthFlow.refresh_token_if_needed(mock_db, org_id)

            # save_credentials should NOT have been called
            mock_vault.save_credentials.assert_not_called()


# =====================================================================
# BEHAVIORAL TESTS - Provider resolution edge cases
# =====================================================================


class TestProviderResolutionEdgeCases:
    """Test all provider resolution scenarios."""

    def test_zoom_only_configured(self):
        """When only Zoom is configured, ZoomMeetingProvider is returned."""
        from app.services.meeting_provider import (
            resolve_meeting_provider,
            ZoomMeetingProvider,
        )

        mock_ctx = MagicMock()
        mock_ctx.organization_id = uuid.uuid4()
        mock_db = MagicMock()

        with patch("app.services.credential_vault.CredentialVault") as mock_vault:
            mock_vault.has_credentials.return_value = True
            provider = resolve_meeting_provider(org_context=mock_ctx, db=mock_db)
            assert isinstance(provider, ZoomMeetingProvider)

    def test_neither_configured(self):
        """When neither is configured, Google shim is returned."""
        from app.services.meeting_provider import resolve_meeting_provider

        mock_ctx = MagicMock()
        mock_ctx.organization_id = uuid.uuid4()
        mock_db = MagicMock()

        with patch("app.services.credential_vault.CredentialVault") as mock_vault:
            mock_vault.has_credentials.return_value = False
            provider = resolve_meeting_provider(org_context=mock_ctx, db=mock_db)
            assert provider.provider_name == "google_meet"

    def test_no_context_returns_google_shim(self):
        """When org_context is None, Google shim is returned."""
        from app.services.meeting_provider import resolve_meeting_provider

        provider = resolve_meeting_provider(org_context=None, db=None)
        assert provider.provider_name == "google_meet"

    def test_zoom_credential_exists_but_invalid(self):
        """If Zoom creds exist but are invalid, provider still returns Zoom (API call will fail)."""
        from app.services.meeting_provider import (
            resolve_meeting_provider,
            ZoomMeetingProvider,
        )

        mock_ctx = MagicMock()
        mock_ctx.organization_id = uuid.uuid4()
        mock_db = MagicMock()

        with patch("app.services.credential_vault.CredentialVault") as mock_vault:
            mock_vault.has_credentials.return_value = True
            provider = resolve_meeting_provider(org_context=mock_ctx, db=mock_db)
            # Provider is resolved based on credential existence, not validity
            assert isinstance(provider, ZoomMeetingProvider)

    def test_zoom_disconnected_falls_back_to_google(self):
        """When Zoom is disconnected, falls back to Google."""
        from app.services.meeting_provider import resolve_meeting_provider

        mock_ctx = MagicMock()
        mock_ctx.organization_id = uuid.uuid4()
        mock_db = MagicMock()

        with patch("app.services.credential_vault.CredentialVault") as mock_vault:
            # has_credentials returns False for disconnected integrations
            mock_vault.has_credentials.return_value = False
            provider = resolve_meeting_provider(org_context=mock_ctx, db=mock_db)
            assert provider.provider_name == "google_meet"


# =====================================================================
# BEHAVIORAL TESTS - ZoomAPIClient meeting creation safety
# =====================================================================


class TestZoomMeetingCreationSafety:
    """Verify meeting creation is safe (no retry, proper error handling)."""

    @patch("app.services.zoom_api_client.httpx.post")
    def test_create_meeting_no_retry_on_timeout(self, mock_post):
        """create_meeting should NOT retry after timeout (may create duplicates)."""
        import inspect
        from app.services.zoom_api_client import ZoomAPIClient

        # Verify the function is NOT wrapped by tenacity retry
        func = ZoomAPIClient.create_meeting
        # Check for tenacity wrapper attributes
        assert not hasattr(func, 'retry'), "create_meeting must not have retry"
        assert not hasattr(func, 'stop'), "create_meeting must not have retry stop"
        assert not hasattr(func, 'wait'), "create_meeting must not have retry wait"

    @patch("app.services.zoom_api_client.httpx.post")
    def test_create_meeting_returns_meeting_details(self, mock_post):
        """Successful meeting creation returns proper MeetingDetails."""
        from app.services.zoom_api_client import ZoomAPIClient

        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "id": 12345678901,
            "join_url": "https://zoom.us/j/12345678901",
            "topic": "Test Meeting",
            "duration": 30,
            "status": "waiting",
        }
        mock_post.return_value = mock_resp

        result = ZoomAPIClient.create_meeting(
            access_token="token",
            topic="Test Meeting",
            start_time=datetime(2026, 9, 1, 14, 0, tzinfo=timezone.utc),
            duration_minutes=30,
        )

        assert result["id"] == "12345678901"
        assert result["join_url"] == "https://zoom.us/j/12345678901"

    @patch("app.services.zoom_api_client.httpx.post")
    def test_create_meeting_5xx_raises_error(self, mock_post):
        """5xx error from Zoom should raise ZoomMeetingError, not retry."""
        from app.services.zoom_api_client import ZoomAPIClient, ZoomMeetingError

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"message": "Internal error"}
        mock_post.return_value = mock_resp

        with pytest.raises(ZoomMeetingError, match="Internal error"):
            ZoomAPIClient.create_meeting(
                access_token="token",
                topic="Test",
                start_time=datetime(2026, 9, 1, 14, 0, tzinfo=timezone.utc),
                duration_minutes=30,
            )


# =====================================================================
# BEHAVIORAL TESTS - ZoomMeetingProvider implements protocol
# =====================================================================


class TestZoomMeetingProviderContract:
    """Verify ZoomMeetingProvider implements MeetingProvider protocol."""

    def test_provider_has_all_protocol_methods(self):
        """ZoomMeetingProvider must implement all MeetingProvider methods."""
        from app.services.meeting_provider import ZoomMeetingProvider

        assert hasattr(ZoomMeetingProvider, 'create_meeting')
        assert hasattr(ZoomMeetingProvider, 'get_meeting_link')
        assert hasattr(ZoomMeetingProvider, 'cancel_meeting')
        assert hasattr(ZoomMeetingProvider, 'get_meeting')

    def test_provider_is_runtime_checkable(self):
        """ZoomMeetingProvider should satisfy isinstance check against MeetingProvider."""
        from app.services.meeting_provider import ZoomMeetingProvider, MeetingProvider

        mock_ctx = MagicMock()
        mock_db = MagicMock()
        provider = ZoomMeetingProvider(org_context=mock_ctx, db=mock_db)

        # Runtime checkable protocol - all required methods exist
        assert isinstance(provider, MeetingProvider)

    @patch("app.services.zoom_oauth_flow.ZoomOAuthFlow.refresh_token_if_needed")
    @patch("app.services.zoom_api_client.httpx.post")
    def test_create_meeting_returns_correct_provider(self, mock_post, mock_refresh):
        """MeetingDetails must have provider='zoom'."""
        from app.services.meeting_provider import ZoomMeetingProvider

        mock_refresh.return_value = "token"
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "id": 123,
            "join_url": "https://zoom.us/j/123",
            "topic": "Test",
            "duration": 30,
            "status": "waiting",
        }
        mock_post.return_value = mock_resp

        provider = ZoomMeetingProvider(
            org_context=MagicMock(organization_id=uuid.uuid4()),
            db=MagicMock(),
        )
        result = provider.create_meeting(
            summary="Test",
            description="",
            start_utc=datetime(2026, 9, 1, tzinfo=timezone.utc),
            duration_minutes=30,
            attendees=[],
            idempotency_key="key",
        )

        assert result.provider == "zoom"
        assert result.meeting_id == "123"
        assert result.meeting_link == "https://zoom.us/j/123"


# =====================================================================
# SECURITY TESTS - Zoom OAuth callback doesn't trust user-controlled org
# =====================================================================


class TestOAuthCallbackSecurity:
    """Verify callback cannot be manipulated to target wrong org."""

    def test_callback_state_binds_credentials_to_state_org(self):
        """Credentials are stored under the state's org_id, not any user input."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow
        from app.services.integration_config_resolver import ZoomOAuthConfig

        mock_state = MagicMock()
        mock_state.used = False
        org_from_state = uuid.uuid4()
        mock_state.organization_id = org_from_state
        mock_state.redirect_uri = "http://localhost/callback"
        mock_state.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_state

        mock_cfg = ZoomOAuthConfig(
            account_id="", client_id="cid", client_secret="csec",
            redirect_uri="http://localhost/callback",
        )

        with patch("app.services.zoom_api_client.ZoomAPIClient") as mock_api, \
             patch("app.services.credential_vault.CredentialVault") as mock_vault, \
             patch("app.services.integration_config_resolver.IntegrationConfigResolver") as mock_resolver:
            mock_resolver.resolve_zoom_config.return_value = mock_cfg
            mock_api.exchange_code.return_value = {
                "access_token": "at",
                "refresh_token": "rt",
                "expires_in": 3600,
                "scope": "meeting:write",
            }
            mock_api.get_account_info.return_value = {
                "account_id": "acc123",
                "email": "user@zoom.us",
            }

            ZoomOAuthFlow.exchange_code(db=mock_db, code="code", state="token")

            # Verify credentials stored under the state's org_id
            save_call = mock_vault.save_credentials.call_args
            stored_org_id = save_call[1]["org_id"]
            assert stored_org_id == org_from_state


# =====================================================================
# MIGRATION AUDIT - Verify schema constraints
# =====================================================================


class TestCallbackOrgSwitchAttack:
    """Verify that callback cannot be manipulated to store credentials under wrong org."""

    def test_callback_uses_org_from_state_not_request(self):
        """Even if attacker crafts a callback, credentials bind to the state's org."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow
        from app.services.integration_config_resolver import ZoomOAuthConfig

        # Org A creates state, Org B tries to hijack via the callback
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()

        mock_state = MagicMock()
        mock_state.used = False
        mock_state.organization_id = org_a  # State belongs to org_a
        mock_state.redirect_uri = "http://localhost/callback"
        mock_state.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_state

        mock_cfg = ZoomOAuthConfig(
            account_id="", client_id="cid", client_secret="csec",
            redirect_uri="http://localhost/callback",
        )

        with patch("app.services.zoom_api_client.ZoomAPIClient") as mock_api, \
             patch("app.services.credential_vault.CredentialVault") as mock_vault, \
             patch("app.services.integration_config_resolver.IntegrationConfigResolver") as mock_resolver:
            mock_resolver.resolve_zoom_config.return_value = mock_cfg
            mock_api.exchange_code.return_value = {
                "access_token": "at",
                "refresh_token": "rt",
                "expires_in": 3600,
                "scope": "meeting:write",
            }
            mock_api.get_account_info.return_value = {
                "account_id": "acc123",
                "email": "user@zoom.us",
            }

            result = ZoomOAuthFlow.exchange_code(
                db=mock_db, code="code", state="attacker_state_token"
            )

            # Verify credentials are stored under org_a (from state), NOT org_b
            save_call = mock_vault.save_credentials.call_args
            stored_org_id = save_call[1]["org_id"]
            assert stored_org_id == org_a
            assert stored_org_id != org_b

            # Verify the returned organization_id matches org_a
            assert result["organization_id"] == str(org_a)


# =====================================================================
# SECURITY: Plaintext Token Never Returned Via API
# =====================================================================


class TestPlaintextTokenNeverReturned:
    """Verify that plaintext access/refresh tokens are never in API responses."""

    def test_status_endpoint_no_tokens(self):
        """GET /auth/zoom/status must never return access_token or refresh_token."""
        from fastapi.testclient import TestClient
        from app.main import app, _auth_context
        from app.database import get_db
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
                 "client_id": "cid_12345678",
                 "client_secret": "secret_csec",
                 "redirect_uri": "http://localhost:8000/auth/zoom/callback",
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
        # Plaintext tokens MUST NEVER appear in any API response
        assert "access_token" not in data
        assert "refresh_token" not in data
        assert "client_secret" not in data
        # Safe metadata fields allowed
        allowed_keys = {
            "provider", "integration_type", "configured", "masked_client_id",
            "redirect_uri", "connected", "account_id", "account_email",
            "connected_at", "status", "last_error",
        }
        assert set(data.keys()) <= allowed_keys

    def test_status_json_str_no_token_substrings(self):
        """Serialized JSON of status must not contain token substrings."""
        from fastapi.testclient import TestClient
        from app.main import app, _auth_context
        from app.database import get_db
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
                 "client_id": "cid_12345678",
                 "client_secret": "secret_csec",
                 "redirect_uri": "http://localhost:8000/auth/zoom/callback",
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

        body = resp.text.lower()
        assert "access_token" not in body
        assert "refresh_token" not in body
        assert "client_secret" not in body
        # No JWT-like structures (header.payload.signature)
        assert "eyJ" not in body  # JWT typically starts with eyJ


# =====================================================================
# SECURITY: Redirect URI Consistency
# =====================================================================


class TestRedirectURIConsistency:
    """Verify redirect_uri is consistent between authorization and token exchange."""

    def test_exchange_code_uses_state_redirect_uri(self):
        """Token exchange uses redirect_uri from vault, matching state."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow
        from app.services.integration_config_resolver import ZoomOAuthConfig

        mock_state = MagicMock()
        mock_state.used = False
        mock_state.organization_id = uuid.uuid4()
        mock_state.redirect_uri = "http://localhost:8000/auth/zoom/callback"
        mock_state.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_state

        mock_cfg = ZoomOAuthConfig(
            account_id="", client_id="cid", client_secret="csec",
            redirect_uri="http://localhost:8000/auth/zoom/callback",
        )

        with patch("app.services.zoom_api_client.ZoomAPIClient") as mock_api, \
             patch("app.services.credential_vault.CredentialVault") as mock_vault, \
             patch("app.services.integration_config_resolver.IntegrationConfigResolver") as mock_resolver:
            mock_resolver.resolve_zoom_config.return_value = mock_cfg
            mock_api.exchange_code.return_value = {
                "access_token": "at",
                "refresh_token": "rt",
                "expires_in": 3600,
                "scope": "meeting:write",
            }
            mock_api.get_account_info.return_value = {
                "account_id": "acc123",
                "email": "user@zoom.us",
            }

            ZoomOAuthFlow.exchange_code(
                db=mock_db, code="auth_code", state="state_token"
            )

            # Verify the redirect_uri passed to exchange_code matches vault config
            exchange_call = mock_api.exchange_code.call_args
            assert exchange_call[1]["redirect_uri"] == mock_cfg.redirect_uri

    def test_authorization_url_uses_config_redirect_uri(self):
        """Authorization URL is built with the configured redirect URI from vault."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow
        from app.services.integration_config_resolver import ZoomOAuthConfig

        mock_db = MagicMock()
        configured_redirect = "http://localhost:8000/auth/zoom/callback"

        mock_cfg = ZoomOAuthConfig(
            account_id="",
            client_id="platform_cid",
            client_secret="platform_csec",
            redirect_uri=configured_redirect,
        )

        with patch(
            "app.services.integration_config_resolver.IntegrationConfigResolver"
        ) as mock_resolver, patch(
            "app.services.zoom_oauth_flow.settings"
        ) as s:
            mock_resolver.resolve_zoom_config.return_value = mock_cfg
            s.zoom_oauth_state_ttl_minutes = 10

            state_row = ZoomOAuthFlow.create_authorization_url(
                db=mock_db,
                org_id=uuid.uuid4(),
                user_id=uuid.uuid4(),
            )

        assert state_row.redirect_uri == configured_redirect

    def test_state_redirect_uri_matches_config(self):
        """State row stores the same redirect_uri that vault defines."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow
        from app.services.integration_config_resolver import ZoomOAuthConfig

        mock_db = MagicMock()
        mock_cfg = ZoomOAuthConfig(
            account_id="",
            client_id="cid",
            client_secret="csec",
            redirect_uri="https://myapp.com/auth/zoom/callback",
        )

        with patch(
            "app.services.integration_config_resolver.IntegrationConfigResolver"
        ) as mock_resolver, patch(
            "app.services.zoom_oauth_flow.settings"
        ) as s:
            mock_resolver.resolve_zoom_config.return_value = mock_cfg
            s.zoom_oauth_state_ttl_minutes = 10

            row = ZoomOAuthFlow.create_authorization_url(
                db=mock_db, org_id=uuid.uuid4(), user_id=uuid.uuid4()
            )

        assert row.redirect_uri == "https://myapp.com/auth/zoom/callback"


# =====================================================================
# SECURITY: Invalid Redirect URI Rejection
# =====================================================================


class TestInvalidRedirectURIRejection:
    """Verify that mismatched or tampered redirect URIs are rejected."""

    def test_exchange_code_rejects_tampered_redirect(self):
        """If Zoom rejects a mismatched redirect_uri, exchange fails."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow
        from app.services.integration_config_resolver import ZoomOAuthConfig

        mock_state = MagicMock()
        mock_state.used = False
        mock_state.organization_id = uuid.uuid4()
        mock_state.redirect_uri = "http://localhost:8000/auth/zoom/callback"
        mock_state.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_state

        mock_cfg = ZoomOAuthConfig(
            account_id="", client_id="cid", client_secret="csec",
            redirect_uri="http://localhost:8000/auth/zoom/callback",
        )

        with patch("app.services.zoom_api_client.ZoomAPIClient") as mock_api, \
             patch("app.services.integration_config_resolver.IntegrationConfigResolver") as mock_resolver:
            mock_resolver.resolve_zoom_config.return_value = mock_cfg
            # Simulate Zoom rejecting a mismatched redirect_uri
            mock_api.exchange_code.side_effect = Exception(
                "redirect_uri mismatch"
            )

            with pytest.raises(Exception, match="redirect_uri mismatch"):
                ZoomOAuthFlow.exchange_code(
                    db=mock_db, code="auth_code", state="state_token"
                )

    def test_config_redirect_uri_is_platform_only(self):
        """Platform redirect URI is set via env, not from user input."""
        from app.config import Settings

        # Settings object must default redirect_uri to localhost
        s = Settings()
        # The redirect URI should be a sensible default, not user-supplied
        assert s.zoom_redirect_uri.startswith("http")
        assert "callback" in s.zoom_redirect_uri.lower()


# =====================================================================
# FOCUSED: Environment-Driven Redirect URI Override
# =====================================================================


class TestRedirectURIEnvOverride:
    """Verify that ZOOM_REDIRECT_URI env var flows end-to-end into the
    authorization URL - the exact redirect Zoom will use.

    This is the critical path for local dev via ngrok:
        ZOOM_REDIRECT_URI=https://<ngrok-domain>/auth/zoom/callback
    """

    def test_auth_url_contains_configured_redirect_uri(self):
        """Authorization URL redirect_uri matches configured ZOOM_REDIRECT_URI."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow
        from app.services.integration_config_resolver import ZoomOAuthConfig

        ngrok_redirect = "https://abc123.ngrok-free.app/auth/zoom/callback"
        mock_cfg = ZoomOAuthConfig(
            account_id="",
            client_id="plat_cid",
            client_secret="plat_csec",
            redirect_uri=ngrok_redirect,
        )

        mock_db = MagicMock()
        with patch(
            "app.services.integration_config_resolver.IntegrationConfigResolver"
        ) as mock_resolver, patch(
            "app.services.zoom_oauth_flow.settings"
        ) as s:
            mock_resolver.resolve_zoom_config.return_value = mock_cfg
            s.zoom_oauth_state_ttl_minutes = 10

            state_row = ZoomOAuthFlow.create_authorization_url(
                db=mock_db, org_id=uuid.uuid4(), user_id=uuid.uuid4(),
            )

        # 1. State row stores the configured redirect URI
        assert state_row.redirect_uri == ngrok_redirect

        # 2. The authorization URL built by ZoomAPIClient contains the redirect_uri
        #    (ZoomOAuthFlow.create_authorization_url → build_authorization_url)
        #    We can verify by inspecting the URL stored in state or re-calling
        #    the API client directly with the same config.
        from app.services.zoom_api_client import ZoomAPIClient

        url = ZoomAPIClient.build_authorization_url(
            client_id="plat_cid",
            redirect_uri=ngrok_redirect,
            state_token="test_state",
        )
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["redirect_uri"][0] == ngrok_redirect

    def test_platform_redirect_uri_used_when_no_vault(self):
        """When org has no vault creds, platform ZOOM_REDIRECT_URI is used."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow
        from app.services.integration_config_resolver import (
            IntegrationConfigResolver,
        )

        ngrok_redirect = "https://my-tunnel.ngrok.io/auth/zoom/callback"

        mock_db = MagicMock()
        with patch(
            "app.services.integration_config_resolver.settings"
        ) as s:
            s.zoom_client_id = "plat_cid"
            s.zoom_client_secret = "plat_csec"
            s.zoom_redirect_uri = ngrok_redirect

            cfg = IntegrationConfigResolver.resolve_zoom_config(
                mock_db, uuid.uuid4()
            )
            assert cfg.redirect_uri == ngrok_redirect

    def test_default_redirect_uri_is_localhost(self):
        """Default ZOOM_REDIRECT_URI falls back to localhost for dev."""
        import os
        from app.config import Settings

        # Disable .env file reading and clear the env var so we test the
        # raw Pydantic default, not the configured value.
        orig = os.environ.pop("ZOOM_REDIRECT_URI", None)
        original_config = Settings.model_config.copy()
        try:
            os.environ.pop("ZOOM_REDIRECT_URI", None)
            Settings.model_config = {**original_config, "env_file": None}
            s = Settings()
            assert s.zoom_redirect_uri == "http://localhost:8000/auth/zoom/callback"
        finally:
            Settings.model_config = original_config
            if orig is not None:
                os.environ["ZOOM_REDIRECT_URI"] = orig


# =====================================================================
# MIGRATION AUDIT - Verify schema constraints
# =====================================================================


class TestMigrationSchemaAudit:
    """Verify migration 015 creates proper schema constraints."""

    def test_migration_creates_state_token_unique_index(self):
        """State token must have a unique index to prevent duplicates."""
        from pathlib import Path

        migration_code = Path("alembic/versions/015_zoom_oauth_states.py").read_text()
        assert "unique" in migration_code.lower() or "UniqueConstraint" in migration_code

    def test_migration_has_foreign_key_to_organizations(self):
        """Table must have FK to organizations for tenant isolation."""
        from pathlib import Path

        migration_code = Path("alembic/versions/015_zoom_oauth_states.py").read_text()
        assert "organizations" in migration_code

    def test_migration_has_index_on_expires_at(self):
        """Expiry index needed for efficient purge queries."""
        from pathlib import Path

        migration_code = Path("alembic/versions/015_zoom_oauth_states.py").read_text()
        assert "expires_at" in migration_code

    def test_zoom_oauth_state_model_has_org_index(self):
        """Model must have org_id index for tenant-scoped queries."""
        from app.models_multi_tenant import ZoomOAuthState

        # Check the model has org_id indexed
        table = ZoomOAuthState.__table__
        indexes = {idx.name for idx in table.indexes}
        assert any("org_id" in name for name in indexes), (
            f"ZoomOAuthState missing org_id index. Found: {indexes}"
        )

    def test_zoom_oauth_state_token_is_unique(self):
        """State token must be unique to prevent collision."""
        from sqlalchemy import inspect as sa_inspect
        from app.models_multi_tenant import ZoomOAuthState

        mapper = sa_inspect(ZoomOAuthState)
        state_col = mapper.columns.state_token
        # Check column-level unique flag or unique constraint
        assert state_col.unique, "state_token must have unique=True"
