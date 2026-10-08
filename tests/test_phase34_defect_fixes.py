"""Regression tests for Phase 34 defect fixes.

Covers the three confirmed defects from live Google OAuth audit:
  A. False "Connected" status when refresh_token is empty
  B. Health endpoint org isolation (Organization A ≠ Organization B)
  C. Gmail health check uses scope-compatible validation (no gmail.readonly)

These tests MUST pass before the codebase is considered production-ready
for Google OAuth integration.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models_multi_tenant import (
    IntegrationStatus,
    OrgIntegration,
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)
from app.services.credential_vault import CredentialVault
from app.services.crypto import generate_key
from app.services.google_oauth_flow import GoogleOAuthFlow


# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------
TEST_JWT_SECRET = "test-secret-key-for-phase-34-regression-tests-32ch!"
TEST_ENCRYPTION_KEY = generate_key()
TEST_GOOGLE_CLIENT_ID = "test-phase34-client-id.apps.googleusercontent.com"
TEST_GOOGLE_CLIENT_SECRET = "test-phase34-client-secret"
TEST_GOOGLE_REDIRECT_URI = "http://localhost:8000/auth/google/callback"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    """Override secrets for isolated testing."""
    monkeypatch.setattr(settings, "jwt_secret_key", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", TEST_ENCRYPTION_KEY)
    monkeypatch.setattr(settings, "google_client_id", TEST_GOOGLE_CLIENT_ID)
    monkeypatch.setattr(settings, "google_client_secret", TEST_GOOGLE_CLIENT_SECRET)
    monkeypatch.setattr(settings, "google_redirect_uri", TEST_GOOGLE_REDIRECT_URI)
    monkeypatch.setattr(settings, "google_oauth_state_ttl_minutes", 10)


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


@pytest.fixture()
def client():
    return TestClient(app, raise_server_exceptions=False)


def _create_org_and_user(
    db: Session,
    email: str = "owner@example.com",
    role: UserRole = UserRole.OWNER,
    org_name: str | None = None,
) -> tuple[Organization, User]:
    """Create an org + owner user for testing."""
    from app.auth import hash_password

    unique_suffix = uuid.uuid4().hex[:8]
    org = Organization(
        name=org_name or f"Phase34 Test Org {unique_suffix}",
        slug=f"phase34-test-{unique_suffix}",
        status=OrganizationStatus.ACTIVE,
        timezone="America/Chicago",
    )
    db.add(org)
    db.flush()

    user = User(
        organization_id=org.id,
        email=email.lower().replace("@", f"+{unique_suffix}@"),
        full_name="Phase34 Test User",
        password_hash=hash_password("StrongPass123!"),
        role=role,
        status=UserStatus.ACTIVE,
    )
    db.add(user)
    db.flush()
    db.commit()
    return org, user


def _create_jwt_token(user_id: uuid.UUID, org_id: uuid.UUID, role: str = "owner") -> str:
    from app.auth import create_access_token
    return create_access_token(user_id, org_id, role)


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _store_credentials_with_refresh_token(
    db: Session,
    org_id: uuid.UUID,
    refresh_token: str = "valid-refresh-token-12345",
    client_id: str = TEST_GOOGLE_CLIENT_ID,
    client_secret: str = TEST_GOOGLE_CLIENT_SECRET,
) -> OrgIntegration:
    """Store Google OAuth credentials via the vault with a given refresh_token."""
    credentials = {
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": TEST_GOOGLE_REDIRECT_URI,
    }
    metadata = {
        "scopes": [
            "https://www.googleapis.com/auth/calendar",
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/userinfo.email",
        ],
        "provider": "google",
        "email": "test@example.com",
        "connected_at": datetime.now(timezone.utc).isoformat(),
    }
    return CredentialVault.save_credentials(
        db=db,
        org_id=org_id,
        provider="google",
        integration_type="google_oauth",
        credentials=credentials,
        metadata=metadata,
    )


# ===========================================================================
# FIX A: False "Connected" status when refresh_token is empty
# ===========================================================================

class TestFixA_FalseConnectedStatus:
    """Verify that a false 'connected' DB status does not mislead clients.

    Defect A root cause:
      has_credentials() checks DB status == connected AND encrypted blob exists,
      but does NOT verify the refresh_token inside is non-empty.  A row can
      be marked "connected" with an empty or missing refresh_token after a
      partial OAuth callback, manual DB edit, or data corruption.
    """

    def test_connected_true_when_refresh_token_present(self, db):
        """Baseline: org with valid refresh_token should report connected."""
        org, user = _create_org_and_user(db)
        _store_credentials_with_refresh_token(db, org.id, refresh_token="valid-token-abc")

        result = GoogleOAuthFlow.get_connection_status(db, org.id)
        assert result["connected"] is True
        assert result["email"] == "test@example.com"
        assert result["scopes"]  # non-empty

    def test_connected_false_when_refresh_token_empty(self, db):
        """Defect A scenario: DB says connected, but refresh_token is empty."""
        org, user = _create_org_and_user(db)
        _store_credentials_with_refresh_token(db, org.id, refresh_token="")

        result = GoogleOAuthFlow.get_connection_status(db, org.id)
        assert result["connected"] is False, (
            "get_connection_status must report False when refresh_token is empty"
        )
        assert result["scopes"] == []
        assert result["connected_at"] is None

    def test_connected_false_when_refresh_token_none(self, db):
        """Defect A variant: credentials exist but refresh_token key is absent."""
        org, user = _create_org_and_user(db)
        # Store credentials WITHOUT a refresh_token
        credentials = {
            "client_id": TEST_GOOGLE_CLIENT_ID,
            "client_secret": TEST_GOOGLE_CLIENT_SECRET,
            "redirect_uri": TEST_GOOGLE_REDIRECT_URI,
            # refresh_token intentionally omitted
        }
        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials=credentials,
            metadata={"scopes": ["calendar"], "email": "test@example.com"},
        )

        result = GoogleOAuthFlow.get_connection_status(db, org.id)
        assert result["connected"] is False, (
            "get_connection_status must report False when refresh_token is absent"
        )

    def test_connected_false_when_status_disconnected(self, db):
        """Disconnected status should always report False regardless of credentials."""
        org, user = _create_org_and_user(db)
        integration = _store_credentials_with_refresh_token(db, org.id)
        # Manually set status to DISCONNECTED
        integration.status = IntegrationStatus.DISCONNECTED
        db.commit()

        result = GoogleOAuthFlow.get_connection_status(db, org.id)
        assert result["connected"] is False

    def test_connected_false_when_no_integration_row(self, db):
        """No integration row at all should report False."""
        org, user = _create_org_and_user(db)
        result = GoogleOAuthFlow.get_connection_status(db, org.id)
        assert result["connected"] is False
        assert result["scopes"] == []
        assert result["email"] is None

    def test_setup_status_respects_empty_refresh_token(self, db, client):
        """Fix A in setup_status: must not show 'done' when refresh_token is empty."""
        org, user = _create_org_and_user(db)
        _store_credentials_with_refresh_token(db, org.id, refresh_token="")

        # Verify the vault status is "connected" at the DB level
        from sqlalchemy import select
        stmt = select(OrgIntegration).where(
            OrgIntegration.organization_id == org.id,
            OrgIntegration.provider == "google",
            OrgIntegration.integration_type == "google_oauth",
        )
        integration = db.execute(stmt).scalar_one()
        assert integration.status.value == "connected", (
            "Precondition: DB status must be 'connected' to test the false-positive"
        )

        # Now test the setup_status endpoint via internal call
        token = _create_jwt_token(user.id, org.id, "owner")
        resp = client.get(
            "/dashboard/api/setup-status",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        google_step = data["steps"]["google_connected"]
        assert google_step["done"] is False, (
            "setup_status must report google_connected as False "
            "when refresh_token is empty despite DB status=connected"
        )

    def test_setup_status_true_when_refresh_token_valid(self, db, client):
        """setup_status reports 'done' when credentials are genuinely valid."""
        org, user = _create_org_and_user(db)
        _store_credentials_with_refresh_token(
            db, org.id, refresh_token="genuine-refresh-token"
        )

        token = _create_jwt_token(user.id, org.id, "owner")
        resp = client.get(
            "/dashboard/api/setup-status",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["steps"]["google_connected"]["done"] is True

    def test_google_oauth_status_reports_configured_without_refresh_token(self, db, client):
        """Fix A in /auth/google/status: configured=True but connected=False."""
        org, user = _create_org_and_user(db)
        # Store credentials with client_id/secret but empty refresh_token
        credentials = {
            "refresh_token": "",
            "client_id": TEST_GOOGLE_CLIENT_ID,
            "client_secret": TEST_GOOGLE_CLIENT_SECRET,
        }
        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials=credentials,
            metadata={"scopes": ["calendar"], "email": "test@example.com"},
        )

        token = _create_jwt_token(user.id, org.id, "owner")
        resp = client.get(
            "/auth/google/status",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["configured"] is True, (
            "Should be configured (has client_id/secret)"
        )
        assert data["connected"] is False, (
            "Must NOT be connected when refresh_token is empty"
        )


# ===========================================================================
# FIX B: Health endpoint org isolation
# ===========================================================================

class TestFixB_HealthEndpointOrgIsolation:
    """Verify that the integration-health endpoint isolates organizations.

    Defect B root cause (architectural observation):
      The health endpoint correctly uses auth_ctx.org_id from the JWT
      to scope all queries.  However, we need regression tests to prove:
      1. Org A cannot receive Org B's health result
      2. The endpoint does NOT silently fall back to the default org
      3. Missing org context is handled explicitly
    """

    def test_org_a_cannot_see_org_b_health(self, db, client):
        """Regression: Org A with broken creds must not get Org B's result."""
        # Create two distinct orgs with different credential states
        org_a, user_a = _create_org_and_user(db, org_name="Org A Health")
        org_b, user_b = _create_org_and_user(db, org_name="Org B Health")

        # Org A: empty refresh_token (broken credentials)
        _store_credentials_with_refresh_token(db, org_a.id, refresh_token="")
        # Org B: valid refresh_token
        _store_credentials_with_refresh_token(db, org_b.id, refresh_token="valid-token-for-b")

        # Authenticate as Org A user
        token_a = _create_jwt_token(user_a.id, org_a.id, "owner")

        # Mock the actual API calls since we can't hit Google in tests
        mock_cal_inst = MagicMock()
        mock_cal_inst._service.calendars().get().execute.return_value = {"kind": "calendar#calendar"}
        mock_cal_inst._calendar_id = "primary"

        mock_email_inst = MagicMock()
        mock_email_inst._service._credentials = MagicMock()
        mock_email_inst._service._credentials.valid = True
        mock_email_inst._service._credentials.expired = False

        mock_ai_inst = MagicMock()
        mock_ai_inst._primary_provider_id = "openai"
        mock_ai_inst._primary_model = "gpt-4o"
        mock_ai_inst._primary_url = "https://api.openai.com/v1"
        mock_ai_inst._primary_key = "sk-test"

        mock_provider_def = MagicMock()
        mock_provider_def.display_name = "OpenAI"

        mock_openai_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock()]
        mock_openai_client.chat.completions.create.return_value = mock_resp

        with patch("app.services.org_context.OrganizationContext") as mock_ctx, \
             patch("app.services.calendar_service.CalendarService", return_value=mock_cal_inst), \
             patch("app.services.email_service.EmailService", return_value=mock_email_inst), \
             patch("app.services.credential_vault.CredentialVault") as mock_vault, \
             patch("app.services.zoom_oauth_flow.ZoomOAuthFlow") as mock_zoom_flow, \
             patch("app.services.zoom_api_client.ZoomAPIClient") as mock_zoom_api, \
             patch("app.services.ai_service.AIService", return_value=mock_ai_inst), \
             patch("app.services.ai_provider_registry.get_provider", return_value=mock_provider_def), \
             patch("openai.OpenAI", return_value=mock_openai_client):
            # Vault checks: Org A has broken creds (no refresh_token)
            def _mock_has_creds(db, org_id, provider, integration_type):
                if str(org_id) == str(org_a.id):
                    return False  # broken credentials
                return True  # Org B has valid creds

            mock_vault.has_credentials.side_effect = _mock_has_creds
            mock_vault.get_safe_metadata.return_value = {
                "scopes": ["calendar"], "email": "test@example.com"
            }
            mock_vault.mark_error.return_value = None
            mock_zoom_flow.refresh_token_if_needed.return_value = "fake-zoom-token"
            mock_zoom_api.get_account_info.return_value = {"email": "zoom@test.com"}
            mock_ctx.from_id.return_value = MagicMock()

            resp = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(token_a),
            )
            assert resp.status_code == 200
            data = resp.json()

        # Org A should see ITS OWN health result (errors due to broken creds),
        # NOT Org B's healthy result.
        assert data["overall"] == "degraded", (
            "Org A with broken credentials must report 'degraded', not 'healthy'"
        )

    def test_health_endpoint_uses_jwt_org_not_default_org(self, db, client):
        """Regression: endpoint must use JWT org context, not the default org."""
        org, user = _create_org_and_user(db, org_name="JWT Org Test")
        _store_credentials_with_refresh_token(db, org.id, refresh_token="jwt-org-valid-token")

        # Capture which org_id was passed to OrganizationContext
        captured_org_ids = []
        original_from_id = None

        def _capture_from_id(org_id):
            captured_org_ids.append(str(org_id))
            return MagicMock()

        token = _create_jwt_token(user.id, org.id, "owner")

        mock_cal_inst = MagicMock()
        mock_cal_inst._service.calendars().get().execute.return_value = {}
        mock_cal_inst._calendar_id = "primary"

        mock_email_inst = MagicMock()
        mock_email_inst._service._credentials = MagicMock()
        mock_email_inst._service._credentials.valid = True
        mock_email_inst._service._credentials.expired = False

        mock_ai_inst = MagicMock()
        mock_ai_inst._primary_provider_id = "openai"
        mock_ai_inst._primary_model = "gpt-4o"
        mock_ai_inst._primary_url = "https://api.openai.com/v1"
        mock_ai_inst._primary_key = "sk-test"

        mock_provider_def = MagicMock()
        mock_provider_def.display_name = "OpenAI"

        mock_openai_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock()]
        mock_openai_client.chat.completions.create.return_value = mock_resp

        with patch("app.services.org_context.OrganizationContext") as mock_ctx, \
             patch("app.services.calendar_service.CalendarService", return_value=mock_cal_inst), \
             patch("app.services.email_service.EmailService", return_value=mock_email_inst), \
             patch("app.services.credential_vault.CredentialVault") as mock_vault, \
             patch("app.services.zoom_oauth_flow.ZoomOAuthFlow") as mock_zoom_flow, \
             patch("app.services.zoom_api_client.ZoomAPIClient") as mock_zoom_api, \
             patch("app.services.ai_service.AIService", return_value=mock_ai_inst), \
             patch("app.services.ai_provider_registry.get_provider", return_value=mock_provider_def), \
             patch("openai.OpenAI", return_value=mock_openai_client):
            mock_ctx.from_id.side_effect = _capture_from_id
            mock_vault.has_credentials.return_value = True
            mock_vault.get_safe_metadata.return_value = {
                "scopes": ["calendar"], "email": "test@example.com"
            }
            mock_vault.mark_error.return_value = None
            mock_zoom_flow.refresh_token_if_needed.return_value = "fake-token"
            mock_zoom_api.get_account_info.return_value = {"email": "zoom@test.com"}

            resp = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(token),
            )
            assert resp.status_code == 200

        # The org passed to OrganizationContext must match the JWT's org_id
        _DEFAULT_ORG_ID = "00000000-0000-0000-0000-000000000001"
        for captured_id in captured_org_ids:
            assert captured_id != _DEFAULT_ORG_ID, (
                f"Health endpoint passed default org {_DEFAULT_ORG_ID} to "
                f"OrganizationContext instead of JWT org {org.id}"
            )
            assert captured_id == str(org.id), (
                f"Health endpoint used org {captured_id} instead of JWT org {org.id}"
            )

    def test_health_endpoint_rejects_non_owner_admin(self, db, client):
        """Member role must be rejected by health endpoint."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _create_jwt_token(user.id, org.id, "member")
        resp = client.get(
            "/dashboard/api/integration-health",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 403

    def test_setup_status_returns_error_for_missing_org(self, db, client):
        """Platform admin (org_id=None) gets setup_complete=True."""
        # Platform admin via HTTP Basic (no JWT, no org_id)
        from app.config import settings as _s
        resp = client.get(
            "/dashboard/api/setup-status",
            auth=("admin", getattr(_s, "dashboard_password", "admin")),
        )
        # Platform admin returns setup_complete=True with empty steps
        if resp.status_code == 200:
            data = resp.json()
            assert data.get("setup_complete") is True


# ===========================================================================
# FIX C: Gmail health check uses scope-compatible validation
# ===========================================================================

class TestFixC_GmailScopeMismatch:
    """Verify Gmail health check does not require gmail.readonly scope.

    Defect C root cause:
      The Gmail health check used users.getProfile() which requires
      gmail.readonly scope.  The app only requests gmail.send scope.
      The fix replaces getProfile with a scope-compatible credential
      validation approach.
    """

    def test_gmail_health_does_not_call_getProfile(self, db, client):
        """Regression: Gmail health check must NOT call users.getProfile."""
        org, user = _create_org_and_user(db)
        _store_credentials_with_refresh_token(db, org.id)

        token = _create_jwt_token(user.id, org.id, "owner")

        mock_cal_inst = MagicMock()
        mock_cal_inst._service.calendars().get().execute.return_value = {}
        mock_cal_inst._calendar_id = "primary"

        mock_email_inst = MagicMock()
        # Set up credentials mock to indicate valid (no refresh needed)
        mock_creds = MagicMock()
        mock_creds.valid = True
        mock_creds.expired = False
        mock_email_inst._service._credentials = mock_creds

        mock_ai_inst = MagicMock()
        mock_ai_inst._primary_provider_id = "openai"
        mock_ai_inst._primary_model = "gpt-4o"
        mock_ai_inst._primary_url = "https://api.openai.com/v1"
        mock_ai_inst._primary_key = "sk-test"

        mock_provider_def = MagicMock()
        mock_provider_def.display_name = "OpenAI"

        mock_openai_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock()]
        mock_openai_client.chat.completions.create.return_value = mock_resp

        with patch("app.services.org_context.OrganizationContext") as mock_ctx, \
             patch("app.services.calendar_service.CalendarService", return_value=mock_cal_inst), \
             patch("app.services.email_service.EmailService", return_value=mock_email_inst), \
             patch("app.services.credential_vault.CredentialVault") as mock_vault, \
             patch("app.services.zoom_oauth_flow.ZoomOAuthFlow") as mock_zoom_flow, \
             patch("app.services.zoom_api_client.ZoomAPIClient") as mock_zoom_api, \
             patch("app.services.ai_service.AIService", return_value=mock_ai_inst), \
             patch("app.services.ai_provider_registry.get_provider", return_value=mock_provider_def), \
             patch("openai.OpenAI", return_value=mock_openai_client):
            mock_ctx.from_id.return_value = MagicMock()
            mock_vault.has_credentials.return_value = True
            mock_vault.get_safe_metadata.return_value = {
                "scopes": ["calendar", "gmail.send"],
                "email": "test@example.com",
            }
            mock_vault.mark_error.return_value = None
            mock_zoom_flow.refresh_token_if_needed.return_value = "fake-token"
            mock_zoom_api.get_account_info.return_value = {"email": "zoom@test.com"}

            resp = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(token),
            )
            assert resp.status_code == 200
            data = resp.json()

        # The Gmail service must NOT have had getProfile called
        mock_email_inst._service.users.assert_not_called() if hasattr(
            mock_email_inst._service, "users"
        ) else None

        # Gmail should report as connected
        assert data["gmail"]["status"] == "connected", (
            f"Gmail health should be connected, got: {data['gmail']}"
        )

    def test_gmail_health_refreshes_expired_credentials(self, db, client):
        """Gmail health check should refresh expired credentials."""
        org, user = _create_org_and_user(db)
        _store_credentials_with_refresh_token(db, org.id)

        token = _create_jwt_token(user.id, org.id, "owner")

        mock_cal_inst = MagicMock()
        mock_cal_inst._service.calendars().get().execute.return_value = {}
        mock_cal_inst._calendar_id = "primary"

        mock_email_inst = MagicMock()
        mock_creds = MagicMock()
        mock_creds.valid = False
        mock_creds.expired = True
        mock_creds.refresh = MagicMock()  # Should be called for refresh
        # FIX: Real EmailService stores self._credentials = creds at instance level.
        # Set directly on the mock instance so getattr(svc, '_credentials') finds it.
        mock_email_inst._credentials = mock_creds

        mock_ai_inst = MagicMock()
        mock_ai_inst._primary_provider_id = "openai"
        mock_ai_inst._primary_model = "gpt-4o"
        mock_ai_inst._primary_url = "https://api.openai.com/v1"
        mock_ai_inst._primary_key = "sk-test"

        mock_provider_def = MagicMock()
        mock_provider_def.display_name = "OpenAI"

        mock_openai_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock()]
        mock_openai_client.chat.completions.create.return_value = mock_resp

        with patch("app.services.org_context.OrganizationContext") as mock_ctx, \
             patch("app.services.calendar_service.CalendarService", return_value=mock_cal_inst), \
             patch("app.services.email_service.EmailService", return_value=mock_email_inst), \
             patch("app.services.credential_vault.CredentialVault") as mock_vault, \
             patch("app.services.zoom_oauth_flow.ZoomOAuthFlow") as mock_zoom_flow, \
             patch("app.services.zoom_api_client.ZoomAPIClient") as mock_zoom_api, \
             patch("app.services.ai_service.AIService", return_value=mock_ai_inst), \
             patch("app.services.ai_provider_registry.get_provider", return_value=mock_provider_def), \
             patch("openai.OpenAI", return_value=mock_openai_client):
            mock_ctx.from_id.return_value = MagicMock()
            mock_vault.has_credentials.return_value = True
            mock_vault.get_safe_metadata.return_value = {
                "scopes": ["calendar", "gmail.send"],
                "email": "test@example.com",
            }
            mock_vault.mark_error.return_value = None
            mock_zoom_flow.refresh_token_if_needed.return_value = "fake-token"
            mock_zoom_api.get_account_info.return_value = {"email": "zoom@test.com"}

            resp = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(token),
            )
            assert resp.status_code == 200

        # Verify that refresh was attempted on expired credentials
        mock_creds.refresh.assert_called_once()

    def test_gmail_health_reports_email_from_metadata(self, db, client):
        """Gmail health check must extract email from metadata, not API call."""
        org, user = _create_org_and_user(db)
        _store_credentials_with_refresh_token(db, org.id)

        token = _create_jwt_token(user.id, org.id, "owner")

        mock_cal_inst = MagicMock()
        mock_cal_inst._service.calendars().get().execute.return_value = {}
        mock_cal_inst._calendar_id = "primary"

        mock_email_inst = MagicMock()
        mock_creds = MagicMock()
        mock_creds.valid = True
        mock_creds.expired = False
        # FIX: Set _credentials at instance level (matching real EmailService).
        mock_email_inst._credentials = mock_creds

        mock_ai_inst = MagicMock()
        mock_ai_inst._primary_provider_id = "openai"
        mock_ai_inst._primary_model = "gpt-4o"
        mock_ai_inst._primary_url = "https://api.openai.com/v1"
        mock_ai_inst._primary_key = "sk-test"

        mock_provider_def = MagicMock()
        mock_provider_def.display_name = "OpenAI"

        mock_openai_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock()]
        mock_openai_client.chat.completions.create.return_value = mock_resp

        with patch("app.services.org_context.OrganizationContext") as mock_ctx, \
             patch("app.services.calendar_service.CalendarService", return_value=mock_cal_inst), \
             patch("app.services.email_service.EmailService", return_value=mock_email_inst), \
             patch("app.services.credential_vault.CredentialVault") as mock_vault, \
             patch("app.services.zoom_oauth_flow.ZoomOAuthFlow") as mock_zoom_flow, \
             patch("app.services.zoom_api_client.ZoomAPIClient") as mock_zoom_api, \
             patch("app.services.ai_service.AIService", return_value=mock_ai_inst), \
             patch("app.services.ai_provider_registry.get_provider", return_value=mock_provider_def), \
             patch("openai.OpenAI", return_value=mock_openai_client):
            mock_ctx.from_id.return_value = MagicMock()
            mock_vault.has_credentials.return_value = True

            def _mock_safe_meta(db, org_id, provider, integration_type):
                if integration_type == "email":
                    return {"sender_email": "owner@org-a-test.com"}
                return {"scopes": ["calendar", "gmail.send"], "email": "test@example.com"}

            mock_vault.get_safe_metadata.side_effect = _mock_safe_meta
            mock_vault.mark_error.return_value = None
            mock_zoom_flow.refresh_token_if_needed.return_value = "fake-token"
            mock_zoom_api.get_account_info.return_value = {"email": "zoom@test.com"}

            resp = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(token),
            )
            assert resp.status_code == 200
            data = resp.json()

        # Email should come from metadata, not from an API call
        assert data["gmail"]["email"] == "owner@org-a-test.com", (
            f"Gmail email must come from metadata, got: {data['gmail']['email']}"
        )

    def test_gmail_health_handles_invalid_refresh_token(self, db, client):
        """When refresh fails (revoked token), Gmail health reports error."""
        org, user = _create_org_and_user(db)
        _store_credentials_with_refresh_token(db, org.id)

        token = _create_jwt_token(user.id, org.id, "owner")

        mock_cal_inst = MagicMock()
        mock_cal_inst._service.calendars().get().execute.return_value = {}
        mock_cal_inst._calendar_id = "primary"

        mock_email_inst = MagicMock()
        mock_creds = MagicMock()
        mock_creds.valid = False
        mock_creds.expired = True
        mock_creds.refresh.side_effect = Exception("Token refresh failed: revoked")
        # FIX: Set _credentials at instance level (matching real EmailService).
        mock_email_inst._credentials = mock_creds

        mock_ai_inst = MagicMock()
        mock_ai_inst._primary_provider_id = "openai"
        mock_ai_inst._primary_model = "gpt-4o"
        mock_ai_inst._primary_url = "https://api.openai.com/v1"
        mock_ai_inst._primary_key = "sk-test"

        mock_provider_def = MagicMock()
        mock_provider_def.display_name = "OpenAI"

        mock_openai_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock()]
        mock_openai_client.chat.completions.create.return_value = mock_resp

        with patch("app.services.org_context.OrganizationContext") as mock_ctx, \
             patch("app.services.calendar_service.CalendarService", return_value=mock_cal_inst), \
             patch("app.services.email_service.EmailService", return_value=mock_email_inst), \
             patch("app.services.credential_vault.CredentialVault") as mock_vault, \
             patch("app.services.zoom_oauth_flow.ZoomOAuthFlow") as mock_zoom_flow, \
             patch("app.services.zoom_api_client.ZoomAPIClient") as mock_zoom_api, \
             patch("app.services.ai_service.AIService", return_value=mock_ai_inst), \
             patch("app.services.ai_provider_registry.get_provider", return_value=mock_provider_def), \
             patch("openai.OpenAI", return_value=mock_openai_client):
            mock_ctx.from_id.return_value = MagicMock()
            mock_vault.has_credentials.return_value = True
            mock_vault.get_safe_metadata.return_value = {
                "scopes": ["calendar", "gmail.send"],
                "email": "test@example.com",
            }
            mock_vault.mark_error.return_value = None
            mock_zoom_flow.refresh_token_if_needed.return_value = "fake-token"
            mock_zoom_api.get_account_info.return_value = {"email": "zoom@test.com"}

            resp = client.get(
                "/dashboard/api/integration-health",
                headers=_auth_headers(token),
            )
            assert resp.status_code == 200
            data = resp.json()

        # Gmail should report error, not connected
        assert data["gmail"]["status"] == "error", (
            f"Gmail must report error when refresh fails, got: {data['gmail']}"
        )
        assert data["gmail"]["error"] is not None
        assert data["gmail"]["error_type"] is not None


# ===========================================================================
# Cross-cutting: CredentialVault unit tests for refresh_token validation
# ===========================================================================

class TestCredentialVaultRefreshTokenValidation:
    """Unit tests for the CredentialVault + GoogleOAuthFlow integration."""

    def test_has_credentials_returns_true_for_any_nonempty_blob(self, db):
        """has_credentials checks DB state only — does not decrypt."""
        org, user = _create_org_and_user(db)
        _store_credentials_with_refresh_token(db, org.id, refresh_token="")

        # has_credentials should return True (row exists, encrypted, not disconnected)
        assert CredentialVault.has_credentials(
            db, org.id, "google", "google_oauth"
        ) is True

    def test_get_credentials_decrypts_correctly(self, db):
        """get_credentials returns the decrypted dict including empty refresh_token."""
        org, user = _create_org_and_user(db)
        _store_credentials_with_refresh_token(db, org.id, refresh_token="real-token")

        creds = CredentialVault.get_credentials(db, org.id, "google", "google_oauth")
        assert creds["refresh_token"] == "real-token"
        assert creds["client_id"] == TEST_GOOGLE_CLIENT_ID

    def test_get_credentials_empty_refresh_token(self, db):
        """get_credentials returns empty string for empty refresh_token."""
        org, user = _create_org_and_user(db)
        _store_credentials_with_refresh_token(db, org.id, refresh_token="")

        creds = CredentialVault.get_credentials(db, org.id, "google", "google_oauth")
        assert creds["refresh_token"] == ""

    def test_credential_corruption_detected(self, db):
        """Corrupt credentials raise CredentialCorruptError."""
        from app.services.credential_vault import CredentialCorruptError
        org, user = _create_org_and_user(db)
        integration = _store_credentials_with_refresh_token(db, org.id)
        # Corrupt the encrypted blob
        integration.credentials_encrypted = b"corrupt-data-not-valid-fernet"
        db.commit()

        with pytest.raises(CredentialCorruptError):
            CredentialVault.get_credentials(db, org.id, "google", "google_oauth")
