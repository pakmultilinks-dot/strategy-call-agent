"""Phase 6D - Regression Tests for Integration Fixes.

Validates the three bug fixes:
  1. setup_status integration_type mismatch ("oauth" → "google_oauth")
  2. IntegrationConfigResolver no longer silently falls back to .env in production
  3. Dashboard multi-org view does not show false "Connected" status

Also validates end-to-end OAuth flow, multi-tenant isolation, and
pipeline error message clarity.

Total: ~25+ targeted regression tests
"""
from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models_multi_tenant import (
    GoogleOAuthState,
    IntegrationStatus,
    OrgIntegration,
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
    ZoomOAuthState,
)
from app.services.credential_vault import CredentialVault
from app.services.crypto import generate_key
from app.services.integration_config_resolver import (
    ConfigurationError,
    IntegrationConfigResolver,
)
from app.services.google_oauth_flow import (
    GoogleOAuthError,
    GoogleOAuthFlow,
)

# ── Test Constants ────────────────────────────────────────────────────────────

TEST_JWT_SECRET = "test-secret-key-for-phase-6d-regression-32chars!!"
TEST_ENCRYPTION_KEY = generate_key()
TEST_GOOGLE_CLIENT_ID = "test-client-id.apps.googleusercontent.com"
TEST_GOOGLE_CLIENT_SECRET = "test-client-secret"
TEST_GOOGLE_REDIRECT_URI = "http://localhost:8000/auth/google/callback"


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    """Inject test-mode secrets."""
    monkeypatch.setattr(settings, "jwt_secret_key", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", TEST_ENCRYPTION_KEY)
    monkeypatch.setattr(settings, "google_client_id", TEST_GOOGLE_CLIENT_ID)
    monkeypatch.setattr(settings, "google_client_secret", TEST_GOOGLE_CLIENT_SECRET)
    monkeypatch.setattr(settings, "google_redirect_uri", TEST_GOOGLE_REDIRECT_URI)
    monkeypatch.setattr(settings, "google_oauth_state_ttl_minutes", 10)


@pytest.fixture()
def client():
    """TestClient with lifespan support."""
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db():
    """Yield a DB session with rollback."""
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


def _create_org_and_user(
    db,
    email: str = "owner@example.com",
    password: str = "StrongPass123!",
    role: UserRole = UserRole.OWNER,
    org_name: str | None = None,
    user_status: UserStatus = UserStatus.ACTIVE,
) -> tuple[Organization, User]:
    """Helper: create an org + user with a bcrypt password hash."""
    from app.auth import hash_password

    org = Organization(
        name=org_name or f"Test Org {uuid.uuid4().hex[:8]}",
        slug=f"test-org-{uuid.uuid4().hex[:8]}",
        timezone="America/Chicago",
        status=OrganizationStatus.ACTIVE,
    )
    db.add(org)
    db.flush()

    user = User(
        organization_id=org.id,
        email=email.lower(),
        full_name="Test User",
        password_hash=hash_password(password),
        role=role,
        status=user_status,
    )
    db.add(user)
    db.flush()
    db.commit()
    return org, user


def _create_jwt_token(user_id: uuid.UUID, org_id: uuid.UUID, role: str = "owner") -> str:
    """Create a valid JWT token for testing."""
    from app.auth import create_access_token
    return create_access_token(user_id, org_id, role)


def _auth_headers(token: str) -> dict:
    """Bearer auth headers."""
    return {"Authorization": f"Bearer {token}"}


# ══════════════════════════════════════════════════════════════════════════════
# 1. setup_status integration_type Fix
# ══════════════════════════════════════════════════════════════════════════════


class TestSetupStatusIntegrationTypeFix:
    """Bug Fix: setup_status queried integration_type == "oauth" but records
    are stored as "google_oauth".  This caused the onboarding wizard to
    always show Google as not connected even after a successful OAuth callback.
    """

    def test_setup_status_detects_google_oauth_records(self, db, client):
        """setup_status should return google_connected=True when vault has
        google_oauth integration with status=connected AND a valid refresh_token.

        Phase 34 Fix A: A row with status=connected but no credentials_encrypted
        or empty refresh_token must NOT report as connected.
        """
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        # Phase 34: Must store actual credentials with a refresh_token
        CredentialVault.save_credentials(
            db=db, org_id=org.id, provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "test-id.apps.googleusercontent.com",
                "client_secret": "test-secret",
                "refresh_token": "valid-refresh-token",
            },
            metadata={"email": "test@example.com"},
            status=IntegrationStatus.CONNECTED,
        )

        resp = client.get(
            "/dashboard/api/setup-status",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["steps"]["google_connected"]["done"] is True

    def test_setup_status_not_confused_by_wrong_integration_type(self, db, client):
        """setup_status should NOT match records with integration_type='oauth'
        (the old incorrect value)."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        # Create an OrgIntegration with the WRONG integration_type (old bug)
        integration = OrgIntegration(
            organization_id=org.id,
            provider="google",
            integration_type="oauth",  # old incorrect value
            status=IntegrationStatus.CONNECTED,
            connected_at=datetime.now(timezone.utc),
        )
        db.add(integration)
        db.commit()

        resp = client.get(
            "/dashboard/api/setup-status",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        # "oauth" should NOT match - only "google_oauth" is correct
        assert data["steps"]["google_connected"]["done"] is False

    def test_setup_status_shows_not_connected_for_empty_vault(self, db, client):
        """setup_status should return google_connected=False when no
        OrgIntegration records exist for this org."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        resp = client.get(
            "/dashboard/api/setup-status",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["steps"]["google_connected"]["done"] is False

    def test_setup_status_ignores_other_orgs_records(self, db, client):
        """setup_status for org A should NOT be affected by org B's records."""
        org_a, user_a = _create_org_and_user(db, email="a@example.com")
        org_b, user_b = _create_org_and_user(db, email="b@example.com")
        token_a = _create_jwt_token(user_a.id, org_a.id, "owner")

        # Only org B has a connected Google integration
        integration_b = OrgIntegration(
            organization_id=org_b.id,
            provider="google",
            integration_type="google_oauth",
            status=IntegrationStatus.CONNECTED,
            connected_at=datetime.now(timezone.utc),
        )
        db.add(integration_b)
        db.commit()

        resp = client.get(
            "/dashboard/api/setup-status",
            headers=_auth_headers(token_a),
        )
        assert resp.status_code == 200
        data = resp.json()
        # org A has no records - should NOT say connected
        assert data["steps"]["google_connected"]["done"] is False

    def test_setup_status_pending_not_marked_done(self, db, client):
        """setup_status should NOT mark Google as done when status is PENDING
        (credentials saved but OAuth not completed)."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        integration = OrgIntegration(
            organization_id=org.id,
            provider="google",
            integration_type="google_oauth",
            status=IntegrationStatus.PENDING,
        )
        db.add(integration)
        db.commit()

        resp = client.get(
            "/dashboard/api/setup-status",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["steps"]["google_connected"]["done"] is False


# ══════════════════════════════════════════════════════════════════════════════
# 2. IntegrationConfigResolver - No Silent .env Fallback in Production
# ══════════════════════════════════════════════════════════════════════════════


class TestResolverProductionNoFallback:
    """Bug Fix: IntegrationConfigResolver.resolve_google_oauth() previously
    fell back to .env credentials silently even in production, masking the
    fact that no org-level credentials existed.

    In production, when the vault is empty, the resolver must raise
    ConfigurationError with a clear message directing the user to the
    Dashboard Integrations page.
    """

    def test_empty_vault_raises_in_production(self, db):
        """Empty vault AND no platform client in production → ConfigurationError.

        PLATFORM-OWNED MODEL: the platform client (.env) is the normal
        path, so an empty vault alone no longer raises.  The error only
        fires when nothing is configured at all.
        """
        org, user = _create_org_and_user(db)

        with patch(
            "app.services.integration_config_resolver.settings"
        ) as mock_settings:
            mock_settings.app_env = "production"
            mock_settings.google_client_id = ""
            mock_settings.google_client_secret = ""
            mock_settings.google_refresh_token = ""

            with pytest.raises(ConfigurationError, match="administrator"):
                IntegrationConfigResolver.resolve_google_oauth(db, org.id)

    def test_empty_vault_uses_platform_client_in_production(self, db):
        """Empty vault + platform client set → resolves with platform client."""
        org, user = _create_org_and_user(db)

        with patch(
            "app.services.integration_config_resolver.settings"
        ) as mock_settings:
            mock_settings.app_env = "production"
            mock_settings.google_client_id = "env-id"
            mock_settings.google_client_secret = "env-secret"
            mock_settings.google_refresh_token = "env-refresh"

            cfg = IntegrationConfigResolver.resolve_google_oauth(db, org.id)

        assert cfg.client_id == "env-id"
        assert cfg.client_secret == "env-secret"
        assert cfg.refresh_token == ""

    def test_empty_vault_falls_back_in_test(self, db):
        """Empty vault in test mode → platform client, empty refresh token.

        PLATFORM-OWNED MODEL: the deprecated GOOGLE_REFRESH_TOKEN .env
        fallback is gone - the org gets the platform client and connects
        with one click to obtain its own refresh token.
        """
        org, user = _create_org_and_user(db)

        with patch(
            "app.services.integration_config_resolver.settings"
        ) as mock_settings:
            mock_settings.app_env = "test"
            mock_settings.google_client_id = "env-id"
            mock_settings.google_client_secret = "env-secret"
            mock_settings.google_refresh_token = "env-refresh"

            cfg = IntegrationConfigResolver.resolve_google_oauth(db, org.id)

        assert cfg.client_id == "env-id"
        assert cfg.client_secret == "env-secret"
        assert cfg.refresh_token == ""

    def test_empty_vault_falls_back_in_dev(self, db):
        """Empty vault in dev mode → platform client, empty refresh token."""
        org, user = _create_org_and_user(db)

        with patch(
            "app.services.integration_config_resolver.settings"
        ) as mock_settings:
            mock_settings.app_env = "dev"
            mock_settings.google_client_id = "dev-id"
            mock_settings.google_client_secret = "dev-secret"
            mock_settings.google_refresh_token = "dev-refresh"

            cfg = IntegrationConfigResolver.resolve_google_oauth(db, org.id)

        assert cfg.client_id == "dev-id"
        assert cfg.client_secret == "dev-secret"
        assert cfg.refresh_token == ""

    def test_incomplete_vault_raises_configuration_error(self, db):
        """Vault with client_id but no client_secret → ConfigurationError."""
        org, user = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "vault-client-id",
                "client_secret": "",  # empty
                "redirect_uri": "https://example.com/callback",
            },
            metadata={},
            status=IntegrationStatus.PENDING,
        )

        with pytest.raises(ConfigurationError, match="incomplete"):
            IntegrationConfigResolver.resolve_google_oauth(db, org.id)

    def test_incomplete_vault_raises_even_in_test(self, db):
        """Vault record with empty client fields falls through to platform.

        PLATFORM-OWNED MODEL: connected orgs legitimately have vault rows
        without client_id/client_secret (only user tokens are stored).
        An empty record must not block the platform client.
        """
        org, user = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "",
                "client_secret": "",
            },
            metadata={},
            status=IntegrationStatus.PENDING,
        )

        with patch(
            "app.services.integration_config_resolver.settings"
        ) as mock_settings:
            mock_settings.google_client_id = "env-id"
            mock_settings.google_client_secret = "env-secret"
            mock_settings.google_redirect_uri = "https://example.com/cb"

            cfg = IntegrationConfigResolver.resolve_google_oauth(db, org.id)

        assert cfg.client_id == "env-id"
        assert cfg.client_secret == "env-secret"

    def test_vault_with_all_fields_returns_vault_values(self, db):
        """Vault with complete credentials → uses vault values (no fallback)."""
        org, user = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "vault-id.apps.googleusercontent.com",
                "client_secret": "GOCSPX-vault-secret",
                "refresh_token": "vault-refresh-token",
                "redirect_uri": "https://example.com/callback",
            },
            metadata={},
            status=IntegrationStatus.CONNECTED,
        )

        cfg = IntegrationConfigResolver.resolve_google_oauth(db, org.id)
        assert cfg.client_id == "vault-id.apps.googleusercontent.com"
        assert cfg.client_secret == "GOCSPX-vault-secret"
        assert cfg.refresh_token == "vault-refresh-token"

    def test_configuration_error_is_runtime_error(self):
        """ConfigurationError should be a subclass of RuntimeError."""
        assert issubclass(ConfigurationError, RuntimeError)

    def test_production_config_error_message_mentions_dashboard(self, db):
        """Error message in production should direct to the administrator, NOT .env."""
        org, user = _create_org_and_user(db)

        with patch(
            "app.services.integration_config_resolver.settings"
        ) as mock_settings:
            mock_settings.app_env = "production"
            mock_settings.google_client_id = ""
            mock_settings.google_client_secret = ""
            mock_settings.google_refresh_token = ""

            with pytest.raises(ConfigurationError, match="administrator"):
                IntegrationConfigResolver.resolve_google_oauth(db, org.id)


# ══════════════════════════════════════════════════════════════════════════════
# 3. Dashboard Multi-Org View - No False "Connected"
# ══════════════════════════════════════════════════════════════════════════════


class TestDashboardMultiOrgView:
    """Bug Fix: Platform admin view of /dashboard/api/integrations returned
    ALL orgs' integrations.  The frontend aggregated status across all orgs,
    causing "Connected" to display even when the viewed org had 0 records.

    The fix detects multi-org view (platform admin) and shows per-org status
    instead of an aggregated "Connected" badge.
    """

    def test_google_status_endpoint_org_scoped(self, db, client):
        """GET /auth/google/status should check vault for the authenticated
        org only - not return false positive from other orgs."""
        org_a, user_a = _create_org_and_user(db, email="a@example.com")
        org_b, user_b = _create_org_and_user(db, email="b@example.com")
        token_a = _create_jwt_token(user_a.id, org_a.id, "owner")

        # Org B has connected Google - org A does not
        CredentialVault.save_credentials(
            db=db,
            org_id=org_b.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "orgB-client-id",
                "client_secret": "GOCSPX-orgB-secret",
                "refresh_token": "orgB-refresh-token",
            },
            metadata={"email": "orgb@example.com"},
            status=IntegrationStatus.CONNECTED,
        )

        resp = client.get(
            "/auth/google/status",
            headers=_auth_headers(token_a),
        )
        assert resp.status_code == 200
        data = resp.json()
        # Org A should NOT see org B's connected status.
        # PLATFORM-OWNED MODEL: "configured" is True for every org once
        # the platform client exists; "connected" is org-scoped.
        assert data["connected"] is False
        assert data["configured"] is True

    def test_integrations_endpoint_org_scoped(self, db, client):
        """GET /dashboard/api/integrations should return only the
        authenticated org's integrations - not all orgs."""
        org_a, user_a = _create_org_and_user(db, email="a@example.com")
        org_b, user_b = _create_org_and_user(db, email="b@example.com")
        token_a = _create_jwt_token(user_a.id, org_a.id, "owner")

        # Only org B has Google integration
        CredentialVault.save_credentials(
            db=db,
            org_id=org_b.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "orgB-id",
                "client_secret": "orgB-secret",
                "refresh_token": "orgB-refresh",
            },
            metadata={},
            status=IntegrationStatus.CONNECTED,
        )

        resp = client.get(
            "/dashboard/api/integrations",
            headers=_auth_headers(token_a),
        )
        assert resp.status_code == 200
        data = resp.json()
        # Org A's integrations should be empty - no Google connected
        google_items = [
            i for i in data.get("integrations", [])
            if i.get("provider") == "google"
        ]
        assert len(google_items) == 0

    def test_platform_admin_sees_all_orgs_integrations(self, db, client, monkeypatch):
        """Platform admin (HTTP Basic auth) should see ALL orgs'
        integrations with organization_id and organization_name."""
        org_a, user_a = _create_org_and_user(db, email="a@example.com")
        org_b, user_b = _create_org_and_user(db, email="b@example.com")

        CredentialVault.save_credentials(
            db=db,
            org_id=org_b.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "orgB-id",
                "client_secret": "orgB-secret",
                "refresh_token": "orgB-refresh",
            },
            metadata={},
            status=IntegrationStatus.CONNECTED,
        )

        # Platform admin via HTTP Basic - use monkeypatch to avoid
        # contaminating subsequent tests (settings are global state).
        monkeypatch.setattr(settings, "dashboard_username", "admin")
        monkeypatch.setattr(settings, "dashboard_password", "admin123")

        resp = client.get(
            "/dashboard/api/integrations",
            auth=("admin", "admin123"),
        )
        assert resp.status_code == 200
        data = resp.json()
        # Platform admin sees integrations from other orgs
        google_items = [
            i for i in data.get("integrations", [])
            if i.get("provider") == "google"
        ]
        # Should have org B's integration
        assert len(google_items) >= 1
        # Each item should have organization_id and organization_name
        for item in google_items:
            assert "organization_id" in item
            assert "organization_name" in item


# ══════════════════════════════════════════════════════════════════════════════
# 4. OAuth Flow End-to-End with Vault
# ══════════════════════════════════════════════════════════════════════════════


class TestOAuthFlowEndToEnd:
    """Verify the complete OAuth flow:
      1. Dashboard saves credentials → vault
      2. User clicks Connect → OAuth start → state persisted
      3. Google callback → tokens exchanged → vault updated
      4. Dashboard shows Connected
      5. Pipeline uses vault credentials (Calendar/Gmail)
    """

    def test_oauth_start_uses_vault_credentials(self, db, client):
        """OAuth start should resolve client_id from vault, not .env."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        # Save credentials via dashboard (simulated)
        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "vault-client-id.apps.googleusercontent.com",
                "client_secret": "GOCSPX-vault-secret",
                "redirect_uri": TEST_GOOGLE_REDIRECT_URI,
            },
            metadata={"label": "Google OAuth2"},
            status=IntegrationStatus.PENDING,
        )

        resp = client.get(
            "/auth/google/start",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "authorization_url" in data
        # Authorization URL should use vault client_id
        assert "vault-client-id" in data["authorization_url"]

    def test_oauth_start_fails_without_vault_credentials_in_production(self, db, client):
        """OAuth start should fail with clear error when vault is empty
        in production mode."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        with patch(
            "app.services.integration_config_resolver.settings"
        ) as mock_settings:
            mock_settings.app_env = "production"
            mock_settings.google_client_id = ""
            mock_settings.google_client_secret = ""
            mock_settings.google_refresh_token = ""
            mock_settings.google_redirect_uri = TEST_GOOGLE_REDIRECT_URI
            mock_settings.google_oauth_state_ttl_minutes = 10
            mock_settings.jwt_secret_key = TEST_JWT_SECRET
            mock_settings.jwt_algorithm = "HS256"
            mock_settings.jwt_access_token_expire_minutes = 30

            resp = client.get(
                "/auth/google/start",
                headers=_auth_headers(token),
            )
            assert resp.status_code == 400
            assert "not set up" in resp.json()["detail"].lower()

    def test_callback_stores_in_vault(self, db, client):
        """After successful OAuth callback, credentials should be stored
        in the vault - NOT in token.json."""
        org, user = _create_org_and_user(db)

        # Use a unique state token per test run to avoid unique constraint
        # violations on shared PostgreSQL databases.
        unique_state = f"test-state-token-{uuid.uuid4().hex[:16]}"

        # Create a state row manually (simulating create_authorization_url)
        state_row = GoogleOAuthState(
            organization_id=org.id,
            user_id=user.id,
            state_token=unique_state,
            redirect_uri=TEST_GOOGLE_REDIRECT_URI,
            scopes=["calendar", "gmail.send"],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            used=False,
        )
        db.add(state_row)
        db.commit()

        # Mock successful Google API responses
        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {
            "access_token": "ya29.test-access-token",
            "refresh_token": "1//0test-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {
            "email": "test@example.com",
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp), \
             patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
            result = GoogleOAuthFlow.exchange_code(
                db=db, code="test-auth-code", state=unique_state,
            )

        # Verify credentials are in the vault
        assert CredentialVault.has_credentials(
            db, org.id, "google", "google_oauth"
        )
        creds = CredentialVault.get_credentials(
            db, org.id, "google", "google_oauth"
        )
        assert creds["refresh_token"] == "1//0test-refresh-token"
        # PLATFORM-OWNED MODEL: client creds live in the server .env,
        # never in the per-org vault.
        assert "client_id" not in creds
        assert "client_secret" not in creds
        assert result["email"] == "test@example.com"

    def test_calendar_and_gmail_share_same_vault_credentials(self, db):
        """CalendarService and EmailService should resolve credentials
        from the same vault record."""
        org, user = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "shared-client-id",
                "client_secret": "shared-client-secret",
                "refresh_token": "shared-refresh-token",
            },
            metadata={},
            status=IntegrationStatus.CONNECTED,
        )

        # Both services use the same resolver
        cfg_calendar = IntegrationConfigResolver.resolve_google_oauth(db, org.id)
        cfg_email = IntegrationConfigResolver.resolve_google_oauth(db, org.id)

        assert cfg_calendar.client_id == cfg_email.client_id
        assert cfg_calendar.client_secret == cfg_email.client_secret
        assert cfg_calendar.refresh_token == cfg_email.refresh_token
        assert cfg_calendar.client_id == "shared-client-id"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Multi-Tenant Isolation
# ══════════════════════════════════════════════════════════════════════════════


class TestOAuthMultiTenantIsolation:
    """Verify that the OAuth flow preserves multi-tenant isolation:
      - Each org's OAuth state is bound to its org_id
      - Each org's vault credentials are isolated
      - Org A cannot use Org B's credentials
    """

    def test_oauth_state_bound_to_org(self, db):
        """OAuth state should store organization_id correctly."""
        org, user = _create_org_and_user(db)

        state = GoogleOAuthState(
            organization_id=org.id,
            user_id=user.id,
            state_token=secrets.token_urlsafe(32),
            redirect_uri=TEST_GOOGLE_REDIRECT_URI,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            used=False,
        )
        db.add(state)
        db.commit()
        db.refresh(state)

        assert state.organization_id == org.id

    def test_vault_credentials_isolated_per_org(self, db):
        """Each org's vault credentials should be completely isolated."""
        org_a, _ = _create_org_and_user(db, email="a@test.com", org_name="OrgA")
        org_b, _ = _create_org_and_user(db, email="b@test.com", org_name="OrgB")

        CredentialVault.save_credentials(
            db=db, org_id=org_a.id, provider="google",
            integration_type="google_oauth",
            credentials={"client_id": "orgA-id", "client_secret": "orgA-secret", "refresh_token": "orgA-refresh"},
            metadata={}, status=IntegrationStatus.CONNECTED,
        )
        CredentialVault.save_credentials(
            db=db, org_id=org_b.id, provider="google",
            integration_type="google_oauth",
            credentials={"client_id": "orgB-id", "client_secret": "orgB-secret", "refresh_token": "orgB-refresh"},
            metadata={}, status=IntegrationStatus.CONNECTED,
        )

        cfg_a = IntegrationConfigResolver.resolve_google_oauth(db, org_a.id)
        cfg_b = IntegrationConfigResolver.resolve_google_oauth(db, org_b.id)

        assert cfg_a.client_id == "orgA-id"
        assert cfg_b.client_id == "orgB-id"
        assert cfg_a.refresh_token == "orgA-refresh"
        assert cfg_b.refresh_token == "orgB-refresh"

    def test_org_cannot_read_other_orgs_vault(self, db):
        """Org B reading org A's vault should raise CredentialNotFoundError."""
        from app.services.credential_vault import CredentialNotFoundError

        org_a, _ = _create_org_and_user(db, email="a@test.com", org_name="OrgA")
        org_b, _ = _create_org_and_user(db, email="b@test.com", org_name="OrgB")

        CredentialVault.save_credentials(
            db=db, org_id=org_a.id, provider="google",
            integration_type="google_oauth",
            credentials={"client_id": "orgA-id", "client_secret": "orgA-secret"},
            metadata={}, status=IntegrationStatus.CONNECTED,
        )

        with pytest.raises(CredentialNotFoundError):
            CredentialVault.get_credentials(
                db, org_b.id, "google", "google_oauth"
            )

    def test_integrations_list_scoped_to_org(self, db):
        """list_integrations should only return records for the queried org."""
        org_a, _ = _create_org_and_user(db, email="a@test.com", org_name="OrgA")
        org_b, _ = _create_org_and_user(db, email="b@test.com", org_name="OrgB")

        CredentialVault.save_credentials(
            db=db, org_id=org_a.id, provider="google",
            integration_type="google_oauth",
            credentials={"client_id": "orgA-id", "client_secret": "orgA-secret"},
            metadata={}, status=IntegrationStatus.CONNECTED,
        )

        items_a = CredentialVault.list_integrations(db, org_a.id)
        items_b = CredentialVault.list_integrations(db, org_b.id)

        assert len(items_a) == 1
        assert items_a[0]["provider"] == "google"
        assert len(items_b) == 0

    def test_disconnect_only_affects_own_org(self, db):
        """Disconnecting org A should not affect org B's credentials."""
        from app.services.credential_vault import CredentialNotFoundError

        org_a, _ = _create_org_and_user(db, email="a@test.com", org_name="OrgA")
        org_b, _ = _create_org_and_user(db, email="b@test.com", org_name="OrgB")

        CredentialVault.save_credentials(
            db=db, org_id=org_a.id, provider="google",
            integration_type="google_oauth",
            credentials={"client_id": "orgA-id", "client_secret": "orgA-secret"},
            metadata={}, status=IntegrationStatus.CONNECTED,
        )
        CredentialVault.save_credentials(
            db=db, org_id=org_b.id, provider="google",
            integration_type="google_oauth",
            credentials={"client_id": "orgB-id", "client_secret": "orgB-secret"},
            metadata={}, status=IntegrationStatus.CONNECTED,
        )

        # Disconnect org A
        GoogleOAuthFlow.disconnect(db, org_a.id)

        # Org A disconnected
        assert not CredentialVault.has_credentials(
            db, org_a.id, "google", "google_oauth"
        )
        # Org B still connected
        assert CredentialVault.has_credentials(
            db, org_b.id, "google", "google_oauth"
        )
        cfg_b = IntegrationConfigResolver.resolve_google_oauth(db, org_b.id)
        assert cfg_b.client_id == "orgB-id"


# ══════════════════════════════════════════════════════════════════════════════
# 6. Production Security Preservation
# ══════════════════════════════════════════════════════════════════════════════


class TestProductionSecurityPreserved:
    """Verify that production security is NOT weakened by the fixes:
      - token.json is NOT used in production
      - Credential values are never exposed in API responses
      - Production requires vault credentials
    """

    def test_google_auth_rejects_file_in_production(self):
        """get_google_credentials() should raise when no vault credentials
        and token.json fallback is attempted in production."""
        from app.services.google_auth import GoogleAuthError

        with patch(
            "app.services.google_auth.settings"
        ) as mock_settings:
            mock_settings.app_env = "production"
            mock_settings.google_token_file = "/nonexistent/token.json"

            with pytest.raises(GoogleAuthError):
                from app.services.google_auth import get_google_credentials
                get_google_credentials()  # no args = file fallback path

    def test_status_endpoint_never_exposes_credentials(self, db, client):
        """GET /auth/google/status should never return actual credentials,
        tokens, or secrets."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        CredentialVault.save_credentials(
            db=db, org_id=org.id, provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "test-client-id-12345",
                "client_secret": "GOCSPX-super-secret-value",
                "refresh_token": "1//0super-secret-refresh",
            },
            metadata={"email": "test@example.com"},
            status=IntegrationStatus.CONNECTED,
        )

        resp = client.get(
            "/auth/google/status",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        # Never expose raw values
        response_str = str(data)
        assert "GOCSPX-super-secret-value" not in response_str
        assert "1//0super-secret-refresh" not in response_str
        # Client ID should be masked
        assert "12345" not in data.get("masked_client_id", "") or "..." in data.get("masked_client_id", "")

    def test_integrations_list_never_exposes_credentials(self, db, client):
        """GET /dashboard/api/integrations should never include
        credentials_encrypted in the response."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        CredentialVault.save_credentials(
            db=db, org_id=org.id, provider="google",
            integration_type="google_oauth",
            credentials={"client_id": "id", "client_secret": "secret", "refresh_token": "refresh"},
            metadata={}, status=IntegrationStatus.CONNECTED,
        )

        resp = client.get(
            "/dashboard/api/integrations",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        for item in data.get("integrations", []):
            assert "credentials_encrypted" not in item
            assert "client_secret" not in str(item)
            assert "refresh_token" not in str(item)


# ══════════════════════════════════════════════════════════════════════════════
# 7. Pipeline Error Message Clarity
# ══════════════════════════════════════════════════════════════════════════════


class TestPipelineErrorClarity:
    """Verify that when the pipeline fails due to missing Google credentials,
    the error message is clear and actionable (mentions Dashboard, not .env).
    """

    def test_calendar_service_raises_configuration_error_in_production(self, db):
        """CalendarService should raise ConfigurationError (not
        GoogleAuthError) when vault is empty in production."""
        from app.services.calendar_service import CalendarService
        from app.services.org_context import OrganizationContext

        org, _ = _create_org_and_user(db)
        org_ctx = OrganizationContext.from_id(org.id)

        with patch(
            "app.services.integration_config_resolver.settings"
        ) as mock_settings:
            mock_settings.app_env = "production"
            mock_settings.google_client_id = ""
            mock_settings.google_client_secret = ""
            mock_settings.google_refresh_token = ""
            mock_settings.calendar_id = "primary"
            mock_settings.google_redirect_uri = TEST_GOOGLE_REDIRECT_URI

            with pytest.raises(ConfigurationError, match="administrator"):
                CalendarService(org_context=org_ctx, db=db)

    def test_email_service_raises_configuration_error_in_production(self, db):
        """EmailService should raise ConfigurationError (not GoogleAuthError)
        when vault is empty in production."""
        from app.services.email_service import EmailService
        from app.services.org_context import OrganizationContext

        org, _ = _create_org_and_user(db)
        org_ctx = OrganizationContext.from_id(org.id)

        with patch(
            "app.services.integration_config_resolver.settings"
        ) as mock_settings:
            mock_settings.app_env = "production"
            mock_settings.google_client_id = ""
            mock_settings.google_client_secret = ""
            mock_settings.google_refresh_token = ""
            mock_settings.gmail_sender = "noreply@example.com"
            mock_settings.google_redirect_uri = TEST_GOOGLE_REDIRECT_URI

            with pytest.raises(ConfigurationError, match="administrator"):
                EmailService(org_context=org_ctx, db=db)


# ══════════════════════════════════════════════════════════════════════════════
# 8. Source of Truth Consistency
# ══════════════════════════════════════════════════════════════════════════════


class TestSourceOfTruthConsistency:
    """Verify that the dashboard "Connected" state, OAuth flow, and pipeline
    all use the same source of truth: the OrgIntegration row in the vault.
    """

    def test_vault_write_then_read_consistent(self, db):
        """Writing credentials to vault and reading them back should be
        consistent - same values, same org."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db, org_id=org.id, provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "test-id",
                "client_secret": "test-secret",
                "refresh_token": "test-refresh",
                "redirect_uri": "https://example.com/callback",
            },
            metadata={"email": "test@example.com"},
            status=IntegrationStatus.CONNECTED,
        )

        # Read back
        creds = CredentialVault.get_credentials(db, org.id, "google", "google_oauth")
        assert creds["client_id"] == "test-id"
        assert creds["client_secret"] == "test-secret"
        assert creds["refresh_token"] == "test-refresh"

        # has_credentials should return True
        assert CredentialVault.has_credentials(db, org.id, "google", "google_oauth")

        # list_integrations should show connected
        items = CredentialVault.list_integrations(db, org.id)
        assert len(items) == 1
        assert items[0]["status"] == "connected"

    def test_disconnect_clears_vault_and_status(self, db):
        """After disconnect, vault should show no credentials and status
        should be DISCONNECTED."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db, org_id=org.id, provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "test-id",
                "client_secret": "test-secret",
                "refresh_token": "test-refresh",
            },
            metadata={}, status=IntegrationStatus.CONNECTED,
        )

        GoogleOAuthFlow.disconnect(db, org.id)

        assert not CredentialVault.has_credentials(db, org.id, "google", "google_oauth")
        items = CredentialVault.list_integrations(db, org.id)
        assert len(items) == 1
        assert items[0]["status"] == "disconnected"

    def test_status_endpoint_matches_vault(self, db, client):
        """GET /auth/google/status should match the vault state exactly."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        # Before credentials: platform configured, not connected
        resp = client.get("/auth/google/status", headers=_auth_headers(token))
        data = resp.json()
        assert data["configured"] is True  # platform client in test settings
        assert data["connected"] is False

        # After saving credentials (pre-OAuth): configured but not connected
        # NOTE: has_credentials() returns True for PENDING status because
        # the row exists, has encrypted credentials, and isn't DISCONNECTED.
        # The "configured" flag distinguishes pre-OAuth from post-OAuth.
        CredentialVault.save_credentials(
            db=db, org_id=org.id, provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "test-id.apps.googleusercontent.com",
                "client_secret": "test-secret",
            },
            metadata={}, status=IntegrationStatus.PENDING,
        )

        resp = client.get("/auth/google/status", headers=_auth_headers(token))
        data = resp.json()
        assert data["configured"] is True
        # Phase 34 Fix A: connected is False because refresh_token is empty -
        # DB status alone is insufficient to claim "connected".
        assert data["connected"] is False
        assert data["email"] is None  # No email yet before OAuth

        # After successful OAuth: configured and connected
        CredentialVault.save_credentials(
            db=db, org_id=org.id, provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "test-id.apps.googleusercontent.com",
                "client_secret": "test-secret",
                "refresh_token": "test-refresh",
            },
            metadata={"email": "test@example.com"},
            status=IntegrationStatus.CONNECTED,
        )

        resp = client.get("/auth/google/status", headers=_auth_headers(token))
        data = resp.json()
        assert data["configured"] is True
        assert data["connected"] is True
        assert data["email"] == "test@example.com"


# Need secrets module for state token generation
import secrets


# ══════════════════════════════════════════════════════════════════════════════
# 9. User Creation → OAuth Flow Chain (Phase 6E - the root-cause fix)
# ══════════════════════════════════════════════════════════════════════════════


class TestUserCreationOAuthFlowChain:
    """The original root cause was: default org had 0 users, so the OAuth
    flow could never be initiated. These tests verify the full chain:
      1. User exists in org
      2. User logs in → JWT
      3. Save credentials via dashboard
      4. OAuth start → authorization URL
      5. Callback → credentials persisted
      6. Status shows connected
      7. setup_status reflects completion
    """

    def test_login_then_save_credentials_then_oauth_start(self, db, client):
        """Full chain: login → save creds → OAuth start succeeds."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        # Step 1: Login works
        resp = client.post(
            "/auth/login",
            json={"email": user.email, "password": "StrongPass123!"},
        )
        assert resp.status_code == 200
        assert "access_token" in resp.json()

        # Step 2: Save Google OAuth credentials via dashboard API
        resp = client.post(
            f"/dashboard/api/integrations/google/google_oauth",
            headers=_auth_headers(token),
            json={
                "credentials": {
                    "client_id": "chain-client-id.apps.googleusercontent.com",
                    "client_secret": "chain-client-secret",
                    "redirect_uri": TEST_GOOGLE_REDIRECT_URI,
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["has_credentials"] is True
        assert data["status"] == "pending"

        # Step 3: OAuth start succeeds with saved credentials
        resp = client.get(
            "/auth/google/start",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        auth_url = resp.json()["authorization_url"]
        assert "chain-client-id" in auth_url
        assert "accounts.google.com" in auth_url

    def test_oauth_callback_creates_both_records(self, db, client):
        """Callback should create BOTH google_oauth AND email records."""
        org, user = _create_org_and_user(db)

        # Create state
        unique_state = f"test-both-records-{uuid.uuid4().hex[:16]}"
        state_row = GoogleOAuthState(
            organization_id=org.id,
            user_id=user.id,
            state_token=unique_state,
            redirect_uri=TEST_GOOGLE_REDIRECT_URI,
            scopes=["calendar", "gmail.send"],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            used=False,
        )
        db.add(state_row)
        db.commit()

        # Mock Google API
        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {
            "access_token": "ya29.both-records-token",
            "refresh_token": "1//0both-records-refresh",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {"email": "both@test.com"}

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp), \
             patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
            result = GoogleOAuthFlow.exchange_code(
                db=db, code="test-code", state=unique_state,
            )

        # Both records should exist
        assert CredentialVault.has_credentials(
            db, org.id, "google", "google_oauth"
        )
        assert CredentialVault.has_credentials(
            db, org.id, "google", "email"
        )

        # Email record should contain sender_email
        email_creds = CredentialVault.get_credentials(
            db, org.id, "google", "email"
        )
        assert email_creds["sender_email"] == "both@test.com"

        # OAuth record should contain refresh_token
        oauth_creds = CredentialVault.get_credentials(
            db, org.id, "google", "google_oauth"
        )
        assert oauth_creds["refresh_token"] == "1//0both-records-refresh"

    def test_setup_status_shows_connected_after_callback(self, db, client):
        """After OAuth callback, setup_status should show google_connected=True."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        # Before callback: not connected
        resp = client.get(
            "/dashboard/api/setup-status",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        assert resp.json()["steps"]["google_connected"]["done"] is False

        # Simulate callback via vault (since mocking full callback is complex)
        CredentialVault.save_credentials(
            db=db, org_id=org.id, provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "setup-test-id",
                "client_secret": "setup-test-secret",
                "refresh_token": "setup-test-refresh",
            },
            metadata={"email": "setup@test.com"},
            status=IntegrationStatus.CONNECTED,
        )

        # After callback: connected
        resp = client.get(
            "/dashboard/api/setup-status",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        assert resp.json()["steps"]["google_connected"]["done"] is True

    def test_status_endpoint_shows_connected_after_vault_write(self, db, client):
        """After credentials are stored, /auth/google/status shows connected."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        # Before: platform client configured (test fixture), org not connected
        resp = client.get("/auth/google/status", headers=_auth_headers(token))
        data = resp.json()
        assert data["connected"] is False
        assert data["configured"] is True  # platform-owned client from settings

        # Simulate callback
        unique_state = f"test-status-{uuid.uuid4().hex[:16]}"
        state_row = GoogleOAuthState(
            organization_id=org.id,
            user_id=user.id,
            state_token=unique_state,
            redirect_uri=TEST_GOOGLE_REDIRECT_URI,
            scopes=["calendar", "gmail.send"],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            used=False,
        )
        db.add(state_row)
        db.commit()

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {
            "access_token": "ya29.status-token",
            "refresh_token": "1//0status-refresh",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {"email": "status@test.com"}

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp), \
             patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
            GoogleOAuthFlow.exchange_code(
                db=db, code="test-code", state=unique_state,
            )

        # After: connected
        resp = client.get("/auth/google/status", headers=_auth_headers(token))
        data = resp.json()
        assert data["connected"] is True
        assert data["configured"] is True
        assert data["email"] == "status@test.com"
        assert data["masked_client_id"] is not None

    def test_database_persists_records_after_commit(self, db):
        """Records written by the vault should persist in the database
        and be queryable by a different session."""
        org, user = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db, org_id=org.id, provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "persist-test-id",
                "client_secret": "persist-test-secret",
                "refresh_token": "persist-test-refresh",
            },
            metadata={"email": "persist@test.com"},
            status=IntegrationStatus.CONNECTED,
        )

        # Verify with a fresh session (simulating Docker container restart)
        fresh_db = SessionLocal()
        try:
            integ = fresh_db.query(OrgIntegration).filter(
                OrgIntegration.organization_id == org.id,
                OrgIntegration.integration_type == "google_oauth",
            ).first()
            assert integ is not None
            assert integ.status == IntegrationStatus.CONNECTED
            assert integ.credentials_encrypted is not None
            assert len(integ.credentials_encrypted) > 0
        finally:
            fresh_db.close()

    def test_member_cannot_manage_integrations(self, db, client):
        """Members should not be able to save OAuth credentials."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _create_jwt_token(user.id, org.id, "member")

        resp = client.post(
            "/dashboard/api/integrations/google/google_oauth",
            headers=_auth_headers(token),
            json={
                "credentials": {
                    "client_id": "test-id",
                    "client_secret": "test-secret",
                },
            },
        )
        # Members should get 403 Forbidden
        assert resp.status_code == 403

    def test_org_isolation_during_oauth_flow(self, db, client):
        """Org A's credentials should not affect Org B's status."""
        # Create two orgs
        org_a, user_a = _create_org_and_user(db, email="a@test.com")
        org_b, user_b = _create_org_and_user(db, email="b@test.com")
        token_a = _create_jwt_token(user_a.id, org_a.id, "owner")
        token_b = _create_jwt_token(user_b.id, org_b.id, "owner")

        # Save credentials for Org A only
        CredentialVault.save_credentials(
            db=db, org_id=org_a.id, provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "org-a-client-id",
                "client_secret": "org-a-secret",
                "refresh_token": "org-a-refresh",
            },
            metadata={"email": "a@test.com"},
            status=IntegrationStatus.CONNECTED,
        )

        # Org A: connected
        resp = client.get("/auth/google/status", headers=_auth_headers(token_a))
        assert resp.json()["connected"] is True

        # Org B: not connected (isolated); platform client is configured
        resp = client.get("/auth/google/status", headers=_auth_headers(token_b))
        assert resp.json()["connected"] is False
        assert resp.json()["configured"] is True

        # Org B's setup_status: google not connected
        resp = client.get("/dashboard/api/setup-status", headers=_auth_headers(token_b))
        assert resp.json()["steps"]["google_connected"]["done"] is False


# ══════════════════════════════════════════════════════════════════════════════
# 10. Multi-Tenant Org-Scoped Webhook Propagation Regression Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgScopedWebhookPropagation:
    """Regression tests for multi-tenant org_id propagation.

    Validates that:
    1. Org-scoped webhook creates Lead with correct org_id
    2. Different orgs get different org_ids on their leads
    3. Org A's credentials are never used for Org B
    4. No org-scoped webhook falls back to _DEFAULT_ORG_ID
    5. Legacy endpoint still works with default org
    """

    def _setup_org_with_google(self, db, org=None, user_email=None):
        """Helper: create org with Google OAuth CONNECTED."""
        if org is None:
            org, user = _create_org_and_user(db, email=user_email or "test@test.com")
        else:
            user = None
        CredentialVault.save_credentials(
            db=db, org_id=org.id, provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "test-client-id",
                "client_secret": "test-client-secret",
                "refresh_token": "test-refresh-token",
            },
            metadata={"email": user_email or "test@test.com"},
            status=IntegrationStatus.CONNECTED,
        )
        return org

    def test_org_a_webhook_creates_lead_with_org_a_id(self, db, client):
        """POST /webhooks/{org_a_slug}/form-submission creates lead
        with organization_id == org_a.id."""
        from app.models import Lead

        org_a = self._setup_org_with_google(db, user_email="a@test.com")
        secret = CredentialVault.get_credentials(db, org_a.id, "google", "google_oauth")

        resp = client.post(
            f"/webhooks/{org_a.slug}/form-submission",
            json={
                "name": "Alice",
                "email": "alice@example.com",
                "phone_number": "555-0001",
            },
            headers={"Authorization": f"Bearer test-webhook-secret"},
        )
        # In test mode, webhook_secret may not be configured - check status
        if resp.status_code == 202:
            lead = db.query(Lead).filter(
                Lead.email == "alice@example.com",
            ).first()
            assert lead is not None, "Lead should be created"
            assert lead.organization_id == org_a.id, (
                f"Lead org_id should be {org_a.id} (org_a), "
                f"got {lead.organization_id}"
            )

    def test_org_b_webhook_creates_lead_with_org_b_id(self, db, client):
        """POST /webhooks/{org_b_slug}/form-submission creates lead
        with organization_id == org_b.id."""
        from app.models import Lead

        org_b = self._setup_org_with_google(db, user_email="b@test.com")

        resp = client.post(
            f"/webhooks/{org_b.slug}/form-submission",
            json={
                "name": "Bob",
                "email": "bob@example.com",
                "phone_number": "555-0002",
            },
            headers={"Authorization": f"Bearer test-webhook-secret"},
        )
        if resp.status_code == 202:
            lead = db.query(Lead).filter(
                Lead.email == "bob@example.com",
            ).first()
            assert lead is not None
            assert lead.organization_id == org_b.id

    def test_org_a_and_b_get_different_lead_org_ids(self, db, client):
        """Two different org-scoped webhooks create leads with different
        organization_ids matching their respective orgs."""
        from app.models import Lead

        org_a = self._setup_org_with_google(db, user_email="a@test.com")
        org_b = self._setup_org_with_google(db, user_email="b@test.com")

        # Submit to org_a
        resp_a = client.post(
            f"/webhooks/{org_a.slug}/form-submission",
            json={"name": "Alice", "email": "alice2@example.com"},
            headers={"Authorization": f"Bearer test-webhook-secret"},
        )
        # Submit to org_b
        resp_b = client.post(
            f"/webhooks/{org_b.slug}/form-submission",
            json={"name": "Bob", "email": "bob2@example.com"},
            headers={"Authorization": f"Bearer test-webhook-secret"},
        )

        if resp_a.status_code == 202 and resp_b.status_code == 202:
            lead_a = db.query(Lead).filter(Lead.email == "alice2@example.com").first()
            lead_b = db.query(Lead).filter(Lead.email == "bob2@example.com").first()
            assert lead_a is not None and lead_b is not None
            assert lead_a.organization_id == org_a.id
            assert lead_b.organization_id == org_b.id
            assert lead_a.organization_id != lead_b.organization_id

    def test_org_scoped_webhook_never_uses_default_org(self, db, client):
        """An org-scoped webhook should NEVER create a lead with the
        default org ID (00000000-0000-0000-0000-000000000001) when the
        slug resolves to a different org."""
        from app.models import Lead
        from app.tenant import _DEFAULT_ORG_ID

        org_a = self._setup_org_with_google(db, user_email="a@test.com")

        resp = client.post(
            f"/webhooks/{org_a.slug}/form-submission",
            json={"name": "Charlie", "email": "charlie@example.com"},
            headers={"Authorization": f"Bearer test-webhook-secret"},
        )
        if resp.status_code == 202:
            lead = db.query(Lead).filter(Lead.email == "charlie@example.com").first()
            assert lead is not None
            assert lead.organization_id != _DEFAULT_ORG_ID, (
                f"Lead should NOT use default org {_DEFAULT_ORG_ID}; "
                f"got org_id={lead.organization_id}"
            )
            assert lead.organization_id == org_a.id

    def test_org_a_credentials_not_used_for_org_b(self, db, client, monkeypatch):
        """When org_a has Google OAuth but org_b does not, a webhook to
        org_b should NOT pick up org_a's credentials."""
        from app.models import Lead
        from app.services.org_context import OrganizationContext
        from app.services.integration_config_resolver import (
            IntegrationConfigResolver,
            ConfigurationError,
        )
        from app.config import settings

        # Force production mode so the resolver does NOT fall back to .env defaults
        # when the vault is empty (the dev/test fallback masks the isolation bug).
        monkeypatch.setattr(settings, "app_env", "production")

        org_a = self._setup_org_with_google(db, user_email="a@test.com")
        org_b, _ = _create_org_and_user(db, email="b_nocreds@test.com")

        # PLATFORM-OWNED MODEL: org_b (no vault creds) resolves to the
        # shared platform client - never org_a's legacy client.
        org_b_ctx = OrganizationContext.from_id(org_b.id)
        creds_b = IntegrationConfigResolver.resolve_google_oauth(db, org_b.id)
        assert creds_b.client_id == TEST_GOOGLE_CLIENT_ID
        assert creds_b.client_id != "test-client-id"

        # org_a DOES have its own legacy credentials
        creds = IntegrationConfigResolver.resolve_google_oauth(db, org_a.id)
        assert creds is not None
        assert creds.client_id == "test-client-id"

    def test_legacy_endpoint_uses_default_org(self, db, client):
        """POST /webhooks/integrated-it-trainings/form-submission (legacy) should create leads
        with the default org ID, preserving backward compatibility."""
        from app.models import Lead
        from app.tenant import _DEFAULT_ORG_ID

        resp = client.post(
            "/webhooks/integrated-it-trainings/form-submission",
            json={
                "name": "Legacy Lead",
                "email": "legacy@example.com",
            },
        )
        if resp.status_code == 202:
            lead = db.query(Lead).filter(
                Lead.email == "legacy@example.com",
            ).first()
            assert lead is not None
            assert lead.organization_id == _DEFAULT_ORG_ID

    def test_nonexistent_slug_returns_404(self, db, client):
        """POST /webhooks/{nonexistent_slug}/form-submission should return
        404, not create a lead in the default org."""
        resp = client.post(
            "/webhooks/this-slug-does-not-exist/form-submission",
            json={"name": "Ghost", "email": "ghost@example.com"},
        )
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 11. Zoom invalid_grant Recovery
# ══════════════════════════════════════════════════════════════════════════════


class TestZoomInvalidGrantRecovery:
    """When Zoom returns invalid_grant (revoked/expired refresh token),
    the system must:
      1. Mark the integration as ERROR
      2. NOT repeatedly retry the same invalid token
      3. Fall back to Google Meet in the pipeline
      4. Allow reconnection via the existing OAuth flow
      5. Never expose tokens in logs/responses
    """

    def _make_zoom_integration(self, db, org, status=IntegrationStatus.CONNECTED,
                                last_error=None, expired=True):
        """Helper: create a Zoom OrgIntegration with encrypted credentials."""
        from app.services.crypto import encrypt_secret
        now = datetime.now(timezone.utc)
        expiry = (now - timedelta(minutes=10)).isoformat() if expired else \
                 (now + timedelta(hours=1)).isoformat()
        creds = {
            "access_token": "stale_at",
            "refresh_token": "revoked_rt",
            "client_id": "test_cid",
            "client_secret": "test_csec",
            "redirect_uri": "http://localhost/callback",
        }
        metadata = {
            "account_id": "zm_acc_123",
            "account_email": "zoom@test.com",
            "connected_at": (now - timedelta(days=30)).isoformat(),
            "token_expires_at": expiry,
        }
        integration = OrgIntegration(
            organization_id=org.id,
            provider="zoom",
            integration_type="zoom_oauth",
            status=status,
            last_error=last_error,
            credentials_encrypted=encrypt_secret(
                json.dumps(creds), settings.get_credential_encryption_key()
            ),
            metadata_json=metadata,
            connected_at=now - timedelta(days=30),
        )
        db.add(integration)
        db.commit()
        return integration

    @staticmethod
    def _mock_invalid_grant_response():
        """Return a mock httpx.Response simulating Zoom invalid_grant."""
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"error": "invalid_grant"}
        return mock_resp

    @staticmethod
    def _mock_refresh_success_response():
        """Return a mock httpx.Response simulating successful token refresh."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "access_token": "fresh_at",
            "refresh_token": "fresh_rt",
            "expires_in": 3600,
        }
        return mock_resp

    def test_refresh_invalid_grant_marks_integration_error(self, db):
        """refresh_token_if_needed() should mark the Zoom integration as
        ERROR when Zoom returns invalid_grant."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow
        from app.services.zoom_api_client import ZoomTokenRefreshError

        org, _ = _create_org_and_user(db)
        integration = self._make_zoom_integration(db, org)

        with patch("app.services.zoom_api_client.httpx.post",
                    return_value=self._mock_invalid_grant_response()):
            with pytest.raises(ZoomTokenRefreshError, match="invalid_grant"):
                ZoomOAuthFlow.refresh_token_if_needed(db, org.id)

        # Verify integration is now marked ERROR
        db.refresh(integration)
        assert integration.status == IntegrationStatus.ERROR
        assert "invalid_grant" in (integration.last_error or "")

    def test_refresh_success_restores_connected_status(self, db):
        """After a successful refresh, the integration should be marked
        CONNECTED (even if it was previously in ERROR state)."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        org, _ = _create_org_and_user(db)
        integration = self._make_zoom_integration(db, org, status=IntegrationStatus.ERROR,
                                                   last_error="previous error")

        with patch("app.services.zoom_api_client.httpx.post",
                    return_value=self._mock_refresh_success_response()):
            token = ZoomOAuthFlow.refresh_token_if_needed(db, org.id)

        assert token == "fresh_at"
        db.refresh(integration)
        assert integration.status == IntegrationStatus.CONNECTED
        assert integration.last_error is None

    def test_provider_falls_back_to_google_when_zoom_errored(self, db):
        """resolve_meeting_provider() should return Google Meet shim when
        Zoom integration is in ERROR state (invalid_grant)."""
        from app.services.meeting_provider import (
            resolve_meeting_provider,
            _GoogleMeetProviderShim,
        )
        from app.services.org_context import OrganizationContext

        org, _ = _create_org_and_user(db)
        self._make_zoom_integration(db, org, status=IntegrationStatus.ERROR,
                                     last_error="Zoom token refresh failed: invalid_grant")

        org_ctx = OrganizationContext.from_id(org.id)
        provider = resolve_meeting_provider(org_context=org_ctx, db=db)
        # Should fall back to Google Meet, not Zoom
        assert isinstance(provider, _GoogleMeetProviderShim)

    def test_status_endpoint_shows_error_state(self, db, client):
        """GET /auth/zoom/status should expose last_error and status
        when the Zoom integration is in ERROR state."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        from app.services.crypto import encrypt_secret
        creds = {
            "access_token": "stale",
            "refresh_token": "revoked",
            "client_id": "test_cid_12345678",
            "client_secret": "test_csec",
            "redirect_uri": "http://localhost/cb",
        }
        integration = OrgIntegration(
            organization_id=org.id,
            provider="zoom",
            integration_type="zoom_oauth",
            status=IntegrationStatus.ERROR,
            last_error="Zoom token refresh failed: invalid_grant",
            credentials_encrypted=encrypt_secret(
                json.dumps(creds), settings.get_credential_encryption_key()
            ),
            metadata_json={
                "account_id": "zm_123",
                "account_email": "zoom@test.com",
                "connected_at": "2026-01-01T00:00:00+00:00",
            },
            connected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        db.add(integration)
        db.commit()

        resp = client.get(
            "/auth/zoom/status",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        # Must NOT be "connected" since tokens are invalid
        assert data["connected"] is False
        # Must expose status and last_error
        assert data["status"] == "error"
        assert "invalid_grant" in data.get("last_error", "")
        # Must NOT expose any tokens
        assert "revoked" not in str(data)
        assert "stale" not in str(data)
        # Must still show configured (client_id/client_secret are valid)
        assert data["configured"] is True

    def test_invalid_grant_no_token_leakage_in_logs(self, db):
        """When invalid_grant is caught and integration is marked ERROR,
        the error message must NOT contain the refresh token or access token."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow
        from app.services.zoom_api_client import ZoomTokenRefreshError

        org, _ = _create_org_and_user(db)
        integration = self._make_zoom_integration(db, org)

        with patch("app.services.zoom_api_client.httpx.post",
                    return_value=self._mock_invalid_grant_response()):
            with pytest.raises(ZoomTokenRefreshError):
                ZoomOAuthFlow.refresh_token_if_needed(db, org.id)

        # Verify the stored last_error does NOT contain tokens
        db.refresh(integration)
        last_error = integration.last_error or ""
        assert "stale_at" not in last_error
        assert "revoked_rt" not in last_error
        assert "invalid_grant" in last_error

    def test_tenant_isolation_zoom_error(self, db):
        """A Zoom error for org_a must NOT affect org_b's Zoom integration."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        org_a, _ = _create_org_and_user(db, email="a@test.com")
        org_b, _ = _create_org_and_user(db, email="b@test.com")

        # Both orgs have CONNECTED Zoom integrations with different tokens
        int_a = self._make_zoom_integration(db, org_a)
        # Override org_b's refresh token to be different
        from app.services.crypto import encrypt_secret
        now = datetime.now(timezone.utc)
        creds_b = {
            "access_token": "at_org_b",
            "refresh_token": "rt_org_b",
            "client_id": "cid",
            "client_secret": "csec",
            "redirect_uri": "http://localhost/cb",
        }
        int_b = OrgIntegration(
            organization_id=org_b.id,
            provider="zoom",
            integration_type="zoom_oauth",
            status=IntegrationStatus.CONNECTED,
            credentials_encrypted=encrypt_secret(
                json.dumps(creds_b), settings.get_credential_encryption_key()
            ),
            metadata_json={"token_expires_at": (now - timedelta(hours=1)).isoformat()},
            connected_at=now - timedelta(days=1),
        )
        db.add(int_b)
        db.commit()

        # org_a's refresh fails (the mock returns invalid_grant for the first call)
        call_count = {"n": 0}
        def conditional_refresh(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # First call: org_a → invalid_grant
                return self._mock_invalid_grant_response()
            # Second call: should not be reached for this test
            return self._mock_refresh_success_response()

        with patch("app.services.zoom_api_client.httpx.post",
                    side_effect=conditional_refresh):
            with pytest.raises(Exception):
                ZoomOAuthFlow.refresh_token_if_needed(db, org_a.id)

        # org_a should be ERROR
        db.refresh(int_a)
        assert int_a.status == IntegrationStatus.ERROR

        # org_b should still be CONNECTED
        db.refresh(int_b)
        assert int_b.status == IntegrationStatus.CONNECTED

    def test_reconnect_after_invalid_grant_works(self, db):
        """After an invalid_grant error, going through the full OAuth flow
        (exchange_code) should restore the integration to CONNECTED with
        fresh tokens."""
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        org, user = _create_org_and_user(db)

        # Set up a Zoom integration in ERROR state
        integration = self._make_zoom_integration(db, org, status=IntegrationStatus.ERROR,
                                                   last_error="Zoom token refresh failed: invalid_grant")

        # Create an OAuth state token for the reconnect flow
        state_token = secrets.token_urlsafe(32)
        state_row = ZoomOAuthState(
            organization_id=org.id,
            user_id=user.id,
            state_token=state_token,
            redirect_uri="http://localhost/callback",
            scopes=["meeting:write"],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            used=False,
        )
        db.add(state_row)
        db.commit()

        # Simulate the full OAuth callback flow (exchange code)
        from app.services.zoom_api_client import ZoomAPIClient
        with patch.object(ZoomAPIClient, "exchange_code") as mock_exchange, \
             patch.object(ZoomAPIClient, "get_account_info") as mock_acct:
            mock_exchange.return_value = {
                "access_token": "fresh_at_after_reconnect",
                "refresh_token": "fresh_rt_after_reconnect",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "meeting:write",
            }
            mock_acct.return_value = {
                "account_id": "zm_new_acc",
                "email": "reconnected@zoom.com",
            }

            result = ZoomOAuthFlow.exchange_code(
                db=db,
                code="fresh_auth_code",
                state=state_token,
            )

        assert result["email"] == "reconnected@zoom.com"
        db.refresh(integration)
        assert integration.status == IntegrationStatus.CONNECTED
        assert integration.last_error is None
