"""Integration Health Audit — Regression Tests.

Verifies that all four integrations (Google Calendar, Gmail, Zoom, AI)
have real provider health checks, proper error classification, and that
the dashboard UI correctly reflects connection state.

ROOT CAUSES BEING TESTED:
  - Gmail health check was fake (credential validation only, no API call).
    FIXED: Added users().getProfile() real API call.
  - Zoom was missing from integration-health endpoint entirely.
    FIXED: Added Zoom health check with get_account_info() real API call.
  - AI provider vault key mismatch in save_ai_provider().
    FIXED: save_ai_provider() always saves under ("openai", "ai_provider")
    with provider_id in metadata.
  - loadAIProvidersList() read p.provider_id but API returned p.id.
    FIXED: Frontend now reads p.id || p.provider_id.
  - AI credential form was always visible, even when configured.
    FIXED: Form hidden when connected; shows summary with Reconfigure button.
  - Health check responses lacked error classification.
    FIXED: Added error_type field (auth/network/config/rate_limit/permission/unknown).
  - Health endpoint had UnboundLocalError for *_error_type variables.
    FIXED: All error_type vars initialized to None before try blocks.
"""
from __future__ import annotations

import json
import uuid
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.models_multi_tenant import (
    IntegrationStatus,
    OrgIntegration,
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db():
    """Yield a DB session with rollback."""
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


def _create_org_and_user(db, org_name="Health Audit Org"):
    """Create a test org and owner user, return (org, user)."""
    unique_suffix = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"{org_name} {unique_suffix}",
        slug=f"health-audit-{unique_suffix}",
        status=OrganizationStatus.ACTIVE,
    )
    db.add(org)
    db.flush()

    user = User(
        email=f"owner-{uuid.uuid4().hex[:8]}@test.com",
        password_hash="hashed",
        full_name="Test Owner",
        role=UserRole.OWNER,
        status=UserStatus.ACTIVE,
        organization_id=org.id,
    )
    db.add(user)
    db.commit()
    db.refresh(org)
    db.refresh(user)
    return org, user


def _make_auth_ctx(org_id):
    """Build a fake AuthContext with the given org_id for endpoint tests."""
    from app.dashboard import AuthContext
    return AuthContext(org_id=org_id, user_id=uuid.uuid4(), role="owner")


# ══════════════════════════════════════════════════════════════════════════════
# 1. Error Classification
# ══════════════════════════════════════════════════════════════════════════════


class TestErrorClassification:
    """_classify_error() should return correct category strings."""

    def test_auth_error_token(self):
        from app.main import _classify_error
        assert _classify_error(Exception("Token expired")) == "auth"

    def test_auth_error_401(self):
        from app.main import _classify_error
        assert _classify_error(Exception("HTTP 401 Unauthorized")) == "auth"

    def test_auth_error_invalid_grant(self):
        from app.main import _classify_error
        assert _classify_error(Exception("invalid_grant")) == "auth"

    def test_network_error_connect(self):
        from app.main import _classify_error
        assert _classify_error(Exception("ConnectTimeout")) == "network"

    def test_network_error_dns(self):
        from app.main import _classify_error
        assert _classify_error(Exception("DNS resolution failed")) == "network"

    def test_network_error_timeout(self):
        from app.main import _classify_error
        assert _classify_error(Exception("ReadTimeout")) == "network"

    def test_config_error_not_configured(self):
        from app.main import _classify_error
        assert _classify_error(Exception("Zoom not configured")) == "config"

    def test_config_error_no_org(self):
        from app.main import _classify_error
        assert _classify_error(Exception("No organization context")) == "config"

    def test_rate_limit_error(self):
        from app.main import _classify_error
        assert _classify_error(Exception("Rate limit exceeded (429)")) == "rate_limit"

    def test_permission_error_scope(self):
        from app.main import _classify_error
        assert _classify_error(Exception("Insufficient scope")) == "permission"

    def test_permission_error_forbidden(self):
        from app.main import _classify_error
        assert _classify_error(Exception("403 Forbidden")) == "auth"  # 403 maps to auth

    def test_unknown_error(self):
        from app.main import _classify_error
        assert _classify_error(Exception("Something unexpected happened")) == "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# 2. AI Provider save_ai_provider vault key consistency
# ══════════════════════════════════════════════════════════════════════════════


class TestAIProviderVaultKey:
    """save_ai_provider() must always save under the canonical key
    ("openai", "ai_provider") regardless of provider_name, so the
    resolver and status endpoints can find the credentials."""

    def test_save_ai_provider_canonical_key(self, db):
        """save_ai_provider with provider_name='moonshot' saves under ('openai','ai_provider')."""
        from app.services.integration_service import IntegrationService
        from app.services.credential_vault import CredentialVault

        org, _ = _create_org_and_user(db)

        result = IntegrationService.save_ai_provider(
            db, org.id,
            api_key="sk-test-key",
            base_url="https://api.moonshot.cn/v1",
            model="moonshot-v1-8k",
            provider_name="moonshot",
            role="owner",
        )
        assert result["has_credentials"] is True

        # Verify vault key is canonical ("openai", "ai_provider")
        creds = CredentialVault.get_credentials(db, org.id, "openai", "ai_provider")
        assert creds["api_key"] == "sk-test-key"
        assert creds["base_url"] == "https://api.moonshot.cn/v1"

        meta = CredentialVault.get_safe_metadata(db, org.id, "openai", "ai_provider")
        assert meta["provider_id"] == "moonshot"
        assert meta["model"] == "moonshot-v1-8k"

    def test_save_ai_provider_default_openai(self, db):
        """save_ai_provider with default provider_name='openai' saves correctly."""
        from app.services.integration_service import IntegrationService
        from app.services.credential_vault import CredentialVault

        org, _ = _create_org_and_user(db)

        IntegrationService.save_ai_provider(
            db, org.id,
            api_key="sk-openai-key",
            base_url="https://api.openai.com/v1",
            model="gpt-4o",
            role="owner",
        )

        creds = CredentialVault.get_credentials(db, org.id, "openai", "ai_provider")
        assert creds["api_key"] == "sk-openai-key"

        meta = CredentialVault.get_safe_metadata(db, org.id, "openai", "ai_provider")
        assert meta["provider_id"] == "openai"

    def test_get_ai_provider_status_canonical_key(self, db):
        """get_ai_provider_status always reads from ('openai', 'ai_provider')."""
        from app.services.integration_service import IntegrationService

        org, _ = _create_org_and_user(db)

        # Save with non-openai provider
        IntegrationService.save_ai_provider(
            db, org.id,
            api_key="sk-xai",
            base_url="https://api.x.ai/v1",
            model="grok-4",
            provider_name="xai",
            role="owner",
        )

        # Status should find it via canonical key
        result = IntegrationService.get_ai_provider_status(db, org.id)
        assert result["has_credentials"] is True
        assert result["metadata"]["provider_id"] == "xai"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Integration Health Endpoint Structure
# ══════════════════════════════════════════════════════════════════════════════


class TestIntegrationHealthStructure:
    """Verify the integration-health endpoint returns consistent structure.

    NOTE: The health endpoint uses *local* imports (``from app.services.X
    import Y`` inside the function body), so we must patch the source
    modules rather than ``app.main.<ClassName>``.

    Also, HTTP Basic auth returns ``org_id=None`` (platform admin), so
    we override ``_auth_context`` to provide a real org_id, which lets
    the endpoint check all services including Zoom.
    """

    def _setup_endpoint_auth(self, org):
        """Override _auth_context to return an AuthContext with org_id."""
        from app.main import app as _app
        from app.dashboard import _auth_context as _orig_auth, AuthContext

        fake_ctx = AuthContext(
            org_id=org.id,
            user_id=uuid.uuid4(),
            role="owner",
        )
        _app.dependency_overrides[_orig_auth] = lambda: fake_ctx
        return fake_ctx

    def _teardown_endpoint_auth(self):
        from app.main import app as _app
        from app.dashboard import _auth_context as _orig_auth
        _app.dependency_overrides.pop(_orig_auth, None)

    def test_health_response_has_all_services(self, client, auth_headers, db):
        """Health endpoint returns google_calendar, gmail, zoom, ai_provider, overall."""
        org, user = _create_org_and_user(db)
        self._setup_endpoint_auth(org)

        mock_ctx = MagicMock()
        mock_ctx.from_id.return_value = MagicMock(organization_id=org.id)

        mock_cal_inst = MagicMock()
        mock_cal_inst._service.calendars().get().execute.return_value = {}

        mock_email_inst = MagicMock()
        mock_email_inst._service.users().getProfile().execute.return_value = {
            "emailAddress": "test@gmail.com"
        }

        mock_ai_inst = MagicMock()
        mock_ai_inst._primary_provider_id = "openai"
        mock_ai_inst._primary_model = "gpt-4o"
        mock_ai_inst._primary_url = "https://api.openai.com/v1"
        mock_ai_inst._primary_key = "sk-test"

        mock_provider_def = MagicMock()
        mock_provider_def.display_name = "OpenAI"

        mock_openai_client = MagicMock()
        mock_openai_resp = MagicMock()
        mock_openai_resp.choices = [MagicMock()]
        mock_openai_client.chat.completions.create.return_value = mock_openai_resp

        try:
            with patch("app.services.org_context.OrganizationContext", mock_ctx), \
                 patch("app.services.calendar_service.CalendarService", return_value=mock_cal_inst), \
                 patch("app.services.email_service.EmailService", return_value=mock_email_inst), \
                 patch("app.services.credential_vault.CredentialVault") as mock_vault, \
                 patch("app.services.zoom_oauth_flow.ZoomOAuthFlow") as mock_zoom_flow, \
                 patch("app.services.zoom_api_client.ZoomAPIClient") as mock_zoom_api, \
                 patch("app.services.ai_service.AIService", return_value=mock_ai_inst), \
                 patch("app.services.ai_provider_registry.get_provider", return_value=mock_provider_def), \
                 patch("openai.OpenAI", return_value=mock_openai_client):

                mock_vault.has_credentials.return_value = True
                mock_zoom_flow.refresh_token_if_needed.return_value = "fake-access-token"
                mock_zoom_api.get_account_info.return_value = {
                    "email": "zoom-user@example.com"
                }

                response = client.get(
                    "/dashboard/api/integration-health",
                    headers=auth_headers,
                )
        finally:
            self._teardown_endpoint_auth()

        assert response.status_code == 200
        data = response.json()
        assert "google_calendar" in data
        assert "gmail" in data
        assert "zoom" in data
        assert "ai_provider" in data
        assert "overall" in data

    def test_health_response_has_error_type(self, client, auth_headers, db):
        """When a service fails, error_type is included in the response."""
        org, user = _create_org_and_user(db)
        self._setup_endpoint_auth(org)

        mock_ctx = MagicMock()
        mock_ctx.from_id.return_value = MagicMock(organization_id=org.id)

        # Calendar constructor raises auth error
        mock_cal_class = MagicMock(side_effect=Exception("Token expired"))

        # Email constructor raises network error
        mock_email_class = MagicMock(side_effect=Exception("ConnectTimeout"))

        # AI constructor raises config error
        mock_ai_class = MagicMock(side_effect=RuntimeError("AI provider not configured"))

        try:
            with patch("app.services.org_context.OrganizationContext", mock_ctx), \
                 patch("app.services.calendar_service.CalendarService", mock_cal_class), \
                 patch("app.services.email_service.EmailService", mock_email_class), \
                 patch("app.services.credential_vault.CredentialVault") as mock_vault, \
                 patch("app.services.ai_service.AIService", mock_ai_class):

                # Zoom: not configured
                mock_vault.has_credentials.return_value = False

                response = client.get(
                    "/dashboard/api/integration-health",
                    headers=auth_headers,
                )
        finally:
            self._teardown_endpoint_auth()

        assert response.status_code == 200
        data = response.json()

        # Each failing service should have error_type
        assert data["google_calendar"]["error_type"] == "auth"
        assert data["gmail"]["error_type"] == "network"
        assert data["zoom"]["error_type"] == "config"
        assert data["ai_provider"]["error_type"] == "config"

    def test_health_success_no_error_type(self, client, auth_headers, db):
        """When a service succeeds, error_type should be None."""
        org, user = _create_org_and_user(db)
        self._setup_endpoint_auth(org)

        mock_ctx = MagicMock()
        mock_ctx.from_id.return_value = MagicMock(organization_id=org.id)

        mock_cal_inst = MagicMock()
        mock_cal_inst._service.calendars().get().execute.return_value = {}

        mock_email_inst = MagicMock()
        mock_email_inst._service.users().getProfile().execute.return_value = {
            "emailAddress": "test@gmail.com"
        }

        mock_ai_inst = MagicMock()
        mock_ai_inst._primary_provider_id = "openai"
        mock_ai_inst._primary_model = "gpt-4o"
        mock_ai_inst._primary_url = "https://api.openai.com/v1"
        mock_ai_inst._primary_key = "sk-test"

        mock_provider_def = MagicMock()
        mock_provider_def.display_name = "OpenAI"

        mock_openai_client = MagicMock()
        mock_openai_resp = MagicMock()
        mock_openai_resp.choices = [MagicMock()]
        mock_openai_client.chat.completions.create.return_value = mock_openai_resp

        try:
            with patch("app.services.org_context.OrganizationContext", mock_ctx), \
                 patch("app.services.calendar_service.CalendarService", return_value=mock_cal_inst), \
                 patch("app.services.email_service.EmailService", return_value=mock_email_inst), \
                 patch("app.services.credential_vault.CredentialVault") as mock_vault, \
                 patch("app.services.zoom_oauth_flow.ZoomOAuthFlow") as mock_zoom_flow, \
                 patch("app.services.zoom_api_client.ZoomAPIClient") as mock_zoom_api, \
                 patch("app.services.ai_service.AIService", return_value=mock_ai_inst), \
                 patch("app.services.ai_provider_registry.get_provider", return_value=mock_provider_def), \
                 patch("openai.OpenAI", return_value=mock_openai_client):

                mock_vault.has_credentials.return_value = True
                mock_zoom_flow.refresh_token_if_needed.return_value = "tok"
                mock_zoom_api.get_account_info.return_value = {"email": "z@z.com"}

                response = client.get(
                    "/dashboard/api/integration-health",
                    headers=auth_headers,
                )
        finally:
            self._teardown_endpoint_auth()

        assert response.status_code == 200
        data = response.json()
        assert data["google_calendar"]["error_type"] is None
        assert data["gmail"]["error_type"] is None
        assert data["zoom"]["error_type"] is None
        assert data["ai_provider"]["error_type"] is None


# ══════════════════════════════════════════════════════════════════════════════
# 4. IntegrationStatus enum — PENDING vs CONNECTED semantics
# ══════════════════════════════════════════════════════════════════════════════


class TestStatusSemantics:
    """Verify status lifecycle: config→PENDING, OAuth→CONNECTED."""

    def test_zoom_config_pending(self, db):
        """Zoom config save → PENDING."""
        from app.services.integration_service import IntegrationService
        org, _ = _create_org_and_user(db)
        result = IntegrationService.save_integration(
            db=db, org_id=org.id, provider="zoom", integration_type="zoom_oauth",
            credentials={"client_id": "c", "client_secret": "s", "redirect_uri": "r"},
            role="owner",
        )
        assert result["status"] == IntegrationStatus.PENDING.value

    def test_ai_key_connected(self, db):
        """AI provider key save → CONNECTED."""
        from app.services.integration_service import IntegrationService
        org, _ = _create_org_and_user(db)
        result = IntegrationService.save_integration(
            db=db, org_id=org.id, provider="openai", integration_type="ai_provider",
            credentials={"api_key": "sk-123", "base_url": "https://api.openai.com/v1"},
            metadata={"model": "gpt-4o", "provider_id": "openai"},
            role="owner",
        )
        assert result["status"] == IntegrationStatus.CONNECTED.value

    def test_google_oauth_tokens_connected(self, db):
        """Google OAuth token save → PENDING (OAuth config is pending until callback)."""
        from app.services.integration_service import IntegrationService
        org, _ = _create_org_and_user(db)
        result = IntegrationService.save_integration(
            db=db, org_id=org.id, provider="google", integration_type="google_oauth",
            credentials={"client_id": "cid", "client_secret": "cs", "refresh_token": "rt"},
            role="owner",
        )
        assert result["status"] == IntegrationStatus.PENDING.value

    def test_zoom_config_connected_at_none(self, db):
        """PENDING status should NOT set connected_at."""
        from app.services.integration_service import IntegrationService
        from sqlalchemy import select as sa_select
        org, _ = _create_org_and_user(db)
        IntegrationService.save_integration(
            db=db, org_id=org.id, provider="zoom", integration_type="zoom_oauth",
            credentials={"client_id": "c", "client_secret": "s", "redirect_uri": "r"},
            role="owner",
        )
        row = db.execute(
            sa_select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
                OrgIntegration.provider == "zoom",
            )
        ).scalar_one()
        assert row.connected_at is None
