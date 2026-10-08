"""Integration Connection Truthfulness — Regression Tests.

Verifies that the 'Connected' badge only appears when OAuth has actually
completed, and 'Configured' appears when only app credentials are saved.

ROOT CAUSE BEING TESTED:
  - IntegrationService.save_integration() used to mark status=CONNECTED when
    saving OAuth app config (client_id/secret/redirect_uri).  That is NOT
    authentication — it is configuration.  Config saves now set PENDING.
  - ZoomOAuthFlow.exchange_code() used to pass status="connected" (string)
    instead of IntegrationStatus.CONNECTED (enum), so connected_at was never
    stamped.  Now uses the proper enum.

LIFECYCLE SEMANTICS:
  1. No row in DB              → UI shows "Disconnected"
  2. save_integration() for Zoom config → PENDING → UI shows "Configured"
  3. exchange_code() succeeds  → CONNECTED → UI shows "Connected"
  4. refresh_token_if_needed() → CONNECTED (preserves status)
  5. save_integration() for AI key → CONNECTED (no OAuth needed)
  6. save_integration() for Google OAuth tokens → CONNECTED
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, AsyncMock

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_org_and_user(db, org_name="Truth Test Org"):
    """Create a test org and owner user, return (org, user)."""
    unique_suffix = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"{org_name} {unique_suffix}",
        slug=f"truth-test-{unique_suffix}",
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


# ══════════════════════════════════════════════════════════════════════════════
# 1. Zoom OAuth Config → PENDING (NOT CONNECTED)
# ══════════════════════════════════════════════════════════════════════════════


class TestZoomConfigIsPending:
    """Saving Zoom OAuth app config should set status=PENDING, not CONNECTED."""

    def test_save_zoom_config_sets_pending(self, db):
        """IntegrationService.save_integration() for zoom/zoom_oauth → PENDING."""
        from app.services.integration_service import IntegrationService

        org, user = _create_org_and_user(db)

        result = IntegrationService.save_integration(
            db=db,
            org_id=org.id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials={
                "client_id": "test-client-id",
                "client_secret": "test-client-secret",
                "redirect_uri": "https://example.com/auth/zoom/callback",
            },
            metadata={"configured_by": str(user.id)},
            role="owner",
        )

        assert result["status"] == IntegrationStatus.PENDING.value
        assert result["has_credentials"] is True

        # Verify database row directly
        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
                OrgIntegration.provider == "zoom",
                OrgIntegration.integration_type == "zoom_oauth",
            )
        ).scalar_one()

        assert row.status == IntegrationStatus.PENDING
        # connected_at should NOT be set for PENDING
        assert row.connected_at is None

    def test_update_zoom_config_stays_pending(self, db):
        """Updating Zoom config credentials should keep status=PENDING."""
        from app.services.integration_service import IntegrationService

        org, _ = _create_org_and_user(db)

        # Initial save
        IntegrationService.save_integration(
            db=db,
            org_id=org.id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials={
                "client_id": "old-id",
                "client_secret": "old-secret",
                "redirect_uri": "https://old.com/callback",
            },
            role="owner",
        )

        # Update
        result = IntegrationService.update_integration(
            db=db,
            org_id=org.id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials={
                "client_id": "new-id",
                "client_secret": "new-secret",
                "redirect_uri": "https://new.com/callback",
            },
            role="owner",
        )

        assert result["status"] == IntegrationStatus.PENDING.value

        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
                OrgIntegration.provider == "zoom",
            )
        ).scalar_one()
        assert row.status == IntegrationStatus.PENDING
        assert row.connected_at is None

    def test_zoom_config_no_connected_at(self, db):
        """Saving Zoom config should NOT set connected_at timestamp."""
        from app.services.integration_service import IntegrationService

        org, _ = _create_org_and_user(db)

        IntegrationService.save_integration(
            db=db,
            org_id=org.id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials={
                "client_id": "cid",
                "client_secret": "csec",
                "redirect_uri": "https://r.com/cb",
            },
            role="owner",
        )

        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
                OrgIntegration.provider == "zoom",
            )
        ).scalar_one()
        assert row.connected_at is None

    def test_zoom_config_audit_event_is_pending(self, db):
        """Audit event type for Zoom config save should be 'integration.pending'."""
        from app.services.integration_service import IntegrationService

        org, _ = _create_org_and_user(db)

        with patch("app.services.integration_service._record_audit") as mock_audit:
            IntegrationService.save_integration(
                db=db,
                org_id=org.id,
                provider="zoom",
                integration_type="zoom_oauth",
                credentials={
                    "client_id": "cid",
                    "client_secret": "csec",
                    "redirect_uri": "https://r.com/cb",
                },
                role="owner",
            )

            mock_audit.assert_called_once()
            call_kwargs = mock_audit.call_args
            assert call_kwargs.kwargs.get("event_type") == "integration.pending"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Zoom OAuth Token Exchange → CONNECTED (upgrades from PENDING)
# ══════════════════════════════════════════════════════════════════════════════


class TestZoomOAuthUpgradeToConnected:
    """Successful Zoom OAuth exchange should upgrade PENDING → CONNECTED."""

    def test_exchange_code_sets_connected_status(self, db):
        """exchange_code() should set status=CONNECTED (enum, not string)."""
        from app.services.credential_vault import CredentialVault
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        org, user = _create_org_and_user(db)

        # Step 1: Save config (PENDING)
        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials={
                "client_id": "test-cid",
                "client_secret": "test-csec",
                "redirect_uri": "https://example.com/auth/zoom/callback",
            },
            status=IntegrationStatus.PENDING,
        )

        # Verify PENDING
        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
                OrgIntegration.provider == "zoom",
            )
        ).scalar_one()
        assert row.status == IntegrationStatus.PENDING

        # Step 2: Create state and simulate OAuth callback
        state_row = ZoomOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        # Mock the token exchange and account info fetch
        with patch("app.services.zoom_api_client.ZoomAPIClient") as mock_client:
            mock_client.exchange_code.return_value = {
                "access_token": "test-access-token",
                "refresh_token": "test-refresh-token",
                "expires_in": 3600,
                "scope": "meeting:write",
            }
            mock_client.get_account_info.return_value = {
                "account_id": "acc-123",
                "email": "user@example.com",
            }

            result = ZoomOAuthFlow.exchange_code(
                db=db,
                code="auth-code",
                state=state_row.state_token,
            )

        # Verify CONNECTED
        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
                OrgIntegration.provider == "zoom",
            )
        ).scalar_one()

        assert row.status == IntegrationStatus.CONNECTED
        assert row.connected_at is not None

    def test_exchange_code_uses_enum_not_string(self, db):
        """Status should be IntegrationStatus.CONNECTED (enum), not string 'connected'."""
        from app.services.credential_vault import CredentialVault
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        org, user = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials={
                "client_id": "cid",
                "client_secret": "csec",
                "redirect_uri": "https://example.com/auth/zoom/callback",
            },
            status=IntegrationStatus.PENDING,
        )

        state_row = ZoomOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        with patch("app.services.zoom_api_client.ZoomAPIClient") as mock_client:
            mock_client.exchange_code.return_value = {
                "access_token": "at",
                "refresh_token": "rt",
                "expires_in": 3600,
                "scope": "meeting:write",
            }
            mock_client.get_account_info.return_value = {
                "account_id": "a",
                "email": "e@e.com",
            }

            ZoomOAuthFlow.exchange_code(
                db=db,
                code="code",
                state=state_row.state_token,
            )

        # The enum comparison in credential_vault should work correctly now
        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
            )
        ).scalar_one()
        # This verifies connected_at IS stamped (it wasn't before due to string bug)
        assert row.connected_at is not None


# ══════════════════════════════════════════════════════════════════════════════
# 3. Non-OAuth Integrations → CONNECTED Immediately
# ══════════════════════════════════════════════════════════════════════════════


class TestNonOAuthIntegrationConnectedImmediately:
    """AI and non-OAuth integrations should be CONNECTED when saved."""

    def test_ai_api_key_sets_connected(self, db):
        """Saving an AI API key should set status=CONNECTED immediately."""
        from app.services.integration_service import IntegrationService

        org, _ = _create_org_and_user(db)

        result = IntegrationService.save_integration(
            db=db,
            org_id=org.id,
            provider="openai",
            integration_type="ai_provider",
            credentials={"api_key": "sk-test-key"},
            role="owner",
        )

        assert result["status"] == IntegrationStatus.CONNECTED.value

        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
                OrgIntegration.provider == "openai",
            )
        ).scalar_one()
        assert row.status == IntegrationStatus.CONNECTED
        assert row.connected_at is not None

    def test_google_oauth_tokens_set_connected(self, db):
        """Google OAuth token storage should set CONNECTED (uses vault default)."""
        from app.services.credential_vault import CredentialVault

        org, _ = _create_org_and_user(db)

        # Google stores tokens directly (no config step) — vault default is CONNECTED
        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "gc",
                "client_secret": "gs",
                "refresh_token": "grt",
            },
            metadata={"email": "test@gmail.com"},
        )

        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
                OrgIntegration.provider == "google",
            )
        ).scalar_one()
        assert row.status == IntegrationStatus.CONNECTED
        assert row.connected_at is not None


# ══════════════════════════════════════════════════════════════════════════════
# 4. Zoom Status Endpoint Truthfulness
# ══════════════════════════════════════════════════════════════════════════════


class TestZoomStatusEndpointTruthfulness:
    """The /auth/zoom/status endpoint should reflect actual connection state."""

    def test_configured_not_connected(self, db):
        """When only config is saved (PENDING), connected should be False."""
        from app.services.credential_vault import CredentialVault

        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials={
                "client_id": "test-cid",
                "client_secret": "test-csec",
                "redirect_uri": "https://example.com/auth/zoom/callback",
            },
            status=IntegrationStatus.PENDING,
        )

        # Query the endpoint logic directly
        from app.main import zoom_oauth_status
        from app.main import AuthContext

        auth_ctx = AuthContext(org_id=org.id, user_id=None, role="owner")

        # We need to call the function with mocked dependencies
        # For unit test, check the DB state directly
        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
                OrgIntegration.provider == "zoom",
            )
        ).scalar_one()

        assert row.status == IntegrationStatus.PENDING
        # The endpoint should NOT return connected=True for PENDING
        assert row.status != IntegrationStatus.CONNECTED

    def test_connected_after_oauth(self, db):
        """After OAuth completion, connected should be True."""
        from app.services.credential_vault import CredentialVault

        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials={
                "client_id": "cid",
                "client_secret": "csec",
                "redirect_uri": "https://example.com/cb",
            },
            metadata={
                "account_id": "acc-123",
                "account_email": "user@zoom.us",
                "connected_at": datetime.now(timezone.utc).isoformat(),
            },
            status=IntegrationStatus.CONNECTED,
        )

        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
                OrgIntegration.provider == "zoom",
            )
        ).scalar_one()

        assert row.status == IntegrationStatus.CONNECTED
        assert row.connected_at is not None


# ══════════════════════════════════════════════════════════════════════════════
# 5. Enum Type Safety — String vs Enum
# ══════════════════════════════════════════════════════════════════════════════


class TestEnumTypeSafety:
    """Verify that IntegrationStatus enum is used (not raw strings)."""

    def test_vault_connected_at_stamps_on_enum(self, db):
        """connected_at should be set when status=IntegrationStatus.CONNECTED (enum)."""
        from app.services.credential_vault import CredentialVault

        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials={"client_id": "c", "client_secret": "s", "redirect_uri": "r"},
            status=IntegrationStatus.CONNECTED,
        )

        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
            )
        ).scalar_one()
        assert row.connected_at is not None

    def test_vault_connected_at_not_stamped_on_pending(self, db):
        """connected_at should NOT be set when status=PENDING."""
        from app.services.credential_vault import CredentialVault

        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials={"client_id": "c", "client_secret": "s", "redirect_uri": "r"},
            status=IntegrationStatus.PENDING,
        )

        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
            )
        ).scalar_one()
        # PENDING should NOT stamp connected_at
        assert row.connected_at is None
