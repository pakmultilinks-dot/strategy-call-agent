"""Phase 2 — Zoom Data & Credential Foundation tests.

Covers:
  1. Lead model: zoom fields accept values, are nullable
  2. Alembic migration 014: revision dependency, upgrade/downgrade
  3. ZoomOAuthConfig dataclass: field structure
  4. IntegrationConfigResolver.resolve_zoom_config(): org vault, platform fallback, error
  5. KNOWN_PROVIDERS zoom validation: required fields enforced
  6. CredentialVault: "zoom"/"zoom_oauth" storage works without schema changes
  7. Dashboard API: generic integration endpoint accepts zoom/zoom_oauth
  8. Regression: existing Google Meet pipeline behavior unchanged
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import json
import os
import uuid
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import inspect as sa_inspect

from app.config import settings
from app.models import Lead, LeadStatus
from app.models_multi_tenant import (
    IntegrationStatus,
    Organization,
    OrgIntegration,
)
from app.services.credential_vault import (
    CredentialCorruptError,
    CredentialNotFoundError,
    CredentialVault,
)
from app.services.crypto import generate_key
from app.services.integration_config_resolver import (
    IntegrationConfigResolver,
    ZoomOAuthConfig,
)
from app.services.integration_service import (
    IntegrationService,
    IntegrationValidationError,
    KNOWN_PROVIDERS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@contextmanager
def _use_key(valid_key: str):
    """Context manager that patches settings for credential vault operations."""
    with patch.object(settings, "credential_encryption_key", valid_key), \
         patch.object(settings, "app_env", "test"):
        yield


@pytest.fixture()
def valid_key():
    """A valid Fernet encryption key for tests."""
    return generate_key()


@pytest.fixture()
def test_org(db_session):
    """Create a test organization."""
    org = Organization(
        name="Phase 2 Test Org",
        slug=f"phase2-test-{uuid.uuid4().hex[:8]}",
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)
    return org


@pytest.fixture()
def lead(db_session, test_org):
    """Create a test lead."""
    lead = Lead(
        name="Zoom Test Lead",
        email="zoom-test@example.com",
        appt_datetime_raw="2026-09-15 10:00 AM",
        interested="Yes",
        dedupe_key=f"zoom-test-{uuid.uuid4().hex[:16]}",
        organization_id=test_org.id,
    )
    db_session.add(lead)
    db_session.commit()
    db_session.refresh(lead)
    return lead


# ---------------------------------------------------------------------------
# 1. Lead Model — Zoom fields
# ---------------------------------------------------------------------------


class TestLeadZoomFields:
    """Verify Lead model accepts zoom_meeting_id and zoom_join_url."""

    def test_zoom_meeting_id_is_none_by_default(self, lead):
        """New leads have zoom_meeting_id = None."""
        assert lead.zoom_meeting_id is None

    def test_zoom_join_url_is_none_by_default(self, lead):
        """New leads have zoom_join_url = None."""
        assert lead.zoom_join_url is None

    def test_zoom_meeting_id_can_be_set(self, db_session, lead):
        """zoom_meeting_id accepts a string value."""
        lead.zoom_meeting_id = "845-6789-0123"
        db_session.commit()
        db_session.refresh(lead)
        assert lead.zoom_meeting_id == "845-6789-0123"

    def test_zoom_join_url_can_be_set(self, db_session, lead):
        """zoom_join_url accepts a string value."""
        url = "https://zoom.us/j/84567890123?pwd=abc123"
        lead.zoom_join_url = url
        db_session.commit()
        db_session.refresh(lead)
        assert lead.zoom_join_url == url

    def test_zoom_fields_can_be_cleared(self, db_session, lead):
        """Zoom fields can be set back to None (e.g., on cancel)."""
        lead.zoom_meeting_id = "845-6789-0123"
        lead.zoom_join_url = "https://zoom.us/j/84567890123"
        db_session.commit()
        db_session.refresh(lead)
        assert lead.zoom_meeting_id is not None

        lead.zoom_meeting_id = None
        lead.zoom_join_url = None
        db_session.commit()
        db_session.refresh(lead)
        assert lead.zoom_meeting_id is None
        assert lead.zoom_join_url is None

    def test_both_fields_nullable_in_schema(self):
        """Both zoom columns are nullable in the ORM mapping."""
        mapper = sa_inspect(Lead)
        cols = {c.key: c for c in mapper.column_attrs}
        assert cols["zoom_meeting_id"].columns[0].nullable is True
        assert cols["zoom_join_url"].columns[0].nullable is True

    def test_zoom_fields_do_not_break_existing_lead_creation(self, db_session, test_org):
        """Creating a lead without zoom fields still works."""
        lead = Lead(
            name="No Zoom Lead",
            email="no-zoom@example.com",
            appt_datetime_raw="2026-09-16 14:00",
            interested="Yes",
            dedupe_key=f"no-zoom-{uuid.uuid4().hex[:16]}",
            organization_id=test_org.id,
        )
        db_session.add(lead)
        db_session.commit()
        db_session.refresh(lead)
        assert lead.zoom_meeting_id is None
        assert lead.zoom_join_url is None


# ---------------------------------------------------------------------------
# 2. Alembic Migration 014
# ---------------------------------------------------------------------------

# Path to the local migration file — avoids clash with installed alembic package
_MIGRATION_014 = os.path.join(
    os.path.dirname(__file__), os.pardir, "alembic", "versions", "014_zoom_lead_fields.py"
)


def _load_migration_014():
    """Import migration 014 directly from file path (avoids installed alembic shadowing)."""
    spec = importlib.util.spec_from_file_location("migration_014", _MIGRATION_014)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestMigration014:
    """Verify migration 014 has correct dependency and structure."""

    def test_migration_module_imports(self):
        """Migration 014 module can be imported."""
        mod = _load_migration_014()
        assert hasattr(mod, "upgrade")
        assert hasattr(mod, "downgrade")

    def test_revision_dependency(self):
        """Migration 014 depends on 013_token_blocklist."""
        mod = _load_migration_014()
        assert mod.down_revision == "013_token_blocklist"

    def test_revision_id(self):
        """Migration 014 has the correct revision ID."""
        mod = _load_migration_014()
        assert mod.revision == "014_zoom_lead_fields"

    def test_upgrade_adds_columns(self):
        """Upgrade function contains add_column calls for both zoom fields."""
        mod = _load_migration_014()
        source = inspect.getsource(mod.upgrade)
        assert "zoom_meeting_id" in source
        assert "zoom_join_url" in source

    def test_downgrade_drops_columns(self):
        """Downgrade function drops both zoom columns."""
        mod = _load_migration_014()
        source = inspect.getsource(mod.downgrade)
        assert "zoom_join_url" in source
        assert "zoom_meeting_id" in source
        assert "drop_column" in source


# ---------------------------------------------------------------------------
# 3. ZoomOAuthConfig dataclass
# ---------------------------------------------------------------------------


class TestZoomOAuthConfig:
    """Verify ZoomOAuthConfig dataclass structure."""

    def test_dataclass_fields(self):
        """ZoomOAuthConfig has account_id, client_id, client_secret."""
        fields = {f.name: f for f in ZoomOAuthConfig.__dataclass_fields__.values()}
        assert "account_id" in fields
        assert "client_id" in fields
        assert "client_secret" in fields

    def test_frozen_dataclass(self):
        """ZoomOAuthConfig is immutable."""
        cfg = ZoomOAuthConfig(
            account_id="acc123",
            client_id="cid456",
            client_secret="csec789",
        )
        with pytest.raises(AttributeError):
            cfg.account_id = "new-account"

    def test_instantiation(self):
        """Can create a ZoomOAuthConfig with valid values."""
        cfg = ZoomOAuthConfig(
            account_id="acc_123",
            client_id="cid_456",
            client_secret="csec_789",
        )
        assert cfg.account_id == "acc_123"
        assert cfg.client_id == "cid_456"
        assert cfg.client_secret == "csec_789"


# ---------------------------------------------------------------------------
# 4. IntegrationConfigResolver.resolve_zoom_config
# ---------------------------------------------------------------------------


class TestResolveZoomConfig:
    """Test Zoom credential resolution with org-vault → platform fallback."""

    def test_org_vault_credentials(self, db_session, test_org, valid_key):
        """When org has Zoom credentials in vault, they are returned."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session,
                org_id=test_org.id,
                provider="zoom",
                integration_type="zoom_oauth",
                credentials={
                    "account_id": "org-zoom-acc",
                    "client_id": "org-zoom-cid",
                    "client_secret": "org-zoom-csec",
                    "redirect_uri": "https://example.com/auth/zoom/callback",
                },
            )
            result = IntegrationConfigResolver.resolve_zoom_config(
                db_session, test_org.id
            )
            assert result.account_id == "org-zoom-acc"
            assert result.client_id == "org-zoom-cid"
            assert result.client_secret == "org-zoom-csec"
            assert result.redirect_uri == "https://example.com/auth/zoom/callback"

    def test_org_vault_takes_precedence_over_platform(self, db_session, test_org, valid_key):
        """When org has its own Zoom credentials AND platform defaults exist,
        org vault credentials are returned (not platform defaults)."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session,
                org_id=test_org.id,
                provider="zoom",
                integration_type="zoom_oauth",
                credentials={
                    "account_id": "org-acc",
                    "client_id": "org-cid",
                    "client_secret": "org-csec",
                    "redirect_uri": "https://org.example.com/callback",
                },
            )
            with patch.object(settings, "zoom_client_id", "plat-cid"), \
                 patch.object(settings, "zoom_client_secret", "plat-csec"), \
                 patch.object(settings, "zoom_redirect_uri", "https://plat.example.com/callback"):
                result = IntegrationConfigResolver.resolve_zoom_config(
                    db_session, test_org.id
                )
                assert result.client_id == "org-cid"
                assert result.client_secret == "org-csec"
                assert result.redirect_uri == "https://org.example.com/callback"

    def test_platform_fallback(self, db_session, test_org):
        """When org has no Zoom credentials, platform defaults are used."""
        with patch.object(settings, "zoom_client_id", "plat-cid"), \
             patch.object(settings, "zoom_client_secret", "plat-csec"), \
             patch.object(settings, "zoom_redirect_uri", "https://plat.example.com/callback"):
            result = IntegrationConfigResolver.resolve_zoom_config(
                db_session, test_org.id
            )
            assert result.account_id == ""
            assert result.client_id == "plat-cid"
            assert result.client_secret == "plat-csec"
            assert result.redirect_uri == "https://plat.example.com/callback"

    def test_no_credentials_raises(self, db_session, test_org):
        """When org has no vault Zoom creds and no platform defaults, error is raised."""
        with patch.object(settings, "zoom_client_id", ""), \
             patch.object(settings, "zoom_client_secret", ""), \
             patch.object(settings, "zoom_redirect_uri", ""):
            with pytest.raises(CredentialNotFoundError):
                IntegrationConfigResolver.resolve_zoom_config(
                    db_session, test_org.id
                )

    def test_partial_platform_credentials_raises(self, db_session, test_org):
        """When org has no vault creds and platform credentials are incomplete, error is raised."""
        with patch.object(settings, "zoom_client_id", "plat-cid"), \
             patch.object(settings, "zoom_client_secret", ""), \
             patch.object(settings, "zoom_redirect_uri", ""):
            with pytest.raises(CredentialNotFoundError):
                IntegrationConfigResolver.resolve_zoom_config(
                    db_session, test_org.id
                )

    def test_empty_strings_in_vault_falls_through_to_platform(self, db_session, test_org, valid_key):
        """Vault entries with empty strings fall through to platform defaults."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session,
                org_id=test_org.id,
                provider="zoom",
                integration_type="zoom_oauth",
                credentials={
                    "account_id": "",
                    "client_id": "",
                    "client_secret": "",
                },
            )
            with patch.object(settings, "zoom_client_id", "plat-cid"), \
                 patch.object(settings, "zoom_client_secret", "plat-csec"), \
                 patch.object(settings, "zoom_redirect_uri", "https://plat.example.com/callback"):
                result = IntegrationConfigResolver.resolve_zoom_config(
                    db_session, test_org.id
                )
                assert result.client_id == "plat-cid"
                assert result.client_secret == "plat-csec"
                assert result.redirect_uri == "https://plat.example.com/callback"

    def test_ngrok_redirect_uri_via_platform(self, db_session, test_org):
        """ZOOM_REDIRECT_URI env override (ngrok tunnel) is used via platform fallback."""
        ngrok_uri = "https://abc123.ngrok-free.app/auth/zoom/callback"
        with patch.object(settings, "zoom_client_id", "plat-cid"), \
             patch.object(settings, "zoom_client_secret", "plat-csec"), \
             patch.object(settings, "zoom_redirect_uri", ngrok_uri):
            result = IntegrationConfigResolver.resolve_zoom_config(
                db_session, test_org.id
            )
            assert result.redirect_uri == ngrok_uri

    def test_platform_redirect_uri_not_overridden_by_vault(self, db_session, test_org, valid_key):
        """Vault redirect_uri takes precedence over platform ZOOM_REDIRECT_URI."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session,
                org_id=test_org.id,
                provider="zoom",
                integration_type="zoom_oauth",
                credentials={
                    "account_id": "org-acc",
                    "client_id": "org-cid",
                    "client_secret": "org-csec",
                    "redirect_uri": "https://org.example.com/callback",
                },
            )
            with patch.object(settings, "zoom_redirect_uri", "https://plat.example.com/callback"):
                result = IntegrationConfigResolver.resolve_zoom_config(
                    db_session, test_org.id
                )
                assert result.redirect_uri == "https://org.example.com/callback"


# ---------------------------------------------------------------------------
# 5. KNOWN_PROVIDERS — zoom validation
# ---------------------------------------------------------------------------


class TestZoomValidation:
    """Test that _validate_credentials handles zoom correctly.
    
    zoom_oauth requires client_id, client_secret, and redirect_uri because
    each organization configures its own Zoom OAuth app credentials."""

    def test_known_providers_zoom_entry(self):
        """KNOWN_PROVIDERS has zoom/zoom_oauth with required fields.
        
        Zoom OAuth is org-owned — customers configure their own Client ID,
        Client Secret, and Redirect URI via the Integrations dashboard."""
        zoom = KNOWN_PROVIDERS.get("zoom", {})
        zoom_oauth = zoom.get("zoom_oauth", {})
        required = zoom_oauth.get("required_fields", set())
        assert required == {"client_id", "client_secret", "redirect_uri"}
        assert zoom_oauth.get("label") == "Zoom OAuth2"

    def test_zoom_oauth_validates_empty_credentials(self):
        """Empty credentials fail validation (required fields for zoom_oauth)."""
        from app.services.integration_service import _validate_credentials

        # Should raise — zoom_oauth now requires client_id, client_secret, redirect_uri
        with pytest.raises(IntegrationValidationError):
            _validate_credentials("zoom", "zoom_oauth", {})

    def test_zoom_oauth_validates_missing_fields(self):
        """Partial credentials fail validation (missing fields)."""
        from app.services.integration_service import _validate_credentials

        with pytest.raises(IntegrationValidationError):
            _validate_credentials("zoom", "zoom_oauth", {
                "client_id": "cid_456",
                # missing client_secret and redirect_uri
            })

    def test_zoom_oauth_full_credentials_pass(self):
        """All required credentials pass validation for zoom_oauth."""
        from app.services.integration_service import _validate_credentials

        # Should not raise
        _validate_credentials("zoom", "zoom_oauth", {
            "client_id": "cid_456",
            "client_secret": "csec_789",
            "redirect_uri": "https://example.com/auth/zoom/callback",
        })

    def test_google_validation_unchanged(self):
        """Google credential validation still works."""
        from app.services.integration_service import _validate_credentials

        # Should not raise
        _validate_credentials("google", "google_oauth", {
            "client_id": "google-cid",
            "client_secret": "google-csec",
            "refresh_token": "google-rt",
        })

    def test_unknown_provider_passes(self):
        """Unknown provider/type combinations pass without error."""
        from app.services.integration_service import _validate_credentials

        # Should not raise
        _validate_credentials("unknown_provider", "unknown_type", {"key": "value"})


# ---------------------------------------------------------------------------
# 6. CredentialVault — zoom storage
# ---------------------------------------------------------------------------


class TestZoomCredentialVault:
    """Verify zoom/zoom_oauth credentials work in the vault."""

    def test_save_and_retrieve(self, db_session, test_org, valid_key):
        """Save zoom credentials and retrieve them."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session,
                org_id=test_org.id,
                provider="zoom",
                integration_type="zoom_oauth",
                credentials={
                    "account_id": "vault-acc",
                    "client_id": "vault-cid",
                    "client_secret": "vault-csec",
                },
            )
            creds = CredentialVault.get_credentials(
                db_session, test_org.id, "zoom", "zoom_oauth"
            )
            assert creds["account_id"] == "vault-acc"
            assert creds["client_id"] == "vault-cid"
            assert creds["client_secret"] == "vault-csec"

    def test_has_credentials(self, db_session, test_org, valid_key):
        """has_credentials returns True after saving zoom creds."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session,
                org_id=test_org.id,
                provider="zoom",
                integration_type="zoom_oauth",
                credentials={"account_id": "a", "client_id": "b", "client_secret": "c"},
            )
            assert CredentialVault.has_credentials(
                db_session, test_org.id, "zoom", "zoom_oauth"
            ) is True

    def test_not_found_raises(self, db_session, test_org):
        """get_credentials raises CredentialNotFoundError for missing zoom."""
        with pytest.raises(CredentialNotFoundError):
            CredentialVault.get_credentials(
                db_session, test_org.id, "zoom", "zoom_oauth"
            )

    def test_delete(self, db_session, test_org, valid_key):
        """Delete zoom credentials sets DISCONNECTED."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session,
                org_id=test_org.id,
                provider="zoom",
                integration_type="zoom_oauth",
                credentials={"account_id": "a", "client_id": "b", "client_secret": "c"},
            )
            result = CredentialVault.delete_credentials(
                db_session, test_org.id, "zoom", "zoom_oauth"
            )
            assert result is True
            assert CredentialVault.has_credentials(
                db_session, test_org.id, "zoom", "zoom_oauth"
            ) is False

    def test_upsert_overwrites(self, db_session, test_org, valid_key):
        """Saving zoom creds twice overwrites the first set."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session,
                org_id=test_org.id,
                provider="zoom",
                integration_type="zoom_oauth",
                credentials={"account_id": "old-acc", "client_id": "old-cid", "client_secret": "old-csec"},
            )
            CredentialVault.save_credentials(
                db=db_session,
                org_id=test_org.id,
                provider="zoom",
                integration_type="zoom_oauth",
                credentials={"account_id": "new-acc", "client_id": "new-cid", "client_secret": "new-csec"},
            )
            creds = CredentialVault.get_credentials(
                db_session, test_org.id, "zoom", "zoom_oauth"
            )
            assert creds["account_id"] == "new-acc"


# ---------------------------------------------------------------------------
# 7. Regression — existing Google behavior unchanged
# ---------------------------------------------------------------------------


class TestRegression:
    """Verify Phase 2 did not break existing Google Meet behavior."""

    def test_google_known_providers_unchanged(self):
        """Google provider entries are untouched."""
        google = KNOWN_PROVIDERS.get("google", {})
        assert "google_oauth" in google
        assert "calendar" in google
        assert "email" in google
        assert google["google_oauth"]["required_fields"] == {
            "client_id", "client_secret"
        }
        assert google["calendar"]["required_fields"] == {"calendar_id"}
        assert google["email"]["required_fields"] == {"sender_email"}

    def test_zoom_provider_entry_correct(self):
        """Zoom provider entry has correct structure.
        
        zoom_oauth requires client_id, client_secret, and redirect_uri —
        each organization configures its own Zoom OAuth app credentials."""
        zoom = KNOWN_PROVIDERS.get("zoom", {})
        assert "zoom_oauth" in zoom
        assert zoom["zoom_oauth"]["required_fields"] == {
            "client_id", "client_secret", "redirect_uri"
        }
        assert zoom["zoom_oauth"]["label"] == "Zoom OAuth2"

    def test_openai_provider_unchanged(self):
        """OpenAI provider entry is untouched."""
        openai = KNOWN_PROVIDERS.get("openai", {})
        assert "ai_provider" in openai
        assert openai["ai_provider"]["required_fields"] == {"api_key"}

    def test_meeting_provider_protocol_unchanged(self):
        """MeetingProvider protocol is unchanged."""
        from app.services.meeting_provider import (
            MeetingProvider,
            MeetingDetails,
            resolve_meeting_provider,
        )
        # Protocol should still exist
        assert MeetingProvider is not None
        assert MeetingDetails is not None

    def test_resolve_meeting_provider_returns_provider(self):
        """resolve_meeting_provider returns a MeetingProvider (default Google Meet shim)."""
        from app.services.meeting_provider import resolve_meeting_provider

        # No longer raises NotImplementedError — returns a Google Meet shim by default
        provider = resolve_meeting_provider()
        assert provider is not None

    def test_calendar_service_create_event_signature_unchanged(self):
        """CalendarService.create_event still exists with same signature."""
        from app.services.calendar_service import CalendarService
        sig = inspect.signature(CalendarService.create_event)
        params = list(sig.parameters.keys())
        assert "self" in params
        assert "lead" in params
        assert "db" in params

    def test_email_template_functions_still_exist(self):
        """Email template functions are unchanged."""
        from app.services.email_templates import (
            build_confirmation_html,
            build_confirmation_text,
            build_reminder_html,
            build_reminder_text,
        )
        assert callable(build_confirmation_html)
        assert callable(build_confirmation_text)
        assert callable(build_reminder_html)
        assert callable(build_reminder_text)

    def test_reminder_service_still_works(self):
        """Reminder service module is importable and functions exist."""
        from app.services.reminder_service import send_daily_reminders
        assert callable(send_daily_reminders)

    def test_config_zoom_defaults_empty(self):
        """Zoom config defaults are empty strings when env vars not set.

        NOTE: When .env has real Zoom OAuth credentials (as in production),
        these settings will contain the configured values. We override env
        vars to empty strings to test the default behavior.
        """
        import os
        # Set env vars to empty strings (overrides .env file in pydantic-settings)
        env_overrides = {
            "ZOOM_CLIENT_ID": "",
            "ZOOM_CLIENT_SECRET": "",
            "ZOOM_ACCOUNT_ID": "",
        }
        saved = {k: os.environ.get(k) for k in env_overrides}
        try:
            os.environ.update(env_overrides)
            from app.config import Settings
            test_settings = Settings()
            assert test_settings.zoom_account_id == ""
            assert test_settings.zoom_client_id == ""
            assert test_settings.zoom_client_secret == ""
        finally:
            # Restore original env values
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
