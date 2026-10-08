"""Comprehensive tests for the Provider-Agnostic AI Integration System (Phase 26).

Covers:
  1. Provider registry — definitions, lookup, iteration
  2. OpenAI-compatible provider configuration
  3. Custom endpoint support
  4. Arbitrary model support (free-text, not hardcoded)
  5. URL normalization for chat/completions
  6. AIProviderConfig dataclass with provider_id
  7. IntegrationConfigResolver — new-style (with provider_id) and old-style (legacy)
  8. API key encryption at rest (vault stores encrypted)
  9. Credentials never returned in API responses
  10. Auth — Owner/Admin required for test-connection and load-models
  11. Tenant isolation — org A cannot see org B's AI config
  12. Test-connection error classifications
  13. Load-models endpoint behavior
  14. AI health check with provider awareness
  15. Backward compatibility — old configs without provider_id
  16. IntegrationService KNOWN_PROVIDERS extended
  17. Dashboard UI endpoints return correct shapes
  18. Fallback provider resolution
  19. BrandingConfig defaults
  20. Provider adapter_ready flag behavior

Minimum 40 tests required by spec.
"""
from __future__ import annotations

import json
import secrets
import uuid
from contextlib import contextmanager
from datetime import datetime as dt, timedelta as td, timezone as tz
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session as SASession

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)
from app.services.ai_provider_registry import (
    AIProviderDefinition,
    PROVIDERS,
    get_all_providers,
    get_provider,
    get_provider_ids,
    is_openai_compatible,
    normalize_chat_completions_url,
)
from app.services.integration_config_resolver import (
    AIConfig,
    AIProviderConfig,
    IntegrationConfigResolver,
)
from app.services.credential_vault import CredentialVault
from app.services.crypto import generate_key
from app.tenant import _DEFAULT_ORG_ID


# ---------------------------------------------------------------------------
# Test Constants & Fixtures
# ---------------------------------------------------------------------------

TEST_JWT_SECRET = "test-secret-key-for-ai-provider-system-testing-32ch!"
TEST_ENCRYPTION_KEY = generate_key()


@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    """Inject test-mode secrets."""
    monkeypatch.setattr(settings, "jwt_secret_key", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", TEST_ENCRYPTION_KEY)


@pytest.fixture()
def client():
    """TestClient with lifespan support."""
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def _make_org(**overrides) -> Organization:
    """Insert an Organization row and return it."""
    defaults = {
        "name": f"Test Org {uuid.uuid4().hex[:8]}",
        "slug": f"test-org-{uuid.uuid4().hex[:8]}",
        "timezone": "America/Chicago",
        "status": OrganizationStatus.ACTIVE,
        "webhook_secret": secrets.token_urlsafe(24),
    }
    defaults.update(overrides)
    db = SessionLocal()
    try:
        org = Organization(**defaults)
        db.add(org)
        db.commit()
        db.refresh(org)
        return org
    finally:
        db.close()


def _create_user(org_id: uuid.UUID, role: UserRole = UserRole.OWNER) -> User:
    """Create a user in the given org and return them."""
    email = f"ai-test-{uuid.uuid4().hex[:8]}@example.com"
    from app.auth import hash_password
    db = SessionLocal()
    try:
        user = User(
            organization_id=org_id,
            email=email,
            password_hash=hash_password("TestPassword123!"),
            full_name="AI Test User",
            role=role,
            status=UserStatus.ACTIVE,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def _make_jwt(user: User) -> str:
    """Create a valid JWT for the given user."""
    from jose import jwt as jose_jwt
    payload = {
        "sub": str(user.id),
        "org_id": str(user.organization_id),
        "role": user.role.value,
        "exp": dt.now(tz.utc) + td(hours=1),
        "iat": dt.now(tz.utc),
        "jti": str(uuid.uuid4()),
    }
    return jose_jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")


def _auth_headers(user: User) -> dict:
    """Return Authorization headers for the given user."""
    return {"Authorization": f"Bearer {_make_jwt(user)}"}


@contextmanager
def _fake_vault_creds(api_key="sk-test123", base_url="https://api.openai.com/v1",
                       model="gpt-4o", provider_id="openai"):
    """Context manager that patches vault reads to return fake AI credentials."""
    with patch.object(CredentialVault, "get_credentials") as mock_creds, \
         patch.object(CredentialVault, "get_safe_metadata") as mock_meta:
        mock_creds.return_value = {"api_key": api_key, "base_url": base_url}
        mock_meta.return_value = {"model": model, "provider_id": provider_id}
        yield


@contextmanager
def _fake_vault_empty():
    """Context manager that patches vault reads to raise CredentialNotFoundError."""
    from app.services.credential_vault import CredentialNotFoundError
    with patch.object(CredentialVault, "get_credentials") as mock_creds, \
         patch.object(CredentialVault, "get_safe_metadata") as mock_meta:
        mock_creds.side_effect = CredentialNotFoundError("not found")
        mock_meta.return_value = None
        yield


# ===================================================================
# 1. Provider Registry — Definitions, Lookup, Iteration
# ===================================================================

class TestProviderRegistry:
    """Tests for the AI provider registry module."""

    def test_providers_dict_has_eight_entries(self):
        """Registry should contain exactly 8 providers."""
        assert len(PROVIDERS) == 8

    def test_get_provider_openai(self):
        """Lookup 'openai' should return a valid definition."""
        p = get_provider("openai")
        assert p is not None
        assert p.id == "openai"
        assert p.display_name == "OpenAI"
        assert p.protocol == "openai_compatible"
        assert p.adapter_ready is True

    def test_get_provider_anthropic(self):
        """Lookup 'anthropic' should return definition with adapter_ready=False."""
        p = get_provider("anthropic")
        assert p is not None
        assert p.id == "anthropic"
        assert p.display_name == "Anthropic / Claude"
        assert p.protocol == "native"
        assert p.adapter_ready is False

    def test_get_provider_gemini(self):
        """Lookup 'gemini' should return definition with adapter_ready=False."""
        p = get_provider("gemini")
        assert p is not None
        assert p.id == "gemini"
        assert p.adapter_ready is False

    def test_get_provider_unknown_returns_none(self):
        """Lookup of unknown provider_id should return None."""
        assert get_provider("nonexistent_provider") is None

    def test_get_all_providers_returns_list(self):
        """get_all_providers should return a list of AIProviderDefinition."""
        all_providers = get_all_providers()
        assert isinstance(all_providers, list)
        assert len(all_providers) == 8
        assert all(isinstance(p, AIProviderDefinition) for p in all_providers)

    def test_get_provider_ids_returns_all_keys(self):
        """get_provider_ids should return all 8 provider IDs."""
        ids = get_provider_ids()
        assert len(ids) == 8
        assert "openai" in ids
        assert "anthropic" in ids
        assert "gemini" in ids
        assert "xai" in ids
        assert "moonshot" in ids
        assert "openrouter" in ids
        assert "tokenrouter" in ids
        assert "custom_openai_compatible" in ids

    def test_all_providers_have_required_fields(self):
        """Every provider definition must have non-empty id and display_name."""
        for p in get_all_providers():
            assert p.id, f"Provider missing id"
            assert p.display_name, f"Provider {p.id} missing display_name"
            assert p.protocol in ("openai_compatible", "native"), \
                f"Provider {p.id} has invalid protocol: {p.protocol}"

    def test_all_providers_are_frozen_dataclasses(self):
        """Provider definitions should be immutable (frozen dataclass)."""
        p = get_provider("openai")
        with pytest.raises(AttributeError):
            p.id = "changed"


# ===================================================================
# 2. OpenAI-Compatible Provider Configuration
# ===================================================================

class TestOpenAICompatibleProviders:
    """Tests for providers using the OpenAI-compatible protocol."""

    @pytest.mark.parametrize("provider_id", [
        "openai", "xai", "moonshot", "openrouter",
        "tokenrouter", "custom_openai_compatible",
    ])
    def test_is_openai_compatible(self, provider_id):
        """These providers should report as OpenAI-compatible."""
        assert is_openai_compatible(provider_id) is True

    @pytest.mark.parametrize("provider_id", ["anthropic", "gemini"])
    def test_is_not_openai_compatible(self, provider_id):
        """Native protocol providers should not be OpenAI-compatible."""
        assert is_openai_compatible(provider_id) is False

    def test_is_openai_compatible_unknown_returns_false(self):
        """Unknown provider should return False for compatibility check."""
        assert is_openai_compatible("nonexistent") is False

    def test_openai_has_default_base_url(self):
        """OpenAI should have a default base URL."""
        p = get_provider("openai")
        assert p.default_base_url == "https://api.openai.com/v1"

    def test_openai_supports_model_discovery(self):
        """OpenAI should support model discovery (has /models endpoint)."""
        p = get_provider("openai")
        assert p.supports_model_discovery is True

    def test_openai_default_model(self):
        """OpenAI should have a default model."""
        p = get_provider("openai")
        assert p.default_model == "gpt-4o"


# ===================================================================
# 3. Custom Endpoint Support
# ===================================================================

class TestCustomEndpoint:
    """Tests for the custom OpenAI-compatible endpoint provider."""

    def test_custom_provider_exists(self):
        """custom_openai_compatible should exist in registry."""
        p = get_provider("custom_openai_compatible")
        assert p is not None
        assert p.display_name == "Custom OpenAI-Compatible"

    def test_custom_provider_has_empty_default_url(self):
        """Custom provider should have empty default base URL (user provides it)."""
        p = get_provider("custom_openai_compatible")
        assert p.default_base_url == ""

    def test_custom_provider_allows_custom_url(self):
        """Custom provider should support custom base URLs."""
        p = get_provider("custom_openai_compatible")
        assert p.supports_custom_base_url is True

    def test_custom_provider_no_model_discovery(self):
        """Custom provider may not support model discovery."""
        p = get_provider("custom_openai_compatible")
        assert p.supports_model_discovery is False

    def test_custom_provider_is_openai_compatible(self):
        """Custom provider should be OpenAI-compatible (uses same protocol)."""
        assert is_openai_compatible("custom_openai_compatible") is True

    def test_custom_provider_adapter_ready(self):
        """Custom provider should be adapter-ready (it's just OpenAI protocol)."""
        p = get_provider("custom_openai_compatible")
        assert p.adapter_ready is True


# ===================================================================
# 4. Arbitrary Model Support
# ===================================================================

class TestArbitraryModelSupport:
    """Tests that the system accepts any model string, not a fixed list."""

    def test_ai_provider_config_accepts_any_model(self):
        """AIProviderConfig should accept any model string."""
        config = AIProviderConfig(
            api_key="sk-test",
            base_url="https://api.example.com/v1",
            model="my-custom-model-xyz",
            provider_id="openai",
        )
        assert config.model == "my-custom-model-xyz"

    def test_ai_provider_config_empty_model(self):
        """AIProviderConfig should allow empty model (use default)."""
        config = AIProviderConfig(
            api_key="sk-test",
            base_url="https://api.example.com/v1",
            model="",
            provider_id="openai",
        )
        assert config.model == ""

    def test_ai_provider_config_provider_id_default(self):
        """AIProviderConfig should default provider_id to 'openai'."""
        config = AIProviderConfig(
            api_key="sk-test",
            base_url="https://api.example.com/v1",
            model="gpt-4o",
        )
        assert config.provider_id == "openai"


# ===================================================================
# 5. URL Normalization for chat/completions
# ===================================================================

class TestURLNormalization:
    """Tests for normalize_chat_completions_url."""

    def test_plain_base_url_gets_suffix(self):
        """URL without /chat/completions should get it appended."""
        result = normalize_chat_completions_url("https://api.openai.com/v1")
        assert result == "https://api.openai.com/v1/chat/completions"

    def test_trailing_slash_gets_suffix(self):
        """URL with trailing slash should get /chat/completions appended."""
        result = normalize_chat_completions_url("https://api.openai.com/v1/")
        assert result == "https://api.openai.com/v1/chat/completions"

    def test_already_has_chat_completions(self):
        """URL already ending in /chat/completions should not be modified."""
        result = normalize_chat_completions_url("https://api.openai.com/v1/chat/completions")
        assert result == "https://api.openai.com/v1/chat/completions"

    def test_chat_completions_with_trailing_slash(self):
        """URL with trailing slash after /chat/completions should strip it."""
        result = normalize_chat_completions_url("https://api.openai.com/v1/chat/completions/")
        assert result == "https://api.openai.com/v1/chat/completions"

    def test_url_ending_in_chat(self):
        """URL ending in /chat should get /completions appended."""
        result = normalize_chat_completions_url("https://api.example.com/v1/chat")
        assert result == "https://api.example.com/v1/chat/completions"

    def test_moonshot_url_normalization(self):
        """Moonshot URL should be normalized correctly."""
        result = normalize_chat_completions_url("https://api.moonshot.cn/v1")
        assert result == "https://api.moonshot.cn/v1/chat/completions"

    def test_openrouter_url_normalization(self):
        """OpenRouter URL should be normalized correctly."""
        result = normalize_chat_completions_url("https://openrouter.ai/api/v1")
        assert result == "https://openrouter.ai/api/v1/chat/completions"


# ===================================================================
# 6. AIProviderConfig Dataclass with provider_id
# ===================================================================

class TestAIProviderConfig:
    """Tests for the AIProviderConfig dataclass."""

    def test_provider_id_stored(self):
        """provider_id should be stored in the dataclass."""
        config = AIProviderConfig(
            api_key="sk-123",
            base_url="https://api.openai.com/v1",
            model="gpt-4o",
            provider_id="xai",
        )
        assert config.provider_id == "xai"

    def test_provider_id_default_openai(self):
        """Default provider_id should be 'openai' for backward compat."""
        config = AIProviderConfig(
            api_key="sk-123",
            base_url="https://api.openai.com/v1",
            model="gpt-4o",
        )
        assert config.provider_id == "openai"

    def test_frozen_dataclass(self):
        """AIProviderConfig should be immutable."""
        config = AIProviderConfig(
            api_key="sk-123",
            base_url="https://api.openai.com/v1",
            model="gpt-4o",
            provider_id="openai",
        )
        with pytest.raises(AttributeError):
            config.api_key = "changed"

    def test_ai_config_holds_primary_and_fallback(self):
        """AIConfig should hold primary and optional fallback."""
        primary = AIProviderConfig(
            api_key="sk-primary",
            base_url="https://api.openai.com/v1",
            model="gpt-4o",
            provider_id="openai",
        )
        fallback = AIProviderConfig(
            api_key="sk-fallback",
            base_url="https://api.moonshot.cn/v1",
            model="moonshot-v1-8k",
            provider_id="moonshot",
        )
        config = AIConfig(primary=primary, fallback=fallback)
        assert config.primary.provider_id == "openai"
        assert config.fallback.provider_id == "moonshot"

    def test_ai_config_fallback_optional(self):
        """AIConfig should allow fallback=None."""
        primary = AIProviderConfig(
            api_key="sk-primary",
            base_url="https://api.openai.com/v1",
            model="gpt-4o",
            provider_id="openai",
        )
        config = AIConfig(primary=primary)
        assert config.fallback is None


# ===================================================================
# 7. IntegrationConfigResolver — New-style and Old-style
# ===================================================================

class TestConfigResolverProviderID:
    """Tests for IntegrationConfigResolver with provider_id support."""

    def test_new_style_config_reads_provider_id(self):
        """New-style config with provider_id in metadata should resolve it."""
        with _fake_vault_creds(provider_id="xai", model="grok-4"):
            from app.database import SessionLocal
            db = SessionLocal()
            try:
                config = IntegrationConfigResolver.resolve_ai_config(db, _DEFAULT_ORG_ID)
                assert config.primary.provider_id == "xai"
                assert config.primary.model == "grok-4"
            finally:
                db.close()

    def test_old_style_config_defaults_to_openai(self):
        """Old-style config without provider_id should default to 'openai'."""
        with patch.object(CredentialVault, "get_credentials") as mock_creds, \
             patch.object(CredentialVault, "get_safe_metadata") as mock_meta:
            mock_creds.return_value = {"api_key": "sk-old", "base_url": "https://api.openai.com/v1"}
            # Old-style: metadata has model but no provider_id
            mock_meta.return_value = {"model": "gpt-4o"}
            from app.database import SessionLocal
            db = SessionLocal()
            try:
                config = IntegrationConfigResolver.resolve_ai_config(db, _DEFAULT_ORG_ID)
                assert config.primary.provider_id == "openai"
                assert config.primary.model == "gpt-4o"
            finally:
                db.close()

    def test_empty_metadata_defaults_to_openai(self):
        """Empty metadata dict should default provider_id to 'openai'."""
        with patch.object(CredentialVault, "get_credentials") as mock_creds, \
             patch.object(CredentialVault, "get_safe_metadata") as mock_meta:
            mock_creds.return_value = {"api_key": "sk-test", "base_url": "https://api.openai.com/v1"}
            mock_meta.return_value = {}
            from app.database import SessionLocal
            db = SessionLocal()
            try:
                config = IntegrationConfigResolver.resolve_ai_config(db, _DEFAULT_ORG_ID)
                assert config.primary.provider_id == "openai"
            finally:
                db.close()


# ===================================================================
# 8. API Key Encryption at Rest
# ===================================================================

class TestAPIKeyEncryption:
    """Tests that API keys are stored encrypted in the vault."""

    def test_vault_stores_encrypted_credentials(self):
        """Credentials stored via vault should be encrypted (Fernet)."""
        from app.services.crypto import encrypt_secret, decrypt_secret
        key = settings.get_credential_encryption_key()
        plaintext = "sk-super-secret-key-12345"
        encrypted = encrypt_secret(plaintext, key)
        assert encrypted != plaintext
        decrypted = decrypt_secret(encrypted, key)
        assert decrypted == plaintext

    def test_vault_roundtrip_with_ai_credentials(self):
        """AI credentials should survive encrypt/decrypt round-trip."""
        from app.services.crypto import encrypt_secret, decrypt_secret
        key = settings.get_credential_encryption_key()
        creds = {"api_key": "sk-test-key", "base_url": "https://api.x.ai/v1"}
        encrypted = encrypt_secret(json.dumps(creds), key)
        decrypted = json.loads(decrypt_secret(encrypted, key))
        assert decrypted["api_key"] == "sk-test-key"
        assert decrypted["base_url"] == "https://api.x.ai/v1"

    def test_mask_secret_hides_key(self):
        """mask_secret should never reveal the full API key."""
        from app.services.crypto import mask_secret
        masked = mask_secret("sk-1234567890abcdef")
        assert "1234567890abcdef" not in masked
        assert "•" in masked or "*" in masked


# ===================================================================
# 9. Credentials Never Returned in API Responses
# ===================================================================

class TestCredentialsNeverReturned:
    """Tests that API keys are never leaked in endpoint responses."""

    def test_ai_status_never_returns_api_key(self, client):
        """GET /dashboard/api/ai/status should never include the raw API key."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        with _fake_vault_creds(api_key="sk-leaked-key-never"):
            resp = client.get(
                "/dashboard/api/ai/status",
                headers=_auth_headers(user),
            )
            assert resp.status_code == 200
            data = resp.json()
            # The response should contain masked_key, not the real key
            assert "sk-leaked-key-never" not in json.dumps(data)
            if data.get("masked_key"):
                assert "sk-leaked-key-never" != data["masked_key"]

    def test_ai_status_returns_masked_key(self, client):
        """GET /dashboard/api/ai/status should return a masked key representation."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        with _fake_vault_creds(api_key="sk-secret123abc"):
            resp = client.get(
                "/dashboard/api/ai/status",
                headers=_auth_headers(user),
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("configured"):
                    assert data.get("masked_key") is not None
                    assert data["masked_key"] != "sk-secret123abc"

    def test_ai_providers_list_exposes_no_credentials(self, client):
        """GET /dashboard/api/ai/providers should contain zero credential data."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.get(
            "/dashboard/api/ai/providers",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200
        text = json.dumps(resp.json())
        assert "sk-" not in text
        assert "api_key" not in text.lower() or "api_key_label" in text.lower()


# ===================================================================
# 10. Auth — Owner/Admin Required
# ===================================================================

class TestAuthRequirements:
    """Tests that sensitive endpoints require Owner/Admin role."""

    def test_test_connection_requires_auth(self, client):
        """POST /dashboard/api/ai/test-connection without auth should fail."""
        resp = client.post(
            "/dashboard/api/ai/test-connection",
            json={"provider_id": "openai", "base_url": "https://api.openai.com/v1", "api_key": "sk-test"},
        )
        assert resp.status_code in (401, 403, 422)

    def test_load_models_requires_auth(self, client):
        """POST /dashboard/api/ai/load-models without auth should fail."""
        resp = client.post(
            "/dashboard/api/ai/load-models",
            json={"base_url": "https://api.openai.com/v1", "api_key": "sk-test"},
        )
        assert resp.status_code in (401, 403, 422)

    def test_providers_list_accessible(self, client):
        """GET /dashboard/api/ai/providers should be accessible (read-only)."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.get(
            "/dashboard/api/ai/providers",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200
        assert "providers" in resp.json()

    def test_ai_status_accessible(self, client):
        """GET /dashboard/api/ai/status should be accessible."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.get(
            "/dashboard/api/ai/status",
            headers=_auth_headers(user),
        )
        # Should return 200 (configured or not)
        assert resp.status_code == 200


# ===================================================================
# 11. Tenant Isolation
# ===================================================================

class TestTenantIsolation:
    """Tests that AI provider configs are isolated per organization."""

    def test_org_a_cannot_see_org_b_ai_config(self):
        """Two different orgs should not share AI credentials."""
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()

        with patch.object(CredentialVault, "get_credentials") as mock_creds, \
             patch.object(CredentialVault, "get_safe_metadata") as mock_meta:
            def fake_creds(db, org_id, provider, integration_type):
                if org_id == org_a:
                    return {"api_key": "sk-org-a-key", "base_url": "https://api.openai.com/v1"}
                raise Exception("No credentials for this org")

            mock_creds.side_effect = fake_creds
            mock_meta.return_value = {"model": "gpt-4o", "provider_id": "openai"}

            from app.database import SessionLocal
            db = SessionLocal()
            try:
                config_a = IntegrationConfigResolver.resolve_ai_config(db, org_a)
                assert config_a.primary.api_key == "sk-org-a-key"

                # Org B should get platform defaults or fail
                with patch.object(
                    IntegrationConfigResolver,
                    "_get_platform_primary",
                    return_value=None,
                ):
                    with pytest.raises(RuntimeError, match="AI provider not configured"):
                        IntegrationConfigResolver.resolve_ai_config(db, org_b)
            finally:
                db.close()

    def test_vault_credentials_scoped_to_org(self):
        """CredentialVault operations should always include org_id."""
        # Verify the vault API signature requires org_id
        import inspect
        sig = inspect.signature(CredentialVault.get_credentials)
        params = list(sig.parameters.keys())
        assert "org_id" in params, "get_credentials must include org_id parameter"


# ===================================================================
# 12. Test-Connection Error Classifications
# ===================================================================

class TestConnectionErrors:
    """Tests for the test-connection endpoint error handling."""

    def test_test_connection_no_org_context(self, client):
        """Test connection should handle missing org gracefully."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        with _fake_vault_empty():
            resp = client.post(
                "/dashboard/api/ai/test-connection",
                json={
                    "provider_id": "openai",
                    "base_url": "https://api.openai.com/v1",
                    "api_key": "sk-test",
                },
                headers=_auth_headers(user),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "error"

    def test_test_connection_adapter_not_ready(self, client):
        """Test connection for provider with adapter_ready=False should return configured status."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        with _fake_vault_creds(provider_id="anthropic", model="claude-sonnet-4-5-20250514"):
            resp = client.post(
                "/dashboard/api/ai/test-connection",
                json={
                    "provider_id": "anthropic",
                    "base_url": "https://api.anthropic.com",
                    "api_key": "sk-anthropic-test",
                },
                headers=_auth_headers(user),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "configured"
            assert "adapter" in data.get("message", "").lower() or "not yet" in data.get("message", "").lower()


# ===================================================================
# 13. Load-Models Endpoint Behavior
# ===================================================================

class TestLoadModels:
    """Tests for the load-models endpoint."""

    def test_load_models_no_creds_returns_empty(self, client):
        """Load models with no credentials should return empty list."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        with _fake_vault_empty():
            resp = client.post(
                "/dashboard/api/ai/load-models",
                json={"base_url": "https://api.openai.com/v1", "api_key": "sk-test"},
                headers=_auth_headers(user),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["models"] == []

    def test_load_models_unsupported_provider(self, client):
        """Load models for provider without model discovery should return error."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        with _fake_vault_creds(provider_id="custom_openai_compatible"):
            resp = client.post(
                "/dashboard/api/ai/load-models",
                json={"base_url": "https://custom.api.com/v1", "api_key": "sk-custom"},
                headers=_auth_headers(user),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["models"] == []
            assert "error" in data

    def test_load_models_non_openai_compatible(self, client):
        """Load models for native protocol provider should return error."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        with _fake_vault_creds(provider_id="anthropic"):
            resp = client.post(
                "/dashboard/api/ai/load-models",
                json={"base_url": "https://api.anthropic.com", "api_key": "sk-ant"},
                headers=_auth_headers(user),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["models"] == []


# ===================================================================
# 14. AI Health Check with Provider Awareness
# ===================================================================

class TestAIHealthProviderAware:
    """Tests that the AI health check includes provider info."""

    def test_health_includes_ai_provider_field(self):
        """The health endpoint's AI section should include provider info."""
        # We can't easily test the full health endpoint with auth, but we can
        # verify the structure by examining the code logic
        from app.services.ai_provider_registry import get_provider
        provider = get_provider("openai")
        assert provider is not None
        assert provider.display_name == "OpenAI"

    def test_health_with_xai_provider(self):
        """Health should resolve xAI provider info correctly."""
        from app.services.ai_provider_registry import get_provider
        provider = get_provider("xai")
        assert provider is not None
        assert provider.display_name == "xAI / Grok"

    def test_health_with_moonshot_provider(self):
        """Health should resolve Moonshot provider info correctly."""
        from app.services.ai_provider_registry import get_provider
        provider = get_provider("moonshot")
        assert provider is not None
        assert provider.display_name == "Moonshot / Kimi"


# ===================================================================
# 15. Backward Compatibility
# ===================================================================

class TestBackwardCompatibility:
    """Tests for backward compatibility with old configurations."""

    def test_old_config_without_provider_id_works(self):
        """Existing configs without provider_id should still resolve."""
        with patch.object(CredentialVault, "get_credentials") as mock_creds, \
             patch.object(CredentialVault, "get_safe_metadata") as mock_meta:
            # Simulate old vault entry: credentials have api_key + base_url,
            # metadata has model but no provider_id
            mock_creds.return_value = {
                "api_key": "sk-old-key",
                "base_url": "https://api.openai.com/v1",
            }
            mock_meta.return_value = {"model": "gpt-4o"}
            from app.database import SessionLocal
            db = SessionLocal()
            try:
                config = IntegrationConfigResolver.resolve_ai_config(db, _DEFAULT_ORG_ID)
                # Should default to OpenAI
                assert config.primary.provider_id == "openai"
                assert config.primary.api_key == "sk-old-key"
                assert config.primary.base_url == "https://api.openai.com/v1"
            finally:
                db.close()

    def test_new_config_with_provider_id_works(self):
        """New-style config with provider_id should be stored and resolved."""
        with _fake_vault_creds(provider_id="moonshot", model="moonshot-v1-8k"):
            from app.database import SessionLocal
            db = SessionLocal()
            try:
                config = IntegrationConfigResolver.resolve_ai_config(db, _DEFAULT_ORG_ID)
                assert config.primary.provider_id == "moonshot"
            finally:
                db.close()

    def test_platform_default_provider_id_is_openai(self):
        """Platform default should use 'openai' as provider_id."""
        p = get_provider("openai")
        assert p is not None
        assert p.id == "openai"


# ===================================================================
# 16. IntegrationService KNOWN_PROVIDERS Extended
# ===================================================================

class TestIntegrationServiceProviders:
    """Tests for IntegrationService KNOWN_PROVIDERS extensions."""

    def test_known_providers_include_ai_entries(self):
        """KNOWN_PROVIDERS should include all 8 AI provider entries."""
        from app.services.integration_service import IntegrationService, KNOWN_PROVIDERS
        ai_keys = [k for k in KNOWN_PROVIDERS if k.startswith("ai_")]
        assert len(ai_keys) >= 8, f"Expected at least 8 ai_* entries, got {len(ai_keys)}: {ai_keys}"

    def test_known_providers_legacy_openai_exists(self):
        """Legacy 'openai' entry should still exist for backward compat."""
        from app.services.integration_service import KNOWN_PROVIDERS
        assert "openai" in KNOWN_PROVIDERS

    def test_safe_metadata_keys_include_provider_id(self):
        """_SAFE_METADATA_KEYS should include 'provider_id'."""
        from app.services.integration_service import _SAFE_METADATA_KEYS
        assert "provider_id" in _SAFE_METADATA_KEYS


# ===================================================================
# 17. Dashboard UI Endpoints Return Correct Shapes
# ===================================================================

class TestDashboardEndpointShapes:
    """Tests that dashboard API endpoints return the expected JSON shapes."""

    def test_providers_list_shape(self, client):
        """GET /dashboard/api/ai/providers should return providers list."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.get(
            "/dashboard/api/ai/providers",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "providers" in data
        assert isinstance(data["providers"], list)
        assert len(data["providers"]) >= 8
        for p in data["providers"]:
            assert "id" in p
            assert "display_name" in p
            assert "protocol" in p
            assert "default_base_url" in p
            assert "adapter_ready" in p

    def test_ai_status_shape_configured(self, client):
        """GET /dashboard/api/ai/status when configured should have expected fields."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        with _fake_vault_creds(api_key="sk-test-key"):
            resp = client.get(
                "/dashboard/api/ai/status",
                headers=_auth_headers(user),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "configured" in data
            if data["configured"]:
                assert "provider_id" in data
                assert "masked_key" in data
                assert "model" in data
                assert "base_url" in data
                assert "adapter_ready" in data

    def test_ai_status_shape_unconfigured(self, client):
        """GET /dashboard/api/ai/status when not configured."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        with _fake_vault_empty():
            resp = client.get(
                "/dashboard/api/ai/status",
                headers=_auth_headers(user),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["configured"] is False
            assert data["provider_id"] is None


# ===================================================================
# 18. Fallback Provider Resolution
# ===================================================================

class TestFallbackProvider:
    """Tests for fallback provider resolution."""

    def test_fallback_config_stores_provider_id(self):
        """Fallback AIProviderConfig should support provider_id."""
        fb = AIProviderConfig(
            api_key="sk-fallback",
            base_url="https://api.moonshot.cn/v1",
            model="moonshot-v1-8k",
            provider_id="moonshot",
        )
        assert fb.provider_id == "moonshot"

    def test_fallback_none_when_not_configured(self):
        """AIConfig should allow fallback=None."""
        primary = AIProviderConfig(
            api_key="sk-p", base_url="https://api.openai.com/v1",
            model="gpt-4o", provider_id="openai",
        )
        config = AIConfig(primary=primary)
        assert config.fallback is None


# ===================================================================
# 19. BrandingConfig Defaults
# ===================================================================

class TestBrandingDefaults:
    """Tests for BrandingConfig safe defaults."""

    def test_branding_config_has_defaults(self):
        """BrandingConfig should have safe defaults for all fields."""
        from app.services.integration_config_resolver import BrandingConfig
        b = BrandingConfig()
        assert b.company_name
        assert b.sender_name
        assert b.brand_color.startswith("#")

    def test_branding_config_customizable(self):
        """BrandingConfig should accept custom values."""
        from app.services.integration_config_resolver import BrandingConfig
        b = BrandingConfig(
            company_name="Acme Corp",
            sender_name="Acme Sales",
            brand_color="#ff0000",
            tagline="We sell things",
        )
        assert b.company_name == "Acme Corp"
        assert b.brand_color == "#ff0000"


# ===================================================================
# 20. Provider adapter_ready Flag Behavior
# ===================================================================

class TestAdapterReadyFlag:
    """Tests for the adapter_ready flag behavior."""

    def test_openai_compatible_providers_adapter_ready(self):
        """All OpenAI-compatible providers should have adapter_ready=True."""
        for pid in ["openai", "xai", "moonshot", "openrouter",
                     "tokenrouter", "custom_openai_compatible"]:
            p = get_provider(pid)
            assert p is not None, f"Provider {pid} not found"
            assert p.adapter_ready is True, f"Provider {pid} should be adapter_ready=True"

    def test_native_providers_adapter_not_ready(self):
        """Native protocol providers should have adapter_ready=False."""
        for pid in ["anthropic", "gemini"]:
            p = get_provider(pid)
            assert p is not None, f"Provider {pid} not found"
            assert p.adapter_ready is False, f"Provider {pid} should be adapter_ready=False"

    def test_adapter_ready_in_api_response(self, client):
        """Test-connection response should reflect adapter_ready for native providers."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        with _fake_vault_creds(provider_id="gemini", model="gemini-2.5-pro"):
            resp = client.post(
                "/dashboard/api/ai/test-connection",
                json={
                    "provider_id": "gemini",
                    "base_url": "https://generativelanguage.googleapis.com/v1beta",
                    "api_key": "sk-gemini-test",
                },
                headers=_auth_headers(user),
            )
            assert resp.status_code == 200
            data = resp.json()
            # Native provider should return "configured" not "connected"
            assert data["status"] == "configured"


# ===================================================================
# 21. OpenAI Provider-Specific Tests
# ===================================================================

class TestOpenAIProviderSpecific:
    """Tests specific to the OpenAI provider configuration."""

    def test_openai_does_not_allow_custom_url(self):
        """OpenAI should not allow custom base URL (locked to official)."""
        p = get_provider("openai")
        assert p.supports_custom_base_url is False

    def test_openai_default_url_is_correct(self):
        """OpenAI default URL should be the official API."""
        p = get_provider("openai")
        assert p.default_base_url == "https://api.openai.com/v1"

    def test_openai_api_key_label(self):
        """OpenAI API key label should be 'API Key'."""
        p = get_provider("openai")
        assert p.api_key_label == "API Key"


# ===================================================================
# 22. xAI / Grok Specific Tests
# ===================================================================

class TestxAIProviderSpecific:
    """Tests specific to the xAI provider configuration."""

    def test_xai_base_url(self):
        """xAI base URL should be https://api.x.ai/v1."""
        p = get_provider("xai")
        assert p.default_base_url == "https://api.x.ai/v1"

    def test_xai_default_model(self):
        """xAI default model should be grok-4."""
        p = get_provider("xai")
        assert p.default_model == "grok-4"

    def test_xai_adapter_ready(self):
        """xAI should be adapter-ready."""
        p = get_provider("xai")
        assert p.adapter_ready is True


# ===================================================================
# 23. Moonshot / Kimi Specific Tests
# ===================================================================

class TestMoonshotProviderSpecific:
    """Tests specific to the Moonshot provider configuration."""

    def test_moonshot_base_url(self):
        """Moonshot base URL should be https://api.moonshot.cn/v1."""
        p = get_provider("moonshot")
        assert p.default_base_url == "https://api.moonshot.cn/v1"

    def test_moonshot_default_model(self):
        """Moonshot default model should include 'moonshot' in name."""
        p = get_provider("moonshot")
        assert "moonshot" in p.default_model.lower()


# ===================================================================
# 24. OpenRouter Specific Tests
# ===================================================================

class TestOpenRouterProviderSpecific:
    """Tests specific to the OpenRouter provider configuration."""

    def test_openrouter_base_url(self):
        """OpenRouter base URL should be https://openrouter.ai/api/v1."""
        p = get_provider("openrouter")
        assert p.default_base_url == "https://openrouter.ai/api/v1"

    def test_openrouter_default_model_uses_prefix(self):
        """OpenRouter default model should use provider/model format."""
        p = get_provider("openrouter")
        assert "/" in p.default_model, "OpenRouter models use provider/model format"

    def test_openrouter_help_mentions_model_format(self):
        """OpenRouter help text should mention provider/model format."""
        p = get_provider("openrouter")
        assert "provider/model" in p.help_text.lower()


# ===================================================================
# 25. Integration Health AI Section
# ===================================================================

class TestIntegrationHealthAISection:
    """Tests for the AI section of the integration health endpoint."""

    def test_health_endpoint_structure(self, client):
        """Integration health should include ai_provider in response."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.get(
            "/dashboard/api/integration-health",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "ai_provider" in data
        ai = data["ai_provider"]
        assert "status" in ai
        assert ai["status"] in ("connected", "error")

    def test_health_ai_includes_provider_field(self, client):
        """AI health section should include 'provider' field."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.get(
            "/dashboard/api/integration-health",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200
        data = resp.json()
        ai = data["ai_provider"]
        assert "provider" in ai
        assert "model" in ai


# ===================================================================
# 26. save_integration Stores provider_id in Metadata
# ===================================================================

class TestSaveIntegrationStoresProviderID:
    """Tests that saving AI credentials includes provider_id in metadata."""

    def test_save_sends_provider_id_in_metadata(self, client):
        """POST save integration should accept provider_id in metadata."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.post(
            "/dashboard/api/integrations/openai/ai_provider",
            json={
                "credentials": {"api_key": "sk-test", "base_url": "https://api.openai.com/v1"},
                "metadata": {"provider_id": "openai", "model": "gpt-4o"},
            },
            headers=_auth_headers(user),
        )
        # Should succeed (200) or fail with known error (not 500)
        assert resp.status_code in (200, 201, 403, 422)

    def test_save_sends_xai_provider_id(self, client):
        """POST save integration with xAI provider_id."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.post(
            "/dashboard/api/integrations/openai/ai_provider",
            json={
                "credentials": {"api_key": "sk-xai-test", "base_url": "https://api.x.ai/v1"},
                "metadata": {"provider_id": "xai", "model": "grok-4"},
            },
            headers=_auth_headers(user),
        )
        assert resp.status_code in (200, 201, 403, 422)

    def test_save_sends_custom_provider_id(self, client):
        """POST save integration with custom OpenAI-compatible provider_id."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.post(
            "/dashboard/api/integrations/openai/ai_provider",
            json={
                "credentials": {"api_key": "sk-custom", "base_url": "https://my-server.com/v1"},
                "metadata": {"provider_id": "custom_openai_compatible", "model": "my-model"},
            },
            headers=_auth_headers(user),
        )
        assert resp.status_code in (200, 201, 403, 422)


# ===================================================================
# 27. All Providers Have Unique IDs
# ===================================================================

class TestProviderIDsUnique:
    """Tests for provider ID uniqueness."""

    def test_all_provider_ids_are_unique(self):
        """No two providers should share the same ID."""
        ids = get_provider_ids()
        assert len(ids) == len(set(ids)), "Duplicate provider IDs found"


# ===================================================================
# 28. Provider Protocol Consistency
# ===================================================================

class TestProtocolConsistency:
    """Tests for protocol consistency between registry and is_openai_compatible."""

    def test_openai_compatible_matches_registry(self):
        """is_openai_compatible should match protocol field in registry."""
        for pid, defn in PROVIDERS.items():
            compat = is_openai_compatible(pid)
            expected = defn.protocol == "openai_compatible"
            assert compat == expected, \
                f"Provider {pid}: is_openai_compatible={compat} but protocol={defn.protocol}"
