"""Comprehensive security tests for the Credential Vault (Phase 6B.2).

Covers:
  - Encryption service: key validation, encrypt/decrypt round-trips, error cases
  - Credential vault: CRUD, org isolation, corruption detection, masking
  - Integration service: named methods, status queries, deletion
  - Security: no credential leakage, secret leak test, cross-org isolation
  - Config: encryption key validation in test mode

Minimum 30 tests required by spec.
"""
from __future__ import annotations

import json
import uuid
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from app.config import settings
from app.models_multi_tenant import IntegrationStatus, Organization
from app.services.credential_vault import (
    CredentialCorruptError,
    CredentialNotFoundError,
    CredentialVault,
    CredentialVaultError,
)
from app.services.crypto import (
    CryptoError,
    DecryptionError,
    InvalidKeyError,
    decrypt_secret,
    derive_key_from_password,
    encrypt_secret,
    generate_key,
    mask_dict_values,
    mask_secret,
    serialize_credentials,
    deserialize_credentials,
    validate_key,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@contextmanager
def _use_key(valid_key: str):
    """Context manager that patches settings for credential vault operations.

    Patches credential_encryption_key field (valid pydantic field) and app_env
    so that settings.get_credential_encryption_key() returns the test key.
    """
    with patch.object(settings, "credential_encryption_key", valid_key), \
         patch.object(settings, "app_env", "test"):
        yield


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def valid_key():
    """A valid Fernet encryption key for tests."""
    return generate_key()


@pytest.fixture()
def second_key():
    """A second valid Fernet key (different from the first)."""
    return generate_key()


@pytest.fixture()
def org(db_session):
    """Create a test organization and return it."""
    org = Organization(
        name="Test Vault Org",
        slug=f"vault-test-{uuid.uuid4().hex[:8]}",
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)
    return org


@pytest.fixture()
def second_org(db_session):
    """Create a second test organization."""
    org = Organization(
        name="Second Vault Org",
        slug=f"vault-second-{uuid.uuid4().hex[:8]}",
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)
    return org


# ---------------------------------------------------------------------------
# 1. Encryption service — key validation
# ---------------------------------------------------------------------------


class TestKeyValidation:
    """Tests for Fernet key validation."""

    def test_valid_key_passes(self, valid_key):
        """A correctly generated Fernet key passes validation."""
        result = validate_key(valid_key)
        assert result == valid_key

    def test_empty_key_raises(self):
        """An empty string raises InvalidKeyError."""
        with pytest.raises(InvalidKeyError, match="not set"):
            validate_key("")

    def test_none_key_raises(self):
        """None raises InvalidKeyError."""
        with pytest.raises(InvalidKeyError, match="not set"):
            validate_key(None)

    def test_whitespace_only_key_raises(self):
        """Whitespace-only key raises InvalidKeyError."""
        with pytest.raises(InvalidKeyError, match="not set"):
            validate_key("   ")

    def test_invalid_key_format_raises(self):
        """A string that's not a valid Fernet key raises InvalidKeyError."""
        with pytest.raises(InvalidKeyError, match="not a valid Fernet key"):
            validate_key("this-is-not-a-fernet-key")

    def test_generate_key_returns_valid(self):
        """generate_key() produces a key that passes validation."""
        key = generate_key()
        result = validate_key(key)
        assert result == key

    def test_key_is_44_chars(self):
        """Fernet keys are exactly 44 characters (32 bytes base64-encoded)."""
        key = generate_key()
        assert len(key) == 44


# ---------------------------------------------------------------------------
# 2. Encryption service — encrypt/decrypt round-trips
# ---------------------------------------------------------------------------


class TestEncryptDecrypt:
    """Tests for encryption and decryption operations."""

    def test_basic_round_trip(self, valid_key):
        """Encrypt then decrypt returns the original plaintext."""
        plaintext = "my-secret-api-key-12345"
        ciphertext = encrypt_secret(plaintext, valid_key)
        decrypted = decrypt_secret(ciphertext, valid_key)
        assert decrypted == plaintext

    def test_empty_plaintext_raises(self, valid_key):
        """Cannot encrypt an empty string."""
        with pytest.raises(CryptoError, match="empty string"):
            encrypt_secret("", valid_key)

    def test_empty_ciphertext_raises(self, valid_key):
        """Cannot decrypt an empty string."""
        with pytest.raises(DecryptionError, match="empty string"):
            decrypt_secret("", valid_key)

    def test_wrong_key_fails_decryption(self, valid_key, second_key):
        """Decrypting with the wrong key raises DecryptionError."""
        ciphertext = encrypt_secret("secret", valid_key)
        with pytest.raises(DecryptionError, match="wrong key"):
            decrypt_secret(ciphertext, second_key)

    def test_version_prefix_present(self, valid_key):
        """Encrypted output starts with 'v1:' version prefix."""
        ciphertext = encrypt_secret("test", valid_key)
        assert ciphertext.startswith("v1:")

    def test_version_prefix_stripped_on_decrypt(self, valid_key):
        """Decryption handles versioned ciphertext correctly."""
        plaintext = "round-trip-test"
        ciphertext = encrypt_secret(plaintext, valid_key)
        assert ciphertext.startswith("v1:")
        result = decrypt_secret(ciphertext, valid_key)
        assert result == plaintext

    def test_unicode_plaintext(self, valid_key):
        """Unicode strings survive round-trip."""
        plaintext = "café résumé 日本語 🔑"
        ciphertext = encrypt_secret(plaintext, valid_key)
        assert decrypt_secret(ciphertext, valid_key) == plaintext

    def test_long_plaintext(self, valid_key):
        """Long strings (10KB) encrypt/decrypt correctly."""
        plaintext = "x" * 10_000
        ciphertext = encrypt_secret(plaintext, valid_key)
        assert decrypt_secret(ciphertext, valid_key) == plaintext

    def test_different_ciphertext_each_time(self, valid_key):
        """Fernet produces different ciphertext each time (random IV)."""
        ct1 = encrypt_secret("same-plaintext", valid_key)
        ct2 = encrypt_secret("same-plaintext", valid_key)
        # Extremely unlikely to be identical
        assert ct1 != ct2
        # But both decrypt to the same value
        assert decrypt_secret(ct1, valid_key) == decrypt_secret(ct2, valid_key)

    def test_corrupt_ciphertext_raises(self, valid_key):
        """Corrupted ciphertext raises DecryptionError."""
        ciphertext = encrypt_secret("test", valid_key)
        # Corrupt a few characters in the middle
        corrupt = ciphertext[:10] + "XXXX" + ciphertext[14:]
        with pytest.raises(DecryptionError):
            decrypt_secret(corrupt, valid_key)

    def test_serialize_credentials_round_trip(self):
        """JSON serialization round-trips correctly."""
        creds = {"api_key": "sk-123", "base_url": "https://api.example.com"}
        serialized = serialize_credentials(creds)
        deserialized = deserialize_credentials(serialized)
        assert deserialized == creds

    def test_serialize_non_dict_raises(self):
        """serialize_credentials rejects non-dict input to deserialize."""
        creds = {"api_key": "sk-123"}
        serialized = serialize_credentials(creds)
        # This is fine — but deserialize should reject arrays
        with pytest.raises(CryptoError, match="Expected a JSON object"):
            deserialize_credentials('["not", "a", "dict"]')

    def test_derive_key_from_password(self):
        """Key derivation from password produces a valid Fernet key."""
        key_str, salt = derive_key_from_password("my-strong-password")
        assert isinstance(key_str, str)
        assert len(key_str) == 44
        ct = encrypt_secret("test", key_str)
        assert decrypt_secret(ct, key_str) == "test"


# ---------------------------------------------------------------------------
# 3. Masking utilities
# ---------------------------------------------------------------------------


class TestMasking:
    """Tests for secret masking functions."""

    def test_mask_secret_basic(self):
        """Shows last 4 chars by default."""
        result = mask_secret("sk-abc123def456")
        assert result == "***********f456"

    def test_mask_secret_short_string(self):
        """Short strings are returned as-is."""
        assert mask_secret("ab") == "ab"
        assert mask_secret("abc") == "abc"

    def test_mask_secret_empty(self):
        """Empty string returns empty."""
        assert mask_secret("") == ""

    def test_mask_secret_custom_visible_chars(self):
        """Custom visible_chars parameter works."""
        result = mask_secret("abcdefghijklmnop", visible_chars=6)
        assert result == "**********klmnop"

    def test_mask_dict_values_keys(self):
        """Sensitive keys are masked in dict values."""
        data = {"api_key": "sk-supersecret123", "base_url": "https://api.example.com", "model": "gpt-4"}
        masked = mask_dict_values(data)
        assert masked["api_key"].endswith("t123")
        assert masked["api_key"].startswith("*")
        assert masked["base_url"] == "https://api.example.com"
        assert masked["model"] == "gpt-4"

    def test_mask_dict_nested(self):
        """Nested dicts are recursively masked."""
        data = {"outer": {"api_key": "sk-secret-nested"}}
        masked = mask_dict_values(data)
        assert masked["outer"]["api_key"].endswith("sted")
        assert masked["outer"]["api_key"].startswith("*")

    def test_mask_secret_does_not_leak(self):
        """Masked output never contains the full original secret."""
        secret = "my-very-long-secret-key-value-12345"
        masked = mask_secret(secret)
        assert secret not in masked
        assert masked != secret


# ---------------------------------------------------------------------------
# 4. Credential Vault — CRUD operations
# ---------------------------------------------------------------------------


class TestCredentialVaultCRUD:
    """Tests for CredentialVault save/get/update/delete."""

    def test_save_and_retrieve(self, db_session, org, valid_key):
        """Save credentials and retrieve them."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session,
                org_id=org.id,
                provider="test_provider",
                integration_type="test_type",
                credentials={"token": "secret-token-123"},
                metadata={"display_name": "Test"},
            )
            creds = CredentialVault.get_credentials(
                db=db_session,
                org_id=org.id,
                provider="test_provider",
                integration_type="test_type",
            )
            assert creds == {"token": "secret-token-123"}

    def test_save_upsert(self, db_session, org, valid_key):
        """Saving with the same provider/type replaces the old entry."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"key": "old"},
            )
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"key": "new"},
            )
            creds = CredentialVault.get_credentials(
                db_session, org.id, "p", "t"
            )
            assert creds == {"key": "new"}

    def test_has_credentials_true(self, db_session, org, valid_key):
        """has_credentials returns True when credentials exist."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"k": "v"},
            )
            assert CredentialVault.has_credentials(db_session, org.id, "p", "t") is True

    def test_has_credentials_false(self, db_session, org):
        """has_credentials returns False when no row exists."""
        assert CredentialVault.has_credentials(
            db_session, org.id, "nonexistent", "nonexistent"
        ) is False

    def test_get_missing_raises(self, db_session, org):
        """Getting credentials for nonexistent integration raises."""
        with pytest.raises(CredentialNotFoundError):
            CredentialVault.get_credentials(
                db_session, org.id, "missing", "missing"
            )

    def test_delete_soft(self, db_session, org, valid_key):
        """Soft delete clears credentials and sets DISCONNECTED status."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"k": "v"},
            )
            result = CredentialVault.delete_credentials(
                db_session, org.id, "p", "t"
            )
            assert result is True
            assert CredentialVault.has_credentials(db_session, org.id, "p", "t") is False

    def test_delete_hard(self, db_session, org, valid_key):
        """Hard delete removes the row entirely."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"k": "v"},
            )
            result = CredentialVault.delete_credentials(
                db_session, org.id, "p", "t", hard_delete=True
            )
            assert result is True
            # Integration row should be gone
            from sqlalchemy import select
            from app.models_multi_tenant import OrgIntegration
            row = db_session.execute(
                select(OrgIntegration).where(
                    OrgIntegration.organization_id == org.id,
                    OrgIntegration.provider == "p",
                )
            ).scalar_one_or_none()
            assert row is None

    def test_delete_nonexistent_returns_false(self, db_session, org):
        """Deleting nonexistent integration returns False."""
        result = CredentialVault.delete_credentials(
            db_session, org.id, "no", "no"
        )
        assert result is False

    def test_list_integrations_no_credentials(self, db_session, org, valid_key):
        """list_integrations never includes credentials_encrypted."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"secret": "value"},
                metadata={"name": "test"},
            )
            items = CredentialVault.list_integrations(db_session, org.id)
            assert len(items) == 1
            assert "credentials_encrypted" not in items[0]
            assert items[0]["has_credentials"] is True
            assert items[0]["metadata"] == {"name": "test"}


# ---------------------------------------------------------------------------
# 5. Credential Vault — org isolation
# ---------------------------------------------------------------------------


class TestCredentialVaultOrgIsolation:
    """Tests that credentials are strictly org-isolated."""

    def test_different_orgs_different_creds(self, db_session, org, second_org, valid_key):
        """Each org has independent credentials."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"org": "first"},
            )
            CredentialVault.save_credentials(
                db=db_session, org_id=second_org.id,
                provider="p", integration_type="t",
                credentials={"org": "second"},
            )
            creds1 = CredentialVault.get_credentials(db_session, org.id, "p", "t")
            creds2 = CredentialVault.get_credentials(db_session, second_org.id, "p", "t")
            assert creds1 == {"org": "first"}
            assert creds2 == {"org": "second"}

    def test_wrong_org_raises_not_found(self, db_session, org, second_org, valid_key):
        """Querying credentials with the wrong org_id raises not found."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"k": "v"},
            )
            with pytest.raises(CredentialNotFoundError):
                CredentialVault.get_credentials(
                    db_session, second_org.id, "p", "t"
                )

    def test_has_credentials_wrong_org_false(self, db_session, org, second_org, valid_key):
        """has_credentials returns False for the wrong org."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"k": "v"},
            )
            assert CredentialVault.has_credentials(
                db_session, second_org.id, "p", "t"
            ) is False

    def test_list_integrations_isolated(self, db_session, org, second_org, valid_key):
        """list_integrations only returns rows for the requested org."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p1", integration_type="t1",
                credentials={"k": "v1"},
            )
            CredentialVault.save_credentials(
                db=db_session, org_id=second_org.id,
                provider="p2", integration_type="t2",
                credentials={"k": "v2"},
            )
            items1 = CredentialVault.list_integrations(db_session, org.id)
            items2 = CredentialVault.list_integrations(db_session, second_org.id)
            assert len(items1) == 1
            assert len(items2) == 1
            assert items1[0]["provider"] == "p1"
            assert items2[0]["provider"] == "p2"

    def test_delete_does_not_affect_other_org(self, db_session, org, second_org, valid_key):
        """Deleting credentials for one org does not affect another."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"k": "v"},
            )
            CredentialVault.save_credentials(
                db=db_session, org_id=second_org.id,
                provider="p", integration_type="t",
                credentials={"k": "v"},
            )
            CredentialVault.delete_credentials(db_session, org.id, "p", "t")
            # second_org's credentials should still exist
            assert CredentialVault.has_credentials(
                db_session, second_org.id, "p", "t"
            ) is True


# ---------------------------------------------------------------------------
# 6. Credential Vault — wrong key / corruption
# ---------------------------------------------------------------------------


class TestCredentialVaultCorruption:
    """Tests for wrong encryption key / corrupt data scenarios."""

    def test_wrong_key_raises_corrupt(self, db_session, org, valid_key, second_key):
        """Decrypting with the wrong key raises CredentialCorruptError."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"k": "v"},
            )
        # Now simulate reading with a different key
        with _use_key(second_key):
            with pytest.raises(CredentialCorruptError, match="Cannot decrypt"):
                CredentialVault.get_credentials(db_session, org.id, "p", "t")

    def test_empty_credentials_field(self, db_session, org):
        """Integration with None credentials returns empty dict."""
        from app.models_multi_tenant import OrgIntegration
        integration = OrgIntegration(
            organization_id=org.id,
            provider="p",
            integration_type="t",
            status=IntegrationStatus.PENDING,
            credentials_encrypted=None,
        )
        db_session.add(integration)
        db_session.commit()
        with _use_key(generate_key()):
            creds = CredentialVault.get_credentials(db_session, org.id, "p", "t")
            assert creds == {}

    def test_metadata_only_no_credentials(self, db_session, org, valid_key):
        """Save with empty credentials and metadata, retrieve returns empty dict."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={},
                metadata={"note": "config-only"},
            )
            creds = CredentialVault.get_credentials(db_session, org.id, "p", "t")
            assert creds == {}


# ---------------------------------------------------------------------------
# 7. Credential Vault — masking display
# ---------------------------------------------------------------------------


class TestCredentialVaultMasking:
    """Tests for masked credential display."""

    def test_masked_credentials(self, db_session, org, valid_key):
        """get_masked_credentials returns masked values."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"api_key": "sk-supersecret12345"},
            )
            masked = CredentialVault.get_masked_credentials(db_session, org.id, "p", "t")
            assert masked is not None
            assert "api_key" in masked
            assert masked["api_key"] != "sk-supersecret12345"
            assert masked["api_key"].endswith("2345")

    def test_masked_credentials_none_when_missing(self, db_session, org):
        """get_masked_credentials returns None when no credentials exist."""
        result = CredentialVault.get_masked_credentials(
            db_session, org.id, "missing", "missing"
        )
        assert result is None


# ---------------------------------------------------------------------------
# 8. Credential Vault — metadata operations
# ---------------------------------------------------------------------------


class TestCredentialVaultMetadata:
    """Tests for metadata update and safe retrieval."""

    def test_update_metadata(self, db_session, org, valid_key):
        """update_metadata replaces metadata without touching credentials."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"k": "v"},
                metadata={"v": 1},
            )
            CredentialVault.update_metadata(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                metadata={"v": 2, "extra": True},
            )
            meta = CredentialVault.get_safe_metadata(db_session, org.id, "p", "t")
            assert meta == {"v": 2, "extra": True}

            # Credentials should be untouched
            creds = CredentialVault.get_credentials(db_session, org.id, "p", "t")
            assert creds == {"k": "v"}

    def test_get_safe_metadata_none_when_missing(self, db_session, org):
        """get_safe_metadata returns None when integration doesn't exist."""
        result = CredentialVault.get_safe_metadata(
            db_session, org.id, "no", "no"
        )
        assert result is None


# ---------------------------------------------------------------------------
# 9. Integration Service — named methods
# ---------------------------------------------------------------------------


class TestIntegrationService:
    """Tests for the IntegrationService named methods."""

    def test_save_and_get_google_oauth(self, db_session, org, valid_key):
        """Save Google OAuth and check status."""
        from app.services.integration_service import IntegrationService

        with _use_key(valid_key):
            result = IntegrationService.save_google_oauth(
                db=db_session, org_id=org.id,
                refresh_token="1//0test",
                client_id="client-123",
                client_secret="secret-456",
                scopes=["calendar"],
            )
            # google_oauth is in _OAUTH_CONFIG_TYPES, so save_integration()
            # correctly returns PENDING until the OAuth callback completes.
            assert result["status"] == "pending"
            assert result["has_credentials"] is True

            status = IntegrationService.get_google_oauth_status(db_session, org.id)
            assert status["has_credentials"] is True
            assert status["metadata"]["scopes"] == ["calendar"]

    def test_save_and_get_ai_provider(self, db_session, org, valid_key):
        """Save AI provider and check status."""
        from app.services.integration_service import IntegrationService

        with _use_key(valid_key):
            IntegrationService.save_ai_provider(
                db=db_session, org_id=org.id,
                api_key="sk-ai-key",
                base_url="https://api.openai.com",
                model="gpt-4",
            )
            status = IntegrationService.get_ai_provider_status(db_session, org.id)
            assert status["has_credentials"] is True
            assert status["metadata"]["model"] == "gpt-4"

    def test_get_all_integration_statuses(self, db_session, org, valid_key):
        """list_integrations returns all rows for the org."""
        from app.services.integration_service import IntegrationService

        with _use_key(valid_key):
            IntegrationService.save_google_oauth(
                db=db_session, org_id=org.id,
                refresh_token="t", client_id="c", client_secret="s",
            )
            IntegrationService.save_ai_provider(
                db=db_session, org_id=org.id,
                api_key="k", base_url="u", model="m",
            )
            statuses = IntegrationService.list_integrations(db_session, org.id)
            assert len(statuses) == 2
            # Ensure no credentials leak
            for item in statuses:
                assert "credentials_encrypted" not in item
                assert "credentials" not in item

    def test_delete_integration(self, db_session, org, valid_key):
        """Delete an integration through IntegrationService."""
        from app.services.integration_service import IntegrationService

        with _use_key(valid_key):
            IntegrationService.save_google_oauth(
                db=db_session, org_id=org.id,
                refresh_token="t", client_id="c", client_secret="s",
            )
            result = IntegrationService.delete_integration(
                db_session, org.id, "google", "google_oauth"
            )
            assert result is True
            status = IntegrationService.get_google_oauth_status(db_session, org.id)
            assert status["has_credentials"] is False


# ---------------------------------------------------------------------------
# 10. Security — no credential leakage in logs/responses
# ---------------------------------------------------------------------------


class TestSecurityNoLeakage:
    """Security tests to ensure credentials never leak."""

    def test_encrypted_blob_not_readable(self, valid_key):
        """The encrypted blob does not contain the plaintext."""
        secret = "my-super-secret-api-key"
        ciphertext = encrypt_secret(secret, valid_key)
        assert secret not in ciphertext

    def test_masked_dict_never_contains_full_secret(self, valid_key):
        """Masked dict values never contain the full original secret."""
        data = {"api_key": "sk-abcdef1234567890", "token": "ghp_verylongtoken123"}
        masked = mask_dict_values(data)
        assert data["api_key"] not in masked.values()
        assert data["token"] not in masked.values()

    def test_db_stores_encrypted_not_plaintext(self, db_session, org, valid_key):
        """The database stores encrypted ciphertext, not plaintext credentials."""
        with _use_key(valid_key):
            secret_value = "sk-real-api-key-never-store-in-plaintext"
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"api_key": secret_value},
            )
            # Read raw DB value
            from sqlalchemy import select
            from app.models_multi_tenant import OrgIntegration
            raw = db_session.execute(
                select(OrgIntegration.credentials_encrypted).where(
                    OrgIntegration.organization_id == org.id,
                )
            ).scalar_one()
            # Raw DB value should NOT contain the secret
            assert secret_value not in raw
            # It should start with v1: (version prefix)
            assert raw.startswith("v1:")

    def test_ciphertext_differs_per_key(self):
        """Same plaintext encrypted with different keys produces different ciphertext."""
        key1 = generate_key()
        key2 = generate_key()
        ct1 = encrypt_secret("same", key1)
        ct2 = encrypt_secret("same", key2)
        assert ct1 != ct2

    def test_list_integrations_excludes_credentials(self, db_session, org, valid_key):
        """list_integrations output never contains credentials."""
        with _use_key(valid_key):
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"secret_key": "top-secret"},
            )
            items = CredentialVault.list_integrations(db_session, org.id)
            for item in items:
                serialized = json.dumps(item)
                assert "top-secret" not in serialized
                assert "credentials_encrypted" not in serialized

    def test_masked_credentials_via_vault(self, db_session, org, valid_key):
        """get_masked_credentials never returns full secret values."""
        with _use_key(valid_key):
            secret = "sk-extremely-secret-api-key-xyz"
            CredentialVault.save_credentials(
                db=db_session, org_id=org.id,
                provider="p", integration_type="t",
                credentials={"api_key": secret},
            )
            masked = CredentialVault.get_masked_credentials(db_session, org.id, "p", "t")
            assert secret not in masked["api_key"]


# ---------------------------------------------------------------------------
# 11. Config — test mode behavior
# ---------------------------------------------------------------------------


class TestConfigEncryptionKey:
    """Tests for Settings.get_credential_encryption_key behavior."""

    def test_test_mode_requires_key(self):
        """In test mode, a missing key raises RuntimeError."""
        with patch.object(settings, "app_env", "test"):
            with patch.object(settings, "credential_encryption_key", ""):
                with pytest.raises(RuntimeError, match="must be set"):
                    settings.get_credential_encryption_key()

    def test_test_mode_with_key_validates(self):
        """In test mode, a valid key is returned."""
        key = generate_key()
        with patch.object(settings, "app_env", "test"):
            with patch.object(settings, "credential_encryption_key", key):
                result = settings.get_credential_encryption_key()
                assert result == key
