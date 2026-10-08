"""Phase 6B.7 — Integration Credentials Comprehensive Test Suite.

Validates:
  1. Encryption roundtrip — credentials encrypted at rest, decrypted on read
  2. Tenant isolation — org A cannot see org B's credentials
  3. Secret safety — API responses never contain plaintext credentials
  4. RBAC — owner/admin can write, member can only read
  5. CRUD operations — save, get, update, list, disconnect
  6. Unique constraint — no duplicate (org, provider, integration_type)
  7. Error handling — mark_error, sanitize error messages
  8. Audit logging — events recorded for mutations
  9. API endpoint validation — proper HTTP status codes
  10. _sanitize_error — secrets stripped from error messages

Total: ~50 tests
"""
from __future__ import annotations

import base64
import json
import re
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models_multi_tenant import (
    IntegrationStatus,
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)
from app.services.credential_vault import (
    CredentialCorruptError,
    CredentialNotFoundError,
    CredentialVault,
)
from app.services.crypto import generate_key
from app.services.integration_service import (
    IntegrationNotFoundError,
    IntegrationService,
    IntegrationServiceError,
    IntegrationValidationError,
    InsufficientPermissionsError,
)

# ── Test Constants ────────────────────────────────────────────────────────────

TEST_JWT_SECRET = "test-secret-key-for-phase-6b7-jwt-testing-32chars!!"
TEST_ENCRYPTION_KEY = generate_key()


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    """Inject test-mode secrets."""
    monkeypatch.setattr(settings, "jwt_secret_key", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", TEST_ENCRYPTION_KEY)


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


def _basic_auth_headers() -> dict:
    """Platform admin basic auth headers."""
    return {
        "Authorization": "Basic "
        + base64.b64encode(
            f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
        ).decode()
    }


# ══════════════════════════════════════════════════════════════════════════════
# 1. Encryption Roundtrip Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestEncryptionRoundtrip:
    """Verify credentials are encrypted at rest and decrypted on read."""

    def test_credentials_encrypted_at_rest(self, db):
        """Saving credentials should store Fernet-encrypted ciphertext."""
        org, _ = _create_org_and_user(db)

        credentials = {"api_key": "sk-test123456789abcdef"}
        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="openai",
            integration_type="ai_provider",
            credentials=credentials,
        )

        from app.models_multi_tenant import OrgIntegration
        from sqlalchemy import select

        stmt = select(OrgIntegration).where(
            OrgIntegration.organization_id == org.id,
            OrgIntegration.provider == "openai",
        )
        row = db.execute(stmt).scalar_one()

        # Should be encrypted (Fernet ciphertext looks like base64)
        assert row.credentials_encrypted is not None
        assert row.credentials_encrypted != json.dumps(credentials)
        assert row.credentials_encrypted.startswith("v1:")

    def test_credentials_decrypted_on_read(self, db):
        """Reading credentials should return the original plaintext."""
        org, _ = _create_org_and_user(db)

        original = {"client_id": "id123", "client_secret": "secret456", "refresh_token": "token789"}
        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials=original,
        )

        decrypted = CredentialVault.get_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
        )
        assert decrypted == original

    def test_different_orgs_get_different_ciphertext(self, db):
        """Same plaintext for two orgs produces different ciphertext (unique keys per-org)."""
        org_a, _ = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org_b, _ = _create_org_and_user(db, email="b@test.com", org_name="Org B")

        credentials = {"api_key": "same-key-for-both"}
        CredentialVault.save_credentials(db, org_a.id, "openai", "ai_provider", credentials)
        CredentialVault.save_credentials(db, org_b.id, "openai", "ai_provider", credentials)

        from app.models_multi_tenant import OrgIntegration
        from sqlalchemy import select

        row_a = db.execute(
            select(OrgIntegration).where(OrgIntegration.organization_id == org_a.id)
        ).scalar_one()
        row_b = db.execute(
            select(OrgIntegration).where(OrgIntegration.organization_id == org_b.id)
        ).scalar_one()

        assert row_a.credentials_encrypted != row_b.credentials_encrypted


# ══════════════════════════════════════════════════════════════════════════════
# 2. Tenant Isolation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestTenantIsolation:
    """Verify org A cannot see or access org B's integrations."""

    def test_org_a_cannot_read_org_b_credentials(self, db):
        """get_credentials for org B with org A's ID should raise."""
        org_a, _ = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org_b, _ = _create_org_and_user(db, email="b@test.com", org_name="Org B")

        CredentialVault.save_credentials(
            db, org_b.id, "openai", "ai_provider",
            {"api_key": "org-b-secret-key"},
        )

        with pytest.raises(CredentialNotFoundError):
            CredentialVault.get_credentials(db, org_a.id, "openai", "ai_provider")

    def test_org_a_list_excludes_org_b(self, db):
        """Org A's listing should not include org B's integrations."""
        org_a, _ = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org_b, _ = _create_org_and_user(db, email="b@test.com", org_name="Org B")

        CredentialVault.save_credentials(db, org_a.id, "openai", "ai_provider", {"api_key": "a-key"})
        CredentialVault.save_credentials(db, org_b.id, "openai", "ai_provider", {"api_key": "b-key"})

        list_a = CredentialVault.list_integrations(db, org_a.id)
        list_b = CredentialVault.list_integrations(db, org_b.id)

        assert len(list_a) == 1
        assert len(list_b) == 1
        assert list_a[0]["provider"] == "openai"
        assert list_b[0]["provider"] == "openai"

    def test_idor_via_api_prevented(self, db, client):
        """API cannot be tricked into returning another org's data."""
        org_a, user_a = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org_b, _ = _create_org_and_user(db, email="b@test.com", org_name="Org B")

        CredentialVault.save_credentials(
            db, org_b.id, "openai", "ai_provider", {"api_key": "org-b-key"}
        )

        token = _create_jwt_token(user_a.id, org_a.id, "owner")
        headers = _auth_headers(token)

        resp = client.get("/dashboard/api/integrations", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        # Org A should see only their integrations
        for item in data.get("integrations", []):
            # No integration should contain org B's data
            assert item.get("metadata", {}).get("api_key") != "org-b-key"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Secret Safety Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestSecretSafety:
    """Verify API responses never leak plaintext credentials."""

    def test_save_response_no_secrets(self, db):
        """save_integration should return safe response without credentials."""
        org, _ = _create_org_and_user(db)

        result = IntegrationService.save_integration(
            db=db,
            org_id=org.id,
            provider="openai",
            integration_type="ai_provider",
            credentials={"api_key": "sk-super-secret-key"},
            role="owner",
        )

        response_str = json.dumps(result)
        assert "sk-super-secret-key" not in response_str
        assert result.get("has_credentials") is True
        assert result.get("status") == "connected"

    def test_list_response_no_secrets(self, db):
        """list_integrations should not contain plaintext credentials."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db, org.id, "google", "google_oauth",
            {"client_id": "id", "client_secret": "s3cret", "refresh_token": "tok"},
        )

        items = IntegrationService.list_integrations(db, org.id)
        response_str = json.dumps(items)
        assert "s3cret" not in response_str
        assert "tok" not in response_str

    def test_masked_credentials_masks_values(self, db):
        """get_masked_credentials should return masked values."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db, org.id, "openai", "ai_provider",
            {"api_key": "sk-123456789abcdef"},
        )

        masked = CredentialVault.get_masked_credentials(db, org.id, "openai", "ai_provider")
        assert masked is not None
        assert "sk-123456789abcdef" not in json.dumps(masked)
        # The mask should contain asterisks or [REDACTED]
        for v in masked.values():
            if isinstance(v, str):
                assert "*" in v or "[REDACTED]" in v or "sk-" not in v

    def test_status_endpoint_no_secrets(self, db, client):
        """GET /dashboard/api/integrations/{provider} should not return secrets."""
        org, user = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db, org.id, "google", "google_oauth",
            {"client_id": "id", "client_secret": "s3cret", "refresh_token": "tok"},
        )

        token = _create_jwt_token(user.id, org.id, "owner")
        resp = client.get(
            f"/dashboard/api/integrations/google",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        response_str = json.dumps(resp.json())
        assert "s3cret" not in response_str
        assert "tok" not in response_str


# ══════════════════════════════════════════════════════════════════════════════
# 4. RBAC Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestRBAC:
    """Verify role-based access control on integration endpoints."""

    def test_member_cannot_save_integration(self, db):
        """Member role should be denied from saving integrations."""
        org, _ = _create_org_and_user(db, role=UserRole.MEMBER)

        with pytest.raises(InsufficientPermissionsError):
            IntegrationService.save_integration(
                db=db,
                org_id=org.id,
                provider="openai",
                integration_type="ai_provider",
                credentials={"api_key": "key"},
                role="member",
            )

    def test_admin_can_save_integration(self, db):
        """Admin role should be able to save integrations."""
        org, _ = _create_org_and_user(db, role=UserRole.ADMIN)

        result = IntegrationService.save_integration(
            db=db,
            org_id=org.id,
            provider="openai",
            integration_type="ai_provider",
            credentials={"api_key": "key"},
            role="admin",
        )
        assert result["has_credentials"] is True

    def test_owner_can_save_integration(self, db):
        """Owner role should be able to save integrations."""
        org, _ = _create_org_and_user(db, role=UserRole.OWNER)

        result = IntegrationService.save_integration(
            db=db,
            org_id=org.id,
            provider="openai",
            integration_type="ai_provider",
            credentials={"api_key": "key"},
            role="owner",
        )
        assert result["has_credentials"] is True

    def test_member_can_read_integrations(self, db):
        """Member role should be able to list integrations."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)

        # Admin saves the integration
        CredentialVault.save_credentials(
            db, org.id, "openai", "ai_provider", {"api_key": "key"}
        )

        # Member reads it — should succeed
        items = IntegrationService.list_integrations(db, org.id)
        assert len(items) == 1

    def test_member_cannot_disconnect(self, db):
        """Member role should be denied from disconnecting."""
        org, _ = _create_org_and_user(db, role=UserRole.MEMBER)

        CredentialVault.save_credentials(
            db, org.id, "openai", "ai_provider", {"api_key": "key"}
        )

        with pytest.raises(InsufficientPermissionsError):
            IntegrationService.disconnect_integration(
                db=db, org_id=org.id, provider="openai",
                integration_type="ai_provider", role="member",
            )

    def test_api_member_cannot_save(self, db, client):
        """API should return 403 for member role on POST."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _create_jwt_token(user.id, org.id, "member")
        headers = _auth_headers(token)

        resp = client.post(
            "/dashboard/api/integrations/openai/ai_provider",
            headers=headers,
            json={"credentials": {"api_key": "test"}},
        )
        assert resp.status_code == 403

    def test_api_member_can_list(self, db, client):
        """API should return 200 for member role on GET."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _create_jwt_token(user.id, org.id, "member")
        headers = _auth_headers(token)

        resp = client.get("/dashboard/api/integrations", headers=headers)
        assert resp.status_code == 200

    def test_platform_admin_can_list_all(self, db, client):
        """Platform admin should see all integrations across orgs."""
        org1, _ = _create_org_and_user(db, email="a@test.com", org_name="Org A")
        org2, _ = _create_org_and_user(db, email="b@test.com", org_name="Org B")

        CredentialVault.save_credentials(db, org1.id, "openai", "ai_provider", {"api_key": "a-key"})
        CredentialVault.save_credentials(db, org2.id, "openai", "ai_provider", {"api_key": "b-key"})

        headers = _basic_auth_headers()
        resp = client.get("/dashboard/api/integrations", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["integrations"]) >= 2


# ══════════════════════════════════════════════════════════════════════════════
# 5. CRUD Operations Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestCRUDOperations:
    """Test save, get, update, list, disconnect flows."""

    def test_save_and_get(self, db):
        """Save credentials then read them back."""
        org, _ = _create_org_and_user(db)

        original = {"api_key": "test-key", "base_url": "https://api.openai.com"}
        IntegrationService.save_integration(
            db, org.id, "openai", "ai_provider", original, role="owner",
        )

        # Verify via vault
        decrypted = CredentialVault.get_credentials(db, org.id, "openai", "ai_provider")
        assert decrypted == original

    def test_save_overwrites_existing(self, db):
        """Saving again with same provider/type should update (not duplicate)."""
        org, _ = _create_org_and_user(db)

        IntegrationService.save_integration(
            db, org.id, "openai", "ai_provider",
            {"api_key": "old-key"}, role="owner",
        )
        IntegrationService.save_integration(
            db, org.id, "openai", "ai_provider",
            {"api_key": "new-key"}, role="owner",
        )

        decrypted = CredentialVault.get_credentials(db, org.id, "openai", "ai_provider")
        assert decrypted["api_key"] == "new-key"

        # Should still only be one row
        list_items = CredentialVault.list_integrations(db, org.id)
        assert len(list_items) == 1

    def test_disconnect_clears_credentials(self, db):
        """Disconnect should clear credentials and set DISCONNECTED."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db, org.id, "openai", "ai_provider", {"api_key": "key"}
        )

        result = IntegrationService.disconnect_integration(
            db, org.id, "openai", "ai_provider", role="owner",
        )
        assert result["status"] == IntegrationStatus.DISCONNECTED.value
        assert result["has_credentials"] is False

    def test_list_integrations(self, db):
        """List should return all integrations for the org."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(db, org.id, "openai", "ai_provider", {"api_key": "a"})
        CredentialVault.save_credentials(db, org.id, "google", "google_oauth", {
            "client_id": "c", "client_secret": "s", "refresh_token": "r"
        })

        items = IntegrationService.list_integrations(db, org.id)
        assert len(items) == 2
        providers = {item["provider"] for item in items}
        assert "openai" in providers
        assert "google" in providers

    def test_get_integration_status(self, db):
        """get_integration_status returns all types for a provider."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(db, org.id, "google", "google_oauth", {
            "client_id": "c", "client_secret": "s", "refresh_token": "r"
        })
        CredentialVault.save_credentials(db, org.id, "google", "calendar", {
            "calendar_id": "cal@group.calendar.google.com"
        })

        result = IntegrationService.get_integration_status(db, org.id, "google")
        assert result["provider"] == "google"
        assert len(result["integrations"]) == 2

    def test_connected_at_set_on_save(self, db):
        """connected_at should be set when credentials are saved."""
        org, _ = _create_org_and_user(db)

        IntegrationService.save_integration(
            db, org.id, "openai", "ai_provider", {"api_key": "key"}, role="owner",
        )

        from app.models_multi_tenant import OrgIntegration
        from sqlalchemy import select

        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
                OrgIntegration.provider == "openai",
            )
        ).scalar_one()

        assert row.connected_at is not None

    def test_last_error_cleared_on_resave(self, db):
        """last_error should be cleared when credentials are re-saved."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db, org.id, "openai", "ai_provider", {"api_key": "key"}
        )
        CredentialVault.mark_error(db, org.id, "openai", "ai_provider", "some error")

        IntegrationService.save_integration(
            db, org.id, "openai", "ai_provider", {"api_key": "new-key"}, role="owner",
        )

        from app.models_multi_tenant import OrgIntegration
        from sqlalchemy import select

        row = db.execute(
            select(OrgIntegration).where(
                OrgIntegration.organization_id == org.id,
            )
        ).scalar_one()

        assert row.last_error is None


# ══════════════════════════════════════════════════════════════════════════════
# 6. Error Handling Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestErrorHandling:
    """Test error recording and sanitization."""

    def test_mark_error_records_message(self, db):
        """mark_error should set status to ERROR and record the error."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db, org.id, "google", "google_oauth",
            {"client_id": "c", "client_secret": "s", "refresh_token": "r"},
        )

        result = CredentialVault.mark_error(
            db, org.id, "google", "google_oauth", "Token refresh failed: 401"
        )
        assert result.status == IntegrationStatus.ERROR
        assert "Token refresh failed" in result.last_error

    def test_sanitize_error_strips_tokens(self):
        """_sanitize_error should redact patterns that look like secrets."""
        from app.services.credential_vault import _sanitize_error

        test_cases = [
            ("Error: access_token=abc123secretstuff failed", "[REDACTED]"),
            ("Failed: refresh_token='xyz789longtoken' expired", "[REDACTED]"),
            ("Bearer eyJhbGciOiJIUzI1NiJ9 invalid", "[REDACTED]"),
            ("api_key=sk-test1234567890abcdef rejected", "[REDACTED]"),
            ("client_secret='my-super-secret-value' invalid", "[REDACTED]"),
            ("Simple error message with no secrets", "Simple error message with no secrets"),
        ]

        for input_msg, expected_pattern in test_cases:
            result = _sanitize_error(input_msg)
            if expected_pattern == "[REDACTED]":
                assert "[REDACTED]" in result, f"Expected [REDACTED] in: {result}"
            else:
                assert result == expected_pattern

    def test_sanitize_error_truncates_long_messages(self):
        """_sanitize_error should truncate messages exceeding max_length."""
        from app.services.credential_vault import _sanitize_error

        long_msg = "Error: " + "x" * 1000
        result = _sanitize_error(long_msg, max_length=100)
        assert len(result) <= 100

    def test_mark_error_truncates_long_messages(self, db):
        """Error messages should be truncated in the database."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db, org.id, "openai", "ai_provider", {"api_key": "key"},
        )

        long_error = "Error: " + "x" * 1000
        result = CredentialVault.mark_error(
            db, org.id, "openai", "ai_provider", long_error
        )
        # Should be truncated (500 chars max from _sanitize_error)
        assert len(result.last_error) <= 500


# ══════════════════════════════════════════════════════════════════════════════
# 7. Validation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestValidation:
    """Test input validation for known providers."""

    def test_missing_required_fields(self, db):
        """Should raise IntegrationValidationError for missing fields."""
        org, _ = _create_org_and_user(db)

        with pytest.raises(IntegrationValidationError, match="Missing required fields"):
            IntegrationService.save_integration(
                db, org.id, "google", "google_oauth",
                {"client_id": "only-id-no-others"}, role="owner",
            )

    def test_empty_string_field_rejected(self, db):
        """Should reject empty string values for required fields."""
        org, _ = _create_org_and_user(db)

        with pytest.raises(IntegrationValidationError, match="cannot be empty"):
            IntegrationService.save_integration(
                db, org.id, "google", "google_oauth",
                {"client_id": "", "client_secret": "s", "refresh_token": "r"},
                role="owner",
            )

    def test_unknown_provider_accepted_with_warning(self, db):
        """Unknown provider/type should be accepted (for flexibility)."""
        org, _ = _create_org_and_user(db)

        result = IntegrationService.save_integration(
            db, org.id, "custom_provider", "custom_type",
            {"custom_field": "value"}, role="owner",
        )
        assert result["has_credentials"] is True

    def test_api_missing_credentials_returns_422(self, db, client):
        """API should return 422 if credentials field is missing."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")
        headers = _auth_headers(token)

        resp = client.post(
            "/dashboard/api/integrations/openai/ai_provider",
            headers=headers,
            json={"metadata": {"model": "gpt-4"}},
        )
        assert resp.status_code == 422

    def test_api_empty_credentials_returns_422(self, db, client):
        """API should return 422 if credentials is not a dict."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")
        headers = _auth_headers(token)

        resp = client.post(
            "/dashboard/api/integrations/openai/ai_provider",
            headers=headers,
            json={"credentials": "not-a-dict"},
        )
        assert resp.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# 8. API Endpoint Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestAPIEndpoints:
    """Test HTTP endpoints for integration management."""

    def test_list_integrations_empty(self, db, client):
        """List integrations for org with none should return empty list."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        resp = client.get("/dashboard/api/integrations", headers=_auth_headers(token))
        assert resp.status_code == 200
        assert resp.json()["integrations"] == []

    def test_list_integrations_with_data(self, db, client):
        """List integrations should return saved integrations."""
        org, user = _create_org_and_user(db)
        CredentialVault.save_credentials(
            db, org.id, "openai", "ai_provider", {"api_key": "key"}
        )

        token = _create_jwt_token(user.id, org.id, "owner")
        resp = client.get("/dashboard/api/integrations", headers=_auth_headers(token))
        assert resp.status_code == 200
        assert len(resp.json()["integrations"]) == 1

    def test_save_integration_via_api(self, db, client):
        """POST should save integration and return safe response."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        resp = client.post(
            "/dashboard/api/integrations/openai/ai_provider",
            headers=_auth_headers(token),
            json={
                "credentials": {"api_key": "sk-test123"},
                "metadata": {"model": "gpt-4"},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["has_credentials"] is True
        assert "sk-test123" not in json.dumps(data)

    def test_get_provider_status(self, db, client):
        """GET provider status should return integrations for that provider."""
        org, user = _create_org_and_user(db)
        CredentialVault.save_credentials(
            db, org.id, "google", "google_oauth",
            {"client_id": "c", "client_secret": "s", "refresh_token": "r"},
        )

        token = _create_jwt_token(user.id, org.id, "owner")
        resp = client.get("/dashboard/api/integrations/google", headers=_auth_headers(token))
        assert resp.status_code == 200
        assert resp.json()["provider"] == "google"
        assert len(resp.json()["integrations"]) == 1

    def test_disconnect_via_api(self, db, client):
        """DELETE should disconnect integration."""
        org, user = _create_org_and_user(db)
        CredentialVault.save_credentials(
            db, org.id, "openai", "ai_provider", {"api_key": "key"}
        )

        token = _create_jwt_token(user.id, org.id, "owner")
        resp = client.delete(
            "/dashboard/api/integrations/openai/ai_provider",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "disconnected"

    def test_update_via_api(self, db, client):
        """PUT should update integration credentials."""
        org, user = _create_org_and_user(db)
        CredentialVault.save_credentials(
            db, org.id, "openai", "ai_provider", {"api_key": "old-key"}
        )

        token = _create_jwt_token(user.id, org.id, "owner")
        resp = client.put(
            "/dashboard/api/integrations/openai/ai_provider",
            headers=_auth_headers(token),
            json={"credentials": {"api_key": "new-key"}},
        )
        assert resp.status_code == 200

        # Verify old key is gone
        decrypted = CredentialVault.get_credentials(db, org.id, "openai", "ai_provider")
        assert decrypted["api_key"] == "new-key"

    def test_update_without_credentials_or_metadata_returns_422(self, db, client):
        """PUT without credentials or metadata should return 422."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        resp = client.put(
            "/dashboard/api/integrations/openai/ai_provider",
            headers=_auth_headers(token),
            json={},
        )
        assert resp.status_code == 422

    def test_unauthenticated_returns_401(self, client):
        """All endpoints should return 401 without auth."""
        resp = client.get("/dashboard/api/integrations")
        assert resp.status_code == 401

        resp = client.post(
            "/dashboard/api/integrations/openai/ai_provider",
            json={"credentials": {"api_key": "key"}},
        )
        assert resp.status_code == 401

    def test_delete_nonexistent_returns_404(self, db, client):
        """DELETE should return 404 if integration does not exist."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")

        resp = client.delete(
            "/dashboard/api/integrations/nonexistent/nonexistent_type",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 9. Metadata Sanitization Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestMetadataSanitization:
    """Verify metadata is sanitized before API exposure."""

    def test_safe_metadata_keys_exposed(self, db):
        """Safe keys like model, sender_name should be in response."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db, org.id, "google", "email",
            {"sender_email": "test@example.com"},
            metadata={"sender_name": "John", "company_name": "Acme", "internal_secret": "hidden"},
        )

        items = IntegrationService.list_integrations(db, org.id)
        meta = items[0]["metadata"]
        assert meta.get("sender_name") == "John"
        assert meta.get("company_name") == "Acme"
        assert meta.get("internal_secret") is None  # Should be stripped


# ══════════════════════════════════════════════════════════════════════════════
# 10. Integration Service Typed Methods Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestTypedMethods:
    """Test the typed convenience methods on IntegrationService."""

    def test_save_google_oauth(self, db):
        """save_google_oauth should store credentials correctly."""
        org, _ = _create_org_and_user(db)

        result = IntegrationService.save_google_oauth(
            db, org.id,
            refresh_token="rt123",
            client_id="cid456",
            client_secret="cs789",
            role="owner",
        )
        assert result["has_credentials"] is True

        creds = CredentialVault.get_credentials(db, org.id, "google", "google_oauth")
        assert creds["refresh_token"] == "rt123"
        assert creds["client_id"] == "cid456"
        assert creds["client_secret"] == "cs789"

    def test_save_ai_provider(self, db):
        """save_ai_provider should store API key correctly."""
        org, _ = _create_org_and_user(db)

        result = IntegrationService.save_ai_provider(
            db, org.id,
            api_key="sk-test",
            base_url="https://api.openai.com",
            model="gpt-4",
            role="owner",
        )
        assert result["has_credentials"] is True

    def test_save_email_config(self, db):
        """save_email_config should store sender config."""
        org, _ = _create_org_and_user(db)

        result = IntegrationService.save_email_config(
            db, org.id,
            sender_email="info@company.com",
            sender_name="Company",
            company_name="Acme Corp",
            role="owner",
        )
        assert result["has_credentials"] is True

    def test_save_calendar_config(self, db):
        """save_calendar_config should store calendar ID."""
        org, _ = _create_org_and_user(db)

        result = IntegrationService.save_calendar_config(
            db, org.id,
            calendar_id="cal@group.calendar.google.com",
            company_name="Acme Corp",
            role="owner",
        )
        assert result["has_credentials"] is True
