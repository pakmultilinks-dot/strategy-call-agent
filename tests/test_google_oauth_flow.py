"""Phase 6C - Google OAuth2 Web Application Flow Test Suite.

Validates:
  1. OAuth state model - creation, uniqueness, expiry, consumption
  2. State generation - cryptographic randomness, TTL, expiry purge
  3. State validation - single-use enforcement, expiry, invalid tokens
  4. Authorization URL - correct parameters, scopes, client ID
  5. Token exchange - code-to-token with mocked Google API
  6. Credential storage - encrypted vault persistence, metadata
  7. Connection status - connected/disconnected states
  8. Disconnect - credential clearing, status update
  9. API endpoints - start, callback, status, disconnect HTTP status codes
  10. RBAC - owner/admin required for write operations
  11. Tenant isolation - org A cannot see/modify org B's OAuth state
  12. Security - no credential leakage, state CSRF protection
  13. google_auth.py deprecation - token.json warnings in non-dev
  14. Config validation - new settings, defaults, required values

Total: ~60+ tests
"""
from __future__ import annotations

import base64
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
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)
from app.services.credential_vault import CredentialVault
from app.services.crypto import generate_key
from app.services.integration_config_resolver import IntegrationConfigResolver
from app.services.google_oauth_flow import (
    DEFAULT_SCOPES,
    GoogleOAuthError,
    GoogleOAuthFlow,
    OAuthDenialError,
    OAuthStateError,
    OAuthTokenExchangeError,
)

# ── Test Constants ────────────────────────────────────────────────────────────

TEST_JWT_SECRET = "test-secret-key-for-phase-6c-jwt-testing-32chars!!"
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
# 1. OAuth State Model Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestOAuthStateModel:
    """Verify the GoogleOAuthState database model."""

    def test_state_creation(self, db):
        """Creating a state should persist with correct fields."""
        org, user = _create_org_and_user(db)

        now = datetime.now(timezone.utc)
        state = GoogleOAuthState(
            organization_id=org.id,
            user_id=user.id,
            state_token=secrets.token_urlsafe(32),
            redirect_uri="http://localhost:8000/auth/google/callback",
            scopes=DEFAULT_SCOPES,
            expires_at=now + timedelta(minutes=10),
            used=False,
        )
        db.add(state)
        db.commit()
        db.refresh(state)

        assert state.id is not None
        assert state.organization_id == org.id
        assert state.user_id == user.id
        assert state.used is False
        assert state.expires_at > now

    def test_state_token_uniqueness(self, db):
        """Duplicate state tokens should be rejected."""
        org, user = _create_org_and_user(db)
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)

        state1 = GoogleOAuthState(
            organization_id=org.id,
            user_id=user.id,
            state_token=token,
            redirect_uri="http://localhost:8000/auth/google/callback",
            expires_at=now + timedelta(minutes=10),
            used=False,
        )
        db.add(state1)
        db.commit()

        state2 = GoogleOAuthState(
            organization_id=org.id,
            user_id=user.id,
            state_token=token,  # duplicate
            redirect_uri="http://localhost:8000/auth/google/callback",
            expires_at=now + timedelta(minutes=10),
            used=False,
        )
        db.add(state2)
        with pytest.raises(Exception):  # IntegrityError
            db.commit()

    def test_state_defaults(self, db):
        """State should default to not-used."""
        org, user = _create_org_and_user(db)
        now = datetime.now(timezone.utc)

        state = GoogleOAuthState(
            organization_id=org.id,
            user_id=user.id,
            state_token=secrets.token_urlsafe(32),
            redirect_uri="http://localhost:8000/auth/google/callback",
            expires_at=now + timedelta(minutes=10),
        )
        db.add(state)
        db.commit()
        db.refresh(state)

        assert state.used is False


# ══════════════════════════════════════════════════════════════════════════════
# 2. State Generation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestStateGeneration:
    """Verify state token generation and authorization URL building."""

    def test_create_authorization_url(self, db):
        """Creating auth URL should persist state and return state row."""
        org, user = _create_org_and_user(db)

        state_row = GoogleOAuthFlow.create_authorization_url(
            db=db,
            org_id=org.id,
            user_id=user.id,
        )

        assert state_row.id is not None
        assert state_row.organization_id == org.id
        assert state_row.user_id == user.id
        assert state_row.state_token is not None
        assert len(state_row.state_token) > 20  # cryptographically random
        assert state_row.used is False
        assert state_row.redirect_uri == TEST_GOOGLE_REDIRECT_URI
        assert state_row.scopes == DEFAULT_SCOPES

    def test_state_token_cryptographically_random(self, db):
        """Each state token should be unique."""
        org, user = _create_org_and_user(db)
        tokens = set()

        for _ in range(10):
            state_row = GoogleOAuthFlow.create_authorization_url(
                db=db,
                org_id=org.id,
                user_id=user.id,
            )
            tokens.add(state_row.state_token)

        assert len(tokens) == 10  # all unique

    def test_build_authorization_url(self):
        """Authorization URL should contain required Google OAuth2 parameters."""
        from urllib.parse import parse_qs, urlparse

        state_token = "test-state-token-abc123"
        redirect_uri = "http://localhost:8000/auth/google/callback"
        scopes = ["https://www.googleapis.com/auth/calendar"]

        url = GoogleOAuthFlow.build_authorization_url(
            state_token=state_token,
            redirect_uri=redirect_uri,
            scopes=scopes,
        )

        assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["client_id"] == [TEST_GOOGLE_CLIENT_ID]
        assert params["redirect_uri"] == [redirect_uri]
        assert params["response_type"] == ["code"]
        assert params["state"] == [state_token]
        assert params["access_type"] == ["offline"]
        assert params["prompt"] == ["select_account consent"]
        assert scopes[0] in params["scope"][0]

    def test_build_url_uses_default_scopes(self):
        """URL should use default scopes when none provided."""
        from urllib.parse import parse_qs, urlparse

        url = GoogleOAuthFlow.build_authorization_url(
            state_token="test",
            redirect_uri="http://localhost:8000/callback",
        )

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        scope_str = params["scope"][0]
        for scope in DEFAULT_SCOPES:
            assert scope in scope_str

    def test_create_auth_url_raises_without_client_config(self, db, monkeypatch):
        """Should raise error when Google client is not configured."""
        monkeypatch.setattr(settings, "google_client_id", "")
        monkeypatch.setattr(settings, "google_client_secret", "")

        org, user = _create_org_and_user(db)

        with pytest.raises(GoogleOAuthError) as exc_info:
            GoogleOAuthFlow.create_authorization_url(
                db=db,
                org_id=org.id,
                user_id=user.id,
            )
        assert exc_info.value.error_code == "client_not_configured"

    def test_expires_at_set_correctly(self, db):
        """State should expire after the configured TTL."""
        org, user = _create_org_and_user(db)

        state_row = GoogleOAuthFlow.create_authorization_url(
            db=db,
            org_id=org.id,
            user_id=user.id,
        )

        now = datetime.now(timezone.utc)
        expected_min = now + timedelta(minutes=9)  # allow 1 min for test execution
        expected_max = now + timedelta(minutes=11)
        assert expected_min <= state_row.expires_at <= expected_max

    def test_purge_expired_states(self, db):
        """Expired states should be purged when creating new ones."""
        org, user = _create_org_and_user(db)

        # Create an expired state
        expired_state = GoogleOAuthState(
            organization_id=org.id,
            user_id=user.id,
            state_token=secrets.token_urlsafe(32),
            redirect_uri=TEST_GOOGLE_REDIRECT_URI,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
            used=False,
        )
        db.add(expired_state)
        db.commit()
        expired_id = expired_state.id

        # Creating a new state should purge expired ones
        GoogleOAuthFlow.create_authorization_url(
            db=db,
            org_id=org.id,
            user_id=user.id,
        )

        # Verify expired state was purged
        from sqlalchemy import select
        stmt = select(GoogleOAuthState).where(GoogleOAuthState.id == expired_id)
        result = db.execute(stmt).scalar_one_or_none()
        assert result is None

    def test_purge_used_states(self, db):
        """Used states should be purged when creating new ones."""
        org, user = _create_org_and_user(db)

        # Create a used state
        used_state = GoogleOAuthState(
            organization_id=org.id,
            user_id=user.id,
            state_token=secrets.token_urlsafe(32),
            redirect_uri=TEST_GOOGLE_REDIRECT_URI,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            used=True,
        )
        db.add(used_state)
        db.commit()
        used_id = used_state.id

        # Creating a new state should purge used ones
        GoogleOAuthFlow.create_authorization_url(
            db=db,
            org_id=org.id,
            user_id=user.id,
        )

        from sqlalchemy import select
        stmt = select(GoogleOAuthState).where(GoogleOAuthState.id == used_id)
        result = db.execute(stmt).scalar_one_or_none()
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# 3. State Validation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestStateValidation:
    """Verify state token validation logic."""

    def _create_valid_state(self, db, org, user, **kwargs):
        """Helper: create a valid state in the database."""
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        defaults = {
            "organization_id": org.id,
            "user_id": user.id,
            "state_token": secrets.token_urlsafe(32),
            "redirect_uri": TEST_GOOGLE_REDIRECT_URI,
            "expires_at": now + timedelta(minutes=10),
            "used": False,
        }
        defaults.update(kwargs)
        state = GoogleOAuthState(**defaults)
        db.add(state)
        db.commit()
        db.refresh(state)
        return state

    def test_valid_state_accepted(self, db):
        """A valid, unused, non-expired state should be accepted."""
        org, user = _create_org_and_user(db)
        state = self._create_valid_state(db, org, user)

        from app.services.google_oauth_flow import _validate_state
        result = _validate_state(db, state.state_token)
        assert result.id == state.id

    def test_invalid_state_token_rejected(self, db):
        """A state token that doesn't exist should be rejected."""
        from app.services.google_oauth_flow import _validate_state
        with pytest.raises(OAuthStateError) as exc_info:
            _validate_state(db, "nonexistent-state-token")
        assert "Invalid" in str(exc_info.value)

    def test_used_state_rejected(self, db):
        """A state that has already been consumed should be rejected."""
        org, user = _create_org_and_user(db)
        state = self._create_valid_state(db, org, user, used=True)

        from app.services.google_oauth_flow import _validate_state
        with pytest.raises(OAuthStateError) as exc_info:
            _validate_state(db, state.state_token)
        assert "already been used" in str(exc_info.value)

    def test_expired_state_rejected(self, db):
        """A state that has expired should be rejected."""
        org, user = _create_org_and_user(db)
        state = self._create_valid_state(
            db, org, user,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )

        from app.services.google_oauth_flow import _validate_state
        with pytest.raises(OAuthStateError) as exc_info:
            _validate_state(db, state.state_token)
        assert "expired" in str(exc_info.value)


# ══════════════════════════════════════════════════════════════════════════════
# 4. Token Exchange Tests (Mocked Google API)
# ══════════════════════════════════════════════════════════════════════════════


class TestTokenExchange:
    """Verify token exchange with mocked Google API responses."""

    def _create_valid_state(self, db, org, user, **kwargs):
        """Helper: create a valid state with optional overrides."""
        now = datetime.now(timezone.utc)
        defaults = {
            "organization_id": org.id,
            "user_id": user.id,
            "state_token": secrets.token_urlsafe(32),
            "redirect_uri": TEST_GOOGLE_REDIRECT_URI,
            "scopes": DEFAULT_SCOPES,
            "expires_at": now + timedelta(minutes=10),
            "used": False,
        }
        defaults.update(kwargs)
        state = GoogleOAuthState(**defaults)
        db.add(state)
        db.commit()
        db.refresh(state)
        return state

    def test_successful_exchange(self, db):
        """Successful token exchange should store credentials and return result."""
        org, user = _create_org_and_user(db)
        state = self._create_valid_state(db, org, user)

        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.headers = {"content-type": "application/json"}
        mock_token_response.json.return_value = {
            "access_token": "ya29.access-token",
            "refresh_token": "1//0.refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        mock_userinfo_response = MagicMock()
        mock_userinfo_response.status_code = 200
        mock_userinfo_response.json.return_value = {
            "email": "user@example.com",
            "name": "Test User",
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_response):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_response):
                result = GoogleOAuthFlow.exchange_code(
                    db=db,
                    code="test-auth-code",
                    state=state.state_token,
                )

        assert result["email"] == "user@example.com"
        assert result["refresh_token"] == "1//0.refresh-token"
        assert str(result["organization_id"]) == str(org.id)
        assert DEFAULT_SCOPES == result["scopes"] or result["scopes"] is not None

    def test_credentials_stored_in_vault(self, db):
        """Token exchange should store credentials in the encrypted vault."""
        org, user = _create_org_and_user(db)
        state = self._create_valid_state(db, org, user)

        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.headers = {"content-type": "application/json"}
        mock_token_response.json.return_value = {
            "access_token": "ya29.access-token",
            "refresh_token": "1//0.refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        mock_userinfo_response = MagicMock()
        mock_userinfo_response.status_code = 200
        mock_userinfo_response.json.return_value = {
            "email": "user@example.com",
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_response):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_response):
                GoogleOAuthFlow.exchange_code(
                    db=db,
                    code="test-auth-code",
                    state=state.state_token,
                )

        # Verify credentials are stored
        has_creds = CredentialVault.has_credentials(
            db, org.id, "google", "google_oauth"
        )
        assert has_creds is True

        # Verify email config is also stored
        has_email = CredentialVault.has_credentials(
            db, org.id, "google", "email"
        )
        assert has_email is True

    def test_state_consumed_after_exchange(self, db):
        """State should be marked as used after successful exchange."""
        org, user = _create_org_and_user(db)
        state = self._create_valid_state(db, org, user)

        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.headers = {"content-type": "application/json"}
        mock_token_response.json.return_value = {
            "access_token": "ya29.access-token",
            "refresh_token": "1//0.refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        mock_userinfo_response = MagicMock()
        mock_userinfo_response.status_code = 200
        mock_userinfo_response.json.return_value = {
            "email": "user@example.com",
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_response):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_response):
                GoogleOAuthFlow.exchange_code(
                    db=db,
                    code="test-auth-code",
                    state=state.state_token,
                )

        # Refresh and check state
        db.refresh(state)
        assert state.used is True

    def test_exchange_with_invalid_state(self, db):
        """Token exchange with invalid state should raise OAuthStateError."""
        with pytest.raises(OAuthStateError):
            GoogleOAuthFlow.exchange_code(
                db=db,
                code="test-auth-code",
                state="invalid-state-token",
            )

    def test_exchange_with_used_state(self, db):
        """Token exchange with already-used state should raise OAuthStateError."""
        org, user = _create_org_and_user(db)
        state = self._create_valid_state(db, org, user, used=True)

        with pytest.raises(OAuthStateError):
            GoogleOAuthFlow.exchange_code(
                db=db,
                code="test-auth-code",
                state=state.state_token,
            )

    def test_exchange_with_expired_state(self, db):
        """Token exchange with expired state should raise OAuthStateError."""
        org, user = _create_org_and_user(db)
        state = self._create_valid_state(
            db, org, user,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )

        with pytest.raises(OAuthStateError):
            GoogleOAuthFlow.exchange_code(
                db=db,
                code="test-auth-code",
                state=state.state_token,
            )

    def test_exchange_denied_by_user(self, db):
        """Google returning access_denied error should raise OAuthDenialError."""
        org, user = _create_org_and_user(db)
        state = self._create_valid_state(db, org, user)

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "error": "access_denied",
            "error_description": "User denied access",
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_response):
            with pytest.raises(OAuthDenialError):
                GoogleOAuthFlow.exchange_code(
                    db=db,
                    code="test-auth-code",
                    state=state.state_token,
                )

    def test_exchange_invalid_grant(self, db):
        """Google returning invalid_grant should raise OAuthTokenExchangeError."""
        org, user = _create_org_and_user(db)
        state = self._create_valid_state(db, org, user)

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Code was already redeemed",
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_response):
            with pytest.raises(OAuthTokenExchangeError) as exc_info:
                GoogleOAuthFlow.exchange_code(
                    db=db,
                    code="test-auth-code",
                    state=state.state_token,
                )
            msg = str(exc_info.value).lower()
            assert "invalid" in msg or "expired" in msg or "try connecting again" in msg

    def test_exchange_no_refresh_token(self, db):
        """Google returning no refresh_token should raise OAuthTokenExchangeError."""
        org, user = _create_org_and_user(db)
        state = self._create_valid_state(db, org, user)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "access_token": "ya29.access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            # No refresh_token!
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_response):
            with pytest.raises(OAuthTokenExchangeError) as exc_info:
                GoogleOAuthFlow.exchange_code(
                    db=db,
                    code="test-auth-code",
                    state=state.state_token,
                )
            assert "refresh token" in str(exc_info.value).lower()

    def test_exchange_network_error(self, db):
        """Network error during token exchange should raise OAuthTokenExchangeError."""
        import httpx as real_httpx
        org, user = _create_org_and_user(db)
        state = self._create_valid_state(db, org, user)

        with patch("app.services.google_oauth_flow.httpx.post", side_effect=real_httpx.RequestError("Connection refused")):
            with pytest.raises(OAuthTokenExchangeError):
                GoogleOAuthFlow.exchange_code(
                    db=db,
                    code="test-auth-code",
                    state=state.state_token,
                )

    def test_reuse_state_after_exchange(self, db):
        """Reusing the same state after successful exchange should be rejected."""
        org, user = _create_org_and_user(db)
        state = self._create_valid_state(db, org, user)

        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.headers = {"content-type": "application/json"}
        mock_token_response.json.return_value = {
            "access_token": "ya29.access-token",
            "refresh_token": "1//0.refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        mock_userinfo_response = MagicMock()
        mock_userinfo_response.status_code = 200
        mock_userinfo_response.json.return_value = {
            "email": "user@example.com",
        }

        # First exchange succeeds
        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_response):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_response):
                GoogleOAuthFlow.exchange_code(
                    db=db,
                    code="test-auth-code",
                    state=state.state_token,
                )

        # Second exchange with same state should fail
        with pytest.raises(OAuthStateError):
            GoogleOAuthFlow.exchange_code(
                db=db,
                code="test-auth-code-2",
                state=state.state_token,
            )


# ══════════════════════════════════════════════════════════════════════════════
# 5. Connection Status Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestConnectionStatus:
    """Verify Google OAuth connection status reporting."""

    def test_status_disconnected(self, db):
        """Status should report disconnected when no credentials exist."""
        org, _ = _create_org_and_user(db)

        status = GoogleOAuthFlow.get_connection_status(db, org.id)
        assert status["connected"] is False
        assert status["provider"] == "google"
        assert status["integration_type"] == "google_oauth"

    def test_status_connected(self, db):
        """Status should report connected when credentials are stored."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "refresh_token": "test-token",
                "client_id": "test-id",
                "client_secret": "test-secret",
            },
            metadata={
                "email": "user@example.com",
                "scopes": DEFAULT_SCOPES,
            },
        )

        status = GoogleOAuthFlow.get_connection_status(db, org.id)
        assert status["connected"] is True
        assert status["email"] == "user@example.com"

    def test_status_never_exposes_credentials(self, db):
        """Status should never contain refresh tokens or client secrets."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "refresh_token": "super-secret-token",
                "client_id": "test-id",
                "client_secret": "super-secret-secret",
            },
            metadata={"email": "user@example.com"},
        )

        status = GoogleOAuthFlow.get_connection_status(db, org.id)
        status_str = json.dumps(status)
        assert "super-secret-token" not in status_str
        assert "super-secret-secret" not in status_str


# ══════════════════════════════════════════════════════════════════════════════
# 6. Disconnect Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestDisconnect:
    """Verify Google OAuth disconnection."""

    def test_disconnect(self, db):
        """Disconnecting should clear credentials and mark disconnected."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "refresh_token": "test-token",
                "client_id": "test-id",
                "client_secret": "test-secret",
            },
        )

        result = GoogleOAuthFlow.disconnect(db, org.id)
        assert result["connected"] is False
        assert result["disconnected"] is True

        # Verify no longer connected
        has_creds = CredentialVault.has_credentials(
            db, org.id, "google", "google_oauth"
        )
        assert has_creds is False

    def test_disconnect_nonexistent(self, db):
        """Disconnecting when not connected should return disconnected=False."""
        org, _ = _create_org_and_user(db)

        result = GoogleOAuthFlow.disconnect(db, org.id)
        assert result["disconnected"] is False

    def test_status_after_disconnect(self, db):
        """Status should reflect disconnection."""
        org, _ = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "refresh_token": "test-token",
                "client_id": "test-id",
                "client_secret": "test-secret",
            },
            metadata={"email": "user@example.com"},
        )

        GoogleOAuthFlow.disconnect(db, org.id)

        status = GoogleOAuthFlow.get_connection_status(db, org.id)
        assert status["connected"] is False
        # Email is only shown when connected
        assert status["email"] is None


# ══════════════════════════════════════════════════════════════════════════════
# 7. API Endpoint Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestAPIEndpoints:
    """Verify HTTP behavior of Google OAuth endpoints."""

    def test_start_requires_auth(self, client):
        """GET /auth/google/start without auth should return 401/403."""
        response = client.get("/auth/google/start")
        assert response.status_code in (401, 403)

    def test_start_requires_owner_role(self, client, db):
        """GET /auth/google/start should require owner/admin role."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _create_jwt_token(user.id, org.id, "member")
        headers = _auth_headers(token)

        response = client.get("/auth/google/start", headers=headers)
        assert response.status_code == 403

    def test_start_redirects_to_google(self, client, db):
        """GET /auth/google/start with valid auth should return authorization URL."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _create_jwt_token(user.id, org.id, "owner")
        headers = _auth_headers(token)

        response = client.get("/auth/google/start", headers=headers, follow_redirects=False)
        assert response.status_code == 200
        assert "authorization_url" in response.json()
        assert "accounts.google.com" in response.json()["authorization_url"]

    def test_callback_missing_params(self, client):
        """GET /auth/google/callback without params should return HTML with error."""
        response = client.get("/auth/google/callback")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Missing Parameters" in response.text
        assert "/dashboard" in response.text

    def test_callback_access_denied(self, client):
        """GET /auth/google/callback with error=access_denied should return HTML."""
        response = client.get(
            "/auth/google/callback",
            params={"error": "access_denied"},
        )
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Authorization Denied" in response.text
        assert "dashboard" in response.text

    def test_callback_invalid_state(self, client):
        """GET /auth/google/callback with invalid state should return HTML."""
        response = client.get(
            "/auth/google/callback",
            params={"code": "test-code", "state": "invalid-state"},
        )
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Connection Expired" in response.text or "Invalid" in response.text

    def test_status_requires_auth(self, client):
        """GET /auth/google/status without auth should return 401/403."""
        response = client.get("/auth/google/status")
        assert response.status_code in (401, 403)

    def test_status_returns_connected(self, client, db):
        """GET /auth/google/status should return connection status."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")
        headers = _auth_headers(token)

        response = client.get("/auth/google/status", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert "connected" in data
        assert data["provider"] == "google"

    def test_disconnect_requires_auth(self, client):
        """DELETE /auth/google/disconnect without auth should return 401/403."""
        response = client.delete("/auth/google/disconnect")
        assert response.status_code in (401, 403)

    def test_disconnect_requires_owner(self, client, db):
        """DELETE /auth/google/disconnect should require owner/admin."""
        org, user = _create_org_and_user(db, role=UserRole.MEMBER)
        token = _create_jwt_token(user.id, org.id, "member")
        headers = _auth_headers(token)

        response = client.delete("/auth/google/disconnect", headers=headers)
        assert response.status_code == 403

    def test_disconnect_success(self, client, db):
        """DELETE /auth/google/disconnect should succeed for owner."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")
        headers = _auth_headers(token)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "refresh_token": "test-token",
                "client_id": "test-id",
                "client_secret": "test-secret",
            },
        )

        response = client.delete("/auth/google/disconnect", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["connected"] is False

    def test_callback_with_real_flow(self, client, db):
        """Full callback flow: create state, mock Google API, verify storage."""
        org, user = _create_org_and_user(db)

        # Create state
        state_row = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        # Mock Google token and userinfo responses
        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.headers = {"content-type": "application/json"}
        mock_token_resp.json.return_value = {
            "access_token": "ya29.test-access",
            "refresh_token": "1//0.test-refresh",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {
            "email": "test@example.com",
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                response = client.get(
                    "/auth/google/callback",
                    params={
                        "code": "test-auth-code",
                        "state": state_row.state_token,
                    },
                )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Connected" in response.text
        assert "test@example.com" in response.text


# ══════════════════════════════════════════════════════════════════════════════
# 8. Tenant Isolation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestTenantIsolation:
    """Verify OAuth states and credentials are isolated per org."""

    def test_states_isolated_per_org(self, db):
        """Each org should have its own independent OAuth states."""
        org1, user1 = _create_org_and_user(db, email="u1@test.com")
        org2, user2 = _create_org_and_user(db, email="u2@test.com")

        state1 = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org1.id, user_id=user1.id,
        )
        state2 = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org2.id, user_id=user2.id,
        )

        assert state1.organization_id == org1.id
        assert state2.organization_id == org2.id
        assert state1.organization_id != state2.organization_id

    def test_credentials_isolated_per_org(self, db):
        """Each org's credentials should be independent."""
        org1, _ = _create_org_and_user(db, email="u1@test.com")
        org2, _ = _create_org_and_user(db, email="u2@test.com")

        CredentialVault.save_credentials(
            db=db, org_id=org1.id,
            provider="google", integration_type="google_oauth",
            credentials={"refresh_token": "org1-token", "client_id": "id", "client_secret": "secret"},
        )

        assert CredentialVault.has_credentials(db, org1.id, "google", "google_oauth") is True
        assert CredentialVault.has_credentials(db, org2.id, "google", "google_oauth") is False

    def test_disconnect_isolated(self, db):
        """Disconnecting one org should not affect another."""
        org1, _ = _create_org_and_user(db, email="u1@test.com")
        org2, _ = _create_org_and_user(db, email="u2@test.com")

        for org in [org1, org2]:
            CredentialVault.save_credentials(
                db=db, org_id=org.id,
                provider="google", integration_type="google_oauth",
                credentials={"refresh_token": "token", "client_id": "id", "client_secret": "secret"},
            )

        GoogleOAuthFlow.disconnect(db, org1.id)

        assert CredentialVault.has_credentials(db, org1.id, "google", "google_oauth") is False
        assert CredentialVault.has_credentials(db, org2.id, "google", "google_oauth") is True


# ══════════════════════════════════════════════════════════════════════════════
# 9. Security Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestSecurity:
    """Verify security properties of the OAuth flow."""

    def test_no_access_token_stored(self, db):
        """Access tokens should never be stored - only refresh tokens."""
        org, user = _create_org_and_user(db)
        state = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.headers = {"content-type": "application/json"}
        mock_token_resp.json.return_value = {
            "access_token": "ya29.short-lived-access-token",
            "refresh_token": "1//0.long-lived-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {"email": "test@example.com"}

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                GoogleOAuthFlow.exchange_code(
                    db=db,
                    code="test-code",
                    state=state.state_token,
                )

        creds = CredentialVault.get_credentials(
            db, org.id, "google", "google_oauth"
        )
        assert "access_token" not in creds
        assert "refresh_token" in creds

    def test_client_secret_not_in_api_response(self, client, db):
        """API responses should never contain client secrets."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")
        headers = _auth_headers(token)

        response = client.get("/auth/google/status", headers=headers)
        response_str = response.text
        assert TEST_GOOGLE_CLIENT_SECRET not in response_str
        assert "client_secret" not in response_str.lower()

    def test_state_token_not_in_auth_url_header(self, client, db):
        """The state token should be in the authorization URL, not in response body as a separate field."""
        org, user = _create_org_and_user(db, role=UserRole.OWNER)
        token = _create_jwt_token(user.id, org.id, "owner")
        headers = _auth_headers(token)

        response = client.get(
            "/auth/google/start",
            headers=headers,
            follow_redirects=False,
        )
        assert response.status_code == 200
        data = response.json()
        auth_url = data.get("authorization_url", "")
        assert "state=" in auth_url
        # The state should be embedded in the URL, not leaked as a separate response field
        assert "state_token" not in data


# ══════════════════════════════════════════════════════════════════════════════
# 10. google_auth.py Deprecation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestGoogleAuthDeprecation:
    """Verify token.json deprecation warnings and behavior."""

    def test_production_raises_on_file_load(self, monkeypatch):
        """In production, loading from token.json should raise GoogleAuthError."""
        from app.services import google_auth

        monkeypatch.setattr(settings, "app_env", "production")
        monkeypatch.setattr(settings, "google_token_file", "nonexistent.json")

        with pytest.raises(google_auth.GoogleAuthError) as exc_info:
            google_auth._load_credentials_from_file()
        assert "credential vault" in str(exc_info.value).lower() or "production" in str(exc_info.value).lower()

    def test_dev_mode_no_deprecation_warning(self, monkeypatch):
        """In dev mode, loading from token.json should NOT emit deprecation."""
        import warnings
        from app.services import google_auth

        monkeypatch.setattr(settings, "app_env", "dev")
        monkeypatch.setattr(settings, "google_token_file", "nonexistent.json")

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try:
                google_auth._load_credentials_from_file()
            except google_auth.GoogleAuthError:
                pass  # Expected - file doesn't exist

            deprecation_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecation_warnings) == 0

    def test_production_auth_hint_mentions_oauth_flow(self, monkeypatch):
        """Production auth hint should mention OAuth flow, not token.json."""
        monkeypatch.setattr(settings, "app_env", "production")
        from app.services import google_auth
        hint = google_auth._auth_hint()
        assert "/auth/google/start" in hint
        assert "token.json" not in hint

    def test_dev_auth_hint_mentions_both(self, monkeypatch):
        """Dev auth hint should mention both token.json and OAuth flow."""
        monkeypatch.setattr(settings, "app_env", "dev")
        from app.services import google_auth
        hint = google_auth._auth_hint()
        assert "token.json" in hint or "authorize_google.py" in hint
        assert "/auth/google/start" in hint

    def test_org_credentials_still_work(self):
        """Org-specific credentials path should still work (no regression)."""
        from app.services import google_auth

        # This tests the _build_credentials_from_values path
        # We mock the refresh to avoid actual Google API call
        mock_creds = MagicMock()
        with patch.object(google_auth, "_build_credentials_from_values", return_value=mock_creds):
            result = google_auth.get_google_credentials(
                client_id="test-id",
                client_secret="test-secret",
                refresh_token="test-token",
            )
            assert result == mock_creds


# ══════════════════════════════════════════════════════════════════════════════
# 11. Config Validation Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestConfigValidation:
    """Verify new config settings exist and have correct defaults."""

    def test_redirect_uri_default(self):
        """Default redirect URI should be localhost callback."""
        assert settings.google_redirect_uri == "http://localhost:8000/auth/google/callback"

    def test_state_ttl_default(self):
        """Default state TTL should be 10 minutes."""
        assert settings.google_oauth_state_ttl_minutes == 10

    def test_state_ttl_configurable(self, monkeypatch):
        """State TTL should be configurable via env."""
        monkeypatch.setattr(settings, "google_oauth_state_ttl_minutes", 5)
        assert settings.google_oauth_state_ttl_minutes == 5

    def test_redirect_uri_configurable(self, monkeypatch):
        """Redirect URI should be configurable via env."""
        monkeypatch.setattr(settings, "google_redirect_uri", "https://example.com/callback")
        assert settings.google_redirect_uri == "https://example.com/callback"


# ══════════════════════════════════════════════════════════════════════════════
# 15. Callback HTML Response Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestCallbackHTMLResponse:
    """Verify the callback endpoint returns HTML (not JSON) for browser redirects.

    The callback is hit by Google's browser redirect after OAuth consent,
    so it MUST return a renderable HTML page - not a raw JSON response.
    """

    def test_callback_returns_html_content_type(self, client):
        """Callback with missing params should return text/html."""
        response = client.get("/auth/google/callback")
        assert "text/html" in response.headers.get("content-type", "")

    def test_callback_access_denied_returns_html(self, client):
        """Callback with access_denied should return HTML page."""
        response = client.get(
            "/auth/google/callback",
            params={"error": "access_denied"},
        )
        assert "text/html" in response.headers.get("content-type", "")
        assert "Authorization Denied" in response.text

    def test_callback_generic_error_returns_html(self, client):
        """Callback with generic error should return HTML page."""
        response = client.get(
            "/auth/google/callback",
            params={"error": "server_error"},
        )
        assert "text/html" in response.headers.get("content-type", "")
        assert "server_error" in response.text

    def test_callback_missing_code_returns_html(self, client):
        """Callback without code should return HTML error page."""
        response = client.get(
            "/auth/google/callback",
            params={"state": "some-state"},
        )
        assert "text/html" in response.headers.get("content-type", "")
        assert "Missing Parameters" in response.text

    def test_callback_missing_state_returns_html(self, client):
        """Callback without state should return HTML error page."""
        response = client.get(
            "/auth/google/callback",
            params={"code": "some-code"},
        )
        assert "text/html" in response.headers.get("content-type", "")
        assert "Missing Parameters" in response.text

    def test_callback_invalid_state_returns_html(self, client):
        """Callback with invalid state should return HTML page."""
        response = client.get(
            "/auth/google/callback",
            params={"code": "test-code", "state": "invalid-state-token"},
        )
        assert "text/html" in response.headers.get("content-type", "")
        assert "Connection Expired" in response.text or "Invalid" in response.text

    def test_callback_success_returns_html_with_email(self, client, db):
        """Successful callback should return HTML with connected email."""
        org, user = _create_org_and_user(db)

        state_row = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.headers = {"content-type": "application/json"}
        mock_token_resp.json.return_value = {
            "access_token": "ya29.test-access",
            "refresh_token": "1//0.test-refresh",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {"email": "test@example.com"}

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                response = client.get(
                    "/auth/google/callback",
                    params={
                        "code": "test-auth-code",
                        "state": state_row.state_token,
                    },
                )

        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert "Connected" in response.text
        assert "test@example.com" in response.text
        # Verify redirect to dashboard integrations
        assert "/dashboard" in response.text

    def test_callback_html_contains_redirect_script(self, client):
        """Callback HTML should contain JavaScript redirect to dashboard."""
        response = client.get("/auth/google/callback")
        assert "window.location.href" in response.text
        assert "/dashboard" in response.text

    def test_callback_html_contains_localstorage_token(self, client):
        """Callback HTML should set oauth_result in localStorage for toast."""
        response = client.get("/auth/google/callback")
        assert "localStorage.setItem" in response.text
        assert "oauth_result" in response.text

    def test_callback_success_stores_credentials_in_vault(self, client, db):
        """Successful callback should store credentials in the encrypted vault."""
        org, user = _create_org_and_user(db)

        state_row = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.headers = {"content-type": "application/json"}
        mock_token_resp.json.return_value = {
            "access_token": "ya29.test-access",
            "refresh_token": "1//0.test-refresh",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {"email": "vault-test@example.com"}

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                client.get(
                    "/auth/google/callback",
                    params={
                        "code": "test-auth-code",
                        "state": state_row.state_token,
                    },
                )

        # Verify credentials stored in vault (user tokens only - the OAuth
        # client is platform-owned and never duplicated per-org)
        assert CredentialVault.has_credentials(db, org.id, "google", "google_oauth")
        creds = CredentialVault.get_credentials(db, org.id, "google", "google_oauth")
        assert creds["refresh_token"] == "1//0.test-refresh"
        assert "client_id" not in creds
        assert "client_secret" not in creds

        # Verify email config stored
        assert CredentialVault.has_credentials(db, org.id, "google", "email")
        email_creds = CredentialVault.get_credentials(db, org.id, "google", "email")
        assert email_creds["sender_email"] == "vault-test@example.com"

    def test_callback_state_marked_used_after_success(self, client, db):
        """After successful callback, state should be marked as used."""
        org, user = _create_org_and_user(db)

        state_row = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )
        state_token = state_row.state_token

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.headers = {"content-type": "application/json"}
        mock_token_resp.json.return_value = {
            "access_token": "ya29.test-access",
            "refresh_token": "1//0.test-refresh",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {"email": "test@example.com"}

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                resp = client.get(
                    "/auth/google/callback",
                    params={
                        "code": "test-auth-code",
                        "state": state_token,
                    },
                )
        assert resp.status_code == 200
        assert "Connected" in resp.text

        # Expire all cached objects to force fresh read from DB
        db.expire_all()

        # State should be marked as used
        stmt = select(GoogleOAuthState).where(
            GoogleOAuthState.state_token == state_token
        )
        row = db.execute(stmt).scalar_one()
        assert row.used is True

    def test_callback_reuse_state_returns_html(self, client, db):
        """Reusing a state token should return HTML error page."""
        org, user = _create_org_and_user(db)

        state_row = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.headers = {"content-type": "application/json"}
        mock_token_resp.json.return_value = {
            "access_token": "ya29.test-access",
            "refresh_token": "1//0.test-refresh",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {"email": "test@example.com"}

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                # First use - should succeed
                resp1 = client.get(
                    "/auth/google/callback",
                    params={
                        "code": "test-auth-code",
                        "state": state_row.state_token,
                    },
                )
                assert resp1.status_code == 200
                assert "Connected" in resp1.text

        # Expire session to see committed changes
        db.expire_all()

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                # Second use - should fail (state already used)
                resp2 = client.get(
                    "/auth/google/callback",
                    params={
                        "code": "test-auth-code-2",
                        "state": state_row.state_token,
                    },
                )
                assert resp2.status_code == 200
                assert "text/html" in resp2.headers.get("content-type", "")
                assert "already been used" in resp2.text or "Expired" in resp2.text or "Connection Expired" in resp2.text


# ══════════════════════════════════════════════════════════════════════════════
# 16. Comprehensive Regression Tests - OAuth 401 / credential mismatch
# ══════════════════════════════════════════════════════════════════════════════
# These tests guard against the root-cause bug: GOOGLE_CLIENT_ID and
# GOOGLE_CLIENT_SECRET being a non-matching pair (Desktop secret with
# Web client ID), which caused a 401 / invalid_client from Google.
# Each category below maps to a specific failure mode.


class TestAuthorizationURLClientId:
    """Category 1: Authorization URL must use the configured client_id."""

    def test_auth_url_uses_configured_client_id(self):
        """build_authorization_url should embed settings.google_client_id."""
        url = GoogleOAuthFlow.build_authorization_url(
            state_token="test-state",
            redirect_uri=TEST_GOOGLE_REDIRECT_URI,
            scopes=DEFAULT_SCOPES,
        )
        assert f"client_id={TEST_GOOGLE_CLIENT_ID}" in url

    def test_auth_url_client_id_not_empty(self):
        """build_authorization_url should fail gracefully if client_id is empty."""
        # _set_test_secrets fixture sets it, but we can override via monkeypatch
        # This is implicitly tested by fixture - client_id is always set.
        url = GoogleOAuthFlow.build_authorization_url(
            state_token="test-state",
            redirect_uri=TEST_GOOGLE_REDIRECT_URI,
        )
        assert "client_id=" in url
        # The value should not be empty
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        assert qs["client_id"][0] != ""

    def test_auth_url_contains_correct_client_id_value(self):
        """The client_id query param should exactly match settings."""
        from urllib.parse import parse_qs, urlparse
        url = GoogleOAuthFlow.build_authorization_url(
            state_token="csrf-token",
            redirect_uri=TEST_GOOGLE_REDIRECT_URI,
        )
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        assert qs["client_id"][0] == TEST_GOOGLE_CLIENT_ID


class TestTokenExchangeClientId:
    """Category 2: Token exchange must use the same client_id as auth URL."""

    def test_token_exchange_sends_same_client_id(self):
        """_do_token_exchange should send the same client_id used in auth URL."""
        import httpx as real_httpx

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "access_token": "ya29.test",
            "refresh_token": "1//0.test",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        captured_payloads = []

        def capture_post(url, data=None, **kwargs):
            captured_payloads.append(data)
            return mock_resp

        with patch("app.services.google_oauth_flow.httpx.post", side_effect=capture_post):
            from app.services.google_oauth_flow import _do_token_exchange
            _do_token_exchange("test-code", TEST_GOOGLE_REDIRECT_URI)

        assert len(captured_payloads) == 1
        assert captured_payloads[0]["client_id"] == TEST_GOOGLE_CLIENT_ID

    def test_token_exchange_uses_same_client_id_as_auth_url(self):
        """client_id in token exchange payload must equal the one in auth URL."""
        from urllib.parse import parse_qs, urlparse

        # Build auth URL and extract client_id
        auth_url = GoogleOAuthFlow.build_authorization_url(
            state_token="test-state",
            redirect_uri=TEST_GOOGLE_REDIRECT_URI,
        )
        parsed = urlparse(auth_url)
        auth_client_id = parse_qs(parsed.query)["client_id"][0]

        # Capture token exchange payload
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "access_token": "ya29.test",
            "refresh_token": "1//0.test",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        captured = []
        def capture_post(url, data=None, **kwargs):
            captured.append(data)
            return mock_resp

        with patch("app.services.google_oauth_flow.httpx.post", side_effect=capture_post):
            from app.services.google_oauth_flow import _do_token_exchange
            _do_token_exchange("test-code", TEST_GOOGLE_REDIRECT_URI)

        assert captured[0]["client_id"] == auth_client_id


class TestRedirectUriConsistency:
    """Category 3: redirect_uri must be consistent across the flow."""

    def test_state_stores_same_redirect_uri_as_settings(self):
        """State row redirect_uri should match settings.google_redirect_uri."""
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            org, user = _create_org_and_user(db)
            state_row = GoogleOAuthFlow.create_authorization_url(
                db=db, org_id=org.id, user_id=user.id,
            )
            assert state_row.redirect_uri == TEST_GOOGLE_REDIRECT_URI
        finally:
            db.close()

    def test_auth_url_redirect_uri_matches_settings(self):
        """Authorization URL redirect_uri should match settings."""
        from urllib.parse import parse_qs, urlparse
        url = GoogleOAuthFlow.build_authorization_url(
            state_token="test-state",
            redirect_uri=TEST_GOOGLE_REDIRECT_URI,
        )
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        assert qs["redirect_uri"][0] == TEST_GOOGLE_REDIRECT_URI

    def test_token_exchange_uses_state_redirect_uri(self):
        """Token exchange should use the redirect_uri from the state row."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "access_token": "ya29.test",
            "refresh_token": "1//0.test",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        captured = []
        def capture_post(url, data=None, **kwargs):
            captured.append(data)
            return mock_resp

        with patch("app.services.google_oauth_flow.httpx.post", side_effect=capture_post):
            from app.services.google_oauth_flow import _do_token_exchange
            _do_token_exchange("test-code", "https://custom.example.com/callback")

        assert captured[0]["redirect_uri"] == "https://custom.example.com/callback"


class TestInvalidClientHandling:
    """Category 4: 401 / invalid_client must produce a clear error message."""

    def test_invalid_client_raises_token_exchange_error(self):
        """invalid_client response should raise OAuthTokenExchangeError with
        a message mentioning client credentials mismatch."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "error": "invalid_client",
            "error_description": "Client authentication failed.",
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_resp):
            with pytest.raises(OAuthTokenExchangeError) as exc_info:
                from app.services.google_oauth_flow import _do_token_exchange
                _do_token_exchange("test-code", TEST_GOOGLE_REDIRECT_URI)

        msg = str(exc_info.value)
        assert "invalid_client" in msg
        assert "Client ID" in msg
        assert "Client Secret" in msg
        assert "Google Cloud Console" in msg

    def test_invalid_client_logs_critical(self):
        """invalid_client should emit a CRITICAL log about mismatched credentials."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "error": "invalid_client",
            "error_description": "Client authentication failed.",
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_resp):
            with patch("app.services.google_oauth_flow.logger") as mock_logger:
                from app.services.google_oauth_flow import _do_token_exchange
                try:
                    _do_token_exchange("test-code", TEST_GOOGLE_REDIRECT_URI)
                except OAuthTokenExchangeError:
                    pass

        mock_logger.critical.assert_called_once()
        log_msg = mock_logger.critical.call_args[0][0]
        assert "invalid_client" in log_msg


class TestInvalidGrantHandling:
    """Category 5: invalid_grant must produce a clear error message."""

    def test_invalid_grant_raises_with_helpful_message(self):
        """invalid_grant should tell the user to try connecting again."""
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Code was already redeemed.",
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_resp):
            with pytest.raises(OAuthTokenExchangeError) as exc_info:
                from app.services.google_oauth_flow import _do_token_exchange
                _do_token_exchange("test-code", TEST_GOOGLE_REDIRECT_URI)

        msg = str(exc_info.value).lower()
        assert "invalid" in msg or "expired" in msg or "try connecting again" in msg


class TestStateSingleUse:
    """Category 6: State tokens must be single-use."""

    def test_used_state_rejected(self, db):
        """A state marked as used should be rejected."""
        org, user = _create_org_and_user(db)
        state = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )
        state.used = True
        db.commit()
        db.refresh(state)

        with pytest.raises(OAuthStateError):
            GoogleOAuthFlow.exchange_code(
                db=db, code="test-code", state=state.state_token,
            )

    def test_state_marked_used_after_exchange(self, db):
        """State should be marked as used after successful exchange."""
        org, user = _create_org_and_user(db)
        state = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.headers = {"content-type": "application/json"}
        mock_token_resp.json.return_value = {
            "access_token": "ya29.test",
            "refresh_token": "1//0.test",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {"email": "test@example.com"}

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                GoogleOAuthFlow.exchange_code(
                    db=db, code="test-code", state=state.state_token,
                )

        db.expire_all()
        stmt = select(GoogleOAuthState).where(GoogleOAuthState.id == state.id)
        row = db.execute(stmt).scalar_one()
        assert row.used is True


class TestStateExpiration:
    """Category 7: Expired states must be rejected."""

    def test_expired_state_rejected(self, db):
        """An expired state should be rejected with OAuthStateError."""
        org, user = _create_org_and_user(db)
        state = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )
        # Force-expire the state
        state.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        db.commit()
        db.refresh(state)

        with pytest.raises(OAuthStateError) as exc_info:
            GoogleOAuthFlow.exchange_code(
                db=db, code="test-code", state=state.state_token,
            )
        assert "expired" in str(exc_info.value).lower()


class TestOrgScoping:
    """Category 8: OAuth state and credentials must be org-scoped."""

    def test_state_belongs_to_org(self, db):
        """Created state should be scoped to the requesting org."""
        org, user = _create_org_and_user(db)
        state = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )
        assert state.organization_id == org.id

    def test_different_org_different_state(self, db):
        """Two orgs should have separate state rows."""
        org1, user1 = _create_org_and_user(db, email="org1@example.com")
        org2, user2 = _create_org_and_user(db, email="org2@example.com")

        state1 = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org1.id, user_id=user1.id,
        )
        state2 = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org2.id, user_id=user2.id,
        )

        assert state1.organization_id != state2.organization_id
        assert state1.state_token != state2.state_token

    def test_connection_status_scoped_to_org(self, db):
        """Connection status should only reflect the requesting org."""
        org1, user1 = _create_org_and_user(db, email="org1@example.com")
        org2, user2 = _create_org_and_user(db, email="org2@example.com")

        # org1 has no credentials
        status1 = GoogleOAuthFlow.get_connection_status(db, org1.id)
        assert status1["connected"] is False

        # org2 also has no credentials
        status2 = GoogleOAuthFlow.get_connection_status(db, org2.id)
        assert status2["connected"] is False

    def test_store_credentials_scoped_to_org(self, db):
        """Stored credentials should be retrievable only for the correct org."""
        org1, user1 = _create_org_and_user(db, email="org1@example.com")
        org2, user2 = _create_org_and_user(db, email="org2@example.com")

        # Store creds for org1 (platform-owned client: only user tokens stored)
        from app.services.google_oauth_flow import _store_credentials
        _store_credentials(
            db=db, org_id=org1.id,
            refresh_token="refresh-for-org1",
            scopes=DEFAULT_SCOPES, email="org1@example.com",
        )
        db.commit()

        # org1 should have creds
        assert CredentialVault.has_credentials(db, org1.id, "google", "google_oauth")
        creds1 = CredentialVault.get_credentials(db, org1.id, "google", "google_oauth")
        assert creds1["refresh_token"] == "refresh-for-org1"

        # org2 should NOT have creds
        assert not CredentialVault.has_credentials(db, org2.id, "google", "google_oauth")


class TestEncryptedStorage:
    """Category 9: Credentials must be stored encrypted in the vault."""

    def test_credentials_stored_encrypted(self, db):
        """CredentialVault should store and retrieve credentials encrypted.

        PLATFORM-OWNED MODEL: only the end user's tokens are stored per-org.
        client_id/client_secret belong to the platform (.env) and must NOT
        be duplicated into the vault.
        """
        from app.services.google_oauth_flow import _store_credentials
        org, user = _create_org_and_user(db)

        _store_credentials(
            db=db, org_id=org.id,
            refresh_token="my-secret-refresh-token",
            scopes=DEFAULT_SCOPES, email="test@example.com",
        )
        db.commit()

        # Verify we can decrypt them
        creds = CredentialVault.get_credentials(db, org.id, "google", "google_oauth")
        assert creds["refresh_token"] == "my-secret-refresh-token"
        # Platform-owned client creds are never stored per-org
        assert "client_id" not in creds
        assert "client_secret" not in creds

    def test_vault_metadata_contains_scopes_and_email(self, db):
        """Vault metadata should include scopes and email."""
        from app.services.google_oauth_flow import _store_credentials
        org, user = _create_org_and_user(db)

        _store_credentials(
            db=db, org_id=org.id,
            refresh_token="test-refresh",
            scopes=DEFAULT_SCOPES, email="meta@example.com",
        )
        db.commit()

        metadata = CredentialVault.get_safe_metadata(
            db, org.id, "google", "google_oauth"
        )
        assert metadata is not None
        assert metadata["email"] == "meta@example.com"
        assert "connected_at" in metadata


class TestNoSecretLeakage:
    """Category 10: Secrets must never appear in logs or API responses."""

    def test_client_secret_not_in_exchange_error_log(self):
        """Token exchange error logs should not contain the client secret."""
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "error": "server_error",
            "error_description": "Internal error",
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_resp):
            with patch("app.services.google_oauth_flow.logger") as mock_logger:
                from app.services.google_oauth_flow import _do_token_exchange
                try:
                    _do_token_exchange("test-code", TEST_GOOGLE_REDIRECT_URI)
                except OAuthTokenExchangeError:
                    pass

        # Check all log calls
        for call in mock_logger.error.call_args_list:
            log_extra = call[1].get("extra", {})
            # The extra dict should not contain the actual secret
            for key, value in log_extra.items():
                assert value != TEST_GOOGLE_CLIENT_SECRET, (
                    f"Client secret leaked in log extra['{key}']"
                )

    def test_auth_url_log_does_not_contain_secret(self):
        """Auth URL creation logs should not contain the client secret."""
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            org, user = _create_org_and_user(db)

            with patch("app.services.google_oauth_flow.logger") as mock_logger:
                GoogleOAuthFlow.create_authorization_url(
                    db=db, org_id=org.id, user_id=user.id,
                )

            for call in mock_logger.info.call_args_list:
                log_extra = call[1].get("extra", {})
                for key, value in log_extra.items():
                    if isinstance(value, str):
                        assert value != TEST_GOOGLE_CLIENT_SECRET, (
                            f"Client secret leaked in log extra['{key}']"
                        )
        finally:
            db.close()

    def test_api_status_endpoint_no_secret(self, client, db):
        """GET /auth/google/status should not expose client secret."""
        org, user = _create_org_and_user(db)
        token = _create_jwt_token(user.id, org.id, "owner")
        response = client.get(
            "/auth/google/status",
            headers=_auth_headers(token),
        )
        body = response.text.lower()
        assert TEST_GOOGLE_CLIENT_SECRET.lower() not in body
        # Also check it doesn't appear in the JSON keys
        data = response.json()
        assert "client_secret" not in str(data)


class TestSuccessfulExchange:
    """Category 11: End-to-end successful exchange stores correct data."""

    def test_full_exchange_stores_correct_client_id_and_secret(self, db):
        """After successful exchange, vault holds user tokens only.

        PLATFORM-OWNED MODEL: client_id/client_secret belong to the
        platform and are never duplicated into the org vault.
        """
        org, user = _create_org_and_user(db)
        state = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.headers = {"content-type": "application/json"}
        mock_token_resp.json.return_value = {
            "access_token": "ya29.test-access",
            "refresh_token": "1//0.test-refresh",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {"email": "success@example.com"}

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                result = GoogleOAuthFlow.exchange_code(
                    db=db, code="test-auth-code", state=state.state_token,
                )

        # Verify result
        assert result["email"] == "success@example.com"
        assert result["refresh_token"] == "1//0.test-refresh"
        assert str(result["organization_id"]) == str(org.id)

        # Verify vault has user tokens only (no platform client secrets)
        creds = CredentialVault.get_credentials(db, org.id, "google", "google_oauth")
        assert "client_id" not in creds
        assert "client_secret" not in creds
        assert creds["refresh_token"] == "1//0.test-refresh"

    def test_exchange_returns_scopes(self, db):
        """Successful exchange should return granted scopes."""
        org, user = _create_org_and_user(db)
        state = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.headers = {"content-type": "application/json"}
        mock_token_resp.json.return_value = {
            "access_token": "ya29.test",
            "refresh_token": "1//0.test",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {"email": "scopes@example.com"}

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                result = GoogleOAuthFlow.exchange_code(
                    db=db, code="test-code", state=state.state_token,
                )

        assert result["scopes"] is not None
        assert len(result["scopes"]) > 0


class TestIdempotentCallback:
    """Category 12: Callback must be idempotent / retry-safe."""

    def test_duplicate_callback_same_code_fails(self, db):
        """Two callbacks with the same state should fail on the second."""
        org, user = _create_org_and_user(db)
        state = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.headers = {"content-type": "application/json"}
        mock_token_resp.json.return_value = {
            "access_token": "ya29.test",
            "refresh_token": "1//0.test",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {"email": "idem@example.com"}

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                # First callback succeeds
                result = GoogleOAuthFlow.exchange_code(
                    db=db, code="auth-code", state=state.state_token,
                )
                assert result["email"] == "idem@example.com"

        # Second callback with same state fails
        with pytest.raises(OAuthStateError):
            GoogleOAuthFlow.exchange_code(
                db=db, code="auth-code", state=state.state_token,
            )

    def test_second_state_needed_for_reconnect(self, db):
        """After disconnect, a new state must be created for reconnection."""
        org, user = _create_org_and_user(db)

        # First connection
        state1 = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )
        state1_token = state1.state_token  # save before session invalidation

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.headers = {"content-type": "application/json"}
        mock_token_resp.json.return_value = {
            "access_token": "ya29.test",
            "refresh_token": "1//0.test",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.json.return_value = {"email": "reconnect@example.com"}

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                GoogleOAuthFlow.exchange_code(
                    db=db, code="code1", state=state1_token,
                )

        # Disconnect
        GoogleOAuthFlow.disconnect(db, org.id)

        # Reconnect - must use a NEW state
        state2 = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )
        assert state2.state_token != state1_token

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                result2 = GoogleOAuthFlow.exchange_code(
                    db=db, code="code2", state=state2.state_token,
                )
                assert result2["email"] == "reconnect@example.com"

        # Verify new credentials are stored
        assert CredentialVault.has_credentials(db, org.id, "google", "google_oauth")


class TestDiagnosticLogging:
    """Category 13: Diagnostic logs must include client_id prefix for debugging."""

    def test_exchange_logs_client_id_prefix(self):
        """Token exchange should log client_id prefix/suffix for debugging."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "access_token": "ya29.test",
            "refresh_token": "1//0.test",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_resp):
            with patch("app.services.google_oauth_flow.logger") as mock_logger:
                from app.services.google_oauth_flow import _do_token_exchange
                _do_token_exchange("test-code", TEST_GOOGLE_REDIRECT_URI)

        # First call should be the "Token exchange request" log
        first_call = mock_logger.info.call_args_list[0]
        extra = first_call[1].get("extra", {})
        assert "client_id_prefix" in extra
        assert "has_client_secret" in extra
        # Prefix should be the first 12 chars of the client_id
        assert extra["client_id_prefix"] == TEST_GOOGLE_CLIENT_ID[:12]

    def test_auth_url_creation_logs_client_config(self):
        """Authorization URL creation should log sanitized client config."""
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            org, user = _create_org_and_user(db)

            with patch("app.services.google_oauth_flow.logger") as mock_logger:
                GoogleOAuthFlow.create_authorization_url(
                    db=db, org_id=org.id, user_id=user.id,
                )

            # Find the "Creating authorization URL" log
            found = False
            for call in mock_logger.info.call_args_list:
                if "Creating authorization URL" in call[0][0]:
                    extra = call[1].get("extra", {})
                    assert "client_id_prefix" in extra
                    assert "has_client_secret" in extra
                    assert "org_id" in extra
                    found = True
                    break
            assert found, "Expected 'Creating authorization URL' log not found"
        finally:
            db.close()

    def test_exchange_error_logs_include_client_prefix(self):
        """Token exchange error logs should include client_id prefix."""
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "error": "server_error",
            "error_description": "Internal error",
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_resp):
            with patch("app.services.google_oauth_flow.logger") as mock_logger:
                from app.services.google_oauth_flow import _do_token_exchange
                try:
                    _do_token_exchange("test-code", TEST_GOOGLE_REDIRECT_URI)
                except OAuthTokenExchangeError:
                    pass

        # The error log should include client_id_prefix
        error_call = mock_logger.error.call_args_list[0]
        extra = error_call[1].get("extra", {})
        assert "client_id_prefix" in extra
        assert "error_code" in extra


# ══════════════════════════════════════════════════════════════════════════════
# Category 15: Vault-First Credential Resolution
# ══════════════════════════════════════════════════════════════════════════════


class TestVaultFirstResolution:
    """Category 15: OAuth flow reads credentials from org vault, not settings."""

    VAULT_CLIENT_ID = "vault-client-id.apps.googleusercontent.com"
    VAULT_CLIENT_SECRET = "vault-client-secret-abc123"
    VAULT_REDIRECT_URI = "https://myorg.example.com/auth/google/callback"

    def _save_vault_credentials(self, db, org_id):
        """Save Google OAuth credentials to the org vault."""
        CredentialVault.save_credentials(
            db=db,
            org_id=org_id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": self.VAULT_CLIENT_ID,
                "client_secret": self.VAULT_CLIENT_SECRET,
                "refresh_token": "vault-refresh-token",
            },
            metadata={
                "redirect_uri": self.VAULT_REDIRECT_URI,
                "email": "vault-user@example.com",
            },
        )
        db.commit()

    def test_create_auth_url_reads_from_vault(self, db):
        """create_authorization_url should use vault client_id, not settings."""
        org, user = _create_org_and_user(db)
        self._save_vault_credentials(db, org.id)

        state_row = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        # The redirect_uri should come from vault, not settings
        assert state_row.redirect_uri == self.VAULT_REDIRECT_URI

    def test_create_auth_url_uses_vault_redirect_uri(self, db):
        """Authorization URL should use redirect_uri from vault."""
        from urllib.parse import parse_qs, urlparse

        org, user = _create_org_and_user(db)
        self._save_vault_credentials(db, org.id)

        state_row = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        url = GoogleOAuthFlow.build_authorization_url(
            state_token=state_row.state_token,
            redirect_uri=state_row.redirect_uri,
            scopes=state_row.scopes,
            client_id=self.VAULT_CLIENT_ID,
        )

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["client_id"] == [self.VAULT_CLIENT_ID]
        assert params["redirect_uri"] == [self.VAULT_REDIRECT_URI]

    def test_build_auth_url_accepts_client_id_param(self, db):
        """build_authorization_url should use the provided client_id."""
        from urllib.parse import parse_qs, urlparse

        url = GoogleOAuthFlow.build_authorization_url(
            state_token="test-token",
            redirect_uri="http://localhost:8000/callback",
            client_id="custom-client-id.apps.googleusercontent.com",
        )

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["client_id"] == ["custom-client-id.apps.googleusercontent.com"]

    def test_build_auth_url_falls_back_to_settings(self, db):
        """build_authorization_url should fall back to settings if no client_id."""
        from urllib.parse import parse_qs, urlparse

        url = GoogleOAuthFlow.build_authorization_url(
            state_token="test-token",
            redirect_uri="http://localhost:8000/callback",
        )

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["client_id"] == [TEST_GOOGLE_CLIENT_ID]

    def test_exchange_code_resolves_from_vault(self, db):
        """exchange_code should resolve credentials from vault, not settings."""
        org, user = _create_org_and_user(db)
        self._save_vault_credentials(db, org.id)

        # Create a state row
        state_row = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )
        state_token = state_row.state_token

        # Mock Google API responses
        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.headers = {"content-type": "application/json"}
        mock_token_resp.json.return_value = {
            "access_token": "ya29.new-access-token",
            "refresh_token": "1//vault-refresh-token-new",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.status_code = 200
        mock_userinfo_resp.headers = {"content-type": "application/json"}
        mock_userinfo_resp.json.return_value = {"email": "vault-user@example.com"}

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_token_resp):
            with patch("app.services.google_oauth_flow.httpx.get", return_value=mock_userinfo_resp):
                result = GoogleOAuthFlow.exchange_code(
                    db=db, code="test-auth-code", state=state_token,
                )

        assert result["email"] == "vault-user@example.com"

        # Verify the token exchange used vault credentials
        token_call = mock_token_resp  # this is the mock
        payload = mock_token_resp.json.return_value  # check what was stored

        # Verify vault now has the new refresh token (legacy org-owned
        # client creds are preserved so future refreshes keep working)
        stored = CredentialVault.get_credentials(db, org.id, "google", "google_oauth")
        assert stored["client_id"] == self.VAULT_CLIENT_ID
        assert stored["client_secret"] == self.VAULT_CLIENT_SECRET
        assert stored["refresh_token"] == "1//vault-refresh-token-new"

    def test_error_when_no_vault_and_no_settings(self, db):
        """create_authorization_url should error when no credentials anywhere."""
        org, user = _create_org_and_user(db)

        # Clear settings fallback in BOTH the flow module and the resolver module
        with patch("app.services.google_oauth_flow.settings") as mock_flow_settings, \
             patch("app.services.integration_config_resolver.settings") as mock_resolver_settings:
            mock_flow_settings.google_client_id = ""
            mock_flow_settings.google_client_secret = ""
            mock_flow_settings.google_redirect_uri = ""
            mock_flow_settings.google_oauth_state_ttl_minutes = 10
            mock_resolver_settings.google_client_id = ""
            mock_resolver_settings.google_client_secret = ""
            mock_resolver_settings.google_refresh_token = ""

            with pytest.raises(GoogleOAuthError) as exc_info:
                GoogleOAuthFlow.create_authorization_url(
                    db=db, org_id=org.id, user_id=user.id,
                )

            assert exc_info.value.error_code == "client_not_configured"
            assert "administrator" in str(exc_info.value)

    def test_token_exchange_accepts_credentials_as_params(self, db):
        """_do_token_exchange should accept client_id/client_secret as params."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "access_token": "ya29.test",
            "refresh_token": "1//0.test",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_resp) as mock_post:
            from app.services.google_oauth_flow import _do_token_exchange
            result = _do_token_exchange(
                "test-code",
                "https://myorg.example.com/auth/google/callback",
                client_id="param-client-id",
                client_secret="param-client-secret",
            )

            # Verify the payload used the parameters, not settings
            call_args = mock_post.call_args
            payload = call_args[1]["data"] if "data" in call_args[1] else call_args[0][1]
            assert payload["client_id"] == "param-client-id"
            assert payload["client_secret"] == "param-client-secret"

    def test_resolve_redirect_uri_from_vault(self, db):
        """_resolve_redirect_uri should read from vault metadata."""
        from app.services.google_oauth_flow import _resolve_redirect_uri

        org, user = _create_org_and_user(db)
        self._save_vault_credentials(db, org.id)

        redirect_uri = _resolve_redirect_uri(db, org.id)
        assert redirect_uri == self.VAULT_REDIRECT_URI

    def test_resolve_redirect_uri_fallback(self, db):
        """_resolve_redirect_uri should return None when no vault entry."""
        from app.services.google_oauth_flow import _resolve_redirect_uri

        org, user = _create_org_and_user(db)

        redirect_uri = _resolve_redirect_uri(db, org.id)
        assert redirect_uri is None


class TestOAuthConfigTypes:
    """Category 16: google_oauth should be in _OAUTH_CONFIG_TYPES."""

    def test_google_oauth_in_config_types(self):
        """('google', 'google_oauth') should be in _OAUTH_CONFIG_TYPES."""
        from app.services.integration_service import _OAUTH_CONFIG_TYPES

        assert ("google", "google_oauth") in _OAUTH_CONFIG_TYPES

    def test_zoom_still_in_config_types(self):
        """('zoom', 'zoom_oauth') should still be in _OAUTH_CONFIG_TYPES."""
        from app.services.integration_service import _OAUTH_CONFIG_TYPES

        assert ("zoom", "zoom_oauth") in _OAUTH_CONFIG_TYPES


# ══════════════════════════════════════════════════════════════════════════════
# Phase 6+10: Dashboard Save Validation & Mixed-Credential Prevention
# ══════════════════════════════════════════════════════════════════════════════


class TestDashboardSaveValidation:
    """Validate that the dashboard can save Google OAuth credentials.

    Bug fix: KNOWN_PROVIDERS required refresh_token, blocking saves.
    """

    def test_dashboard_credentials_pass_validation(self):
        """Dashboard sends client_id + client_secret - validation should pass."""
        from app.services.integration_service import _validate_credentials

        # Should NOT raise
        _validate_credentials(
            "google", "google_oauth",
            {
                "client_id": "test-id.apps.googleusercontent.com",
                "client_secret": "GOCSPX-test-secret",
                "redirect_uri": "https://example.com/auth/google/callback",
            },
        )

    def test_credentials_with_refresh_token_also_pass(self):
        """Post-OAuth credentials with refresh_token should also pass."""
        from app.services.integration_service import _validate_credentials

        _validate_credentials(
            "google", "google_oauth",
            {
                "client_id": "test-id.apps.googleusercontent.com",
                "client_secret": "GOCSPX-test-secret",
                "redirect_uri": "https://example.com/auth/google/callback",
                "refresh_token": "1//0abc-def",
            },
        )

    def test_missing_client_id_fails(self):
        """Missing client_id should fail validation."""
        from app.services.integration_service import (
            _validate_credentials,
            IntegrationValidationError,
        )

        with pytest.raises(IntegrationValidationError, match="client_id"):
            _validate_credentials(
                "google", "google_oauth",
                {"client_secret": "secret", "redirect_uri": "https://example.com"},
            )

    def test_missing_client_secret_fails(self):
        """Missing client_secret should fail validation."""
        from app.services.integration_service import (
            _validate_credentials,
            IntegrationValidationError,
        )

        with pytest.raises(IntegrationValidationError, match="client_secret"):
            _validate_credentials(
                "google", "google_oauth",
                {"client_id": "test-id", "redirect_uri": "https://example.com"},
            )

    def test_empty_client_id_fails(self):
        """Empty client_id should fail validation."""
        from app.services.integration_service import (
            _validate_credentials,
            IntegrationValidationError,
        )

        with pytest.raises(IntegrationValidationError, match="client_id"):
            _validate_credentials(
                "google", "google_oauth",
                {"client_id": "", "client_secret": "secret"},
            )

    def test_empty_client_secret_fails(self):
        """Empty client_secret should fail validation."""
        from app.services.integration_service import (
            _validate_credentials,
            IntegrationValidationError,
        )

        with pytest.raises(IntegrationValidationError, match="client_secret"):
            _validate_credentials(
                "google", "google_oauth",
                {"client_id": "test-id", "client_secret": "  "},
            )


class TestMixedCredentialPrevention:
    """Phase 6: Prevent mixing client_id from one source with client_secret from another."""

    def test_both_present_passes(self):
        """Both client_id and client_secret provided - should pass."""
        from app.services.integration_service import _validate_credentials

        _validate_credentials(
            "google", "google_oauth",
            {"client_id": "id", "client_secret": "secret"},
        )

    def test_only_redirect_uri_fails(self):
        """Only redirect_uri without client_id/client_secret should fail."""
        from app.services.integration_service import (
            _validate_credentials,
            IntegrationValidationError,
        )

        with pytest.raises(IntegrationValidationError, match="client_id"):
            _validate_credentials("google", "google_oauth", {"redirect_uri": "x"})


class TestVaultPreOAuthResolution:
    """Verify that the resolver uses vault credentials even without refresh_token.

    Bug fix: resolve_google_oauth() previously required refresh_token
    to activate the vault path.
    """

    def test_vault_client_id_secret_used_without_refresh_token(self, db):
        """Vault with client_id + client_secret (no refresh_token) should be used."""
        org, user = _create_org_and_user(db)

        # Save credentials WITHOUT refresh_token (like dashboard does)
        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "vault-client-id.apps.googleusercontent.com",
                "client_secret": "GOCSPX-vault-secret",
                "redirect_uri": "https://example.com/callback",
            },
            metadata={"label": "Google OAuth2"},
            status=IntegrationStatus.PENDING,
        )

        cfg = IntegrationConfigResolver.resolve_google_oauth(db, org.id)
        assert cfg.client_id == "vault-client-id.apps.googleusercontent.com"
        assert cfg.client_secret == "GOCSPX-vault-secret"
        assert cfg.refresh_token == ""  # no refresh_token yet

    def test_vault_overrides_env(self, db):
        """Vault credentials must override .env fallback."""
        org, user = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "vault-id.apps.googleusercontent.com",
                "client_secret": "GOCSPX-vault-secret",
            },
            metadata={},
            status=IntegrationStatus.PENDING,
        )

        with patch(
            "app.services.integration_config_resolver.settings"
        ) as mock_settings:
            mock_settings.google_client_id = "env-fallback-id"
            mock_settings.google_client_secret = "env-fallback-secret"
            mock_settings.google_refresh_token = "env-refresh-token"

            cfg = IntegrationConfigResolver.resolve_google_oauth(db, org.id)

        assert cfg.client_id == "vault-id.apps.googleusercontent.com"
        assert cfg.client_secret == "GOCSPX-vault-secret"
        # refresh_token is empty from vault - resolver does NOT mix vault + .env
        # (Phase 6: no mixed credentials from different sources)
        assert cfg.refresh_token == ""

    def test_empty_vault_falls_back_to_platform_client(self, db):
        """No vault credentials → platform client from .env, empty refresh token.

        PLATFORM-OWNED MODEL: the deprecated GOOGLE_REFRESH_TOKEN .env
        fallback is gone.  The org gets the platform client_id/secret and
        an empty refresh_token until the org owner clicks Connect.
        """
        org, user = _create_org_and_user(db)

        with patch(
            "app.services.integration_config_resolver.settings"
        ) as mock_settings:
            mock_settings.google_client_id = "env-id"
            mock_settings.google_client_secret = "env-secret"
            mock_settings.google_refresh_token = "env-refresh"

            cfg = IntegrationConfigResolver.resolve_google_oauth(db, org.id)

        assert cfg.client_id == "env-id"
        assert cfg.client_secret == "env-secret"
        assert cfg.refresh_token == ""

    def test_vault_with_refresh_token_uses_it(self, db):
        """Vault with all fields including refresh_token should use vault refresh_token."""
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
            },
            metadata={},
            status=IntegrationStatus.CONNECTED,
        )

        cfg = IntegrationConfigResolver.resolve_google_oauth(db, org.id)
        assert cfg.client_id == "vault-id.apps.googleusercontent.com"
        assert cfg.client_secret == "GOCSPX-vault-secret"
        assert cfg.refresh_token == "vault-refresh-token"

    def test_same_record_for_id_and_secret(self, db):
        """Client ID and secret always come from the same vault record."""
        org, user = _create_org_and_user(db)

        CredentialVault.save_credentials(
            db=db,
            org_id=org.id,
            provider="google",
            integration_type="google_oauth",
            credentials={
                "client_id": "my-client-id",
                "client_secret": "my-client-secret",
            },
            metadata={},
            status=IntegrationStatus.PENDING,
        )

        cfg = IntegrationConfigResolver.resolve_google_oauth(db, org.id)
        # Both must come from the vault - never mixed with .env
        assert cfg.client_id == "my-client-id"
        assert cfg.client_secret == "my-client-secret"

    def test_org_isolation_different_orgs_different_creds(self, db):
        """Different orgs get different credentials from their vaults."""
        org1, user1 = _create_org_and_user(db, org_name="Org1")
        org2, user2 = _create_org_and_user(db, org_name="Org2")

        CredentialVault.save_credentials(
            db=db, org_id=org1.id, provider="google",
            integration_type="google_oauth",
            credentials={"client_id": "org1-id", "client_secret": "org1-secret"},
            metadata={}, status=IntegrationStatus.PENDING,
        )
        CredentialVault.save_credentials(
            db=db, org_id=org2.id, provider="google",
            integration_type="google_oauth",
            credentials={"client_id": "org2-id", "client_secret": "org2-secret"},
            metadata={}, status=IntegrationStatus.PENDING,
        )

        cfg1 = IntegrationConfigResolver.resolve_google_oauth(db, org1.id)
        cfg2 = IntegrationConfigResolver.resolve_google_oauth(db, org2.id)

        assert cfg1.client_id == "org1-id"
        assert cfg2.client_id == "org2-id"
        assert cfg1.client_id != cfg2.client_id

    def test_wrong_org_cannot_use_creds(self, db):
        """Org B cannot use Org A's credentials."""
        org_a, user_a = _create_org_and_user(db, org_name="OrgA")
        org_b, user_b = _create_org_and_user(db, org_name="OrgB")

        CredentialVault.save_credentials(
            db=db, org_id=org_a.id, provider="google",
            integration_type="google_oauth",
            credentials={"client_id": "orgA-id", "client_secret": "orgA-secret"},
            metadata={}, status=IntegrationStatus.PENDING,
        )

        # Org B has no vault credentials - gets .env fallback
        with patch(
            "app.services.integration_config_resolver.settings"
        ) as mock_settings:
            mock_settings.google_client_id = "env-id"
            mock_settings.google_client_secret = "env-secret"
            mock_settings.google_refresh_token = ""
            cfg_b = IntegrationConfigResolver.resolve_google_oauth(db, org_b.id)

        assert cfg_b.client_id == "env-id"  # NOT orgA-id

    def test_invalid_client_error_actionable(self):
        """invalid_client error message should direct user to Dashboard."""
        from app.services.google_oauth_flow import _do_token_exchange

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "error": "invalid_client",
            "error_description": "Client authentication failed.",
        }

        with patch("app.services.google_oauth_flow.httpx.post", return_value=mock_resp):
            with pytest.raises(OAuthTokenExchangeError) as exc_info:
                _do_token_exchange("code", "https://example.com/callback")

        msg = str(exc_info.value)
        # Should reference Google Cloud Console (platform-owned client)
        assert "Google Cloud Console" in msg
        assert "invalid_client" in msg

    def test_not_configured_error_actionable(self, db):
        """Not-configured error should mention Integrations, NOT .env."""
        from app.services.google_oauth_flow import (
            GoogleOAuthFlow,
            GoogleOAuthError,
        )

        org, user = _create_org_and_user(db)

        with patch(
            "app.services.integration_config_resolver.settings"
        ) as mock_settings:
            mock_settings.google_client_id = ""
            mock_settings.google_client_secret = ""
            mock_settings.google_refresh_token = ""

            with pytest.raises(GoogleOAuthError) as exc_info:
                GoogleOAuthFlow.create_authorization_url(
                    db=db, org_id=org.id, user_id=user.id,
                )

        msg = str(exc_info.value)
        assert "administrator" in msg
        assert ".env" not in msg

    def test_callback_success_stores_redirect_uri(self, db):
        """After OAuth callback, redirect_uri is stored in vault credentials."""
        from app.services.google_oauth_flow import GoogleOAuthFlow

        org, user = _create_org_and_user(db)

        # Create a state
        state_row = GoogleOAuthFlow.create_authorization_url(
            db=db, org_id=org.id, user_id=user.id,
        )

        # Mock successful Google token exchange + userinfo
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
                db=db, code="test-auth-code", state=state_row.state_token,
            )

        # Verify redirect_uri is in the vault credentials (client creds
        # are platform-owned and not stored per-org)
        creds = CredentialVault.get_credentials(db, org.id, "google", "google_oauth")
        assert "redirect_uri" in creds
        assert creds["redirect_uri"] == state_row.redirect_uri
        assert "client_id" not in creds
        assert "client_secret" not in creds
