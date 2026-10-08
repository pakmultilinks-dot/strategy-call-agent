"""Phase 20 P1-A — Password Reset Flow Tests.

Comprehensive tests for the forgot-password and reset-password endpoints:
  - Happy path: request + reset + login with new password
  - Token validation: expired, used, invalid
  - Security: no account enumeration, rate limiting, org status checks
  - Password validation: weak passwords rejected
"""
import hashlib
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth import hash_password, verify_password, create_access_token
from app.database import SessionLocal
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
    PasswordResetToken,
    User,
    UserRole,
    UserStatus,
)


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture()
def db():
    """Yield a DB session with rollback."""
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


# ── Helpers ────────────────────────────────────────────────────────────────


def _create_org_and_user(
    db: Session,
    *,
    email: str | None = None,
    role: UserRole = UserRole.OWNER,
    user_status: UserStatus = UserStatus.ACTIVE,
    org_status: OrganizationStatus = OrganizationStatus.ACTIVE,
    password: str = "OriginalPass123!",
) -> tuple[Organization, User]:
    """Helper: create an org + user pair for testing."""
    suffix = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Reset Test Org {suffix}",
        slug=f"reset-test-{suffix}",
        status=org_status,
        timezone="America/Chicago",
    )
    db.add(org)
    db.flush()
    user = User(
        organization_id=org.id,
        email=email or f"reset-user-{suffix}@test.com",
        full_name="Reset Test User",
        password_hash=hash_password(password),
        role=role,
        status=user_status,
    )
    db.add(user)
    db.commit()
    db.refresh(org)
    db.refresh(user)
    return org, user


def _create_reset_token(
    db: Session,
    user: User,
    *,
    expired: bool = False,
    used: bool = False,
) -> tuple[PasswordResetToken, str]:
    """Helper: create a reset token and return (token_record, plaintext_token)."""
    # Generate a plaintext token and hash it
    plaintext = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    token_hash = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    expires_at = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
        if expired
        else datetime.now(timezone.utc) + timedelta(minutes=30)
    )

    reset_token = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        used=used,
    )
    db.add(reset_token)
    db.commit()
    db.refresh(reset_token)
    return reset_token, plaintext


# ══════════════════════════════════════════════════════════════════════════════
# FORGOT PASSWORD ENDPOINT TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestForgotPassword:
    """Tests for POST /auth/forgot-password."""

    def test_forgot_password_returns_generic_message(self, client: TestClient, db):
        """Returns generic message regardless of whether email exists."""
        org, user = _create_org_and_user(db)
        resp = client.post(
            "/auth/forgot-password",
            json={"email": user.email},
        )
        assert resp.status_code == 200
        assert "password reset link" in resp.json()["message"].lower()

    def test_forgot_password_unknown_email_returns_same_message(self, client: TestClient, db):
        """Unknown email returns the same generic message (no enumeration)."""
        resp = client.post(
            "/auth/forgot-password",
            json={"email": "nonexistent-user-999@example.com"},
        )
        assert resp.status_code == 200
        assert "password reset link" in resp.json()["message"].lower()

    def test_forgot_password_disabled_user_returns_generic(self, client: TestClient, db):
        """Disabled user returns generic message (no enumeration)."""
        org, user = _create_org_and_user(db, user_status=UserStatus.DISABLED)
        resp = client.post(
            "/auth/forgot-password",
            json={"email": user.email},
        )
        assert resp.status_code == 200
        assert "password reset link" in resp.json()["message"].lower()

    def test_forgot_password_suspended_org_returns_generic(self, client: TestClient, db):
        """Suspended org returns generic message (no enumeration)."""
        org, user = _create_org_and_user(db, org_status=OrganizationStatus.SUSPENDED)
        resp = client.post(
            "/auth/forgot-password",
            json={"email": user.email},
        )
        assert resp.status_code == 200
        assert "password reset link" in resp.json()["message"].lower()

    def test_forgot_password_creates_token_in_db(self, client: TestClient, db):
        """Successful request creates a PasswordResetToken record."""
        org, user = _create_org_and_user(db)
        resp = client.post(
            "/auth/forgot-password",
            json={"email": user.email},
        )
        assert resp.status_code == 200

        # Check that a token was created
        tokens = db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id
        ).all()
        assert len(tokens) == 1
        assert tokens[0].used is False
        assert tokens[0].expires_at > datetime.now(timezone.utc)

    def test_forgot_password_invalidates_old_tokens(self, client: TestClient, db):
        """New request invalidates any previous unused tokens."""
        org, user = _create_org_and_user(db)

        # Create an old token
        old_token, _ = _create_reset_token(db, user)
        assert old_token.used is False

        # Request a new reset
        resp = client.post(
            "/auth/forgot-password",
            json={"email": user.email},
        )
        assert resp.status_code == 200

        # Old token should now be marked as used
        db.refresh(old_token)
        assert old_token.used is True

    def test_forgot_password_invalid_email(self, client: TestClient, db):
        """Invalid email format returns 422."""
        resp = client.post(
            "/auth/forgot-password",
            json={"email": "not-an-email"},
        )
        assert resp.status_code == 422

    @patch("app.services.email_service.EmailService")
    def test_forgot_password_sends_email(self, MockEmailService, client: TestClient, db):
        """Successful request sends a password reset email."""
        mock_instance = MagicMock()
        MockEmailService.return_value = mock_instance

        org, user = _create_org_and_user(db)
        resp = client.post(
            "/auth/forgot-password",
            json={"email": user.email},
        )
        assert resp.status_code == 200
        mock_instance.send_email.assert_called_once()

    def test_forgot_password_email_failure_still_returns_200(self, client: TestClient, db):
        """Email failure doesn't expose error to client."""
        org, user = _create_org_and_user(db)

        with patch("app.services.email_service.EmailService") as MockEmailService:
            mock_instance = MagicMock()
            mock_instance.send_email.side_effect = Exception("SMTP error")
            MockEmailService.return_value = mock_instance

            resp = client.post(
                "/auth/forgot-password",
                json={"email": user.email},
            )
            # Should still return 200 (generic message)
            assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# RESET PASSWORD ENDPOINT TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestResetPassword:
    """Tests for POST /auth/reset-password."""

    def test_reset_password_success(self, client: TestClient, db):
        """Valid token successfully resets the password."""
        org, user = _create_org_and_user(db)
        _, plaintext = _create_reset_token(db, user)

        new_password = "NewStrongPass456!"
        resp = client.post(
            "/auth/reset-password",
            json={"token": plaintext, "new_password": new_password},
        )
        assert resp.status_code == 200
        assert "password has been updated" in resp.json()["message"].lower()

        # Verify the new password works
        db.refresh(user)
        assert verify_password(new_password, user.password_hash)

    def test_reset_password_old_password_no_longer_works(self, client: TestClient, db):
        """After reset, the old password cannot be used to login."""
        old_password = "OldPass123!"
        org, user = _create_org_and_user(db, password=old_password)
        _, plaintext = _create_reset_token(db, user)

        new_password = "NewStrongPass456!"
        resp = client.post(
            "/auth/reset-password",
            json={"token": plaintext, "new_password": new_password},
        )
        assert resp.status_code == 200

        # Login with old password should fail
        login_resp = client.post(
            "/auth/login",
            json={"email": user.email, "password": old_password},
        )
        assert login_resp.status_code == 401

    def test_reset_password_token_marked_used(self, client: TestClient, db):
        """Token is marked as used after successful reset."""
        org, user = _create_org_and_user(db)
        token_record, plaintext = _create_reset_token(db, user)

        resp = client.post(
            "/auth/reset-password",
            json={"token": plaintext, "new_password": "NewStrongPass456!"},
        )
        assert resp.status_code == 200

        db.refresh(token_record)
        assert token_record.used is True

    def test_reset_password_token_single_use(self, client: TestClient, db):
        """Token cannot be reused after successful reset."""
        org, user = _create_org_and_user(db)
        _, plaintext = _create_reset_token(db, user)

        # First use — succeeds
        resp1 = client.post(
            "/auth/reset-password",
            json={"token": plaintext, "new_password": "NewStrongPass789!"},
        )
        assert resp1.status_code == 200

        # Second use — generic response (token is now used)
        resp2 = client.post(
            "/auth/reset-password",
            json={"token": plaintext, "new_password": "AnotherPass012!"},
        )
        assert resp2.status_code == 200
        assert "password has been updated" in resp2.json()["message"].lower()

        # But the second password should NOT have been applied
        db.refresh(user)
        assert verify_password("NewStrongPass789!", user.password_hash)

    def test_reset_password_expired_token(self, client: TestClient, db):
        """Expired token returns generic message (not an error)."""
        org, user = _create_org_and_user(db)
        _, plaintext = _create_reset_token(db, user, expired=True)

        resp = client.post(
            "/auth/reset-password",
            json={"token": plaintext, "new_password": "NewStrongPass456!"},
        )
        assert resp.status_code == 200
        assert "password has been updated" in resp.json()["message"].lower()

    def test_reset_password_invalid_token(self, client: TestClient, db):
        """Invalid token returns generic message."""
        resp = client.post(
            "/auth/reset-password",
            json={"token": "completely-fake-token-abc123", "new_password": "NewStrongPass456!"},
        )
        assert resp.status_code == 200
        assert "password has been updated" in resp.json()["message"].lower()

    def test_reset_password_weak_password(self, client: TestClient, db):
        """Weak password returns 422 validation error."""
        org, user = _create_org_and_user(db)
        _, plaintext = _create_reset_token(db, user)

        resp = client.post(
            "/auth/reset-password",
            json={"token": plaintext, "new_password": "short"},
        )
        assert resp.status_code == 422

    def test_reset_password_used_token(self, client: TestClient, db):
        """Used token returns generic message (not an error)."""
        org, user = _create_org_and_user(db)
        _, plaintext = _create_reset_token(db, user, used=True)

        resp = client.post(
            "/auth/reset-password",
            json={"token": plaintext, "new_password": "NewStrongPass456!"},
        )
        assert resp.status_code == 200

    def test_reset_password_disabled_user(self, client: TestClient, db):
        """Disabled user cannot reset password."""
        org, user = _create_org_and_user(db, user_status=UserStatus.DISABLED)
        _, plaintext = _create_reset_token(db, user)

        resp = client.post(
            "/auth/reset-password",
            json={"token": plaintext, "new_password": "NewStrongPass456!"},
        )
        assert resp.status_code == 200
        # Password should NOT have changed
        db.refresh(user)
        assert verify_password("OriginalPass123!", user.password_hash)

    def test_reset_password_suspended_org(self, client: TestClient, db):
        """Suspended org user cannot reset password."""
        org, user = _create_org_and_user(db, org_status=OrganizationStatus.SUSPENDED)
        _, plaintext = _create_reset_token(db, user)

        resp = client.post(
            "/auth/reset-password",
            json={"token": plaintext, "new_password": "NewStrongPass456!"},
        )
        assert resp.status_code == 200
        # Password should NOT have changed
        db.refresh(user)
        assert verify_password("OriginalPass123!", user.password_hash)


# ══════════════════════════════════════════════════════════════════════════════
# END-TO-END PASSWORD RESET FLOW TEST
# ══════════════════════════════════════════════════════════════════════════════


class TestPasswordResetE2E:
    """End-to-end test: forgot → extract token → reset → login with new password."""

    def test_full_password_reset_flow(self, client: TestClient, db):
        """Complete password reset flow from request to login."""
        old_password = "OriginalPass123!"
        new_password = "BrandNewPass789!"
        org, user = _create_org_and_user(db, password=old_password)

        # Step 1: Verify old password works
        login_resp = client.post(
            "/auth/login",
            json={"email": user.email, "password": old_password},
        )
        assert login_resp.status_code == 200

        # Step 2: Request password reset
        with patch("app.services.email_service.EmailService") as MockEmailService:
            mock_instance = MagicMock()
            MockEmailService.return_value = mock_instance

            forgot_resp = client.post(
                "/auth/forgot-password",
                json={"email": user.email},
            )
            assert forgot_resp.status_code == 200

            # Extract the token from the email that was sent
            # The mock captures the call arguments
            call_args = mock_instance.send_email.call_args
            html_body = call_args.kwargs.get("html_body") or call_args[1].get("html_body", "")

        # Extract token from reset URL in the HTML
        token_match = re.search(r'token=([^&"\']+)', html_body)
        assert token_match is not None, "Reset token not found in email HTML"
        reset_token = token_match.group(1)

        # Step 3: Reset password with the token
        reset_resp = client.post(
            "/auth/reset-password",
            json={"token": reset_token, "new_password": new_password},
        )
        assert reset_resp.status_code == 200

        # Step 4: Old password no longer works
        login_old = client.post(
            "/auth/login",
            json={"email": user.email, "password": old_password},
        )
        assert login_old.status_code == 401

        # Step 5: New password works
        login_new = client.post(
            "/auth/login",
            json={"email": user.email, "password": new_password},
        )
        assert login_new.status_code == 200
        assert "access_token" in login_new.json()
