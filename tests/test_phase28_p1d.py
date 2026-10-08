"""Phase 28 — P1-D & P1-C: JWT Revocation, Logout, Password Change.

Covers:
  P1-D: Token blocklist, logout endpoint, bulk revocation, cleanup
  P1-C: Password change endpoint (requires current password)

Baseline: 1330 tests (Phase 27).
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session as SASession

from app.database import SessionLocal
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
    TokenBlocklist,
    User,
    UserRole,
    UserStatus,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_test_org(
    db,
    plan: str = "business",
) -> tuple[Organization, User, str, dict]:
    """Create a fresh org+user and return (org, user, token, auth_header)."""
    from app.auth import create_access_token, hash_password

    org = Organization(
        name=f"P28 Test Org {uuid.uuid4().hex[:8]}",
        slug=f"p28-test-{uuid.uuid4().hex[:8]}",
        timezone="America/Chicago",
        status=OrganizationStatus.ACTIVE,
        plan=plan,
        plan_started_at=datetime.now(timezone.utc),
    )
    db.add(org)
    db.flush()

    user = User(
        organization_id=org.id,
        email=f"p28-{uuid.uuid4().hex[:8]}@test.com",
        full_name="P28 Test User",
        password_hash=hash_password("StrongPass123!"),
        role=UserRole.OWNER,
        status=UserStatus.ACTIVE,
    )
    db.add(user)
    db.commit()
    db.refresh(org)
    db.refresh(user)

    token = create_access_token(
        user_id=user.id,
        organization_id=org.id,
        role=user.role.value,
    )
    auth_header = {"Authorization": f"Bearer {token}"}
    return org, user, token, auth_header


@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    """Inject test-mode secrets for JWT creation."""
    from app.config import settings
    from app.services.crypto import generate_key
    monkeypatch.setattr(settings, "jwt_secret_key", "test-phase28-secret-key-for-testing-32ch")
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", generate_key())


# ============================================================================
# P1-D: JWT Token Has JTI Claim
# ============================================================================

class TestJTIClaim:
    """Verify that JWT tokens now include a unique jti claim."""

    def test_token_contains_jti(self):
        from app.auth import create_access_token, decode_access_token
        token = create_access_token(
            user_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            role="owner",
        )
        payload = decode_access_token(token)
        assert "jti" in payload
        assert isinstance(payload["jti"], str)
        assert len(payload["jti"]) > 0

    def test_jti_is_unique_per_token(self):
        from app.auth import create_access_token, decode_access_token
        t1 = create_access_token(uuid.uuid4(), uuid.uuid4(), "owner")
        t2 = create_access_token(uuid.uuid4(), uuid.uuid4(), "owner")
        p1 = decode_access_token(t1)
        p2 = decode_access_token(t2)
        assert p1["jti"] != p2["jti"]

    def test_jti_is_valid_uuid(self):
        from app.auth import create_access_token, decode_access_token
        token = create_access_token(uuid.uuid4(), uuid.uuid4(), "admin")
        payload = decode_access_token(token)
        # Should be parseable as UUID
        uuid.UUID(payload["jti"])


# ============================================================================
# P1-D: Token Blocklist
# ============================================================================

class TestTokenBlocklist:
    """Verify the token blocklist model and revocation functions."""

    def test_revoke_token_adds_to_blocklist(self):
        from app.auth import revoke_token, _is_token_revoked
        session = SessionLocal()
        try:
            org, user, _, _ = _create_test_org(session)
            jti = str(uuid.uuid4())
            revoke_token(
                jti=jti,
                user_id=user.id,
                organization_id=org.id,
                reason="logout",
                db=session,
            )
            assert _is_token_revoked(jti, session) is True
        finally:
            session.close()

    def test_revoke_token_idempotent(self):
        from app.auth import revoke_token
        session = SessionLocal()
        try:
            org, user, _, _ = _create_test_org(session)
            jti = str(uuid.uuid4())
            revoke_token(jti=jti, user_id=user.id, organization_id=org.id, db=session)
            # Second revocation should not raise
            revoke_token(jti=jti, user_id=user.id, organization_id=org.id, db=session)
        finally:
            session.close()

    def test_non_revoked_token_not_in_blocklist(self):
        from app.auth import _is_token_revoked
        session = SessionLocal()
        try:
            jti = str(uuid.uuid4())
            assert _is_token_revoked(jti, session) is False
        finally:
            session.close()

    def test_bulk_revoke_all_user_tokens(self):
        from app.auth import revoke_all_user_tokens, _is_all_user_tokens_revoked
        session = SessionLocal()
        try:
            org, user, _, _ = _create_test_org(session)
        finally:
            session.close()

        # Use a fresh session to verify and perform revocation
        session2 = SessionLocal()
        try:
            assert _is_all_user_tokens_revoked(user.id, session2) is False
            revoke_all_user_tokens(
                user_id=user.id,
                organization_id=org.id,
                reason="password_change",
                db=session2,
            )
            assert _is_all_user_tokens_revoked(user.id, session2) is True
        finally:
            session2.close()

    def test_bulk_revoke_idempotent(self):
        from app.auth import revoke_all_user_tokens
        session = SessionLocal()
        try:
            org, user, _, _ = _create_test_org(session)
        finally:
            session.close()

        session2 = SessionLocal()
        try:
            count1 = revoke_all_user_tokens(user.id, org.id, db=session2)
            count2 = revoke_all_user_tokens(user.id, org.id, db=session2)
            assert count1 == 1
            assert count2 == 0
        finally:
            session2.close()

    def test_cleanup_expired_blocklist(self):
        from app.auth import revoke_token, cleanup_expired_blocklist
        session = SessionLocal()
        try:
            org, user, _, _ = _create_test_org(session)
            # Add an already-expired entry
            expired_jti = str(uuid.uuid4())
            past = datetime.now(timezone.utc) - timedelta(hours=1)
            revoke_token(
                jti=expired_jti,
                user_id=user.id,
                organization_id=org.id,
                expires_at=past,
                db=session,
            )
            # Add a future entry
            future_jti = str(uuid.uuid4())
            future = datetime.now(timezone.utc) + timedelta(hours=1)
            revoke_token(
                jti=future_jti,
                user_id=user.id,
                organization_id=org.id,
                expires_at=future,
                db=session,
            )
            # Cleanup should remove only the expired entry
            count = cleanup_expired_blocklist(session)
            assert count >= 1
            # Future entry should still exist
            from app.auth import _is_token_revoked
            assert _is_token_revoked(future_jti, session) is True
            assert _is_token_revoked(expired_jti, session) is False
        finally:
            session.close()

    def test_blocklist_table_has_expected_columns(self):
        """Verify the TokenBlocklist model maps to the expected table."""
        session = SessionLocal()
        try:
            org, user, _, _ = _create_test_org(session)
        finally:
            session.close()

        session2 = SessionLocal()
        try:
            entry = TokenBlocklist(
                jti=str(uuid.uuid4()),
                user_id=user.id,
                organization_id=org.id,
                reason="test",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
            session2.add(entry)
            session2.flush()
            assert entry.id is not None
            assert entry.jti is not None
            assert entry.reason == "test"
            assert entry.revoked_at is not None
            session2.rollback()
        finally:
            session2.close()


# ============================================================================
# P1-D: Logout Endpoint
# ============================================================================

class TestLogoutEndpoint:
    """Verify POST /auth/logout revokes the current token."""

    def test_logout_returns_204(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_test_org(session)
        finally:
            session.close()

        r = client.post("/auth/logout", headers=auth)
        assert r.status_code == 204

    def test_logout_revokes_token(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_test_org(session)
        finally:
            session.close()

        # Logout
        r = client.post("/auth/logout", headers=auth)
        assert r.status_code == 204

        # Try using the revoked token — should get 401
        r2 = client.get("/auth/me", headers=auth)
        assert r2.status_code == 401

    def test_logout_without_auth_returns_401(self, client: TestClient):
        r = client.post("/auth/logout")
        assert r.status_code == 401

    def test_logout_with_invalid_token_returns_401(self, client: TestClient):
        r = client.post("/auth/logout", headers={"Authorization": "Bearer invalid-token"})
        assert r.status_code == 401

    def test_logout_idempotent(self, client: TestClient):
        """Logging out twice should not crash."""
        session = SessionLocal()
        try:
            org, user, token, auth = _create_test_org(session)
        finally:
            session.close()

        r1 = client.post("/auth/logout", headers=auth)
        assert r1.status_code == 204

        # Second logout with the same (now-invalid) token
        r2 = client.post("/auth/logout", headers=auth)
        # Should still succeed (no-op) since token is already invalid
        assert r2.status_code in (204, 401)

    def test_other_tokens_still_work_after_logout(self, client: TestClient):
        """Logging out one token doesn't affect other valid tokens."""
        session = SessionLocal()
        try:
            from app.auth import create_access_token
            org, user, _, _ = _create_test_org(session)
            # Create two tokens
            token1 = create_access_token(user.id, org.id, user.role.value)
            token2 = create_access_token(user.id, org.id, user.role.value)
            auth1 = {"Authorization": f"Bearer {token1}"}
            auth2 = {"Authorization": f"Bearer {token2}"}
        finally:
            session.close()

        # Logout token1
        r = client.post("/auth/logout", headers=auth1)
        assert r.status_code == 204

        # token2 should still work
        r2 = client.get("/auth/me", headers=auth2)
        assert r2.status_code == 200

    def test_login_after_logout_works(self, client: TestClient):
        """User can log in again after logging out."""
        session = SessionLocal()
        try:
            from app.auth import hash_password
            org = Organization(
                name=f"Logout Test Org {uuid.uuid4().hex[:8]}",
                slug=f"logout-test-{uuid.uuid4().hex[:8]}",
                timezone="America/Chicago",
                status=OrganizationStatus.ACTIVE,
                plan="business",
                plan_started_at=datetime.now(timezone.utc),
            )
            session.add(org)
            session.flush()
            user = User(
                organization_id=org.id,
                email=f"logout-{uuid.uuid4().hex[:8]}@test.com",
                full_name="Logout Test User",
                password_hash=hash_password("StrongPass123!"),
                role=UserRole.OWNER,
                status=UserStatus.ACTIVE,
            )
            session.add(user)
            session.commit()
            email = user.email
        finally:
            session.close()

        # Login
        r = client.post("/auth/login", json={"email": email, "password": "StrongPass123!"})
        assert r.status_code == 200
        new_token = r.json()["access_token"]

        # Logout
        r2 = client.post("/auth/logout", headers={"Authorization": f"Bearer {new_token}"})
        assert r2.status_code == 204

        # Login again
        r3 = client.post("/auth/login", json={"email": email, "password": "StrongPass123!"})
        assert r3.status_code == 200
        assert "access_token" in r3.json()


# ============================================================================
# P1-C: Password Change Endpoint
# ============================================================================

class TestPasswordChangeEndpoint:
    """Verify POST /auth/change-password."""

    def test_change_password_success(self, client: TestClient):
        session = SessionLocal()
        try:
            from app.auth import hash_password
            org, user, token, auth = _create_test_org(session)
            email = user.email
        finally:
            session.close()

        r = client.post(
            "/auth/change-password",
            json={
                "current_password": "StrongPass123!",
                "new_password": "NewStrong456!",
            },
            headers=auth,
        )
        assert r.status_code == 200
        assert "message" in r.json()

        # Old token should be revoked (bulk revocation)
        r2 = client.get("/auth/me", headers=auth)
        assert r2.status_code == 401

        # Login with new password
        r3 = client.post(
            "/auth/login",
            json={"email": email, "password": "NewStrong456!"},
        )
        assert r3.status_code == 200

    def test_change_password_wrong_current(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_test_org(session)
        finally:
            session.close()

        r = client.post(
            "/auth/change-password",
            json={
                "current_password": "WrongPassword!",
                "new_password": "NewStrong456!",
            },
            headers=auth,
        )
        assert r.status_code == 400
        assert "incorrect" in r.json()["detail"].lower()

    def test_change_password_same_password(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_test_org(session)
        finally:
            session.close()

        r = client.post(
            "/auth/change-password",
            json={
                "current_password": "StrongPass123!",
                "new_password": "StrongPass123!",
            },
            headers=auth,
        )
        assert r.status_code == 400
        assert "different" in r.json()["detail"].lower()

    def test_change_password_weak_new(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_test_org(session)
        finally:
            session.close()

        r = client.post(
            "/auth/change-password",
            json={
                "current_password": "StrongPass123!",
                "new_password": "short",
            },
            headers=auth,
        )
        assert r.status_code == 422

    def test_change_password_requires_auth(self, client: TestClient):
        r = client.post(
            "/auth/change-password",
            json={
                "current_password": "anything",
                "new_password": "NewStrong456!",
            },
        )
        assert r.status_code == 401


# ============================================================================
# P1-D: Token Blocklist Integration — Revoked Token is Rejected
# ============================================================================

class TestTokenRevocationIntegration:
    """Verify revoked tokens are properly rejected by get_current_user."""

    def test_revoked_token_returns_401(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_test_org(session)
        finally:
            session.close()

        # Token works before logout
        r1 = client.get("/auth/me", headers=auth)
        assert r1.status_code == 200

        # Logout (revokes token)
        r2 = client.post("/auth/logout", headers=auth)
        assert r2.status_code == 204

        # Token should now be rejected
        r3 = client.get("/auth/me", headers=auth)
        assert r3.status_code == 401
        assert "revoked" in r3.json()["detail"].lower() or "invalid" in r3.json()["detail"].lower()

    def test_bulk_revoke_returns_401(self, client: TestClient):
        session = SessionLocal()
        try:
            from app.auth import create_access_token
            org, user, token, auth = _create_test_org(session)
            # Create a second token
            token2 = create_access_token(user.id, org.id, user.role.value)
            auth2 = {"Authorization": f"Bearer {token2}"}
        finally:
            session.close()

        # Change password (triggers bulk revocation)
        r = client.post(
            "/auth/change-password",
            json={
                "current_password": "StrongPass123!",
                "new_password": "NewStrong456!",
            },
            headers=auth,
        )
        assert r.status_code == 200

        # Both old tokens should be rejected
        r2 = client.get("/auth/me", headers=auth)
        assert r2.status_code == 401

        r3 = client.get("/auth/me", headers=auth2)
        assert r3.status_code == 401

    def test_new_token_works_after_password_change(self, client: TestClient):
        session = SessionLocal()
        try:
            from app.auth import hash_password
            org = Organization(
                name=f"PC Test Org {uuid.uuid4().hex[:8]}",
                slug=f"pc-test-{uuid.uuid4().hex[:8]}",
                timezone="America/Chicago",
                status=OrganizationStatus.ACTIVE,
                plan="business",
                plan_started_at=datetime.now(timezone.utc),
            )
            session.add(org)
            session.flush()
            user = User(
                organization_id=org.id,
                email=f"pc-{uuid.uuid4().hex[:8]}@test.com",
                full_name="PC Test User",
                password_hash=hash_password("StrongPass123!"),
                role=UserRole.OWNER,
                status=UserStatus.ACTIVE,
            )
            session.add(user)
            session.commit()
            email = user.email
        finally:
            session.close()

        # Login to get a fresh token
        r_login = client.post("/auth/login", json={"email": email, "password": "StrongPass123!"})
        assert r_login.status_code == 200
        fresh_token = r_login.json()["access_token"]
        fresh_auth = {"Authorization": f"Bearer {fresh_token}"}

        # Change password
        r = client.post(
            "/auth/change-password",
            json={
                "current_password": "StrongPass123!",
                "new_password": "NewStrong456!",
            },
            headers=fresh_auth,
        )
        assert r.status_code == 200

        # Login again with new password
        r2 = client.post("/auth/login", json={"email": email, "password": "NewStrong456!"})
        assert r2.status_code == 200
        new_token = r2.json()["access_token"]

        # New token should work
        r3 = client.get("/auth/me", headers={"Authorization": f"Bearer {new_token}"})
        assert r3.status_code == 200
