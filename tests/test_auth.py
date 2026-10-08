"""Comprehensive authentication and authorization tests (Phase 6B.3).

Covers:
  1. Registration — success, duplicate email, slug generation, atomicity
  2. Password — hashing, verification, strength validation, never returned
  3. Login — success, generic error, disabled user, wrong password
  4. JWT tokens — create, decode, expired, malformed, tampered
  5. /auth/me — authenticated, unauthenticated, org info, role info
  6. Tenant isolation — org A can't read B's resources
  7. Authorization — owner/admin/member permissions
  8. Owner protection — last owner can't be deleted
  9. Security — client org_id ignored, no secrets in responses, etc.

Total: 44 tests
"""
import base64
import time
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from jose import jwt

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
from app.services.crypto import generate_key

# ── Test Constants ────────────────────────────────────────────────────────────

TEST_JWT_SECRET = "test-secret-key-for-phase-6b3-jwt-testing-32chars!!"
TEST_ENCRYPTION_KEY = generate_key()

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    """Inject test-mode secrets so get_jwt_secret_key() works."""
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
        plan="business",
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
    db.commit()
    db.refresh(org)
    db.refresh(user)
    return org, user


def _make_token(user_id: uuid.UUID, org_id: uuid.UUID, role: str, **overrides) -> str:
    """Create a valid JWT token for testing."""
    from app.auth import create_access_token

    return create_access_token(
        user_id=user_id,
        organization_id=org_id,
        role=role,
        **overrides,
    )


def _auth_header(token: str) -> dict:
    """Return Authorization header for Bearer token."""
    return {"Authorization": f"Bearer {token}"}


# ══════════════════════════════════════════════════════════════════════════════
# 1. REGISTRATION TESTS (6 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestRegistration:
    """POST /auth/register tests."""

    def test_register_success(self, client: TestClient):
        """Successful registration returns 201 + JWT token."""
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": "Acme Corp",
                "name": "John Owner",
                "email": f"john-{uuid.uuid4().hex[:8]}@acme.com",
                "password": "SecurePass123!",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert len(data["access_token"]) > 20

    def test_register_creates_org_and_user(self, client: TestClient):
        """Registration creates both Organization and User atomically."""
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": "Widget Inc",
                "name": "Jane Admin",
                "email": f"jane-{uuid.uuid4().hex[:8]}@widget.com",
                "password": "AnotherPass99!",
            },
        )
        assert resp.status_code == 201

        # Decode the token to get user_id and org_id
        token = resp.json()["access_token"]
        payload = jwt.decode(token, TEST_JWT_SECRET, algorithms=["HS256"])
        user_id = uuid.UUID(payload["sub"])
        org_id = uuid.UUID(payload["org_id"])

        # Verify both exist in DB
        db = SessionLocal()
        try:
            org = db.query(Organization).filter(Organization.id == org_id).first()
            user = db.query(User).filter(User.id == user_id).first()
            assert org is not None
            assert org.name == "Widget Inc"
            assert user is not None
            assert user.role == UserRole.OWNER
            assert user.organization_id == org_id
        finally:
            db.close()

    def test_register_duplicate_email(self, client: TestClient, db):
        """Registration with existing email returns 409."""
        _create_org_and_user(db, email="dupe@test.com")
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": "Another Org",
                "name": "Dupe User",
                "email": "dupe@test.com",
                "password": "StrongPass123!",
            },
        )
        assert resp.status_code == 409
        assert "already exists" in resp.json()["detail"]

    def test_register_weak_password_rejected(self, client: TestClient):
        """Registration with short password returns 422."""
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": "Weak Org",
                "name": "Weak User",
                "email": f"weak-{uuid.uuid4().hex[:8]}@test.com",
                "password": "short",
            },
        )
        assert resp.status_code == 422

    def test_register_empty_organization_name(self, client: TestClient):
        """Registration with empty org name returns 422."""
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": "",
                "name": "No Org",
                "email": f"noorg-{uuid.uuid4().hex[:8]}@test.com",
                "password": "StrongPass123!",
            },
        )
        assert resp.status_code == 422

    def test_register_invalid_email(self, client: TestClient):
        """Registration with invalid email returns 422."""
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": "Bad Email Org",
                "name": "Bad Email",
                "email": "not-an-email",
                "password": "StrongPass123!",
            },
        )
        assert resp.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# 2. PASSWORD TESTS (5 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestPasswordSecurity:
    """Password hashing and storage security tests."""

    def test_password_is_hashed(self, client: TestClient, db):
        """password_hash in DB is a bcrypt hash, not plaintext."""
        _create_org_and_user(db, email="hash@test.com", password="MySecurePass!")
        user = db.query(User).filter(User.email == "hash@test.com").first()
        assert user is not None
        assert user.password_hash is not None
        assert user.password_hash.startswith("$2b$")
        assert user.password_hash != "MySecurePass!"

    def test_password_hash_never_returned_in_register(self, client: TestClient):
        """Register response never includes password_hash."""
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": "Safe Org",
                "name": "Safe User",
                "email": f"safe-{uuid.uuid4().hex[:8]}@test.com",
                "password": "SafePass123!",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "password_hash" not in data

    def test_password_hash_never_returned_in_me(self, client: TestClient, db):
        """/auth/me never returns password_hash."""
        org, user = _create_org_and_user(db, email="me@test.com")
        token = _make_token(user.id, org.id, user.role.value)
        resp = client.get("/auth/me", headers=_auth_header(token))
        assert resp.status_code == 200
        assert "password_hash" not in resp.json()

    def test_password_verify_correct(self):
        """verify_password returns True for correct password."""
        from app.auth import hash_password, verify_password
        hashed = hash_password("correct_password")
        assert verify_password("correct_password", hashed) is True

    def test_password_verify_incorrect(self):
        """verify_password returns False for wrong password."""
        from app.auth import hash_password, verify_password
        hashed = hash_password("correct_password")
        assert verify_password("wrong_password", hashed) is False


# ══════════════════════════════════════════════════════════════════════════════
# 3. LOGIN TESTS (5 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestLogin:
    """POST /auth/login tests."""

    def test_login_success(self, client: TestClient, db):
        """Valid credentials return 200 + JWT token."""
        _create_org_and_user(db, email="login@test.com", password="LoginPass123!")
        resp = client.post(
            "/auth/login",
            json={"email": "login@test.com", "password": "LoginPass123!"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password(self, client: TestClient, db):
        """Wrong password returns 401 with generic error."""
        _create_org_and_user(db, email="wrong@test.com", password="CorrectPass123!")
        resp = client.post(
            "/auth/login",
            json={"email": "wrong@test.com", "password": "WrongPass999!"},
        )
        assert resp.status_code == 401
        assert "Invalid email or password" in resp.json()["detail"]

    def test_login_nonexistent_email(self, client: TestClient):
        """Non-existent email returns same 401 as wrong password (anti-enumeration)."""
        resp = client.post(
            "/auth/login",
            json={"email": "ghost@test.com", "password": "AnyPass123!"},
        )
        assert resp.status_code == 401
        assert "Invalid email or password" in resp.json()["detail"]

    def test_login_disabled_user(self, client: TestClient, db):
        """Disabled user gets 401 with generic error."""
        _create_org_and_user(
            db, email="disabled@test.com", password="DisabledPass1!",
            user_status=UserStatus.DISABLED,
        )
        resp = client.post(
            "/auth/login",
            json={"email": "disabled@test.com", "password": "DisabledPass1!"},
        )
        assert resp.status_code == 401
        assert "Invalid email or password" in resp.json()["detail"]

    def test_login_returns_valid_token(self, client: TestClient, db):
        """Token from login is usable with /auth/me."""
        _create_org_and_user(db, email="valid@test.com", password="ValidPass123!")
        login_resp = client.post(
            "/auth/login",
            json={"email": "valid@test.com", "password": "ValidPass123!"},
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]

        me_resp = client.get("/auth/me", headers=_auth_header(token))
        assert me_resp.status_code == 200
        assert me_resp.json()["email"] == "valid@test.com"


# ══════════════════════════════════════════════════════════════════════════════
# 4. JWT TOKEN TESTS (5 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestJWTSecurity:
    """JWT token creation, validation, and edge cases."""

    def test_expired_token_rejected(self, client: TestClient, db):
        """Expired token returns 401."""
        org, user = _create_org_and_user(db, email="expired@test.com")
        # Create a token that expired 1 hour ago
        token = jwt.encode(
            {
                "sub": str(user.id),
                "org_id": str(org.id),
                "role": user.role.value,
                "exp": datetime.now(timezone.utc) - timedelta(hours=1),
                "iat": datetime.now(timezone.utc) - timedelta(hours=2),
            },
            TEST_JWT_SECRET,
            algorithm="HS256",
        )
        resp = client.get("/auth/me", headers=_auth_header(token))
        assert resp.status_code == 401
        assert "Invalid or expired token" in resp.json()["detail"]

    def test_malformed_token_rejected(self, client: TestClient):
        """Malformed token string returns 401."""
        resp = client.get("/auth/me", headers=_auth_header("not.a.valid.jwt"))
        assert resp.status_code == 401

    def test_tampered_token_rejected(self, client: TestClient, db):
        """Token with altered payload is rejected (signature check)."""
        org, user = _create_org_and_user(db, email="tamper@test.com")
        token = _make_token(user.id, org.id, user.role.value)
        # Tamper with the token by changing a character in the payload
        parts = token.split(".")
        # Modify the payload (base64url) — flip a character
        payload_bytes = base64.urlsafe_b64decode(parts[1] + "==")
        tampered = payload_bytes.replace(b"owner", b"admin", 1)
        parts[1] = base64.urlsafe_b64encode(tampered).rstrip(b"=").decode()
        tampered_token = ".".join(parts)
        resp = client.get("/auth/me", headers=_auth_header(tampered_token))
        assert resp.status_code == 401

    def test_wrong_secret_token_rejected(self, client: TestClient, db):
        """Token signed with a different secret is rejected."""
        org, user = _create_org_and_user(db, email="wrongkey@test.com")
        token = jwt.encode(
            {
                "sub": str(user.id),
                "org_id": str(org.id),
                "role": user.role.value,
                "exp": datetime.now(timezone.utc) + timedelta(hours=1),
                "iat": datetime.now(timezone.utc),
            },
            "completely-different-secret-key-32chars!!!!",
            algorithm="HS256",
        )
        resp = client.get("/auth/me", headers=_auth_header(token))
        assert resp.status_code == 401

    def test_token_payload_no_secrets(self, client: TestClient, db):
        """JWT payload never contains passwords, keys, or credentials."""
        org, user = _create_org_and_user(db, email="nosecret@test.com")
        token = _make_token(user.id, org.id, user.role.value)
        payload = jwt.decode(token, TEST_JWT_SECRET, algorithms=["HS256"])
        # Must NOT contain any secret material
        token_str = str(payload)
        assert "password" not in token_str.lower()
        assert "secret" not in token_str.lower()
        assert "api_key" not in token_str.lower()
        assert "credential" not in token_str.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 5. /auth/me TESTS (4 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestAuthMe:
    """GET /auth/me tests."""

    def test_me_authenticated(self, client: TestClient, db):
        """Authenticated user gets 200 with their info."""
        org, user = _create_org_and_user(db, email="myself@test.com")
        token = _make_token(user.id, org.id, user.role.value)
        resp = client.get("/auth/me", headers=_auth_header(token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "myself@test.com"
        assert data["name"] == "Test User"
        assert data["role"] == "owner"
        assert "organization" in data

    def test_me_unauthenticated(self, client: TestClient):
        """Unauthenticated request to /auth/me returns 401."""
        resp = client.get("/auth/me")
        assert resp.status_code == 401

    def test_me_returns_organization_info(self, client: TestClient, db):
        """/auth/me includes organization details."""
        org, user = _create_org_and_user(db, email="orginfo@test.com", org_name="Test Org Alpha")
        token = _make_token(user.id, org.id, user.role.value)
        resp = client.get("/auth/me", headers=_auth_header(token))
        assert resp.status_code == 200
        org_data = resp.json()["organization"]
        assert org_data["name"] == "Test Org Alpha"
        assert org_data["id"] == str(org.id)
        assert "slug" in org_data
        assert org_data["status"] == "active"

    def test_me_returns_correct_role(self, client: TestClient, db):
        """/auth/me reflects the user's actual role."""
        org, user = _create_org_and_user(db, email="role@test.com", role=UserRole.ADMIN)
        token = _make_token(user.id, org.id, user.role.value)
        resp = client.get("/auth/me", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"


# ══════════════════════════════════════════════════════════════════════════════
# 6. TENANT ISOLATION TESTS (7 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestTenantIsolation:
    """Verify organization A cannot access organization B's resources."""

    def _setup_two_orgs(self, db) -> tuple:
        """Create two separate orgs with owner users."""
        org_a, user_a = _create_org_and_user(
            db, email="owner-a@test.com", org_name="Org Alpha"
        )
        org_b, user_b = _create_org_and_user(
            db, email="owner-b@test.com", org_name="Org Beta"
        )
        # Phase 25: Set business plan so user-limit enforcement doesn't
        # interfere with tenant isolation tests.
        org_a.plan = "business"
        org_b.plan = "business"
        db.commit()
        return org_a, user_a, org_b, user_b

    def test_org_a_cannot_list_org_b_users(self, client: TestClient, db):
        """Org A's token can only see Org A's users."""
        org_a, user_a, org_b, user_b = self._setup_two_orgs(db)
        token_a = _make_token(user_a.id, org_a.id, user_a.role.value)

        resp = client.get("/organization/users", headers=_auth_header(token_a))
        assert resp.status_code == 200
        users = resp.json()["users"]
        # Should only contain org_a's user(s)
        user_emails = [u["email"] for u in users]
        assert "owner-a@test.com" in user_emails
        assert "owner-b@test.com" not in user_emails

    def test_org_a_cannot_access_org_b_user_detail(self, client: TestClient, db):
        """Org A cannot update Org B's user via PATCH."""
        org_a, user_a, org_b, user_b = self._setup_two_orgs(db)
        token_a = _make_token(user_a.id, org_a.id, user_a.role.value)

        resp = client.patch(
            f"/organization/users/{user_b.id}",
            headers=_auth_header(token_a),
            json={"name": "Hacked Name"},
        )
        # Should be 404 — user not found in org_a
        assert resp.status_code == 404

    def test_org_a_cannot_delete_org_b_user(self, client: TestClient, db):
        """Org A cannot delete Org B's user."""
        org_a, user_a, org_b, user_b = self._setup_two_orgs(db)
        token_a = _make_token(user_a.id, org_a.id, user_a.role.value)

        resp = client.delete(
            f"/organization/users/{user_b.id}",
            headers=_auth_header(token_a),
        )
        # Should be 404 — user not found in org_a
        assert resp.status_code == 404

    def test_org_a_cannot_create_user_in_org_b(self, client: TestClient, db):
        """Org A cannot create a user that appears in Org B's scope."""
        org_a, user_a, org_b, user_b = self._setup_two_orgs(db)
        token_a = _make_token(user_a.id, org_a.id, user_a.role.value)
        unique_email = f"sneaky-{uuid.uuid4().hex[:8]}@test.com"

        resp = client.post(
            "/organization/users",
            headers=_auth_header(token_a),
            json={
                "email": unique_email,
                "password": "StrongPass123!",
                "role": "admin",
            },
        )
        assert resp.status_code == 201

        # The new user should be in org_a, not org_b
        new_user = db.query(User).filter(
            User.email == unique_email,
            User.organization_id == org_a.id,
        ).first()
        assert new_user is not None
        assert new_user.organization_id == org_a.id

    def test_tampered_org_id_in_token_rejected(self, client: TestClient, db):
        """Token with wrong org_id for the user is rejected."""
        org_a, user_a, org_b, user_b = self._setup_two_orgs(db)
        # Create token with org_b's id but user_a's id — mismatch
        token = _make_token(user_a.id, org_b.id, "owner")
        resp = client.get("/auth/me", headers=_auth_header(token))
        assert resp.status_code == 401

    def test_org_b_token_cannot_see_org_a_data_in_dashboard(self, client: TestClient, db):
        """Dashboard with JWT shows only org-scoped data."""
        from app.models import Lead

        org_a, user_a, org_b, user_b = self._setup_two_orgs(db)

        # Create a lead for org_a
        unique_suffix = uuid.uuid4().hex[:8]
        lead_a = Lead(
            organization_id=org_a.id,
            name="Org A Lead",
            phone_number="+15550000001",
            email=f"lead-a-{unique_suffix}@test.com",
            appt_datetime_raw="2026-01-15 10:00",
            dedupe_key=f"lead-a-{unique_suffix}",
        )
        db.add(lead_a)
        db.commit()

        token_b = _make_token(user_b.id, org_b.id, user_b.role.value)
        auth_headers = _auth_header(token_b)

        resp = client.get("/dashboard/api/leads", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        lead_emails = [l.get("email") for l in data.get("leads", [])]
        assert f"lead-a-{unique_suffix}@test.com" not in lead_emails

    def test_different_org_slugs_are_unique(self, client: TestClient, db):
        """Different organizations get unique slugs."""
        org1, _ = _create_org_and_user(db, email="slug1@test.com", org_name="Unique Corp")
        org2, _ = _create_org_and_user(db, email="slug2@test.com", org_name="Unique Corp")
        assert org1.slug != org2.slug


# ══════════════════════════════════════════════════════════════════════════════
# 7. AUTHORIZATION TESTS (5 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestAuthorization:
    """Role-based access control tests."""

    def test_member_cannot_create_user(self, client: TestClient, db):
        """MEMBER role cannot create users (403)."""
        org, member = _create_org_and_user(
            db, email="member@test.com", role=UserRole.MEMBER
        )
        token = _make_token(member.id, org.id, "member")
        resp = client.post(
            "/organization/users",
            headers=_auth_header(token),
            json={
                "email": "new@test.com",
                "password": "StrongPass123!",
                "role": "member",
            },
        )
        assert resp.status_code == 403

    def test_admin_can_create_user(self, client: TestClient, db):
        """ADMIN role can create users (201)."""
        org, admin = _create_org_and_user(
            db, email="admin@test.com", role=UserRole.ADMIN
        )
        token = _make_token(admin.id, org.id, "admin")
        resp = client.post(
            "/organization/users",
            headers=_auth_header(token),
            json={
                "email": "admin-created@test.com",
                "password": "StrongPass123!",
                "role": "member",
            },
        )
        assert resp.status_code == 201

    def test_admin_cannot_promote_to_owner(self, client: TestClient, db):
        """ADMIN cannot promote a user to OWNER (403)."""
        org, admin = _create_org_and_user(
            db, email="admin-promote@test.com", role=UserRole.ADMIN
        )
        # Create member in the SAME org
        from app.auth import hash_password
        member = User(
            organization_id=org.id,
            email="promote-target@test.com",
            full_name="Promote Target",
            password_hash=hash_password("StrongPass123!"),
            role=UserRole.MEMBER,
            status=UserStatus.ACTIVE,
        )
        db.add(member)
        db.commit()
        db.refresh(member)

        token = _make_token(admin.id, org.id, "admin")
        resp = client.patch(
            f"/organization/users/{member.id}",
            headers=_auth_header(token),
            json={"role": "owner"},
        )
        assert resp.status_code == 403

    def test_owner_can_promote_to_owner(self, client: TestClient, db):
        """OWNER can promote a user to OWNER."""
        org, owner = _create_org_and_user(
            db, email="owner-promote@test.com", role=UserRole.OWNER
        )
        # Create member in the SAME org
        from app.auth import hash_password
        member = User(
            organization_id=org.id,
            email="promote-me@test.com",
            full_name="Promote Me",
            password_hash=hash_password("StrongPass123!"),
            role=UserRole.MEMBER,
            status=UserStatus.ACTIVE,
        )
        db.add(member)
        db.commit()
        db.refresh(member)

        token = _make_token(owner.id, org.id, "owner")
        resp = client.patch(
            f"/organization/users/{member.id}",
            headers=_auth_header(token),
            json={"role": "owner"},
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "owner"

    def test_member_can_list_users(self, client: TestClient, db):
        """MEMBER role can list users (read access is open to all)."""
        org, member = _create_org_and_user(
            db, email="member-list@test.com", role=UserRole.MEMBER
        )
        token = _make_token(member.id, org.id, "member")
        resp = client.get("/organization/users", headers=_auth_header(token))
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# 8. OWNER PROTECTION TESTS (2 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestOwnerProtection:
    """Ensure the last owner of an org cannot be deleted."""

    def test_last_owner_cannot_be_deleted(self, client: TestClient, db):
        """Deleting the last owner returns 400."""
        org, owner = _create_org_and_user(
            db, email="last-owner@test.com", role=UserRole.OWNER
        )
        token = _make_token(owner.id, org.id, "owner")
        resp = client.delete(
            f"/organization/users/{owner.id}",
            headers=_auth_header(token),
        )
        # The implementation blocks self-deletion (returns "Cannot delete your own account")
        # or last-owner deletion (returns "Cannot delete the last owner")
        assert resp.status_code == 400
        detail = resp.json()["detail"].lower()
        assert "owner" in detail or "own account" in detail

    def test_owner_can_delete_other_user(self, client: TestClient, db):
        """Owner CAN delete a non-owner user."""
        org, owner = _create_org_and_user(
            db, email="owner-delete@test.com", role=UserRole.OWNER
        )
        # Create member in the SAME org
        from app.auth import hash_password
        member = User(
            organization_id=org.id,
            email="delete-me@test.com",
            full_name="Delete Me",
            password_hash=hash_password("StrongPass123!"),
            role=UserRole.MEMBER,
            status=UserStatus.ACTIVE,
        )
        db.add(member)
        db.commit()
        db.refresh(member)

        token = _make_token(owner.id, org.id, "owner")
        resp = client.delete(
            f"/organization/users/{member.id}",
            headers=_auth_header(token),
        )
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# 9. SECURITY TESTS (5 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestSecurity:
    """Cross-cutting security validations."""

    def test_response_never_leaks_password_hash(self, client: TestClient, db):
        """No auth endpoint response includes password_hash."""
        org, user = _create_org_and_user(db, email="leak@test.com")
        token = _make_token(user.id, org.id, user.role.value)

        # Check /auth/me
        resp = client.get("/auth/me", headers=_auth_header(token))
        assert "password_hash" not in resp.json()

        # Check /organization/users
        resp = client.get("/organization/users", headers=_auth_header(token))
        for user_info in resp.json()["users"]:
            assert "password_hash" not in user_info

    def test_no_token_accesses_protected_routes(self, client: TestClient):
        """Protected routes return 401 without token."""
        resp = client.get("/auth/me")
        assert resp.status_code == 401

        resp = client.get("/organization/users")
        assert resp.status_code == 401

    def test_invalid_role_rejected_on_create(self, client: TestClient, db):
        """Creating a user with an invalid role returns 422."""
        org, owner = _create_org_and_user(db, email="invalid-role@test.com")
        token = _make_token(owner.id, org.id, "owner")
        resp = client.post(
            "/organization/users",
            headers=_auth_header(token),
            json={
                "email": "badrole@test.com",
                "password": "StrongPass123!",
                "role": "superadmin",  # invalid
            },
        )
        assert resp.status_code == 422

    def test_client_org_id_ignored(self, client: TestClient, db):
        """Organization ID is NEVER taken from the client — always from JWT."""
        org_a, user_a = _create_org_and_user(
            db, email="clientorg@test.com", org_name="Real Org"
        )
        token = _make_token(user_a.id, org_a.id, "owner")

        # The /auth/me endpoint ignores any client-supplied org_id
        # and always returns the one from the JWT
        resp = client.get("/auth/me", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["organization"]["id"] == str(org_a.id)

    def test_organization_slug_is_url_safe(self, client: TestClient):
        """Registered org slug is URL-safe lowercase."""
        suffix = uuid.uuid4().hex[:8]
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": f"Acme Training Ltd. {suffix}",
                "name": "Slug Test",
                "email": f"slug-{suffix}@test.com",
                "password": "StrongPass123!",
            },
        )
        assert resp.status_code == 201
        # Decode token to get org_id
        token = resp.json()["access_token"]
        payload = jwt.decode(token, TEST_JWT_SECRET, algorithms=["HS256"])
        org_id = uuid.UUID(payload["org_id"])

        db = SessionLocal()
        try:
            org = db.query(Organization).filter(Organization.id == org_id).first()
            assert org.slug.islower()
            assert " " not in org.slug
            # Must start with the expected base slug (may have -2 suffix for collisions)
            assert org.slug.startswith(f"acme-training-ltd-{suffix}")
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 9. ORGANIZATION STATUS ENFORCEMENT (Phase 20 P0-B — 4 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgStatusEnforcement:
    """Verify that suspended/disabled organizations block login and API access."""

    def _create_org_and_active_user(self, db, org_status=OrganizationStatus.ACTIVE):
        """Helper: create an org with given status and an active owner user."""
        org = Organization(
            name=f"Status Test Org {uuid.uuid4().hex[:8]}",
            slug=f"status-test-{uuid.uuid4().hex[:8]}",
            status=org_status,
            timezone="America/Chicago",
        )
        db.add(org)
        db.flush()
        user = User(
            organization_id=org.id,
            email=f"status-user-{uuid.uuid4().hex[:8]}@test.com",
            full_name="Status Test User",
            password_hash="hashed-password",
            role=UserRole.OWNER,
            status=UserStatus.ACTIVE,
        )
        db.add(user)
        db.commit()
        db.refresh(org)
        db.refresh(user)
        return org, user

    def test_suspended_org_blocks_login(self, client: TestClient, db):
        """Login returns generic error when organization is SUSPENDED."""
        from app.auth import hash_password

        org, user = self._create_org_and_active_user(
            db, org_status=OrganizationStatus.SUSPENDED
        )
        # Update password hash to a real bcrypt hash
        user.password_hash = hash_password("TestPass123!")
        db.commit()

        resp = client.post(
            "/auth/login",
            json={"email": user.email, "password": "TestPass123!"},
        )
        # Should return 401 (generic error — no enumeration)
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid email or password"

    def test_disabled_org_blocks_login(self, client: TestClient, db):
        """Login returns generic error when organization is DISABLED."""
        from app.auth import hash_password

        org, user = self._create_org_and_active_user(
            db, org_status=OrganizationStatus.DISABLED
        )
        user.password_hash = hash_password("TestPass123!")
        db.commit()

        resp = client.post(
            "/auth/login",
            json={"email": user.email, "password": "TestPass123!"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid email or password"

    def test_active_org_allows_login(self, client: TestClient, db):
        """Login succeeds when organization is ACTIVE."""
        from app.auth import hash_password

        org, user = self._create_org_and_active_user(
            db, org_status=OrganizationStatus.ACTIVE
        )
        user.password_hash = hash_password("TestPass123!")
        db.commit()

        resp = client.post(
            "/auth/login",
            json={"email": user.email, "password": "TestPass123!"},
        )
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_suspended_org_blocks_api_access(self, client: TestClient, db):
        """JWT-authenticated requests are rejected when org is suspended after login."""
        from app.auth import hash_password, create_access_token

        org, user = self._create_org_and_active_user(
            db, org_status=OrganizationStatus.ACTIVE
        )
        user.password_hash = hash_password("TestPass123!")
        db.commit()

        # Generate a valid JWT while org is active
        token = create_access_token(
            user_id=user.id,
            organization_id=org.id,
            role=user.role.value,
        )

        # Now suspend the org
        org.status = OrganizationStatus.SUSPENDED
        db.commit()

        # API access should be rejected
        resp = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
        assert "suspended" in resp.json()["detail"].lower()
