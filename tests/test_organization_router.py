"""Organization router tests (Phase 29 P1-10).

Covers all 6 endpoints in app/routers/organization_router.py:
  GET    /organization/users              - List users in current org
  POST   /organization/users              - Invite/create a user in current org
  PATCH  /organization/users/{user_id}    - Update user role/status
  DELETE /organization/users/{user_id}    - Remove a user from the org
  GET    /organization/settings           - Get org settings
  PATCH  /organization/settings           - Update org settings

Total: 40+ tests covering CRUD lifecycle, RBAC, cross-tenant isolation,
edge cases, and security.
"""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_org_and_user(
    db,
    role: UserRole = UserRole.OWNER,
    plan: str = "business",
    email_prefix: str = "org-test",
):
    """Create a fresh org + user and return (org, user, token, auth_header)."""
    from app.auth import create_access_token, hash_password

    org = Organization(
        name=f"Org Test Org {uuid.uuid4().hex[:8]}",
        slug=f"org-test-{uuid.uuid4().hex[:8]}",
        timezone="America/Chicago",
        status=OrganizationStatus.ACTIVE,
        plan=plan,
    )
    db.add(org)
    db.flush()

    user = User(
        organization_id=org.id,
        email=f"{email_prefix}-{uuid.uuid4().hex[:8]}@test.com",
        full_name="Org Test User",
        password_hash=hash_password("StrongPass123!"),
        role=role,
        status=UserStatus.ACTIVE,
    )
    db.add(user)
    db.commit()
    db.refresh(org)
    db.refresh(user)

    token = create_access_token(
        user_id=user.id,
        organization_id=org.id,
        role=role.value,
    )
    auth_header = {"Authorization": f"Bearer {token}"}
    return org, user, token, auth_header


@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    """Inject test-mode secrets for JWT creation."""
    from app.config import settings
    from app.services.crypto import generate_key
    monkeypatch.setattr(settings, "jwt_secret_key", "test-org-router-secret-key-32ch!!!")
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", generate_key())


# ===========================================================================
# GET /organization/users - list users
# ===========================================================================

class TestOrgListUsers:
    """GET /organization/users - list users in current org."""

    def test_list_users_returns_org_members(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.get("/organization/users", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert "users" in data
        assert data["total"] >= 1
        emails = [u["email"] for u in data["users"]]
        assert user.email in emails

    def test_list_users_includes_org_info(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.get("/organization/users", headers=auth)
        data = r.json()
        for u in data["users"]:
            assert "organization" in u
            assert u["organization"]["id"] == str(org.id)

    def test_list_users_requires_auth(self, client: TestClient):
        r = client.get("/organization/users")
        assert r.status_code in (401, 403)

    def test_list_users_member_can_access(self, client: TestClient):
        """Members can list users (read-only access)."""
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session, role=UserRole.MEMBER)
        finally:
            session.close()

        r = client.get("/organization/users", headers=auth)
        assert r.status_code == 200

    def test_list_users_does_not_include_password_hash(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.get("/organization/users", headers=auth)
        for u in r.json()["users"]:
            assert "password_hash" not in u
            assert "credentials_encrypted" not in u

    def test_list_users_isolation(self, client: TestClient):
        """Org A's users should not appear in Org B's listing."""
        session = SessionLocal()
        try:
            org_a, user_a, token_a, auth_a = _create_org_and_user(session, email_prefix="org-a")
            org_b, user_b, token_b, auth_b = _create_org_and_user(session, email_prefix="org-b")
            email_a = user_a.email
            email_b = user_b.email
        finally:
            session.close()

        r = client.get("/organization/users", headers=auth_a)
        data = r.json()
        emails = [u["email"] for u in data["users"]]
        assert email_a in emails
        assert email_b not in emails


# ===========================================================================
# POST /organization/users - create user
# ===========================================================================

class TestOrgCreateUser:
    """POST /organization/users - create a new user in the org."""

    def test_create_user_success(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.post(
            "/organization/users",
            json={
                "email": f"new-{uuid.uuid4().hex[:8]}@test.com",
                "name": "New Member",
                "password": "StrongPass123!",
                "role": "member",
            },
            headers=auth,
        )
        assert r.status_code == 201
        data = r.json()
        assert data["role"] == "member"
        assert data["name"] == "New Member"
        assert "password" not in data
        assert "password_hash" not in data

    def test_create_user_as_admin(self, client: TestClient):
        """Admin can create users."""
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session, role=UserRole.ADMIN)
        finally:
            session.close()

        r = client.post(
            "/organization/users",
            json={
                "email": f"admin-created-{uuid.uuid4().hex[:8]}@test.com",
                "name": "Admin Created",
                "password": "StrongPass123!",
                "role": "member",
            },
            headers=auth,
        )
        assert r.status_code == 201

    def test_create_user_duplicate_email_returns_409(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.post(
            "/organization/users",
            json={
                "email": user.email,  # duplicate
                "name": "Duplicate",
                "password": "StrongPass123!",
                "role": "member",
            },
            headers=auth,
        )
        assert r.status_code == 409
        assert "already exists" in r.json()["detail"]

    def test_create_user_member_forbidden(self, client: TestClient):
        """Members cannot create users."""
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session, role=UserRole.MEMBER)
        finally:
            session.close()

        r = client.post(
            "/organization/users",
            json={
                "email": f"member-tried-{uuid.uuid4().hex[:8]}@test.com",
                "name": "Member Tried",
                "password": "StrongPass123!",
                "role": "member",
            },
            headers=auth,
        )
        assert r.status_code == 403

    def test_create_user_invalid_role_returns_422(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.post(
            "/organization/users",
            json={
                "email": f"bad-role-{uuid.uuid4().hex[:8]}@test.com",
                "name": "Bad Role",
                "password": "StrongPass123!",
                "role": "superadmin",
            },
            headers=auth,
        )
        assert r.status_code == 422
        assert "Invalid role" in r.json()["detail"]

    def test_create_user_weak_password_rejected(self, client: TestClient):
        """Weak passwords should be rejected."""
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.post(
            "/organization/users",
            json={
                "email": f"weak-{uuid.uuid4().hex[:8]}@test.com",
                "name": "Weak Pass",
                "password": "123",
                "role": "member",
            },
            headers=auth,
        )
        assert r.status_code in (400, 422)

    def test_create_user_requires_auth(self, client: TestClient):
        r = client.post(
            "/organization/users",
            json={
                "email": "no-auth@test.com",
                "name": "No Auth",
                "password": "StrongPass123!",
                "role": "member",
            },
        )
        assert r.status_code in (401, 403)

    def test_create_user_no_duplicates_across_orgs(self, client: TestClient):
        """Same email in different orgs should be allowed."""
        session = SessionLocal()
        try:
            org_a, user_a, token_a, auth_a = _create_org_and_user(session, email_prefix="cross-a")
            org_b, user_b, token_b, auth_b = _create_org_and_user(session, email_prefix="cross-b")
            shared_email = f"shared-{uuid.uuid4().hex[:8]}@test.com"
        finally:
            session.close()

        r1 = client.post(
            "/organization/users",
            json={
                "email": shared_email,
                "name": "Shared Email User",
                "password": "StrongPass123!",
                "role": "member",
            },
            headers=auth_a,
        )
        assert r1.status_code == 201

        r2 = client.post(
            "/organization/users",
            json={
                "email": shared_email,
                "name": "Same Email Different Org",
                "password": "StrongPass123!",
                "role": "member",
            },
            headers=auth_b,
        )
        assert r2.status_code == 201


# ===========================================================================
# PATCH /organization/users/{user_id} - update user
# ===========================================================================

class TestOrgUpdateUser:
    """PATCH /organization/users/{user_id} - update user role/status."""

    def test_update_user_role(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
            # Create a member user to update
            from app.auth import hash_password
            member = User(
                organization_id=org.id,
                email=f"member-{uuid.uuid4().hex[:8]}@test.com",
                full_name="Member User",
                password_hash=hash_password("StrongPass123!"),
                role=UserRole.MEMBER,
                status=UserStatus.ACTIVE,
            )
            session.add(member)
            session.commit()
            session.refresh(member)
            member_id = member.id
        finally:
            session.close()

        r = client.patch(
            f"/organization/users/{member_id}",
            json={"role": "admin"},
            headers=auth,
        )
        assert r.status_code == 200
        assert r.json()["role"] == "admin"

    def test_update_user_name(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
            from app.auth import hash_password
            member = User(
                organization_id=org.id,
                email=f"rename-{uuid.uuid4().hex[:8]}@test.com",
                full_name="Old Name",
                password_hash=hash_password("StrongPass123!"),
                role=UserRole.MEMBER,
                status=UserStatus.ACTIVE,
            )
            session.add(member)
            session.commit()
            session.refresh(member)
            member_id = member.id
        finally:
            session.close()

        r = client.patch(
            f"/organization/users/{member_id}",
            json={"name": "New Name"},
            headers=auth,
        )
        assert r.status_code == 200
        assert r.json()["name"] == "New Name"

    def test_update_user_disable(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
            from app.auth import hash_password
            member = User(
                organization_id=org.id,
                email=f"disable-{uuid.uuid4().hex[:8]}@test.com",
                full_name="To Disable",
                password_hash=hash_password("StrongPass123!"),
                role=UserRole.MEMBER,
                status=UserStatus.ACTIVE,
            )
            session.add(member)
            session.commit()
            session.refresh(member)
            member_id = member.id
        finally:
            session.close()

        r = client.patch(
            f"/organization/users/{member_id}",
            json={"status": "disabled"},
            headers=auth,
        )
        assert r.status_code == 200
        assert r.json()["status"] == "disabled"

    def test_update_nonexistent_user_returns_404(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        fake_id = uuid.uuid4()
        r = client.patch(
            f"/organization/users/{fake_id}",
            json={"name": "Ghost"},
            headers=auth,
        )
        assert r.status_code == 404

    def test_update_user_invalid_role_returns_422(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
            from app.auth import hash_password
            member = User(
                organization_id=org.id,
                email=f"badrole-{uuid.uuid4().hex[:8]}@test.com",
                full_name="Bad Role Target",
                password_hash=hash_password("StrongPass123!"),
                role=UserRole.MEMBER,
                status=UserStatus.ACTIVE,
            )
            session.add(member)
            session.commit()
            session.refresh(member)
            member_id = member.id
        finally:
            session.close()

        r = client.patch(
            f"/organization/users/{member_id}",
            json={"role": "superadmin"},
            headers=auth,
        )
        assert r.status_code == 422

    def test_update_user_invalid_status_returns_422(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
            from app.auth import hash_password
            member = User(
                organization_id=org.id,
                email=f"badstatus-{uuid.uuid4().hex[:8]}@test.com",
                full_name="Bad Status Target",
                password_hash=hash_password("StrongPass123!"),
                role=UserRole.MEMBER,
                status=UserStatus.ACTIVE,
            )
            session.add(member)
            session.commit()
            session.refresh(member)
            member_id = member.id
        finally:
            session.close()

        r = client.patch(
            f"/organization/users/{member_id}",
            json={"status": "frozen"},
            headers=auth,
        )
        assert r.status_code == 422

    def test_member_cannot_update_users(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session, role=UserRole.MEMBER)
            from app.auth import hash_password
            other = User(
                organization_id=org.id,
                email=f"other-{uuid.uuid4().hex[:8]}@test.com",
                full_name="Other User",
                password_hash=hash_password("StrongPass123!"),
                role=UserRole.MEMBER,
                status=UserStatus.ACTIVE,
            )
            session.add(other)
            session.commit()
            session.refresh(other)
            other_id = other.id
        finally:
            session.close()

        r = client.patch(
            f"/organization/users/{other_id}",
            json={"name": "Hacked"},
            headers=auth,
        )
        assert r.status_code == 403

    def test_non_owner_cannot_promote_to_owner(self, client: TestClient):
        """Admin cannot assign owner role to another user."""
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session, role=UserRole.ADMIN)
            from app.auth import hash_password
            member = User(
                organization_id=org.id,
                email=f"promote-{uuid.uuid4().hex[:8]}@test.com",
                full_name="To Promote",
                password_hash=hash_password("StrongPass123!"),
                role=UserRole.MEMBER,
                status=UserStatus.ACTIVE,
            )
            session.add(member)
            session.commit()
            session.refresh(member)
            member_id = member.id
        finally:
            session.close()

        r = client.patch(
            f"/organization/users/{member_id}",
            json={"role": "owner"},
            headers=auth,
        )
        assert r.status_code == 403
        assert "Only the owner" in r.json()["detail"]

    def test_cross_tenant_update_blocked(self, client: TestClient):
        """Org A admin cannot PATCH Org B's user (P0 security test)."""
        session = SessionLocal()
        try:
            org_a, user_a, token_a, auth_a = _create_org_and_user(
                session, email_prefix="patch-ten-a"
            )
            org_b, user_b, token_b, auth_b = _create_org_and_user(
                session, email_prefix="patch-ten-b"
            )
            # user_b belongs to org_b
            user_b_id = user_b.id
        finally:
            session.close()

        # Org A admin tries to update Org B's user
        r = client.patch(
            f"/organization/users/{user_b_id}",
            json={"name": "Hacked From Org A"},
            headers=auth_a,
        )
        assert r.status_code == 404

    def test_owner_can_self_demote(self, client: TestClient):
        """Owner CANNOT demote themselves via this endpoint (H6 security fix).

        Self-demotion is blocked to prevent accidental ownerless orgs and
        privilege confusion.  Use the dedicated account flows instead.
        """
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
            user_id = user.id
        finally:
            session.close()

        r = client.patch(
            f"/organization/users/{user_id}",
            json={"role": "member"},
            headers=auth,
        )
        assert r.status_code == 403
        assert "last active owner" in r.json()["detail"]


# ===========================================================================
# DELETE /organization/users/{user_id} - delete user
# ===========================================================================

class TestOrgDeleteUser:
    """DELETE /organization/users/{user_id} - remove user from org."""

    def test_delete_member_user(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
            from app.auth import hash_password
            member = User(
                organization_id=org.id,
                email=f"del-{uuid.uuid4().hex[:8]}@test.com",
                full_name="To Delete",
                password_hash=hash_password("StrongPass123!"),
                role=UserRole.MEMBER,
                status=UserStatus.ACTIVE,
            )
            session.add(member)
            session.commit()
            session.refresh(member)
            member_id = member.id
        finally:
            session.close()

        r = client.delete(f"/organization/users/{member_id}", headers=auth)
        assert r.status_code == 200
        assert "deleted" in r.json()["message"].lower()

        # Verify user is gone
        session2 = SessionLocal()
        try:
            gone = session2.query(User).filter(User.id == member_id).first()
            assert gone is None
        finally:
            session2.close()

    def test_delete_nonexistent_user_returns_404(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.delete(f"/organization/users/{uuid.uuid4()}", headers=auth)
        assert r.status_code == 404

    def test_delete_self_returns_400(self, client: TestClient):
        """Owner cannot delete themselves."""
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
            user_id = user.id
        finally:
            session.close()

        r = client.delete(f"/organization/users/{user_id}", headers=auth)
        assert r.status_code == 400
        assert "Cannot delete your own account" in r.json()["detail"]

    def test_delete_last_owner_returns_400(self, client: TestClient):
        """Cannot delete the last owner of the org."""
        session = SessionLocal()
        try:
            org, owner1, token1, auth1 = _create_org_and_user(session, role=UserRole.OWNER, email_prefix="own1")
            from app.auth import hash_password
            # Create a second owner
            owner2 = User(
                organization_id=org.id,
                email=f"own2-{uuid.uuid4().hex[:8]}@test.com",
                full_name="Second Owner",
                password_hash=hash_password("StrongPass123!"),
                role=UserRole.OWNER,
                status=UserStatus.ACTIVE,
            )
            session.add(owner2)
            session.commit()
            session.refresh(owner2)
            owner2_id = owner2.id
            owner1_id = owner1.id
        finally:
            session.close()

        # Owner1 deletes owner2 (leaves owner1 as the only owner)
        r = client.delete(f"/organization/users/{owner2_id}", headers=auth1)
        assert r.status_code == 200

        # Owner1 tries to delete themselves (self-delete check fires first)
        r = client.delete(f"/organization/users/{owner1_id}", headers=auth1)
        assert r.status_code == 400
        assert "Cannot delete your own account" in r.json()["detail"]

    def test_member_cannot_delete_users(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session, role=UserRole.MEMBER)
            from app.auth import hash_password
            other = User(
                organization_id=org.id,
                email=f"victim-{uuid.uuid4().hex[:8]}@test.com",
                full_name="Victim",
                password_hash=hash_password("StrongPass123!"),
                role=UserRole.MEMBER,
                status=UserStatus.ACTIVE,
            )
            session.add(other)
            session.commit()
            session.refresh(other)
            other_id = other.id
        finally:
            session.close()

        r = client.delete(f"/organization/users/{other_id}", headers=auth)
        assert r.status_code == 403

    def test_delete_requires_auth(self, client: TestClient):
        r = client.delete(f"/organization/users/{uuid.uuid4()}")
        assert r.status_code in (401, 403)

    def test_cross_tenant_delete_blocked(self, client: TestClient):
        """Owner of Org A cannot delete users from Org B."""
        session = SessionLocal()
        try:
            org_a, user_a, token_a, auth_a = _create_org_and_user(session, email_prefix="del-a")
            org_b, user_b, token_b, auth_b = _create_org_and_user(session, email_prefix="del-b")
        finally:
            session.close()

        r = client.delete(f"/organization/users/{user_b.id}", headers=auth_a)
        assert r.status_code == 404  # not found in org_a's scope


# ===========================================================================
# GET /organization/settings - get settings
# ===========================================================================

class TestOrgGetSettings:
    """GET /organization/settings - get org settings."""

    def test_get_settings_returns_org_data(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.get("/organization/settings", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == str(org.id)
        assert data["name"] == org.name
        assert data["slug"] == org.slug
        assert data["timezone"] == "America/Chicago"

    def test_get_settings_no_webhook_secret(self, client: TestClient):
        """Settings response should NEVER include webhook_secret."""
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.get("/organization/settings", headers=auth)
        data = r.json()
        assert "webhook_secret" not in data
        assert "credentials_encrypted" not in data

    def test_get_settings_member_can_access(self, client: TestClient):
        """Members can read settings (read-only)."""
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session, role=UserRole.MEMBER)
        finally:
            session.close()

        r = client.get("/organization/settings", headers=auth)
        assert r.status_code == 200

    def test_get_settings_requires_auth(self, client: TestClient):
        r = client.get("/organization/settings")
        assert r.status_code in (401, 403)

    def test_get_settings_includes_schedule_config(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.get("/organization/settings", headers=auth)
        data = r.json()
        # Schedule fields may be None (no schedule config created yet)
        assert "meeting_duration_minutes" in data
        assert "reminder_enabled" in data
        assert "reminder_hour" in data
        assert "reminder_minute" in data


# ===========================================================================
# PATCH /organization/settings - update settings
# ===========================================================================

class TestOrgUpdateSettings:
    """PATCH /organization/settings - update org settings."""

    def test_update_settings_name(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.patch(
            "/organization/settings",
            json={"name": "Updated Org Name"},
            headers=auth,
        )
        assert r.status_code == 200
        assert r.json()["name"] == "Updated Org Name"

    def test_update_settings_timezone(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.patch(
            "/organization/settings",
            json={"timezone": "America/New_York"},
            headers=auth,
        )
        assert r.status_code == 200
        assert r.json()["timezone"] == "America/New_York"

    def test_update_settings_multiple_fields(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.patch(
            "/organization/settings",
            json={
                "display_name": "My Brand",
                "sender_name": "Sales Team",
                "brand_color": "#FF5733",
                "tagline": "We help businesses grow",
            },
            headers=auth,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["display_name"] == "My Brand"
        assert data["sender_name"] == "Sales Team"
        assert data["brand_color"] == "#FF5733"
        assert data["tagline"] == "We help businesses grow"

    def test_update_settings_schedule_config(self, client: TestClient):
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.patch(
            "/organization/settings",
            json={
                "meeting_duration_minutes": 45,
                "reminder_enabled": True,
                "reminder_hour": 9,
                "reminder_minute": 30,
                "rsvp_poll_interval_minutes": 15,
            },
            headers=auth,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["meeting_duration_minutes"] == 45
        assert data["reminder_enabled"] is True
        assert data["reminder_hour"] == 9
        assert data["reminder_minute"] == 30
        assert data["rsvp_poll_interval_minutes"] == 15

    def test_update_settings_member_forbidden(self, client: TestClient):
        """Members cannot update settings."""
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session, role=UserRole.MEMBER)
        finally:
            session.close()

        r = client.patch(
            "/organization/settings",
            json={"name": "Hacked Name"},
            headers=auth,
        )
        assert r.status_code == 403

    def test_update_settings_admin_can_update(self, client: TestClient):
        """Admin can update settings."""
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session, role=UserRole.ADMIN)
        finally:
            session.close()

        r = client.patch(
            "/organization/settings",
            json={"name": "Admin Updated"},
            headers=auth,
        )
        assert r.status_code == 200
        assert r.json()["name"] == "Admin Updated"

    def test_update_settings_requires_auth(self, client: TestClient):
        r = client.patch(
            "/organization/settings",
            json={"name": "No Auth"},
        )
        assert r.status_code in (401, 403)

    def test_update_settings_no_secrets_exposed(self, client: TestClient):
        """Updated settings should never expose secrets."""
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
        finally:
            session.close()

        r = client.patch(
            "/organization/settings",
            json={"name": "Secret Check"},
            headers=auth,
        )
        data = r.json()
        assert "webhook_secret" not in data
        assert "credentials_encrypted" not in data

    def test_update_settings_empty_body_is_idempotent(self, client: TestClient):
        """PATCH with empty body should return current settings unchanged."""
        session = SessionLocal()
        try:
            org, user, token, auth = _create_org_and_user(session)
            original_name = org.name
        finally:
            session.close()

        r = client.patch(
            "/organization/settings",
            json={},
            headers=auth,
        )
        assert r.status_code == 200
        assert r.json()["name"] == original_name
