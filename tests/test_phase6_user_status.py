"""Tests for Phase 6 - User Status Management (Dashboard Operational Completeness).

Covers:
  1. Owner/admin can toggle user status (active ↔ disabled)
  2. Member cannot change user status (403)
  3. Cannot disable the last owner
  4. Invalid status value rejected (422)
  5. Cross-org isolation for status changes
  6. Dashboard HTML shows status dropdown in edit modal
  7. Dashboard HTML shows actual status in user table (not hardcoded "Active")
  8. User list shows actual status in API response

Approach: Uses dependency override pattern (same as Phase 5) to mock auth
and DB - avoids SQLite connect_timeout issue with --noconftest runs.

The organization router uses `get_current_user` from app.auth (returns User ORM).
The dashboard uses `_auth_context` from app.dashboard (returns AuthContext).
We override both depending on which router we're testing.
"""
import uuid
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.auth import get_current_user
from app.dashboard import _auth_context, AuthContext
from app.database import get_db
from app.models_multi_tenant import Organization, User, UserStatus


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_user(role="owner", org_id=None, status=UserStatus.ACTIVE):
    """Create a mock User ORM object for org router tests."""
    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.organization_id = org_id or uuid.uuid4()
    user.role = MagicMock()
    user.role.value = role
    user.role.__str__ = lambda s, r=role: r
    user.role.__eq__ = lambda s, o, r=role: (getattr(o, "value", o) == r) or (o is r)
    user.status = status
    user.full_name = "Test User"
    user.email = f"test-{uuid.uuid4().hex[:6]}@example.com"
    user.created_at = MagicMock()
    return user


def _make_org():
    """Create a mock Organization ORM object."""
    org = MagicMock(spec=Organization)
    org.id = uuid.uuid4()
    org.name = "Test Org"
    org.slug = "test-org"
    org.status = MagicMock()
    org.status.value = "active"
    return org


def _make_auth_ctx(org_id=True, role="owner", is_platform_admin=False):
    """Create a mock AuthContext for dashboard routes."""
    ctx = MagicMock(spec=AuthContext)
    ctx.org_id = MagicMock() if org_id else None
    ctx.user_id = MagicMock()
    ctx.role = role
    ctx.is_platform_admin = is_platform_admin
    return ctx


def _dep(value):
    """Return a FastAPI dependency function that yields `value`."""
    def _fn():
        return value
    return _fn


def _build_user_query_chain(target_user):
    """Build a mock chain for db.query(User).filter(...).first() → target_user."""
    mock = MagicMock()
    mock.filter.return_value.first.return_value = target_user
    return mock


def _build_org_query_chain(org):
    """Build a mock chain for db.query(Organization).filter(...).first() → org."""
    mock = MagicMock()
    mock.filter.return_value.first.return_value = org
    return mock


def _build_list_query_chain(users):
    """Build a mock chain for db.query(User).filter(...).order_by(...).all() → users."""
    mock = MagicMock()
    mock.filter.return_value.order_by.return_value.all.return_value = users
    return mock


def _make_mock_db(user_query=None, org_query=None, list_query=None):
    """Create a mock DB session that returns different query chains based on model.

    db.query(User) → user_query chain
    db.query(Organization) → org_query chain
    """
    mock_db = MagicMock()

    def query_side_effect(model):
        if model is User:
            if list_query is not None:
                return list_query
            if user_query is not None:
                return user_query
        if model is Organization:
            if org_query is not None:
                return org_query
        return MagicMock()

    mock_db.query.side_effect = query_side_effect
    return mock_db


# ══════════════════════════════════════════════════════════════════════════════
# 1. Owner/Admin Can Toggle Status
# ══════════════════════════════════════════════════════════════════════════════


class TestOwnerCanDisableUser:
    """Owner can disable an active user."""

    def test_owner_disables_member(self):
        from app.main import app as _app

        org = _make_org()
        caller = _make_user(role="owner", org_id=org.id)
        target_id = uuid.uuid4()
        target = _make_user(role="member", org_id=org.id, status=UserStatus.ACTIVE)
        target.id = target_id

        user_q = _build_user_query_chain(target)
        org_q = _build_org_query_chain(org)
        mock_db = _make_mock_db(user_query=user_q, org_query=org_q)

        _app.dependency_overrides[get_current_user] = _dep(caller)
        _app.dependency_overrides[get_db] = _dep(mock_db)
        try:
            client = TestClient(_app, raise_server_exceptions=False)
            resp = client.patch(
                f"/organization/users/{target_id}",
                json={"status": "disabled"},
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["status"] == "disabled"
        finally:
            _app.dependency_overrides.clear()

    def test_owner_disables_admin(self):
        from app.main import app as _app

        org = _make_org()
        caller = _make_user(role="owner", org_id=org.id)
        target_id = uuid.uuid4()
        target = _make_user(role="admin", org_id=org.id, status=UserStatus.ACTIVE)
        target.id = target_id

        user_q = _build_user_query_chain(target)
        org_q = _build_org_query_chain(org)
        mock_db = _make_mock_db(user_query=user_q, org_query=org_q)

        _app.dependency_overrides[get_current_user] = _dep(caller)
        _app.dependency_overrides[get_db] = _dep(mock_db)
        try:
            client = TestClient(_app, raise_server_exceptions=False)
            resp = client.patch(
                f"/organization/users/{target_id}",
                json={"status": "disabled"},
            )
            assert resp.status_code == 200, resp.text
            assert resp.json()["status"] == "disabled"
        finally:
            _app.dependency_overrides.clear()


class TestOwnerCanEnableUser:
    """Owner can re-enable a disabled user."""

    def test_owner_enables_disabled_member(self):
        from app.main import app as _app

        org = _make_org()
        caller = _make_user(role="owner", org_id=org.id)
        target_id = uuid.uuid4()
        target = _make_user(role="member", org_id=org.id, status=UserStatus.DISABLED)
        target.id = target_id

        user_q = _build_user_query_chain(target)
        org_q = _build_org_query_chain(org)
        mock_db = _make_mock_db(user_query=user_q, org_query=org_q)

        _app.dependency_overrides[get_current_user] = _dep(caller)
        _app.dependency_overrides[get_db] = _dep(mock_db)
        try:
            client = TestClient(_app, raise_server_exceptions=False)
            resp = client.patch(
                f"/organization/users/{target_id}",
                json={"status": "active"},
            )
            assert resp.status_code == 200, resp.text
            assert resp.json()["status"] == "active"
        finally:
            _app.dependency_overrides.clear()


class TestAdminCanToggleStatus:
    """Admin can toggle member status."""

    def test_admin_disables_member(self):
        from app.main import app as _app

        org = _make_org()
        caller = _make_user(role="admin", org_id=org.id)
        target_id = uuid.uuid4()
        target = _make_user(role="member", org_id=org.id, status=UserStatus.ACTIVE)
        target.id = target_id

        user_q = _build_user_query_chain(target)
        org_q = _build_org_query_chain(org)
        mock_db = _make_mock_db(user_query=user_q, org_query=org_q)

        _app.dependency_overrides[get_current_user] = _dep(caller)
        _app.dependency_overrides[get_db] = _dep(mock_db)
        try:
            client = TestClient(_app, raise_server_exceptions=False)
            resp = client.patch(
                f"/organization/users/{target_id}",
                json={"status": "disabled"},
            )
            assert resp.status_code == 200, resp.text
            assert resp.json()["status"] == "disabled"
        finally:
            _app.dependency_overrides.clear()


# ══════════════════════════════════════════════════════════════════════════════
# 2. Member Cannot Change Status
# ══════════════════════════════════════════════════════════════════════════════


class TestMemberCannotChangeStatus:
    """Members are rejected with 403 when trying to change user status."""

    def test_member_cannot_disable(self):
        from app.main import app as _app

        org = _make_org()
        caller = _make_user(role="member", org_id=org.id)
        mock_db = MagicMock()

        _app.dependency_overrides[get_current_user] = _dep(caller)
        _app.dependency_overrides[get_db] = _dep(mock_db)
        try:
            client = TestClient(_app, raise_server_exceptions=False)
            resp = client.patch(
                f"/organization/users/{uuid.uuid4()}",
                json={"status": "disabled"},
            )
            assert resp.status_code == 403
        finally:
            _app.dependency_overrides.clear()


# ══════════════════════════════════════════════════════════════════════════════
# 3. Cannot Disable Last Owner
# ══════════════════════════════════════════════════════════════════════════════


class TestLastOwnerProtection:
    """Last-owner protection check (applies to DELETE, not PATCH).

    Note: The PATCH /organization/users/{user_id} endpoint does NOT currently
    prevent disabling the last owner. This is an accepted gap documented in
    the adversarial audit - it can be addressed in a future phase.
    """

    def test_owner_can_disable_self_via_patch(self):
        """PATCH now BLOCKS disabling the last owner (H6 security fix).

        Previously this was allowed (no guard in update_user); the fix
        prevents orphaning the organization.
        """
        from app.main import app as _app

        org = _make_org()
        caller = _make_user(role="owner", org_id=org.id)
        caller.status = UserStatus.ACTIVE

        user_q = _build_user_query_chain(caller)
        org_q = _build_org_query_chain(org)
        mock_db = _make_mock_db(user_query=user_q, org_query=org_q)

        _app.dependency_overrides[get_current_user] = _dep(caller)
        _app.dependency_overrides[get_db] = _dep(mock_db)
        try:
            client = TestClient(_app, raise_server_exceptions=False)
            resp = client.patch(
                f"/organization/users/{caller.id}",
                json={"status": "disabled"},
            )
            # PATCH now prevents last-owner disable
            assert resp.status_code == 403, resp.text
        finally:
            _app.dependency_overrides.clear()

    def test_delete_prevents_last_owner(self):
        """DELETE endpoint prevents removing the last owner."""
        from app.main import app as _app

        org = _make_org()
        caller = _make_user(role="owner", org_id=org.id)
        target = _make_user(role="owner", org_id=org.id)
        target.id = caller.id  # Same user

        user_q = MagicMock()
        user_q.filter.return_value.first.return_value = target

        mock_db = MagicMock()
        def query_side_effect(model):
            if model is User:
                return user_q
            return MagicMock()
        mock_db.query.side_effect = query_side_effect

        _app.dependency_overrides[get_current_user] = _dep(caller)
        _app.dependency_overrides[get_db] = _dep(mock_db)
        try:
            client = TestClient(_app, raise_server_exceptions=False)
            resp = client.delete(f"/organization/users/{caller.id}")
            assert resp.status_code in (400, 403), resp.text
        finally:
            _app.dependency_overrides.clear()


# ══════════════════════════════════════════════════════════════════════════════
# 4. Invalid Status Value Rejected
# ══════════════════════════════════════════════════════════════════════════════


class TestInvalidStatusValue:
    """Invalid status values should be rejected."""

    def test_invalid_status_returns_422(self):
        from app.main import app as _app

        org = _make_org()
        caller = _make_user(role="owner", org_id=org.id)
        mock_db = MagicMock()

        _app.dependency_overrides[get_current_user] = _dep(caller)
        _app.dependency_overrides[get_db] = _dep(mock_db)
        try:
            client = TestClient(_app, raise_server_exceptions=False)
            resp = client.patch(
                f"/organization/users/{uuid.uuid4()}",
                json={"status": "suspended"},
            )
            assert resp.status_code == 422
        finally:
            _app.dependency_overrides.clear()


# ══════════════════════════════════════════════════════════════════════════════
# 5. Cross-Org Isolation
# ══════════════════════════════════════════════════════════════════════════════


class TestStatusChangeCrossOrgIsolation:
    """Status changes must be scoped to the caller's organization."""

    def test_org_a_cannot_disable_org_b_user(self):
        from app.main import app as _app

        caller = _make_user(role="owner")
        target_id = uuid.uuid4()

        # User query returns None - target not found in caller's org
        mock_db = MagicMock()
        user_q = MagicMock()
        user_q.filter.return_value.first.return_value = None
        mock_db.query.side_effect = lambda model: user_q if model is User else MagicMock()

        _app.dependency_overrides[get_current_user] = _dep(caller)
        _app.dependency_overrides[get_db] = _dep(mock_db)
        try:
            client = TestClient(_app, raise_server_exceptions=False)
            resp = client.patch(
                f"/organization/users/{target_id}",
                json={"status": "disabled"},
            )
            assert resp.status_code == 404
        finally:
            _app.dependency_overrides.clear()


# ══════════════════════════════════════════════════════════════════════════════
# 6. Dashboard HTML - Status UI Elements
# ══════════════════════════════════════════════════════════════════════════════


class TestDashboardHTMLStatusUI:
    """Dashboard HTML should include user status management UI elements."""

    def test_edit_modal_has_status_dropdown(self):
        from app.main import app as _app

        ctx = _make_auth_ctx(role="owner", is_platform_admin=True)
        _app.dependency_overrides[_auth_context] = _dep(ctx)
        try:
            client = TestClient(_app, raise_server_exceptions=False)
            resp = client.get("/dashboard")
            assert resp.status_code == 200
            html = resp.text
            assert "um-e-status" in html
            assert 'value="active"' in html
            assert 'value="disabled"' in html
        finally:
            _app.dependency_overrides.clear()

    def test_user_table_shows_dynamic_status(self):
        from app.main import app as _app

        ctx = _make_auth_ctx(role="owner", is_platform_admin=True)
        _app.dependency_overrides[_auth_context] = _dep(ctx)
        try:
            client = TestClient(_app, raise_server_exceptions=False)
            resp = client.get("/dashboard")
            assert resp.status_code == 200
            html = resp.text
            # loadUsers should read u.status from the API response
            assert "u.status" in html
            # Should conditionally render based on u.status
            assert "disabled" in html
        finally:
            _app.dependency_overrides.clear()

    def test_update_user_sends_status(self):
        from app.main import app as _app

        ctx = _make_auth_ctx(role="owner", is_platform_admin=True)
        _app.dependency_overrides[_auth_context] = _dep(ctx)
        try:
            client = TestClient(_app, raise_server_exceptions=False)
            resp = client.get("/dashboard")
            assert resp.status_code == 200
            html = resp.text
            # updateUser function should read status from um-e-status
            assert "um-e-status" in html
            # Should send status in the JSON payload
            assert "status:status" in html.replace(" ", "")
        finally:
            _app.dependency_overrides.clear()


# ══════════════════════════════════════════════════════════════════════════════
# 7. User List Shows Actual Status
# ══════════════════════════════════════════════════════════════════════════════


class TestUserListShowsActualStatus:
    """GET /organization/users should return actual user status."""

    def test_list_users_includes_status_field(self):
        from app.main import app as _app

        org = _make_org()
        caller = _make_user(role="owner", org_id=org.id)
        mock_user1 = _make_user(role="member", org_id=org.id, status=UserStatus.ACTIVE)
        mock_user2 = _make_user(role="admin", org_id=org.id, status=UserStatus.DISABLED)

        list_q = MagicMock()
        list_q.filter.return_value.order_by.return_value.all.return_value = [mock_user1, mock_user2]
        org_q = _build_org_query_chain(org)
        mock_db = _make_mock_db(list_query=list_q, org_query=org_q)

        _app.dependency_overrides[get_current_user] = _dep(caller)
        _app.dependency_overrides[get_db] = _dep(mock_db)
        try:
            client = TestClient(_app, raise_server_exceptions=False)
            resp = client.get("/organization/users")
            assert resp.status_code == 200, resp.text
            users = resp.json()["users"]
            assert len(users) == 2
            statuses = {u["status"] for u in users}
            assert "active" in statuses
            assert "disabled" in statuses
        finally:
            _app.dependency_overrides.clear()
