"""Phase 6E — Webhook Management API & Apps Script Hardening.

Covers:
  1. Webhook config GET endpoint — returns safe masked secret
  2. Webhook config PATCH — updates secret (Owner/Admin only)
  3. Webhook config PATCH — rejects MEMBER role
  4. Webhook secret rotation — generates new random secret
  5. Webhook config test — validates configuration
  6. Webhook ingestion — request-id tracking via X-Request-ID header
  7. Webhook ingestion — request-id echoed in duplicate responses
  8. Webhook ingestion — request-id echoed in accepted responses
  9. Webhook ingestion — request-id echoed in ignored responses
  10. Webhook auth failure — logged to EventLog
  11. Masked secret helper — edge cases
  12. Webhook config — not found for missing org
  13. Apps Script — request-id and source headers (unit test of sendToWebhook logic)

Total: 20+ tests
"""
import json
import secrets
import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models import EventLog, Lead
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)
from app.routers.webhook_config_router import _mask_secret
from app.services.crypto import generate_key


# ── Test Constants ────────────────────────────────────────────────────────────

TEST_JWT_SECRET = "test-secret-key-for-phase-6e-jwt-testing-32chars!!"
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


def _make_org(**overrides) -> Organization:
    """Insert an Organization row and return it.

    Default plan is "starter" (has_pipeline_automation=True) so the
    Phase 27 pipeline feature gate does not block execution in
    webhook-routing tests.  Tests that specifically need a free-tier
    org can pass ``plan="free"`` explicitly.
    """
    defaults = {
        "name": f"Test Org {uuid.uuid4().hex[:8]}",
        "slug": f"test-org-{uuid.uuid4().hex[:8]}",
        "timezone": "America/Chicago",
        "status": OrganizationStatus.ACTIVE,
        "webhook_secret": secrets.token_urlsafe(24),
        "plan": "starter",
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


def _create_user(
    org_id: uuid.UUID,
    role: UserRole = UserRole.ADMIN,
    email: str | None = None,
) -> User:
    """Create a user in the given org and return them."""
    if email is None:
        email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    from app.auth import hash_password

    db = SessionLocal()
    try:
        user = User(
            organization_id=org_id,
            email=email,
            password_hash=hash_password("TestPassword123!"),
            full_name="Test User",
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
    from datetime import datetime, timedelta, timezone

    payload = {
        "sub": str(user.id),
        "org_id": str(user.organization_id),
        "role": user.role.value,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4()),
    }
    return jose_jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")


def _auth_headers(user: User) -> dict:
    """Return Authorization headers for the given user."""
    return {"Authorization": f"Bearer {_make_jwt(user)}"}


def _unique_payload(**overrides) -> dict:
    """Generate a unique valid payload with UUID email to avoid dedup."""
    uid = uuid.uuid4().hex[:8]
    base = {
        "Interested?": "Yes",
        "Name": "Test User",
        "Company Address": "123 Test St",
        "Phone Number": "555-0100",
        "Direct Number": "555-0101",
        "Courses": "Python, Docker",
        "Email Address": f"test-{uid}@example.com",
        "Scheduled Date": "tomorrow",
        "Caller Name": "Agent Smith",
        "Phone Appt. Date/Time": f"tomorrow {uid[:2]}:{uid[2:4]}",
    }
    base.update(overrides)
    return base


# ══════════════════════════════════════════════════════════════════════════════
# 1. Masked Secret Helper
# ══════════════════════════════════════════════════════════════════════════════


class TestMaskSecret:
    """_mask_secret() must safely mask webhook secrets for display."""

    def test_none_returns_none(self):
        assert _mask_secret(None) is None

    def test_empty_string_returns_none(self):
        assert _mask_secret("") is None

    def test_short_secret_masked_completely(self):
        result = _mask_secret("abc")
        assert result == "***"

    def test_exactly_8_chars_masked_partially(self):
        result = _mask_secret("12345678")
        # 8 chars: (8-4)=4 asterisks + last 4
        assert result == "****5678"

    def test_9_chars_shows_last_4(self):
        result = _mask_secret("123456789")
        # 9 chars: (9-4)=5 asterisks + last 4
        assert result == "*****6789"

    def test_long_secret_shows_last_4(self):
        secret = "abcdefghij1234567890"  # 20 chars
        result = _mask_secret(secret)
        # 20 chars: (20-4)=16 asterisks + last 4
        assert not result.startswith("abcd")
        assert result.endswith("7890")
        assert result.startswith("*")
        assert "*" in result

    def test_16_char_secret_masked_correctly(self):
        secret = "abcdefghijklmnop"  # 16 chars
        result = _mask_secret(secret)
        # 16 chars: (16-4)=12 asterisks + last 4
        assert not result.startswith("abcd")
        assert result.endswith("mnop")
        assert result.startswith("*")
        assert len(result) == 16
        assert "*" in result


# ══════════════════════════════════════════════════════════════════════════════
# 2. Webhook Config GET
# ══════════════════════════════════════════════════════════════════════════════


class TestGetWebhookConfig:
    """GET /organization/webhook/config returns safe webhook info."""

    def test_returns_config_for_admin(self, client: TestClient):
        org = _make_org()
        user = _create_user(org.id, UserRole.ADMIN)
        resp = client.get(
            "/organization/webhook/config",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_slug"] == org.slug
        assert data["has_secret"] is True
        assert data["webhook_url"].endswith(f"/{org.slug}/form-submission")
        # Secret should be masked, not full
        assert data["secret_masked"] is not None
        assert org.webhook_secret not in (data["secret_masked"] or "")

    def test_returns_config_for_member(self, client: TestClient):
        """Any authenticated user can view config."""
        org = _make_org()
        user = _create_user(org.id, UserRole.MEMBER)
        resp = client.get(
            "/organization/webhook/config",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200

    def test_no_secret_configured(self, client: TestClient):
        org = _make_org(webhook_secret=None)
        user = _create_user(org.id, UserRole.ADMIN)
        resp = client.get(
            "/organization/webhook/config",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["has_secret"] is False
        assert data["secret_masked"] is None

    def test_unauthenticated_returns_401(self, client: TestClient):
        resp = client.get("/organization/webhook/config")
        assert resp.status_code == 401

    def test_full_secret_never_in_response(self, client: TestClient):
        org = _make_org(webhook_secret="supersecretvalue123")
        user = _create_user(org.id, UserRole.ADMIN)
        resp = client.get(
            "/organization/webhook/config",
            headers=_auth_headers(user),
        )
        body = resp.text
        assert "supersecretvalue123" not in body


# ══════════════════════════════════════════════════════════════════════════════
# 3. Webhook Config PATCH
# ══════════════════════════════════════════════════════════════════════════════


class TestUpdateWebhookConfig:
    """PATCH /organization/webhook/config updates webhook secret."""

    def test_admin_can_update_secret(self, client: TestClient):
        org = _make_org()
        user = _create_user(org.id, UserRole.ADMIN)
        new_secret = secrets.token_urlsafe(32)
        resp = client.patch(
            "/organization/webhook/config",
            json={"webhook_secret": new_secret},
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["has_secret"] is True

        # Verify in DB
        db = SessionLocal()
        try:
            updated = db.query(Organization).filter(Organization.id == org.id).first()
            assert updated.webhook_secret == new_secret
        finally:
            db.close()

    def test_owner_can_update_secret(self, client: TestClient):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.patch(
            "/organization/webhook/config",
            json={"webhook_secret": "new-owner-secret-12345"},
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200

    def test_member_cannot_update_secret(self, client: TestClient):
        org = _make_org()
        user = _create_user(org.id, UserRole.MEMBER)
        resp = client.patch(
            "/organization/webhook/config",
            json={"webhook_secret": "new-secret-123456"},
            headers=_auth_headers(user),
        )
        assert resp.status_code == 403

    def test_secret_too_short_rejected(self, client: TestClient):
        org = _make_org()
        user = _create_user(org.id, UserRole.ADMIN)
        resp = client.patch(
            "/organization/webhook/config",
            json={"webhook_secret": "short"},
            headers=_auth_headers(user),
        )
        assert resp.status_code == 422

    def test_full_secret_never_returned(self, client: TestClient):
        org = _make_org()
        user = _create_user(org.id, UserRole.ADMIN)
        new_secret = "my-new-super-secret-key-12345"
        resp = client.patch(
            "/organization/webhook/config",
            json={"webhook_secret": new_secret},
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200
        # Full secret should not appear in response body
        assert new_secret not in resp.text


# ══════════════════════════════════════════════════════════════════════════════
# 4. Webhook Secret Rotation
# ══════════════════════════════════════════════════════════════════════════════


class TestRotateWebhookSecret:
    """POST /organization/webhook/rotate-secret generates a new secret."""

    def test_rotation_generates_new_secret(self, client: TestClient):
        org = _make_org()
        old_secret = org.webhook_secret
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.post(
            "/organization/webhook/rotate-secret",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200
        data = resp.json()
        new_secret = data["webhook_secret"]
        assert new_secret != old_secret
        assert len(new_secret) > 16

        # Verify in DB
        db = SessionLocal()
        try:
            updated = db.query(Organization).filter(Organization.id == org.id).first()
            assert updated.webhook_secret == new_secret
        finally:
            db.close()

    def test_rotation_message_includes_instructions(self, client: TestClient):
        org = _make_org()
        user = _create_user(org.id, UserRole.ADMIN)
        resp = client.post(
            "/organization/webhook/rotate-secret",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "Apps Script" in data["message"]
        assert "WEBHOOK_SECRET" in data["message"]

    def test_member_cannot_rotate(self, client: TestClient):
        org = _make_org()
        user = _create_user(org.id, UserRole.MEMBER)
        resp = client.post(
            "/organization/webhook/rotate-secret",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 403

    def test_each_rotation_unique(self, client: TestClient):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        secrets_set = set()
        for _ in range(5):
            resp = client.post(
                "/organization/webhook/rotate-secret",
                headers=_auth_headers(user),
            )
            assert resp.status_code == 200
            secrets_set.add(resp.json()["webhook_secret"])
        assert len(secrets_set) == 5


# ══════════════════════════════════════════════════════════════════════════════
# 5. Webhook Config Test
# ══════════════════════════════════════════════════════════════════════════════


class TestWebhookConfigTest:
    """POST /organization/webhook/test validates webhook configuration."""

    def test_valid_config(self, client: TestClient):
        org = _make_org()
        user = _create_user(org.id, UserRole.MEMBER)
        # Patch settings to have a global webhook_secret so validation passes
        with patch.object(settings, "webhook_secret", "global-secret"):
            resp = client.post(
                "/organization/webhook/test",
                headers=_auth_headers(user),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["org_slug"] == org.slug
        assert data["has_secret"] is True
        assert data["org_active"] is True

    def test_org_without_secret_warns(self, client: TestClient):
        org = _make_org(webhook_secret=None)
        user = _create_user(org.id, UserRole.MEMBER)
        with patch.object(settings, "webhook_secret", None):
            resp = client.post(
                "/organization/webhook/test",
                headers=_auth_headers(user),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False
        assert data["has_secret"] is False
        assert "secret" in data["message"].lower()

    def test_org_with_own_secret_passes(self, client: TestClient):
        org = _make_org(webhook_secret="org-secret-12345678")
        user = _create_user(org.id, UserRole.MEMBER)
        with patch.object(settings, "webhook_secret", None):
            resp = client.post(
                "/organization/webhook/test",
                headers=_auth_headers(user),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True


# ══════════════════════════════════════════════════════════════════════════════
# 6-9. Request-ID Tracking on Webhook Ingestion
# ══════════════════════════════════════════════════════════════════════════════


class TestRequestIdTracking:
    """X-Request-ID header is extracted and echoed in webhook responses."""

    def test_request_id_in_accepted_response(self, client: TestClient):
        org = _make_org()
        request_id = str(uuid.uuid4())
        payload = _unique_payload()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={
                "Authorization": f"Bearer {org.webhook_secret}",
                "X-Request-ID": request_id,
            },
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"
        assert data["request_id"] == request_id

    def test_request_id_in_duplicate_response(self, client: TestClient):
        org = _make_org()
        request_id = str(uuid.uuid4())
        payload = _unique_payload()
        # First submission — accepted
        resp1 = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={
                "Authorization": f"Bearer {org.webhook_secret}",
                "X-Request-ID": str(uuid.uuid4()),
            },
        )
        assert resp1.status_code == 202

        # Second submission — duplicate
        resp2 = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={
                "Authorization": f"Bearer {org.webhook_secret}",
                "X-Request-ID": request_id,
            },
        )
        assert resp2.status_code == 202
        data = resp2.json()
        assert data["status"] == "duplicate"
        assert data["request_id"] == request_id

    def test_request_id_in_ignored_response(self, client: TestClient):
        org = _make_org()
        request_id = str(uuid.uuid4())
        payload = _unique_payload(**{"Interested?": "No"})
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={
                "Authorization": f"Bearer {org.webhook_secret}",
                "X-Request-ID": request_id,
            },
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "ignored"
        assert data["request_id"] == request_id

    def test_no_request_id_still_works(self, client: TestClient):
        """Backward compatibility — no X-Request-ID header is fine."""
        org = _make_org()
        payload = _unique_payload()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": f"Bearer {org.webhook_secret}"},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"
        assert "request_id" not in data

    def test_request_id_in_event_log(self, client: TestClient):
        """The request_id is included in the EventLog payload."""
        org = _make_org()
        request_id = str(uuid.uuid4())
        payload = _unique_payload()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={
                "Authorization": f"Bearer {org.webhook_secret}",
                "X-Request-ID": request_id,
            },
        )
        assert resp.status_code == 202
        lead_id = resp.json()["lead_id"]

        # Verify EventLog contains request_id
        db = SessionLocal()
        try:
            events = db.query(EventLog).filter(
                EventLog.lead_id == uuid.UUID(lead_id)
            ).all()
            form_events = [e for e in events if e.event_type == "form_submitted"]
            assert len(form_events) == 1
            payload_data = json.loads(form_events[0].payload)
            assert payload_data["request_id"] == request_id
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 10. Webhook Auth Failure Logging
# ══════════════════════════════════════════════════════════════════════════════


class TestWebhookAuthFailureLogging:
    """Webhook auth failures are logged to EventLog."""

    def test_invalid_token_logged(self, client: TestClient):
        org = _make_org()
        payload = _unique_payload()

        # Count existing events before the request
        db = SessionLocal()
        try:
            before_count = db.query(EventLog).filter(
                EventLog.event_type == "webhook_auth_failed",
            ).count()
        finally:
            db.close()

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": "Bearer wrong-secret-value"},
        )
        assert resp.status_code == 401

        # Verify a new EventLog entry was created
        db = SessionLocal()
        try:
            after_count = db.query(EventLog).filter(
                EventLog.event_type == "webhook_auth_failed",
            ).count()
            assert after_count > before_count, (
                f"Expected webhook_auth_failed events to increase: "
                f"before={before_count}, after={after_count}"
            )
            # Verify the latest event's payload
            latest = db.query(EventLog).filter(
                EventLog.event_type == "webhook_auth_failed",
            ).order_by(EventLog.created_at.desc()).first()
            payload_data = json.loads(latest.payload)
            assert payload_data["reason"] == "invalid_token"
            assert payload_data["org_slug"] == org.slug
        finally:
            db.close()

    def test_missing_auth_header_logged(self, client: TestClient):
        org = _make_org()
        payload = _unique_payload()

        # Count existing events before the request
        db = SessionLocal()
        try:
            before_count = db.query(EventLog).filter(
                EventLog.event_type == "webhook_auth_failed",
            ).count()
        finally:
            db.close()

        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
        )
        assert resp.status_code == 401

        db = SessionLocal()
        try:
            # Scope assertion to THIS test's org to avoid cross-test contamination
            org_events = db.query(EventLog).filter(
                EventLog.event_type == "webhook_auth_failed",
                EventLog.organization_id == org.id,
            )
            after_count = org_events.count()
            assert after_count >= 1, (
                f"Expected webhook_auth_failed events for org {org.slug}: "
                f"found {after_count}"
            )
            latest = org_events.order_by(EventLog.created_at.desc()).first()
            payload_data = json.loads(latest.payload)
            assert payload_data["reason"] == "missing_header"
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 11-13. Webhook Config Edge Cases
# ══════════════════════════════════════════════════════════════════════════════


class TestWebhookConfigEdgeCases:
    """Edge cases for webhook configuration endpoints."""

    def test_unauthenticated_get_returns_401(self, client: TestClient):
        resp = client.get("/organization/webhook/config")
        assert resp.status_code == 401

    def test_unauthenticated_patch_returns_401(self, client: TestClient):
        resp = client.patch(
            "/organization/webhook/config",
            json={"webhook_secret": "new-secret-12345678"},
        )
        assert resp.status_code == 401

    def test_unauthenticated_rotate_returns_401(self, client: TestClient):
        resp = client.post("/organization/webhook/rotate-secret")
        assert resp.status_code == 401

    def test_unauthenticated_test_returns_401(self, client: TestClient):
        resp = client.post("/organization/webhook/test")
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# 14. Audit Event Logging on Config Changes
# ══════════════════════════════════════════════════════════════════════════════


class TestConfigAuditLogging:
    """Webhook config changes are logged to EventLog."""

    def test_secret_update_logged(self, client: TestClient):
        org = _make_org()
        user = _create_user(org.id, UserRole.ADMIN)
        resp = client.patch(
            "/organization/webhook/config",
            json={"webhook_secret": "new-secret-audit-test-123"},
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200

        db = SessionLocal()
        try:
            latest = db.query(EventLog).filter(
                EventLog.event_type == "webhook_secret_updated",
                EventLog.organization_id == org.id,
            ).order_by(EventLog.created_at.desc()).first()
            assert latest is not None
            payload_data = json.loads(latest.payload)
            assert payload_data["actor_email"] == user.email
        finally:
            db.close()

    def test_secret_rotation_logged(self, client: TestClient):
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.post(
            "/organization/webhook/rotate-secret",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200

        db = SessionLocal()
        try:
            latest = db.query(EventLog).filter(
                EventLog.event_type == "webhook_secret_rotated",
                EventLog.organization_id == org.id,
            ).order_by(EventLog.created_at.desc()).first()
            assert latest is not None
            payload_data = json.loads(latest.payload)
            assert payload_data["actor_email"] == user.email
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# 15. Org-Scoped Route Response Structure
# ══════════════════════════════════════════════════════════════════════════════


class TestOrgRouteResponseStructure:
    """Org-scoped webhook route returns proper response structure."""

    def test_accepted_response_has_expected_fields(self, client: TestClient):
        org = _make_org()
        payload = _unique_payload()
        resp = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": f"Bearer {org.webhook_secret}"},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert "status" in data
        assert "lead_id" in data
        assert data["status"] == "accepted"

    def test_duplicate_response_has_expected_fields(self, client: TestClient):
        org = _make_org()
        payload = _unique_payload()
        # First submission
        resp1 = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": f"Bearer {org.webhook_secret}"},
        )
        # Second submission
        resp2 = client.post(
            f"/webhooks/{org.slug}/form-submission",
            json=payload,
            headers={"Authorization": f"Bearer {org.webhook_secret}"},
        )
        assert resp2.status_code == 202
        data = resp2.json()
        assert data["status"] == "duplicate"
        assert "lead_id" not in data  # duplicates don't return lead_id


# ══════════════════════════════════════════════════════════════════════════════
# Problem #3 Regression Tests — Frontend ↔ Backend field alignment
# ══════════════════════════════════════════════════════════════════════════════


class TestRotateSecretFieldContract:
    """Verify rotate-secret response uses 'webhook_secret' (not 'secret').

    Regression for Problem #3: the frontend read data.secret while the
    backend returned webhook_secret — causing the rotated secret to be
    silently lost (undefined in JS).  These tests lock down the contract.
    """

    def test_response_uses_webhook_secret_field(self, client: TestClient):
        """Response body must contain 'webhook_secret', not 'secret'."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.post(
            "/organization/webhook/rotate-secret",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "webhook_secret" in data, (
            "Response must include 'webhook_secret' field (not 'secret')"
        )

    def test_response_secret_is_nonempty(self, client: TestClient):
        """The returned secret must be a non-empty string."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.post(
            "/organization/webhook/rotate-secret",
            headers=_auth_headers(user),
        )
        data = resp.json()
        assert isinstance(data["webhook_secret"], str)
        assert len(data["webhook_secret"]) > 0

    def test_response_has_message_field(self, client: TestClient):
        """Response must also include 'message' with usage instructions."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.post(
            "/organization/webhook/rotate-secret",
            headers=_auth_headers(user),
        )
        data = resp.json()
        assert "message" in data
        assert isinstance(data["message"], str)
        assert len(data["message"]) > 0

    def test_no_secret_field_in_response(self, client: TestClient):
        """Response must NOT have a bare 'secret' key (that was the bug)."""
        org = _make_org()
        user = _create_user(org.id, UserRole.OWNER)
        resp = client.post(
            "/organization/webhook/rotate-secret",
            headers=_auth_headers(user),
        )
        data = resp.json()
        assert "secret" not in data, (
            "Response must NOT contain a bare 'secret' key — "
            "use 'webhook_secret' instead"
        )


class TestWebhookTestFieldContract:
    """Verify webhook test response uses 'message' for issue details.

    Regression for Problem #3: the frontend read data.issues (an array)
    while the backend returned issues joined into data.message (a string).
    These tests lock down the contract.
    """

    def test_invalid_config_returns_message_with_issues(self, client: TestClient):
        """When config is invalid, 'message' must contain issue details."""
        org = _make_org(webhook_secret=None)
        user = _create_user(org.id, UserRole.MEMBER)
        with patch.object(settings, "webhook_secret", None):
            resp = client.post(
                "/organization/webhook/test",
                headers=_auth_headers(user),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False
        assert "message" in data
        assert len(data["message"]) > 0, (
            "When invalid, 'message' should contain human-readable issue details"
        )

    def test_valid_config_returns_valid_message(self, client: TestClient):
        """When config is valid, 'message' confirms validity."""
        org = _make_org()
        user = _create_user(org.id, UserRole.MEMBER)
        with patch.object(settings, "webhook_secret", "global-secret"):
            resp = client.post(
                "/organization/webhook/test",
                headers=_auth_headers(user),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert "message" in data
        assert len(data["message"]) > 0
