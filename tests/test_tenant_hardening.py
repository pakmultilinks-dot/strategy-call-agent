"""Phase 1 - Multi-Tenant Organization Resolution Hardening: Regression Tests.

Validates that all tenant resolution functions require explicit organization_id
and that no code path silently falls back to a default organization.

Tests A–F:
  A. get_current_organization_id() raises RuntimeError (no default fallback)
  B. resolve_organization_id(None) raises RuntimeError
  C. set_lead_organization(lead, None) raises RuntimeError
  D. set_event_organization(event, None) raises RuntimeError
  E. set_failed_job_organization(job, None) raises RuntimeError
  F. Legacy /webhooks/form-submission returns 410 Gone
"""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import EventLog, FailedJob, Lead, LeadStatus
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_org(**overrides) -> Organization:
    """Insert an Organization row and return it."""
    defaults = {
        "name": f"Test Org {uuid.uuid4().hex[:8]}",
        "slug": f"test-org-{uuid.uuid4().hex[:8]}",
        "timezone": "America/Chicago",
        "status": OrganizationStatus.ACTIVE,
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


def _make_lead(org_id: uuid.UUID, **overrides) -> Lead:
    """Insert a Lead row with organization_id."""
    defaults = {
        "name": "Test Lead",
        "email": f"lead-{uuid.uuid4().hex[:8]}@example.com",
        "company_address": "Test Co",
        "appt_datetime_raw": "tomorrow 2pm",
        "dedupe_key": f"test-{uuid.uuid4().hex}",
        "status": LeadStatus.PENDING,
        "organization_id": org_id,
    }
    defaults.update(overrides)
    db = SessionLocal()
    try:
        lead = Lead(**defaults)
        db.add(lead)
        db.commit()
        db.refresh(lead)
        return lead
    finally:
        db.close()


# ══════════════════════════════════════════════════════════════════════════════
# A. get_current_organization_id() raises RuntimeError
# ══════════════════════════════════════════════════════════════════════════════


class TestGetCurrentOrganizationIdRaises:
    """Verify get_current_organization_id() no longer returns a default org."""

    def test_raises_runtime_error(self):
        """Calling get_current_organization_id() must raise RuntimeError."""
        from app.tenant import get_current_organization_id
        with pytest.raises(RuntimeError, match="deprecated"):
            get_current_organization_id()

    def test_error_message_indicates_deprecation(self):
        """The error message should tell the caller to pass explicit org_id."""
        from app.tenant import get_current_organization_id
        with pytest.raises(RuntimeError, match="explicit organization_id"):
            get_current_organization_id()


# ══════════════════════════════════════════════════════════════════════════════
# B. resolve_organization_id(None) raises RuntimeError
# ══════════════════════════════════════════════════════════════════════════════


class TestResolveOrganizationIdRaises:
    """Verify resolve_organization_id(None) no longer returns a default org."""

    def test_none_raises_runtime_error(self):
        """resolve_organization_id(None) must raise RuntimeError."""
        from app.tenant import resolve_organization_id
        with pytest.raises(RuntimeError, match="must provide"):
            resolve_organization_id(None)

    def test_explicit_id_passes_through(self):
        """resolve_organization_id(explicit_id) must return the same id."""
        from app.tenant import resolve_organization_id
        org_id = uuid.uuid4()
        result = resolve_organization_id(org_id)
        assert result == org_id

    def test_no_arg_raises_runtime_error(self):
        """resolve_organization_id() with no args must raise (default is None)."""
        from app.tenant import resolve_organization_id
        with pytest.raises(RuntimeError, match="must provide"):
            resolve_organization_id()


# ══════════════════════════════════════════════════════════════════════════════
# C. set_lead_organization(lead, None) raises RuntimeError
# ══════════════════════════════════════════════════════════════════════════════


class TestSetLeadOrganizationRaises:
    """Verify set_lead_organization requires explicit org_id."""

    def test_none_raises_runtime_error(self):
        """set_lead_organization(lead, None) must raise RuntimeError."""
        from app.tenant import set_lead_organization
        org = _make_org()
        lead = _make_lead(org.id)
        with pytest.raises(RuntimeError, match="must provide"):
            set_lead_organization(lead, None)

    def test_explicit_id_sets_organization(self):
        """set_lead_organization(lead, explicit_id) must set organization_id."""
        from app.tenant import set_lead_organization
        org = _make_org()
        lead = _make_lead(org.id)
        new_org = _make_org()
        set_lead_organization(lead, new_org.id)
        assert lead.organization_id == new_org.id


# ══════════════════════════════════════════════════════════════════════════════
# D. set_event_organization(event, None) raises RuntimeError
# ══════════════════════════════════════════════════════════════════════════════


class TestSetEventOrganizationRaises:
    """Verify set_event_organization requires explicit org_id."""

    def test_none_raises_runtime_error(self):
        """set_event_organization(event, None) must raise RuntimeError."""
        from app.tenant import set_event_organization
        org = _make_org()
        lead = _make_lead(org.id)
        db = SessionLocal()
        try:
            event = EventLog(
                lead_id=lead.id,
                event_type="test",
                organization_id=org.id,
            )
            db.add(event)
            db.commit()
            db.refresh(event)
            with pytest.raises(RuntimeError, match="must provide"):
                set_event_organization(event, None)
        finally:
            db.close()

    def test_explicit_id_sets_organization(self):
        """set_event_organization(event, explicit_id) must set organization_id."""
        from app.tenant import set_event_organization
        org = _make_org()
        lead = _make_lead(org.id)
        new_org = _make_org()
        db = SessionLocal()
        try:
            event = EventLog(
                lead_id=lead.id,
                event_type="test",
                organization_id=org.id,
            )
            db.add(event)
            db.commit()
            db.refresh(event)
            set_event_organization(event, new_org.id)
            assert event.organization_id == new_org.id
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# E. set_failed_job_organization(job, None) raises RuntimeError
# ══════════════════════════════════════════════════════════════════════════════


class TestSetFailedJobOrganizationRaises:
    """Verify set_failed_job_organization requires explicit org_id."""

    def test_none_raises_runtime_error(self):
        """set_failed_job_organization(job, None) must raise RuntimeError."""
        from app.tenant import set_failed_job_organization
        org = _make_org()
        db = SessionLocal()
        try:
            job = FailedJob(
                job_type="test",
                payload="{}",
                error="test",
                organization_id=org.id,
            )
            db.add(job)
            db.commit()
            db.refresh(job)
            with pytest.raises(RuntimeError, match="must provide"):
                set_failed_job_organization(job, None)
        finally:
            db.close()

    def test_explicit_id_sets_organization(self):
        """set_failed_job_organization(job, explicit_id) must set organization_id."""
        from app.tenant import set_failed_job_organization
        org = _make_org()
        new_org = _make_org()
        db = SessionLocal()
        try:
            job = FailedJob(
                job_type="test",
                payload="{}",
                error="test",
                organization_id=org.id,
            )
            db.add(job)
            db.commit()
            db.refresh(job)
            set_failed_job_organization(job, new_org.id)
            assert job.organization_id == new_org.id
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# F. Legacy /webhooks/form-submission returns 410 Gone
# ══════════════════════════════════════════════════════════════════════════════


class TestLegacyWebhookReturns410:
    """Verify the legacy webhook endpoint is deprecated with 410 Gone."""

    def test_legacy_endpoint_returns_410(self):
        """POST /webhooks/form-submission must return 410 Gone."""
        client = TestClient(app, raise_server_exceptions=False)
        payload = {
            "name": "Test Lead",
            "email": "test@example.com",
            "company_address": "Test Co",
            "appt_datetime_raw": "tomorrow 2pm",
            "interested": "Yes",
        }
        response = client.post("/webhooks/form-submission", json=payload)
        assert response.status_code == 410
        body = response.json()
        assert "gone" in body.get("detail", {}).get("error", "").lower()
        assert "org_slug" in body.get("detail", {}).get("message", "").lower()

    def test_legacy_endpoint_with_auth_returns_410(self):
        """Even with valid auth, the legacy endpoint returns 410 Gone."""
        from app.config import settings
        import base64
        client = TestClient(app, raise_server_exceptions=False)
        auth = base64.b64encode(
            f"{settings.dashboard_username}:{settings.dashboard_password}".encode()
        ).decode()
        payload = {
            "name": "Test Lead",
            "email": "test@example.com",
            "company_address": "Test Co",
            "appt_datetime_raw": "tomorrow 2pm",
            "interested": "Yes",
        }
        response = client.post(
            "/webhooks/form-submission",
            json=payload,
            headers={"Authorization": f"Basic {auth}"},
        )
        assert response.status_code == 410


# ══════════════════════════════════════════════════════════════════════════════
# Supplementary: service-layer regression tests
# ══════════════════════════════════════════════════════════════════════════════


class TestServiceLayerHardening:
    """Verify service-layer functions also require explicit org_id."""

    def test_record_failed_job_requires_org(self):
        """record_failed_job() must NOT raise when organization_id is None.

        M13: it runs inside except handlers - raising would mask the
        original error.  Instead it logs loudly and returns without
        persisting (a platform-scoped failure has no org to attribute).
        """
        from app.services.retry import record_failed_job
        db = SessionLocal()
        try:
            # Must not raise.
            record_failed_job(db, job_type="test", payload=None, error="test")
        finally:
            db.close()

    def test_log_audit_event_requires_org(self):
        """log_audit_event() must raise when organization_id is None."""
        from app.services.audit_service import log_audit_event
        db = SessionLocal()
        try:
            with pytest.raises(RuntimeError, match="requires explicit organization_id"):
                log_audit_event(db, event_type="test.event")
        finally:
            db.close()
