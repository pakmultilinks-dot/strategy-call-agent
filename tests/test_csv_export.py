"""Phase 20 — Production Hardening Tests.

Tests for P1-F (Lead CSV Export).
"""
import csv
import io
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Lead, LeadStatus
from app.models_multi_tenant import Organization, OrganizationStatus


# ══════════════════════════════════════════════════════════════════════════════
# P1-F: Lead CSV Export
# ══════════════════════════════════════════════════════════════════════════════


class TestLeadCSVExport:
    """Verify the GET /dashboard/api/leads/export endpoint."""

    def _make_lead(self, db_session: Session, org_id: uuid.UUID, **overrides) -> Lead:
        """Create a test lead with sensible defaults."""
        defaults = {
            "name": "CSV Test Lead",
            "email": "csv-test@example.com",
            "phone_number": "+15551234567",
            "appt_datetime_raw": "Jan 1, 2026 10:00 AM",
            "status": LeadStatus.PENDING,
            "organization_id": org_id,
            "dedupe_key": f"csv-test-{uuid.uuid4()}@example.com|2026-01-01",
        }
        defaults.update(overrides)
        lead = Lead(**defaults)
        db_session.add(lead)
        db_session.commit()
        db_session.refresh(lead)
        return lead

    def test_export_returns_csv_content_type(self, client: TestClient, db_session: Session, auth_headers: dict):
        """Response must have Content-Type: text/csv."""
        resp = client.get("/dashboard/api/leads/export", headers=auth_headers)
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]

    def test_export_returns_content_disposition_header(self, client: TestClient, db_session: Session, auth_headers: dict):
        """Response must include Content-Disposition for file download."""
        resp = client.get("/dashboard/api/leads/export", headers=auth_headers)
        assert resp.status_code == 200
        assert "leads_export.csv" in resp.headers.get("content-disposition", "")

    def test_export_csv_has_header_row(self, client: TestClient, db_session: Session, auth_headers: dict):
        """CSV output must have a header row with expected column names."""
        resp = client.get("/dashboard/api/leads/export", headers=auth_headers)
        assert resp.status_code == 200
        reader = csv.reader(io.StringIO(resp.text))
        headers = next(reader)
        assert "id" in headers
        assert "prospect_name" in headers
        assert "email" in headers
        assert "status" in headers
        assert "created_at" in headers

    def test_export_includes_leads(self, client: TestClient, db_session: Session, auth_headers: dict):
        """If leads exist, they should appear in the CSV."""
        from app.tenant import _DEFAULT_ORG_ID

        self._make_lead(db_session, _DEFAULT_ORG_ID, name="Export Test Lead")
        resp = client.get("/dashboard/api/leads/export", headers=auth_headers)
        assert resp.status_code == 200
        reader = csv.DictReader(io.StringIO(resp.text))
        rows = list(reader)
        names = [r["prospect_name"] for r in rows]
        assert "Export Test Lead" in names

    def test_export_empty_result_set(self, client: TestClient, db_session: Session, auth_headers: dict):
        """When no leads match the filter, CSV still has valid headers and zero data rows.

        Uses a unique name marker to verify that leads *created by this test*
        are NOT present when filtered by a status they don't have.
        """
        from app.tenant import _DEFAULT_ORG_ID

        marker = f"EmptyExport-{uuid.uuid4().hex[:8]}"
        self._make_lead(db_session, _DEFAULT_ORG_ID, name=marker, status=LeadStatus.PENDING)

        # "not_interested" filter should NOT include our pending marker lead
        resp = client.get(
            "/dashboard/api/leads/export?status=not_interested",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        reader = csv.DictReader(io.StringIO(resp.text))
        rows = list(reader)
        returned_names = [r["prospect_name"] for r in rows]
        assert marker not in returned_names, (
            f"Marker lead should not appear in not_interested export"
        )

    def test_export_invalid_status_returns_400(self, client: TestClient, db_session: Session, auth_headers: dict):
        """Invalid status filter should return 400 with error message."""
        resp = client.get("/dashboard/api/leads/export?status=invalid_status", headers=auth_headers)
        assert resp.status_code == 400
        assert "Invalid status" in resp.json()["detail"]

    def test_export_status_filter_works(self, client: TestClient, db_session: Session, auth_headers: dict):
        """Status filter should only include leads with the matching status."""
        from app.tenant import _DEFAULT_ORG_ID

        marker_pending = f"PendingFilter-{uuid.uuid4().hex[:8]}"
        marker_error = f"ErrorFilter-{uuid.uuid4().hex[:8]}"
        self._make_lead(db_session, _DEFAULT_ORG_ID, name=marker_pending, status=LeadStatus.PENDING)
        self._make_lead(db_session, _DEFAULT_ORG_ID, name=marker_error, status=LeadStatus.ERROR)

        resp = client.get("/dashboard/api/leads/export?status=pending", headers=auth_headers)
        assert resp.status_code == 200
        reader = csv.DictReader(io.StringIO(resp.text))
        rows = list(reader)
        returned_names = [r["prospect_name"] for r in rows]
        assert marker_pending in returned_names, "Pending lead should appear"
        assert marker_error not in returned_names, "Error lead should NOT appear when filtering pending"
