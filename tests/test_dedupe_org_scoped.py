"""Regression: Dedupe key must be org-scoped.

CRITICAL BUG FIX: The dedupe_key was previously ``email|appt_raw`` with a
UNIQUE constraint but NO organization scoping.  This meant two different
organizations receiving the same email + appointment time would silently
lose the second submission as "duplicate" — a cross-tenant data-loss bug.

Fix: ``compute_dedupe_key(organization_id=...)`` now prepends the org UUID
to the key, making the UNIQUE constraint org-scoped.
"""
from __future__ import annotations

import uuid

import pytest


class TestDedupeKeyOrgScoped:
    """Verify that dedupe keys include organization_id."""

    def test_dedupe_key_includes_org_id(self):
        """New dedupe key must contain the organization UUID."""
        from app.schemas import FormSubmission

        sub = FormSubmission(
            email="alice@example.com",
            appt_datetime_raw="Sep 7, 2026 10:00 AM",
            name="Alice",
        )
        org_id = uuid.uuid4()
        key = sub.compute_dedupe_key(organization_id=str(org_id))
        assert str(org_id) in key
        assert "alice@example.com" in key.lower()

    def test_different_orgs_produce_different_keys(self):
        """Two orgs with the same email+appt must get different dedupe keys."""
        from app.schemas import FormSubmission

        sub = FormSubmission(
            email="alice@example.com",
            appt_datetime_raw="Sep 7, 2026 10:00 AM",
            name="Alice",
        )
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()
        key_a = sub.compute_dedupe_key(organization_id=str(org_a))
        key_b = sub.compute_dedupe_key(organization_id=str(org_b))
        assert key_a != key_b

    def test_same_org_same_submission_produces_same_key(self):
        """Idempotency: same org + same submission = same dedupe key."""
        from app.schemas import FormSubmission

        sub = FormSubmission(
            email="alice@example.com",
            appt_datetime_raw="Sep 7, 2026 10:00 AM",
            name="Alice",
        )
        org_id = uuid.uuid4()
        key1 = sub.compute_dedupe_key(organization_id=str(org_id))
        key2 = sub.compute_dedupe_key(organization_id=str(org_id))
        assert key1 == key2

    def test_no_org_id_falls_back_to_global_key(self):
        """Backward compat: no org_id still produces a valid dedupe key."""
        from app.schemas import FormSubmission

        sub = FormSubmission(
            email="alice@example.com",
            appt_datetime_raw="Sep 7, 2026 10:00 AM",
            name="Alice",
        )
        key = sub.compute_dedupe_key()
        assert key == "alice@example.com|sep 7, 2026 10:00 am"
        assert "|" in key

    def test_cross_tenant_webhook_no_collision(self):
        """End-to-end: two different orgs can accept the same email+appt.

        This tests the schema level only — the actual DB unique constraint
        is validated by the existing test_billing_removal tests and the
        broader regression suite.
        """
        from app.schemas import FormSubmission

        sub = FormSubmission(
            email="bob@example.com",
            appt_datetime_raw="Oct 15, 2026 2:30 PM",
            name="Bob",
        )
        org_x = uuid.uuid4()
        org_y = uuid.uuid4()
        key_x = sub.compute_dedupe_key(organization_id=str(org_x))
        key_y = sub.compute_dedupe_key(organization_id=str(org_y))
        # Must be different — no cross-tenant dedup
        assert key_x != key_y
        # Both must contain the email for traceability
        assert "bob@example.com" in key_x.lower()
        assert "bob@example.com" in key_y.lower()
