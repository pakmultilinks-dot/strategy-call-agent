"""Shared Google Form label constants for tests.

Centralises the IT Training form labels so test payloads stay in sync
with ``DEFAULT_FORM_FIELD_MAPPING`` and the ``FormSubmission`` Pydantic
aliases.  Any future change to the default form labels needs only an
update here (plus the source-of-truth in ``app/models_multi_tenant.py``
and ``app/schemas.py``).

Usage::

    from tests.form_labels import DEFAULT_PAYLOAD, FORM_LABELS

    payload = DEFAULT_PAYLOAD(email="unique@example.com")
    assert "Email Address" in payload
"""

from __future__ import annotations

import uuid

# ── Canonical IT Training form labels (the Google Form question text) ────────
# These must match the keys in DEFAULT_FORM_FIELD_MAPPING exactly.
FORM_LABELS = {
    "name": "Name",
    "email": "Email Address",
    "appt_datetime_raw": "Phone Appt. Date/Time",
    "company_address": "Company Address",
    "phone_number": "Phone Number",
    "direct_number": "Direct Number",
    "courses": "Courses",
    "interested": "Interested?",
    "caller_name": "Caller Name",
    "scheduled_date": "Scheduled Date",
    "scheduled_date_time": "Scheduled Date and Time",
    "form_date": "Date",
    "form_time": "Time",
}

# Required field labels (subset of FORM_LABELS).
REQUIRED_LABELS = {
    "name": FORM_LABELS["name"],
    "email": FORM_LABELS["email"],
    "appt_datetime_raw": FORM_LABELS["appt_datetime_raw"],
}


def _uid() -> str:
    """Short random suffix for unique emails / IDs inside tests."""
    return uuid.uuid4().hex[:8]


def DEFAULT_PAYLOAD(
    *,
    name: str = "Jane Doe",
    email: str | None = None,
    appt_datetime: str = "tomorrow 10:00 AM",
    extra: dict | None = None,
) -> dict:
    """Build a minimal valid IT Training payload with sensible defaults.

    ``email`` is auto-generated (unique per call) when not supplied.
    ``extra`` lets callers inject additional form labels for a test.
    """
    payload = {
        FORM_LABELS["name"]: name,
        FORM_LABELS["email"]: email or f"test-{_uid()}@example.com",
        FORM_LABELS["appt_datetime_raw"]: appt_datetime,
    }
    if extra:
        payload.update(extra)
    return payload


# ── Alternative label sets for custom-mapping tests ──────────────────────────

# A realistic non-IT-Training label set (e.g., "Strategy Call" form).
CUSTOM_LABELS_A: dict[str, str] = {
    "Full Name": "name",
    "Contact Email": "email",
    "Preferred Appointment": "appt_datetime_raw",
    "WhatsApp": "phone_number",
    "Program": "courses",
    "Location": "company_address",
}

# Another distinct set for cross-org isolation tests.
CUSTOM_LABELS_B: dict[str, str] = {
    "Applicant Name": "name",
    "Email": "email",
    "Phone Appt. Date/Time": "appt_datetime_raw",
}
