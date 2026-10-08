"""Pydantic request/response schemas (Phase 0.5 + Phase 29 field mapping)."""
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    StringConstraints,
    field_validator,
)

from app.models import CallOutcome, FollowUpPriority, FollowUpStatus, LeadStatus

# Normalized "Interested?" values. Blank/None stays None (not processed);
# anything outside YES_VALUES/NO_VALUES is rejected as ambiguous rather
# than silently guessed.
YES_VALUES = {"yes"}
NO_VALUES = {"no"}

_NON_EMAIL_PLACEHOLDERS = {"n/a", "na", "none", "-", "--", "no", "noemail"}


class FormSubmission(BaseModel):
    """Validates an incoming Google Form payload BEFORE it becomes a Lead.

    Field aliases map 1:1 to the exact Google Form question labels.
    Supports both legacy hardcoded aliases (backward compatible) and
    dynamic mapping via ``from_webhook_payload()`` (Phase 29).

    NOTE: These aliases are IT Training form labels.  They serve only as
    a legacy fallback when **no** ``OrgFormFieldMapping`` exists for the
    organization.  When an org *does* have a mapping, form labels are
    translated to canonical field names by ``from_webhook_payload()``
    before Pydantic validation - these aliases are never consulted.

    **COUPLING**: The alias strings below must stay in sync with
    ``DEFAULT_FORM_FIELD_MAPPING`` in ``app/models_multi_tenant.py``.
    The default mapping dict maps the *same* Google Form labels to the
    same Python field names.  If you change an alias here, update the
    default mapping too, and vice versa.
    """

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)

    interested: Annotated[str | None, StringConstraints(to_lower=True)] = Field(
        default=None, alias="Interested?"
    )
    name: Annotated[str, StringConstraints(min_length=1)] = Field(alias="Name")
    company_address: str | None = Field(default=None, alias="Company Address")
    phone_number: str | None = Field(default=None, alias="Phone Number")
    direct_number: str | None = Field(default=None, alias="Direct Number")
    courses: str | None = Field(default=None, alias="Courses")
    email: EmailStr = Field(alias="Email Address")
    scheduled_date: str | None = Field(default=None, alias="Scheduled Date")
    caller_name: str | None = Field(default=None, alias="Caller Name")
    appt_datetime_raw: Annotated[str, StringConstraints(min_length=1)] = Field(
        alias="Phone Appt. Date/Time"
    )
    scheduled_date_time: str | None = Field(
        default=None, alias="Scheduled Date and Time"
    )
    form_date: str | None = Field(default=None, alias="Date")
    form_time: str | None = Field(default=None, alias="Time")

    @classmethod
    def from_webhook_payload(
        cls,
        payload: dict,
        field_mapping: dict[str, str],
    ) -> "FormSubmission":
        """Create a FormSubmission from a raw webhook payload using an
        organization's field mapping.

        When the mapping is the default (or equivalent to the hardcoded
        aliases), this produces the same result as ``FormSubmission(**payload)``.

        When the mapping is custom, form question labels are translated
        to canonical field names before validation.

        Uses ``map_payload_to_fields()`` for the actual translation to
        avoid duplicating the label→field mapping loop.

        Args:
            payload: Raw webhook payload keyed by form question labels.
            field_mapping: Dict mapping form_label → lead_field name.
                           An empty dict falls back to legacy alias behavior.

        Returns:
            Validated FormSubmission instance.

        Raises:
            pydantic.ValidationError: If required fields are missing or invalid.
        """
        from app.services.field_mapping_resolver import map_payload_to_fields

        # Phase 34: map_payload_to_fields now handles normalised key
        # matching for BOTH the explicit-mapping path and the legacy
        # Pydantic-alias fallback (when field_mapping is empty).
        mapped = map_payload_to_fields(payload, field_mapping)
        return cls(**mapped)

    @field_validator("interested", mode="before")
    @classmethod
    def normalize_interested(cls, v: object) -> str | None:
        """Normalize "Interested?" to lowercase, stripped.

        Blank -> None. "yes"/"Yes"/"YES" -> "yes" (equivalent). Garbage or
        ambiguous values raise instead of being silently guessed.
        """
        if v is None:
            return None
        s = str(v).strip().lower()
        if s == "":
            return None
        if s in YES_VALUES:
            return "yes"
        if s in NO_VALUES:
            return "no"
        raise ValueError(f"ambiguous Interested? value: {v!r}")

    @field_validator("email", mode="before")
    @classmethod
    def reject_placeholder_emails(cls, v: object) -> object:
        """Reject common non-email placeholders before strict validation."""
        if isinstance(v, str) and v.strip().lower() in _NON_EMAIL_PLACEHOLDERS:
            raise ValueError(f"placeholder email not allowed: {v!r}")
        # Detect phone numbers supplied as email - a common form-mapping error
        # where the wrong column value lands in the Email Address field.
        if isinstance(v, str):
            stripped = v.strip()
            # Phone-like: starts with + or digits, contains 7+ digits total
            digits = re.sub(r"\D", "", stripped)
            if (stripped.startswith("+") or (digits == stripped and len(digits) >= 7)) and len(digits) >= 7:
                raise ValueError(
                    f"Field 'Email Address' received a phone number ({v!r}). "
                    "Please provide a valid email address."
                )
        return v

    def compute_dedupe_key(
        self,
        organization_id: str | None = None,
        appt_utc: datetime | None = None,
    ) -> str:
        """Dedupe key: org-scoped normalized email + appointment instant.

        Including ``organization_id`` prevents cross-tenant collisions:
        two different orgs receiving the same email+appt must NOT dedup
        against each other.

        M11: when the parsed UTC instant is available it is used instead
        of the raw string, so equivalent inputs ("Aug 27 2026 9am" vs
        "2026-08-27 09:00") dedupe against each other.
        """
        email = str(self.email).strip().lower()
        if appt_utc is not None:
            aware = appt_utc
            if aware.tzinfo is None:
                aware = aware.replace(tzinfo=timezone.utc)
            # Normalize to minute precision: dateparser may include
            # microseconds from "now", which would make identical payloads
            # produce different keys on retry.
            aware = aware.astimezone(timezone.utc).replace(
                second=0, microsecond=0
            )
            appt = aware.isoformat()
        else:
            appt = re.sub(r"\s+", " ", self.appt_datetime_raw.strip().lower())
        key = f"{email}|{appt}"
        if organization_id is not None:
            key = f"{organization_id}|{key}"
        return key

    def get_appt_datetime_candidates(self) -> list[str]:
        """Return ordered list of raw datetime strings to try parsing.

        The Google Form may send appointment data in different fields
        depending on how the form is configured:

        1. ``Phone Appt. Date/Time`` - combined date+time (primary)
        2. ``Scheduled Date and Time`` - alternative combined field
        3. ``Date`` + ``Time`` - separate fields to combine
        4. ``Date`` alone (date only, no time)

        Returns candidates in priority order (primary field first).
        Empty/blank values are excluded.
        """
        candidates: list[str] = []

        # 1. Primary: "Phone Appt. Date/Time"
        if self.appt_datetime_raw and self.appt_datetime_raw.strip():
            candidates.append(self.appt_datetime_raw.strip())

        # 2. Alternative: "Scheduled Date and Time"
        if self.scheduled_date_time and self.scheduled_date_time.strip():
            candidates.append(self.scheduled_date_time.strip())

        # 3. Combined: "Date" + "Time"
        date_val = self.form_date.strip() if self.form_date else ""
        time_val = self.form_time.strip() if self.form_time else ""
        if date_val and time_val:
            candidates.append(f"{date_val} {time_val}")
        elif date_val:
            candidates.append(date_val)

        return candidates


class ManualLeadRequest(BaseModel):
    """Schema for manual lead entry from the dashboard UI.

    Requires name, email, and appointment datetime at minimum.
    Phone, company, and notes are optional.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    name: Annotated[str, StringConstraints(min_length=1, max_length=255)] = Field(
        description="Prospect's full name"
    )
    email: EmailStr = Field(description="Prospect's email address")
    phone_number: str | None = Field(
        default=None, description="Prospect's phone number"
    )
    company_address: str | None = Field(
        default=None, description="Prospect's company name or address"
    )
    appt_datetime_raw: Annotated[str, StringConstraints(min_length=1)] = Field(
        description="Appointment date/time in free text (e.g. 'tomorrow 2pm', '2026-08-20 3:00 PM CT')"
    )
    notes: str | None = Field(default=None, description="Optional notes about the lead")
    assigned_to: uuid.UUID | None = Field(
        default=None,
        description="UUID of the team member to assign this lead to",
    )

    @field_validator("email", mode="before")
    @classmethod
    def reject_placeholder_emails(cls, v: object) -> object:
        """Reject common non-email placeholders."""
        if isinstance(v, str) and v.strip().lower() in _NON_EMAIL_PLACEHOLDERS:
            raise ValueError(f"placeholder email not allowed: {v!r}")
        return v

    def compute_dedupe_key(
        self,
        organization_id: str | None = None,
        appt_utc: datetime | None = None,
    ) -> str:
        """Dedupe key: org-scoped normalized email + appointment instant.

        M8: ``organization_id`` is included so two orgs creating a manual
        lead with the same email+time don't collide on the global unique
        index (spurious 409).

        M11: when the parsed UTC instant is available it is used instead
        of the raw string, so "Aug 27 2026 9am" and "2026-08-27 09:00"
        (same instant) dedupe against each other.
        """
        email = str(self.email).strip().lower()
        if appt_utc is not None:
            aware = appt_utc
            if aware.tzinfo is None:
                aware = aware.replace(tzinfo=timezone.utc)
            # Normalize to minute precision: dateparser may include
            # microseconds from "now", which would make identical payloads
            # produce different keys on retry.
            aware = aware.astimezone(timezone.utc).replace(
                second=0, microsecond=0
            )
            appt = aware.isoformat()
        else:
            appt = re.sub(r"\s+", " ", self.appt_datetime_raw.strip().lower())
        key = f"manual|{email}|{appt}"
        if organization_id is not None:
            key = f"{organization_id}|{key}"
        return key


class EditLeadRequest(BaseModel):
    """Schema for editing lead information from the dashboard UI.

    Only user-facing fields that exist on the Lead model are editable.
    Protected fields (id, organization_id, dedupe_key, status, calendar_event_id,
    created_at, updated_at, pipeline fields) are NOT editable through this endpoint.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    name: Annotated[str, StringConstraints(min_length=1, max_length=255)] | None = Field(
        default=None, description="Prospect's full name"
    )
    email: EmailStr | None = Field(
        default=None, description="Prospect's email address"
    )
    phone_number: str | None = Field(
        default=None, description="Prospect's phone number"
    )
    company_address: str | None = Field(
        default=None, description="Prospect's company name or address"
    )
    appt_datetime_raw: Annotated[str, StringConstraints(min_length=1)] | None = Field(
        default=None,
        description="Appointment date/time in free text (e.g. 'tomorrow 2pm')",
    )
    customer_timezone: str | None = Field(
        default=None,
        description="IANA timezone name (e.g. 'America/New_York'). Re-resolved from appt_datetime_raw when it changes.",
    )
    assigned_to: uuid.UUID | None = Field(
        default=None,
        description="UUID of the team member to assign this lead to",
    )

    @field_validator("email", mode="before")
    @classmethod
    def reject_placeholder_emails(cls, v: object) -> object:
        """Reject common non-email placeholders."""
        if isinstance(v, str) and v.strip().lower() in _NON_EMAIL_PLACEHOLDERS:
            raise ValueError(f"placeholder email not allowed: {v!r}")
        return v


# Allowed manual status transitions from the LeadStatus docstring.
# Maps current status → set of allowed next statuses.
ALLOWED_STATUS_TRANSITIONS: dict[str, set[str]] = {
    "pending": {"scheduled", "error", "not_interested", "pending"},
    "scheduled": {"accepted", "tentative", "declined", "reminded", "completed"},
    "accepted": {"reminded", "declined", "completed"},
    "tentative": {"accepted", "declined", "completed"},
    "reminded": {"completed", "declined"},
    # Terminal states - no transitions allowed
    "completed": set(),
    "declined": set(),
    "not_interested": set(),
    "error": {"pending"},  # Allow retry from error back to pending
}


class UpdateStatusRequest(BaseModel):
    """Schema for changing lead status via dedicated endpoint."""

    status: LeadStatus = Field(description="New status for the lead")


class LeadOut(BaseModel):
    """Safe read-only representation of a Lead for future API responses.

    Internal fields (e.g. dedupe_key) are intentionally excluded.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    interested: str | None
    name: str
    company_address: str | None
    phone_number: str | None
    direct_number: str | None
    courses: str | None
    email: str
    scheduled_date: str | None
    caller_name: str | None
    appt_datetime_raw: str
    appt_datetime_utc: datetime | None
    status: LeadStatus
    calendar_event_id: str | None
    reminder_sent_at: datetime | None
    call_outcome: CallOutcome | None = None
    call_notes: str | None = None
    call_duration_minutes: int | None = None
    cancelled_at: datetime | None = None
    reschedule_count: int = 0
    created_at: datetime
    updated_at: datetime


# ── Phase 18: Follow-Up Schemas ──────────────────────────────────────


class CreateFollowUpRequest(BaseModel):
    """Schema for creating a new follow-up task.

    lead_id is required. assigned_to is optional.
    organization_id, created_by are derived server-side from auth context.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    lead_id: uuid.UUID = Field(description="Associated lead ID")
    title: Annotated[str, StringConstraints(min_length=1, max_length=255)] = Field(
        description="Follow-up task title"
    )
    notes: str | None = Field(
        default=None, description="Optional notes about this follow-up"
    )
    priority: FollowUpPriority = Field(
        default=FollowUpPriority.MEDIUM,
        description="Priority level (low, medium, high, urgent)",
    )
    due_at: datetime | None = Field(
        default=None,
        description="Optional due date/time (ISO 8601 with timezone)",
    )
    assigned_to: uuid.UUID | None = Field(
        default=None,
        description="Optional user ID to assign this follow-up to",
    )


class UpdateFollowUpRequest(BaseModel):
    """Schema for updating follow-up details (partial update).

    Only user-supplied fields are updated. status changes go through
    the dedicated status endpoint.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    title: Annotated[str, StringConstraints(min_length=1, max_length=255)] | None = Field(
        default=None, description="Updated task title"
    )
    notes: str | None = Field(
        default=None, description="Updated notes"
    )
    priority: FollowUpPriority | None = Field(
        default=None, description="Updated priority level"
    )
    due_at: datetime | None = Field(
        default=None, description="Updated due date/time"
    )
    assigned_to: uuid.UUID | None = Field(
        default=None, description="Updated assigned user ID"
    )


class FollowUpStatusRequest(BaseModel):
    """Schema for changing follow-up status through validated transitions."""

    status: FollowUpStatus = Field(description="New status for the follow-up")


class FollowUpResponse(BaseModel):
    """Safe read-only representation of a FollowUp for API responses."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    lead_id: uuid.UUID
    lead_name: str | None = None
    created_by: uuid.UUID
    email_sent_at: datetime | None = None
    email_retry_count: int = 0
    last_error: str | None = None
    created_by_name: str | None = None
    assigned_to: uuid.UUID | None = None
    assigned_to_name: str | None = None
    title: str
    notes: str | None = None
    priority: FollowUpPriority
    status: FollowUpStatus
    due_at: datetime | None = None
    completed_at: datetime | None = None
    completed_by: uuid.UUID | None = None
    cancelled_at: datetime | None = None
    cancelled_by: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime


# ── Phase 12: Call Management Schemas ────────────────────────────────


class UpdateCallRequest(BaseModel):
    """Update call outcome, notes, and/or duration for a lead.

    All fields are optional (partial update).  Only the fields provided
    in the request body will be updated on the Lead.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    call_outcome: CallOutcome | None = Field(
        default=None, description="Outcome of the call"
    )
    call_notes: str | None = Field(
        default=None, description="Free-text notes from the call"
    )
    call_duration_minutes: int | None = Field(
        default=None,
        ge=0,
        le=1440,
        description="Call duration in minutes (0-1440)",
    )


class CancelCallRequest(BaseModel):
    """Request to cancel a scheduled call.

    Optionally provide a reason for cancellation.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    reason: str | None = Field(
        default=None, description="Optional reason for cancellation"
    )


class RescheduleCallRequest(BaseModel):
    """Request to reschedule a call to a new date/time.

    Requires the new appointment datetime. Optionally provide a reason.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    appt_datetime_raw: Annotated[str, StringConstraints(min_length=1)] = Field(
        description="New appointment date/time in free text (e.g. 'tomorrow 2pm', '2026-08-20 3:00 PM CT')"
    )
    reason: str | None = Field(
        default=None, description="Optional reason for rescheduling"
    )
