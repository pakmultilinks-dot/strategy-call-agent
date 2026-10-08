"""SQLAlchemy ORM models (Phase 0.5 + Phase 12 call management + Phase 18 follow-ups).

Tables: leads, events_log, failed_jobs, schedule_config, follow_ups.
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CallOutcome(str, enum.Enum):
    """Outcome of a completed or attempted call.

    Set after the call occurs (or fails to occur).  NULL means the call
    has not happened yet (pending, scheduled, etc.).
    """
    CONNECTED = "connected"
    COMPLETED = "completed"
    NO_ANSWER = "no_answer"
    VOICEMAIL = "voicemail"
    BUSY = "busy"
    WRONG_NUMBER = "wrong_number"
    RESCHEDULED = "rescheduled"
    CANCELLED = "cancelled"
    NO_SHOW = "no_show"
    NOT_INTERESTED = "not_interested"


class LeadStatus(str, enum.Enum):
    """Lifecycle of a lead.

Valid transitions:
    PENDING → SCHEDULED (pipeline success)
    PENDING → ERROR (pipeline failure)
    PENDING → NOT_INTERESTED (Interested=No on form)
    SCHEDULED → ACCEPTED (RSVP accepted)
    SCHEDULED → TENTATIVE (RSVP tentative)
    SCHEDULED → DECLINED (RSVP declined or event missing)
    SCHEDULED → REMINDED (reminder sent)
    SCHEDULED → COMPLETED (meeting time passed)
    ACCEPTED → REMINDED (reminder sent)
    ACCEPTED → DECLINED (RSVP declined)
    ACCEPTED → COMPLETED (meeting time passed)
    TENTATIVE → ACCEPTED (RSVP accepted)
    TENTATIVE → DECLINED (RSVP declined)
    TENTATIVE → COMPLETED (meeting time passed)
    REMINDED → COMPLETED (meeting time passed)
    REMINDED → DECLINED (RSVP declined)

Terminal states: COMPLETED, DECLINED, NOT_INTERESTED, ERROR.
NOTE: "declined" means the Calendar event was UPDATED (title prefixed
with [DECLINED], color set to red, transparency set to free) and the
prospect is marked internally as declined. The event is preserved as
historical evidence.

"not_interested" means the prospect answered "No" to the Interested?
question on the Google Form. No calendar event, no email, no processing.
    """
    PENDING = "pending"
    SCHEDULED = "scheduled"
    ACCEPTED = "accepted"
    TENTATIVE = "tentative"
    DECLINED = "declined"
    NOT_INTERESTED = "not_interested"
    REMINDED = "reminded"
    ERROR = "error"
    COMPLETED = "completed"


# ---------------------------------------------------------------------------
# Lead
# ---------------------------------------------------------------------------

class Lead(Base):
    """A booked strategy call ingested from the Google Form.

A Lead must NEVER be hard-deleted from the database, even after the
Calendar event tied to it is marked [DECLINED] - this row is the
system's only historical record. Future phases must NOT "clean up"
declined leads.

When a lead is declined (RSVP rejection), the Calendar event is
UPDATED (not deleted): title prefixed with [DECLINED], color set to
red (11), transparency set to transparent. The calendar_event_id is
PRESERVED on the lead for traceability.
    """
    __tablename__ = "leads"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # --- Google Form fields, mapped 1:1 (names not renamed/reinterpreted) ---
    interested: Mapped[str | None] = mapped_column(
        String, nullable=True
    )  # "Interested?" - normalized lowercase by the schema; may be blank/ambiguous
    name: Mapped[str] = mapped_column(String, nullable=False)  # "Name"
    company_address: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # "Company Address"
    phone_number: Mapped[str | None] = mapped_column(
        String, nullable=True
    )  # "Phone Number"
    direct_number: Mapped[str | None] = mapped_column(
        String, nullable=True
    )  # "Direct Number"
    courses: Mapped[str | None] = mapped_column(
        String, nullable=True
    )  # "Courses"
    email: Mapped[str | None] = mapped_column(
        String, nullable=True
    )  # "Email"
    scheduled_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )  # "Scheduled Date"
    caller_name: Mapped[str | None] = mapped_column(
        String, nullable=True
    )  # "Caller Name"
    appt_datetime_raw: Mapped[str | None] = mapped_column(
        String, nullable=True
    )  # "Appt Date/Time" raw string from form
    appt_datetime_utc: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )  # Parsed UTC datetime
    customer_timezone: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )  # IANA timezone resolved at parse time (e.g. "America/New_York")

    # --- Pipeline-computed fields (set by processing logic) ---
    status: Mapped[LeadStatus] = mapped_column(
        Enum(
            LeadStatus,
            name="lead_status",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
        default=LeadStatus.PENDING,
        server_default=LeadStatus.PENDING.value,
    )
    calendar_event_id: Mapped[str | None] = mapped_column(
        String, nullable=True, unique=True
    )  # Google Calendar event ID
    dedupe_key: Mapped[str | None] = mapped_column(
        String, nullable=True, unique=True
    )  # Composite key for deduplication

    # --- Multi-tenant FK ---
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )

    # --- Phase 10 / Phase 11 fields ---
    reminder_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    processing_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # --- Phase 12 call-management fields ---
    call_outcome: Mapped[CallOutcome | None] = mapped_column(
        Enum(
            CallOutcome,
            name="call_outcome",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=True,
    )
    call_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    call_duration_minutes: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    reschedule_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    zoom_meeting_id: Mapped[str | None] = mapped_column(String, nullable=True)
    zoom_join_url: Mapped[str | None] = mapped_column(String, nullable=True)

    # --- Assignment ---
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # --- Timestamps ---
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # --- Relationships ---
    # "save-update, merge" ensures cascading refresh for the events list
    events: Mapped[list["EventLog"]] = relationship(
        back_populates="lead", cascade="save-update, merge"
    )
    follow_ups: Mapped[list["FollowUp"]] = relationship(
        back_populates="lead"
    )
    organization: Mapped["Organization | None"] = relationship(
        back_populates="leads"
    )

    __table_args__ = (
        Index("ix_leads_dedupe_key", "dedupe_key", unique=True),
        Index("ix_leads_organization_id", "organization_id"),
        Index("ix_leads_org_status", "organization_id", "status"),
        Index("ix_leads_org_email", "organization_id", "email"),
        Index("ix_leads_assigned_to", "assigned_to"),
        Index("ix_leads_org_assigned", "organization_id", "assigned_to"),
    )


# ---------------------------------------------------------------------------
# EventLog
# ---------------------------------------------------------------------------

class EventLog(Base):
    """Audit trail - every meaningful action on a Lead gets a row here,
always, no exceptions (rows are written by later phases)."""
    __tablename__ = "events_log"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    lead_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("leads.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
    )

    # --- Relationships ---
    lead: Mapped["Lead"] = relationship(back_populates="events")

    __table_args__ = (
        Index("ix_events_log_organization_id", "organization_id"),
        Index("ix_events_log_org_created", "organization_id", "created_at"),
    )


# ---------------------------------------------------------------------------
# FailedJob
# ---------------------------------------------------------------------------

class FailedJob(Base):
    """Failed Google/Gmail/AI calls queued for retry logic (later phases)."""
    __tablename__ = "failed_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    job_type: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    resolved: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_failed_jobs_organization_id", "organization_id"),
        Index("ix_failed_jobs_org_created", "organization_id", "created_at"),
    )


# ---------------------------------------------------------------------------
# ScheduleConfig
# ---------------------------------------------------------------------------

class ScheduleConfig(Base):
    """Single-row table storing the configurable schedule (Phase 5).

Seeded with defaults on first startup so behavior is unchanged until the
business owner explicitly changes something via the dashboard.
    """
    __tablename__ = "schedule_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    reminder_time: Mapped[str] = mapped_column(
        String, nullable=False, default="08:00"
    )
    rsvp_poll_interval_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=10
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


# ---------------------------------------------------------------------------
# FollowUp Enums
# ---------------------------------------------------------------------------

class FollowUpStatus(str, enum.Enum):
    """Lifecycle of a follow-up task.

Transitions:
    PENDING → IN_PROGRESS (work started)
    PENDING → COMPLETED (immediate completion)
    PENDING → CANCELLED
    IN_PROGRESS → COMPLETED
    IN_PROGRESS → CANCELLED
Terminal states: COMPLETED, CANCELLED.
    """
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class FollowUpPriority(str, enum.Enum):
    """Priority levels for follow-up tasks."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


# Allowed status transitions (used by validation logic)
ALLOWED_FOLLOWUP_TRANSITIONS = {
    FollowUpStatus.PENDING: {FollowUpStatus.IN_PROGRESS, FollowUpStatus.COMPLETED, FollowUpStatus.CANCELLED},
    FollowUpStatus.IN_PROGRESS: {FollowUpStatus.COMPLETED, FollowUpStatus.CANCELLED},
}


# ---------------------------------------------------------------------------
# FollowUp
# ---------------------------------------------------------------------------

class FollowUp(Base):
    """A follow-up task associated with a lead.

Follow-ups track actionable next steps after a call: callbacks,
document requests, contract reviews, etc. Each follow-up belongs
to a single lead within a single organization (multi-tenant).

Security rules:
  - organization_id is NEVER set from client input; derived from JWT.
  - created_by / completed_by / cancelled_by are derived from auth context.
  - All queries filter by organization_id for tenant isolation.
    """
    __tablename__ = "follow_ups"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    lead_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("leads.id"),
        nullable=False,
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
    )
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    priority: Mapped[FollowUpPriority] = mapped_column(
        Enum(
            FollowUpPriority,
            name="follow_up_priority",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
        default=FollowUpPriority.MEDIUM,
        server_default=FollowUpPriority.MEDIUM.value,
    )
    status: Mapped[FollowUpStatus] = mapped_column(
        Enum(
            FollowUpStatus,
            name="follow_up_status",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
        default=FollowUpStatus.PENDING,
        server_default=FollowUpStatus.PENDING.value,
    )
    due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True,
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancelled_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True,
    )
    overdue_email_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    email_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    email_retry_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Timestamps ---
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # --- Relationships ---
    lead: Mapped["Lead"] = relationship(back_populates="follow_ups")

    __table_args__ = (
        Index("ix_follow_ups_organization_id", "organization_id"),
        Index("ix_follow_ups_lead_id", "lead_id"),
        Index("ix_follow_ups_org_status", "organization_id", "status"),
        Index("ix_follow_ups_org_due_at", "organization_id", "due_at"),
        Index("ix_follow_ups_status_due_at", "status", "due_at"),
    )


# ---------------------------------------------------------------------------
# RSVP Token (Phase 4 - Customer Accept/Decline Workflow)
# ---------------------------------------------------------------------------

class RSVPToken(Base):
    """One-time RSVP token embedded in confirmation emails.

Security:
  - Token is stored as a bcrypt hash - plaintext is NEVER persisted.
  - Each token is single-use (consumed=True after use).
  - Tokens expire after RSVP_TOKEN_EXPIRY_DAYS (default 30).
  - Only leads in pollable states (SCHEDULED, ACCEPTED, TENTATIVE) can receive tokens.
  - Each token is scoped to a specific lead + organization.

Usage:
  - Generated during pipeline completion (after confirmation email is sent).
  - Embedded in confirmation email as Accept/Decline buttons.
  - Customer clicks a button → public route validates token → processes RSVP.
  - Idempotent: re-clicking the same link shows 'already processed'.
    """
    __tablename__ = "rsvp_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    lead_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("leads.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    choice: Mapped[str] = mapped_column(
        String(16), nullable=False
    )  # "accept" or "decline"
    consumed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # --- Relationships ---
    lead: Mapped["Lead"] = relationship()

    __table_args__ = (
        Index("ix_rsvp_tokens_lead_id", "lead_id"),
        Index("ix_rsvp_tokens_organization_id", "organization_id"),
        Index("ix_rsvp_tokens_token_hash", "token_hash", unique=True),
        Index("ix_rsvp_tokens_expires_at", "expires_at"),
    )
