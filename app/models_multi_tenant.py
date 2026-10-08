"""SQLAlchemy ORM models for multi-tenant foundation (Phase 6B.1).

Tables: organizations, users, org_integrations, org_schedule_config.

These models establish the tenant boundary for the SaaS conversion.
Every customer-owned resource (leads, events, failed_jobs) will gain
an organization_id foreign key pointing back to the owning Organization.

SECURITY: organization_id is the primary data isolation boundary.
In Phase 6B.3+, all queries MUST filter by organization_id derived from
the authenticated user — never from client-supplied parameters.
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

# Re-export the Base from models.py so all tables live in one metadata.
from app.models import Base

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class OrganizationStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"


class UserRole(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


class IntegrationStatus(str, enum.Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    PENDING = "pending"


# ---------------------------------------------------------------------------
# Organization
# ---------------------------------------------------------------------------

class Organization(Base):
    """A customer/company tenant. Every owned resource belongs to exactly one.

    Example:
        Organization(
            name="Integrated IT Trainings",
            slug="integrated-it-trainings",
            timezone="America/Chicago",
        )
    """

    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    slug: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    display_name: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[OrganizationStatus] = mapped_column(
        Enum(
            OrganizationStatus,
            name="organization_status",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
        default=OrganizationStatus.ACTIVE,
        server_default=OrganizationStatus.ACTIVE.value,
    )
    timezone: Mapped[str] = mapped_column(
        String, nullable=False, default="America/Chicago"
    )
    # Billing/subscription fields retained for DB schema compatibility
    # but no longer enforced — all features are unconditionally available.
    plan: Mapped[str] = mapped_column(
        String, nullable=False, default="business"
    )
    plan_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    trial_ends_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # ─── Subscription fields (retained for DB compat, not enforced) ──────────
    subscription_id: Mapped[str | None] = mapped_column(
        String, nullable=True, comment="Retained for DB schema compatibility; no longer enforced"
    )
    subscription_status: Mapped[str | None] = mapped_column(
        String, nullable=True, comment="Retained for DB schema compatibility; no longer enforced"
    )
    sender_name: Mapped[str | None] = mapped_column(String, nullable=True)
    brand_color: Mapped[str | None] = mapped_column(String(7), nullable=True)
    tagline: Mapped[str | None] = mapped_column(String(500), nullable=True)
    webhook_secret: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    users: Mapped[list["User"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    integrations: Mapped[list["OrgIntegration"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    schedule_config: Mapped["OrgScheduleConfig | None"] = relationship(
        back_populates="organization", uselist=False, cascade="all, delete-orphan"
    )
    leads: Mapped[list["Lead"]] = relationship(
        back_populates="organization"
    )
    form_field_mappings: Mapped[list["OrgFormFieldMapping"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_organizations_slug", "slug", unique=True),
    )


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class User(Base):
    """Dashboard user scoped to a single Organization.

    email + organization_id is the effective unique constraint.
    password_hash is nullable initially (OAuth-only login coming in 6B.3).
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    email: Mapped[str] = mapped_column(String, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    full_name: Mapped[str | None] = mapped_column(String, nullable=True)
    role: Mapped[UserRole] = mapped_column(
        Enum(
            UserRole,
            name="user_role",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
        default=UserRole.MEMBER,
        server_default=UserRole.MEMBER.value,
    )
    status: Mapped[UserStatus] = mapped_column(
        Enum(
            UserStatus,
            name="user_status",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
        default=UserStatus.ACTIVE,
        server_default=UserStatus.ACTIVE.value,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    organization: Mapped[Organization] = relationship(back_populates="users")

    __table_args__ = (
        UniqueConstraint("organization_id", "email", name="uq_users_org_email"),
        Index("ix_users_organization_id", "organization_id"),
    )


# ---------------------------------------------------------------------------
# OrgIntegration
# ---------------------------------------------------------------------------

class OrgIntegration(Base):
    """Per-organization external service credential/configuration.

    provider + integration_type identify the service:
      provider="google", integration_type="google_oauth"   → Google OAuth tokens
      provider="openai", integration_type="ai_provider"    → OpenAI API key
      provider="google", integration_type="email"          → Gmail sender config
      provider="google", integration_type="calendar"       → Calendar ID

    credentials_encrypted: nullable for now until encryption infra exists.
    metadata_json: flexible storage for non-secret config (sender names,
    display names, model preferences, etc.).

    SECURITY: credentials_encrypted MUST NEVER be exposed through API responses.
    """

    __tablename__ = "org_integrations"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider: Mapped[str] = mapped_column(String, nullable=False)
    integration_type: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[IntegrationStatus] = mapped_column(
        Enum(
            IntegrationStatus,
            name="integration_status",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
        default=IntegrationStatus.PENDING,
        server_default=IntegrationStatus.PENDING.value,
    )
    credentials_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    connected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    organization: Mapped[Organization] = relationship(back_populates="integrations")

    __table_args__ = (
        Index("ix_org_integrations_org_id", "organization_id"),
        Index("ix_org_integrations_org_provider", "organization_id", "provider"),
    )


# ---------------------------------------------------------------------------
# OrgScheduleConfig
# ---------------------------------------------------------------------------

class OrgScheduleConfig(Base):
    """Per-organization schedule configuration (replaces global schedule_config).

    Each organization has its own:
    - Reminder time (interpreted in the org's timezone)
    - Reminder window (how far ahead to look for same-day meetings)
    - RSVP poll interval
    - Scheduler enabled/disabled toggle
    """

    __tablename__ = "org_schedule_config"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    timezone: Mapped[str] = mapped_column(
        String, nullable=False, default="America/Chicago"
    )
    reminder_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    reminder_hour: Mapped[int] = mapped_column(
        Integer, nullable=False, default=8, server_default="8"
    )
    reminder_minute: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # How many minutes before the meeting to send the reminder.
    # None = send at the scheduled hour regardless (current behavior).
    reminder_window_minutes: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=None, server_default=None
    )
    rsvp_poll_interval_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=10, server_default="10"
    )
    scheduler_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    meeting_duration_minutes: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    organization: Mapped[Organization] = relationship(back_populates="schedule_config")

    __table_args__ = (
        Index("ix_org_schedule_config_org_id", "organization_id"),
    )

# ---------------------------------------------------------------------------
# GoogleOAuthState
# ---------------------------------------------------------------------------

class GoogleOAuthState(Base):
    """Transient state token for Google OAuth2 CSRF protection.

    Each row represents a pending OAuth authorization request.
    The state token is a cryptographically random string that:

      1. Is sent to Google as the OAuth2 `state` parameter
      2. Is returned by Google in the callback redirect
      3. Is validated to prevent CSRF attacks

    Lifecycle:

      - Created when user clicks 'Connect Google'
      - Consumed (used=True) when callback is received
      - A new state is generated for each attempt
    """

    __tablename__ = "google_oauth_states"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    state_token: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    redirect_uri: Mapped[str | None] = mapped_column(String, nullable=True)
    scopes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    organization: Mapped[Organization] = relationship()
    user: Mapped["User"] = relationship()

    __table_args__ = (
        Index("ix_google_oauth_states_org_id", "organization_id"),
        Index("ix_google_oauth_states_state_token", "state_token"),
        Index("ix_google_oauth_states_expires_at", "expires_at"),
    )


# ---------------------------------------------------------------------------
# ZoomOAuthState
# ---------------------------------------------------------------------------

class ZoomOAuthState(Base):
    """CSRF state token for Zoom OAuth2 Web Application flow.

    Mirrors ``GoogleOAuthState`` exactly:

      - Cryptographically random ``state_token`` (secrets.token_urlsafe)
      - Bound to a specific organization and user
      - Single-use (consumed on callback)
      - Expires after OAUTH_STATE_TTL_MINUTES (default 10)
    """

    __tablename__ = "zoom_oauth_states"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    state_token: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    redirect_uri: Mapped[str | None] = mapped_column(String, nullable=True)
    scopes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    organization: Mapped[Organization] = relationship()
    user: Mapped["User"] = relationship()

    __table_args__ = (
        Index("ix_zoom_oauth_states_org_id", "organization_id"),
        Index("ix_zoom_oauth_states_state_token", "state_token"),
        Index("ix_zoom_oauth_states_expires_at", "expires_at"),
    )


# ---------------------------------------------------------------------------
# PasswordResetToken (Phase 20 P1-A)
# ---------------------------------------------------------------------------

class PasswordResetToken(Base):
    """One-time password reset token (Phase 20 P1-A).

    SECURITY:
    - Token is stored as a bcrypt hash — plaintext is NEVER persisted.
    - Each token is single-use (used=True after reset).
    - Tokens expire after TOKEN_EXPIRY_MINUTES (default 30).
    - Only ACTIVE users with ACTIVE orgs can request tokens.
    """
    __tablename__ = "password_reset_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    user: Mapped["User"] = relationship()

    __table_args__ = (
        Index("ix_password_reset_tokens_user_id", "user_id"),
        Index("ix_password_reset_tokens_token_hash", "token_hash"),
        Index("ix_password_reset_tokens_expires_at", "expires_at"),
    )


# ---------------------------------------------------------------------------
# Token Blocklist (Phase 28 — P1-D: JWT Revocation)
# ---------------------------------------------------------------------------

class TokenBlocklist(Base):
    """Revoked JWT tokens (Phase 28 — P1-D).

    When a user logs out or changes their password, the current JWT's jti
    (or all JTIs for the user) are inserted here.  ``get_current_user()``
    checks this table on every authenticated request.

    SECURITY:
    - Only jti + user_id + revoked_at are stored — no token content.
    - Expired blocklist entries are cleaned up periodically.
    - Bulk revocation (all user tokens) uses a user-level token_version.
    """
    __tablename__ = "token_blocklist"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    jti: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(
        String(50), nullable=False, default="logout"
    )
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship()
    organization: Mapped[Organization] = relationship()

    __table_args__ = (
        Index("ix_token_blocklist_user_id", "user_id"),
        Index("ix_token_blocklist_expires_at", "expires_at"),
    )


# ---------------------------------------------------------------------------
# OrgFormFieldMapping (Phase 29 — Google Form field mapping)
# ---------------------------------------------------------------------------

# Canonical Lead model fields that can be mapped from form labels.
# Used for validation when creating/updating mappings.
VALID_LEAD_FIELDS: set[str] = {
    "name",
    "email",
    "company_address",
    "phone_number",
    "direct_number",
    "courses",
    "interested",
    "caller_name",
    "scheduled_date",
    "appt_datetime_raw",
    "scheduled_date_time",
    "form_date",
    "form_time",
}

# Fields that are required for the pipeline to function.
REQUIRED_LEAD_FIELDS: set[str] = {
    "name",
    "email",
    "appt_datetime_raw",
}


# Default form label → lead field mapping (backward-compatible).
#
# **COUPLING**: The form labels (dict keys) here are IT Training labels
# and must stay in sync with the Pydantic Field aliases in
# ``FormSubmission`` (``app/schemas.py``).  When no custom mapping
# exists for an org, this dict is used as the fallback.  The Pydantic
# aliases serve the same purpose for the legacy alias fallback path
# (``from_webhook_payload()`` when ``field_mapping`` is empty).
DEFAULT_FORM_FIELD_MAPPING: dict[str, str] = {
    "Name": "name",
    "Email Address": "email",
    "Phone Appt. Date/Time": "appt_datetime_raw",
    "Company Address": "company_address",
    "Phone Number": "phone_number",
    "Direct Number": "direct_number",
    "Courses": "courses",
    "Interested?": "interested",
    "Caller Name": "caller_name",
    "Scheduled Date": "scheduled_date",
    "Scheduled Date and Time": "scheduled_date_time",
    "Date": "form_date",
    "Time": "form_time",
}


class OrgFormFieldMapping(Base):
    """Per-organization mapping from Google Form question labels to
    canonical Lead model fields.

    When an organization has custom mappings configured, the webhook
    ingestion boundary uses these to translate the form payload into
    the canonical ``FormSubmission`` fields.  When no mappings exist,
    the default mapping (``DEFAULT_FORM_FIELD_MAPPING``) is used.
    """

    __tablename__ = "org_form_field_mappings"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    form_label: Mapped[str] = mapped_column(
        String, nullable=False,
        comment="Question label from Google Form",
    )
    lead_field: Mapped[str] = mapped_column(
        String, nullable=False,
        comment="Target Lead model column name",
    )
    is_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false",
    )
    display_order: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    organization: Mapped[Organization] = relationship(back_populates="form_field_mappings")

    __table_args__ = (
        Index("ix_ffm_org_id", "organization_id"),
        Index("ix_ffm_org_form_label", "organization_id", "form_label"),
    )

