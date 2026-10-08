"""Pydantic schemas for authentication endpoints (Phase 6B.3).

Request/response models for:
  - POST /auth/register
  - POST /auth/login
  - GET  /auth/me
  - User management endpoints

SECURITY: These schemas define exactly what is sent/received over the wire.
password_hash is NEVER included in any response.
credentials_encrypted is NEVER included.
"""
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

# ---------------------------------------------------------------------------
# Auth Request Schemas
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    """Request body for POST /auth/register.

    Creates both an Organization and an Owner User atomically.
    """
    organization_name: str = Field(
        ..., min_length=1, max_length=200,
        description="Name of the customer's organization/company",
    )
    name: str = Field(
        ..., min_length=1, max_length=200,
        description="Full name of the owner user",
    )
    email: EmailStr = Field(
        ..., description="Email address for the owner account",
    )
    password: str = Field(
        ..., min_length=8, max_length=128,
        description="Password (minimum 8 characters)",
    )


class LoginRequest(BaseModel):
    """Request body for POST /auth/login."""
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., min_length=1, description="Password")


# ---------------------------------------------------------------------------
# Auth Response Schemas
# ---------------------------------------------------------------------------


class TokenResponse(BaseModel):
    """Response from POST /auth/login and POST /auth/register."""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")


class OrganizationInfo(BaseModel):
    """Safe organization info for API responses."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    status: str


class UserInfo(BaseModel):
    """Safe user info for /auth/me response.

    NEVER includes password_hash, credentials_encrypted, or any secrets.
    """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    name: str | None = None
    role: str
    status: str = "active"
    organization: OrganizationInfo


def build_safe_user_info(user: "User", org: "Organization") -> UserInfo:
    """Build a safe UserInfo response — NEVER includes password_hash.

    Shared helper used by auth_router and organization_router.
    """
    return UserInfo(
        id=user.id,
        email=user.email,
        name=user.full_name,
        role=user.role.value if user.role else "member",
        status=user.status.value if user.status else "active",
        organization=OrganizationInfo(
            id=org.id,
            name=org.name,
            slug=org.slug,
            status=org.status.value if org.status else "active",
        ),
    )


# ---------------------------------------------------------------------------
# User Management Schemas
# ---------------------------------------------------------------------------


class UserCreateRequest(BaseModel):
    """Request body for POST /organization/users."""
    email: EmailStr = Field(..., description="Email address")
    name: str | None = Field(default=None, max_length=200, description="Full name")
    password: str = Field(
        ..., min_length=8, max_length=128,
        description="Password (minimum 8 characters)",
    )
    role: str = Field(
        default="member",
        description="User role: owner, admin, or member",
    )


class UserUpdateRequest(BaseModel):
    """Request body for PATCH /organization/users/{user_id}."""
    name: str | None = Field(default=None, max_length=200, description="Full name")
    role: str | None = Field(default=None, description="User role: owner, admin, or member")
    status: str | None = Field(default=None, description="User status: active or disabled")


class UserListResponse(BaseModel):
    """Response from GET /organization/users."""
    users: list[UserInfo]
    total: int


class MessageResponse(BaseModel):
    """Generic message response."""
    message: str


# ---------------------------------------------------------------------------
# Organization Settings Schemas (Phase 6F)
# ---------------------------------------------------------------------------


class OrganizationSettingsResponse(BaseModel):
    """Safe organization settings for API responses.

    NEVER includes webhook_secret, credentials, or tokens.
    """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    display_name: str | None = None
    status: str
    timezone: str
    sender_name: str | None = None
    brand_color: str | None = None
    tagline: str | None = None
    # Schedule config (read-only for members)
    meeting_duration_minutes: int | None = None
    reminder_enabled: bool | None = None
    reminder_hour: int | None = None
    reminder_minute: int | None = None
    rsvp_poll_interval_minutes: int | None = None


class OrganizationSettingsUpdate(BaseModel):
    """Request body for PATCH /organization/settings.

    Only Owner/Admin can modify. All fields optional (partial update).
    """
    name: str | None = Field(default=None, min_length=1, max_length=200)
    display_name: str | None = Field(default=None, max_length=200)
    timezone: str | None = Field(default=None, max_length=64)
    sender_name: str | None = Field(default=None, max_length=200)
    brand_color: str | None = Field(default=None, max_length=7)
    tagline: str | None = Field(default=None, max_length=500)
    meeting_duration_minutes: int | None = Field(default=None, ge=15, le=120)
    reminder_enabled: bool | None = None
    reminder_hour: int | None = Field(default=None, ge=0, le=23)
    reminder_minute: int | None = Field(default=None, ge=0, le=59)
    rsvp_poll_interval_minutes: int | None = Field(default=None, ge=1, le=1440)

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, v: str | None) -> str | None:
        """Ensure timezone is a valid IANA timezone identifier."""
        if v is None:
            return v
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, KeyError, ValueError):
            raise ValueError(
                f"'{v}' is not a valid IANA timezone. "
                "Use identifiers like America/Chicago, Europe/London, Asia/Tokyo, or UTC."
            )
        return v


# ---------------------------------------------------------------------------
# Password Reset Schemas (Phase 20 P1-A)
# ---------------------------------------------------------------------------


class ForgotPasswordRequest(BaseModel):
    """Request body for POST /auth/forgot-password.

    Always returns a generic response regardless of whether the email exists,
    to prevent account enumeration.
    """
    email: EmailStr = Field(..., description="Email address for password reset")


class ResetPasswordRequest(BaseModel):
    """Request body for POST /auth/reset-password.

    Uses a one-time token from the email link.
    """
    token: str = Field(..., min_length=1, max_length=256, description="Password reset token")
    new_password: str = Field(
        ..., min_length=8, max_length=128,
        description="New password (minimum 8 characters)",
    )


# ---------------------------------------------------------------------------
# Password Change Schemas (Phase 28 — P1-C)
# ---------------------------------------------------------------------------


class ChangePasswordRequest(BaseModel):
    """Request body for POST /auth/change-password.

    Requires current password for verification. Invalidates all existing
    tokens upon success.
    """
    current_password: str = Field(..., min_length=1, description="Current password")
    new_password: str = Field(
        ..., min_length=8, max_length=128,
        description="New password (minimum 8 characters)",
    )
