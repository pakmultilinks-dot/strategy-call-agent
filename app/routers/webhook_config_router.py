"""Organization webhook configuration router (Phase 6E).

Endpoints:
  GET   /organization/webhook/config   — View webhook configuration (any auth)
  PATCH /organization/webhook/config   — Update webhook secret (Owner/Admin)
  POST  /organization/webhook/rotate-secret — Generate new random secret (Owner/Admin)
  POST  /organization/webhook/test     — Validate webhook configuration

SECURITY:
  - All operations scoped to current_user.organization_id
  - webhook_secret is NEVER returned in full — only masked/presence flag
  - Only Owner/Admin can modify webhook configuration
  - New secrets are generated with cryptographic randomness (secrets.token_urlsafe)
  - Audit events are logged for all configuration changes
"""
import json
import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth import get_current_user, require_role
from app.database import get_db
from app.models_multi_tenant import Organization, UserRole
from app.services.rate_limit import check_rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/organization/webhook", tags=["organization-webhook"])


# ── Request/Response Schemas ─────────────────────────────────────────────────


class WebhookConfigResponse(BaseModel):
    """Safe representation of the organization's webhook configuration.

    SECURITY: The full webhook_secret is NEVER included in responses.
    Only a masked version and a boolean indicating presence are returned.
    """
    org_slug: str = Field(..., description="Organization slug for webhook URL")
    webhook_url: str = Field(..., description="Full webhook URL for this organization")
    has_secret: bool = Field(..., description="Whether a webhook secret is configured")
    secret_masked: str | None = Field(
        None,
        description="Masked version of the webhook secret (first 4 + last 4 chars)",
    )


class WebhookConfigUpdateRequest(BaseModel):
    """Request body for updating the webhook secret."""
    webhook_secret: str = Field(
        ...,
        min_length=16,
        max_length=256,
        description="New webhook secret (minimum 16 characters)",
    )


class WebhookRotateSecretResponse(BaseModel):
    """Response after rotating the webhook secret."""
    webhook_secret: str = Field(
        ...,
        description="The new webhook secret (shown once — copy to Apps Script immediately)",
    )
    message: str = Field(
        default="Secret rotated. Update your Apps Script configuration immediately.",
        description="Instructions for the user",
    )


class WebhookTestResponse(BaseModel):
    """Response from webhook configuration validation."""
    valid: bool = Field(..., description="Whether the webhook configuration is valid")
    org_slug: str = Field(..., description="Organization slug")
    has_secret: bool = Field(..., description="Whether a secret is configured")
    org_active: bool = Field(..., description="Whether the organization is active")
    message: str = Field(..., description="Human-readable validation result")


# ── Helpers ──────────────────────────────────────────────────────────────────


def _mask_secret(secret: str | None) -> str | None:
    """Return a masked version of a secret — safe for display.

    Shows only the last 4 characters with asterisks for the rest.
    This prevents leaking 50% of the secret (previous behavior showed
    first 4 + last 4 = 8 characters for a 16-char minimum secret).
    """
    if not secret:
        return None
    if len(secret) <= 4:
        return "*" * len(secret)
    return f"{'*' * (len(secret) - 4)}{secret[-4:]}"


def _build_webhook_url(org_slug: str) -> str:
    """Build the full webhook URL for an organization.

    Uses the app's base URL from settings if available,
    otherwise provides a placeholder that the admin must configure.
    """
    from app.config import settings
    base = getattr(settings, "app_base_url", None) or "https://your-domain.com"
    return f"{base.rstrip('/')}/webhooks/{org_slug}/form-submission"


def _log_config_event(
    db: Session,
    org_id,
    event_type: str,
    payload: dict | None = None,
) -> None:
    """Log a webhook configuration change as an audit event.

    Phase 6E: Uses NULL lead_id since config changes don't involve a Lead.
    The events_log.lead_id column was made nullable in migration 005.
    """
    from app.models import EventLog

    db.add(
        EventLog(
            lead_id=None,
            event_type=event_type,
            payload=json.dumps(payload) if payload else None,
            organization_id=org_id,
        )
    )
    db.commit()


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/config", response_model=WebhookConfigResponse)
def get_webhook_config(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> WebhookConfigResponse:
    """View the current organization's webhook configuration.

    Returns the webhook URL, slug, and whether a secret is configured.
    The full secret is NEVER returned — only a masked version.

    Accessible by any authenticated user in the organization.
    """
    org = db.query(Organization).filter(
        Organization.id == current_user.organization_id
    ).first()

    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="organization not found",
        )

    return WebhookConfigResponse(
        org_slug=org.slug,
        webhook_url=_build_webhook_url(org.slug),
        has_secret=bool(org.webhook_secret),
        secret_masked=_mask_secret(org.webhook_secret),
    )


@router.patch("/config", response_model=WebhookConfigResponse)
def update_webhook_config(
    payload: WebhookConfigUpdateRequest,
    current_user=Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> WebhookConfigResponse:
    """Update the organization's webhook secret.

    Only Owner and Admin roles can modify webhook configuration.
    The new secret must be at least 16 characters.

    Returns the updated configuration with the masked secret.
    """
    org = db.query(Organization).filter(
        Organization.id == current_user.organization_id
    ).first()

    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="organization not found",
        )

    org.webhook_secret = payload.webhook_secret
    db.commit()
    db.refresh(org)

    # Audit log
    _log_config_event(
        db,
        org.id,
        "webhook_secret_updated",
        {"actor_email": current_user.email},
    )

    logger.info(
        "webhook secret updated for org=%s by user=%s",
        org.slug,
        current_user.email,
    )

    return WebhookConfigResponse(
        org_slug=org.slug,
        webhook_url=_build_webhook_url(org.slug),
        has_secret=bool(org.webhook_secret),
        secret_masked=_mask_secret(org.webhook_secret),
    )


@router.post("/rotate-secret", response_model=WebhookRotateSecretResponse)
def rotate_webhook_secret(
    current_user=Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> WebhookRotateSecretResponse:
    """Generate a new cryptographically random webhook secret.

    Only Owner and Admin roles can rotate the secret.
    The new secret is returned ONCE — the user must copy it to their
    Apps Script configuration immediately.

    SECURITY: The old secret is invalidated immediately upon rotation.
    """
    org = db.query(Organization).filter(
        Organization.id == current_user.organization_id
    ).first()

    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="organization not found",
        )

    # Phase 28 P1-B: Rate-limit secret rotation (5/hour per org)
    if current_user.organization_id:
        check_rate_limit(
            key=f"webhook_rotate:{current_user.organization_id}",
            max_attempts=5, window_seconds=3600,
            label="webhook secret rotation",
        )

    # Generate a cryptographically secure 48-character secret
    new_secret = secrets.token_urlsafe(36)  # 48 chars URL-safe

    org.webhook_secret = new_secret
    db.commit()
    db.refresh(org)

    # Audit log (never log the actual secret)
    _log_config_event(
        db,
        org.id,
        "webhook_secret_rotated",
        {"actor_email": current_user.email},
    )

    logger.info(
        "webhook secret rotated for org=%s by user=%s",
        org.slug,
        current_user.email,
    )

    return WebhookRotateSecretResponse(
        webhook_secret=new_secret,
        message=(
            "Secret rotated successfully. Copy this secret to your Apps Script "
            "Project Settings → Script Properties → WEBHOOK_SECRET immediately. "
            "This secret will not be shown again."
        ),
    )


@router.post("/test", response_model=WebhookTestResponse)
def test_webhook_config(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> WebhookTestResponse:
    """Validate the organization's webhook configuration.

    Checks that the org is active, has a slug, and optionally has a
    secret configured. Does NOT send a real webhook — this is a
    configuration validation only.

    Accessible by any authenticated user in the organization.
    """
    from app.models_multi_tenant import OrganizationStatus

    org = db.query(Organization).filter(
        Organization.id == current_user.organization_id
    ).first()

    if org is None:
        return WebhookTestResponse(
            valid=False,
            org_slug="",
            has_secret=False,
            org_active=False,
            message="Organization not found",
        )

    issues = []

    if org.status != OrganizationStatus.ACTIVE:
        issues.append(f"Organization status is '{org.status.value}' (must be 'active')")

    if not org.slug:
        issues.append("Organization has no slug configured")

    if not org.webhook_secret and not getattr(
        __import__("app.config", fromlist=["settings"]), "settings"
    ).webhook_secret:
        issues.append(
            "No webhook secret configured (org or global). "
            "Set a secret for production use."
        )

    valid = len(issues) == 0
    message = "Webhook configuration is valid" if valid else "; ".join(issues)

    return WebhookTestResponse(
        valid=valid,
        org_slug=org.slug or "",
        has_secret=bool(org.webhook_secret),
        org_active=org.status == OrganizationStatus.ACTIVE,
        message=message,
    )
