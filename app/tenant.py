"""Tenant resolution helpers for multi-tenant support.

All tenant resolution functions require an explicit organization_id.
No fallback to a default organization is permitted — callers MUST
supply the correct org_id extracted from the JWT token, the org-scoped
webhook path, or the Lead/EventLog/FailedJob record itself.

DESIGN NOTES:
- All functions return UUID (the organization_id)
- The "current organization" is determined by context (JWT, webhook slug)
- get_current_organization_id() raises RuntimeError if no org context
- resolve_organization_id(None) raises RuntimeError
- _DEFAULT_ORG_ID exists ONLY for migration seed data reference

PHASE 1: Hardened — removed all runtime default-org fallbacks.
"""
from __future__ import annotations

import logging
import uuid

from app.database import SessionLocal
from app.models import EventLog, FailedJob, Lead
from app.models_multi_tenant import Organization, OrganizationStatus

logger = logging.getLogger(__name__)

# The default organization ID — matches the ID seeded in migration 001_multi_tenant.
_DEFAULT_ORG_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


def get_default_organization_id() -> uuid.UUID:
    """Return the default organization ID.

    This is the deterministic UUID used throughout the system to represent
    the original single-tenant installation, now wrapped in an Organization.

    Returns:
        The default organization UUID (00000000-0000-0000-0000-000000000001).
    """
    return _DEFAULT_ORG_ID


def get_current_organization_id() -> uuid.UUID:
    """DEPRECATED — raises RuntimeError.

    This function previously returned the default organization as a
    fallback.  As of Phase 1 (Multi-Tenant Hardening), all callers
    MUST pass an explicit organization_id.  Any code path that reaches
    this function indicates a missing org resolution and is treated
    as a fatal programming error.

    Raises:
        RuntimeError: Always. Callers must supply org_id explicitly.
    """
    raise RuntimeError(
        "get_current_organization_id() is deprecated — all callers must "
        "pass an explicit organization_id.  This indicates a missing tenant "
        "resolution in the calling code."
    )


def resolve_organization_id(
    organization_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Resolve an organization ID, raising if None.

    Phase 1 (Hardening): Falls back to the default org if no explicit
    organization_id is provided.  Callers MUST supply org_id.

    Args:
        organization_id: Explicit organization ID.  Must not be None.

    Returns:
        The resolved organization UUID.

    Raises:
        RuntimeError: If organization_id is None.
    """
    if organization_id is not None:
        return organization_id
    raise RuntimeError(
        "resolve_organization_id(None) — caller must provide an explicit "
        "organization_id.  No default fallback is permitted."
    )


def set_lead_organization(
    lead: Lead,
    organization_id: uuid.UUID | None = None,
) -> None:
    """Set the organization_id on a Lead instance.

    Phase 1: Requires explicit organization_id — raises if None.

    Args:
        lead: The Lead ORM instance to update.
        organization_id: The organization to assign (required).

    Raises:
        RuntimeError: If organization_id is None.
    """
    lead.organization_id = resolve_organization_id(organization_id)


def set_event_organization(
    event: EventLog,
    organization_id: uuid.UUID | None = None,
) -> None:
    """Set the organization_id on an EventLog instance.

    Phase 1: Requires explicit organization_id — raises if None.

    Args:
        event: The EventLog ORM instance to update.
        organization_id: The organization to assign (required).

    Raises:
        RuntimeError: If organization_id is None.
    """
    event.organization_id = resolve_organization_id(organization_id)


def set_failed_job_organization(
    job: FailedJob,
    organization_id: uuid.UUID | None = None,
) -> None:
    """Set the organization_id on a FailedJob instance.

    Phase 1: Requires explicit organization_id — raises if None.

    Args:
        job: The FailedJob ORM instance to update.
        organization_id: The organization to assign (required).

    Raises:
        RuntimeError: If organization_id is None.
    """
    job.organization_id = resolve_organization_id(organization_id)


def lookup_organization_by_slug(
    slug: str,
    db: Session | None = None,
) -> Organization | None:
    """Look up an Organization by its URL-safe slug.

    Returns the Organization if found AND active, or None otherwise.
    Does NOT raise exceptions — callers decide the HTTP response.

    Args:
        slug: The URL-safe slug (e.g. "integrated-it-trainings").
        db: Optional existing session; creates one if None.

    Returns:
        The Organization ORM instance, or None if not found / not active.
    """
    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        org = (
            db.query(Organization)
            .filter(Organization.slug == slug)
            .first()
        )
        if org is None:
            return None
        if org.status != OrganizationStatus.ACTIVE:
            logger.warning(
                "webhook org lookup: org '%s' found but status=%s (not active)",
                slug,
                org.status.value,
            )
            return None
        return org
    finally:
        if own_session:
            db.close()


def verify_org_webhook_secret(
    organization: Organization,
    provided_token: str,
) -> bool:
    """Verify the provided Bearer token against the org's webhook secret.

    Checks the org-specific webhook_secret first. If the org has no
    configured webhook_secret, falls back to the global settings.webhook_secret.

    Uses constant-time comparison (secrets.compare_digest) to prevent
    timing attacks.

    Args:
        organization: The Organization ORM instance.
        provided_token: The raw Bearer token from the Authorization header.

    Returns:
        True if the token matches, False otherwise.
    """
    import secrets

    # Try org-specific secret first
    org_secret = getattr(organization, "webhook_secret", None)
    if org_secret:
        return secrets.compare_digest(provided_token, org_secret)

    # Fall back to global webhook secret
    from app.config import settings
    if settings.webhook_secret:
        return secrets.compare_digest(provided_token, settings.webhook_secret)

    # No secret configured anywhere — reject (never allow unauthenticated)
    return False
