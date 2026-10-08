"""Token lifecycle health monitoring (Phase 5).

Periodically checks that Zoom and Google OAuth tokens are still valid
and warns when they are nearing expiry.  Runs as an APScheduler job.

No credentials are logged — only status and expiry metadata.

Design:
  - Queries all org_integrations with active Google/Zoom tokens.
  - For each, checks the ``token_expires_at`` in metadata_json.
  - Warns when < 24 hours remain, alerts when < 1 hour or expired.
  - Returns a summary dict for logging and optional dashboard display.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

logger = logging.getLogger("strategy-call-agent.token_health")

# Warning thresholds
_WARNING_HOURS = 24
_ALERT_HOURS = 1


def check_token_health(db: Any, org_id: uuid.UUID | None = None) -> dict[str, Any]:
    """Check health of OAuth tokens, optionally scoped to a single org.

    Args:
        db: SQLAlchemy session.
        org_id: When provided, only check integrations for this org.
               When None (platform admin), check all organizations.

    Returns a summary dict with per-org results:
        {
            "checked": int,
            "healthy": int,
            "warning": int,   # expiring within 24h
            "critical": int,  # expiring within 1h or expired
            "orgs": { org_id_str: { "google": ..., "zoom": ... } }
        }

    This function does NOT refresh or modify any tokens — it only reads
    metadata and reports status.
    """
    from app.models_multi_tenant import IntegrationStatus, OrgIntegration

    now = datetime.now(timezone.utc)
    warning_cutoff = now + timedelta(hours=_WARNING_HOURS)
    alert_cutoff = now + timedelta(hours=_ALERT_HOURS)

    summary: dict[str, Any] = {
        "checked": 0,
        "healthy": 0,
        "warning": 0,
        "critical": 0,
        "orgs": {},
    }

    # Query org integrations — scoped to a single org when org_id is provided
    stmt = select(OrgIntegration).where(
        OrgIntegration.status != IntegrationStatus.DISCONNECTED,
        OrgIntegration.credentials_encrypted.isnot(None),
    )
    if org_id is not None:
        stmt = stmt.where(OrgIntegration.organization_id == org_id)
    integrations = db.execute(stmt).scalars().all()

    for integration in integrations:
        org_key = str(integration.organization_id)
        provider = integration.provider
        integration_type = integration.integration_type

        # Only check OAuth token integrations (not API keys like OpenAI)
        if not (
            (provider == "google" and integration_type in ("google_oauth", "calendar", "email"))
            or (provider == "zoom" and integration_type == "zoom_oauth")
        ):
            continue

        summary["checked"] += 1

        metadata = integration.metadata_json or {}
        org_results = summary["orgs"].setdefault(org_key, {})

        # Determine the service key for the summary
        service_key = f"{provider}_{integration_type}"

        # Extract token expiry from metadata
        expires_at_str = metadata.get("token_expires_at")
        if not expires_at_str:
            # No expiry info — token may be a file-based credential or API key
            org_results[service_key] = {
                "status": "unknown",
                "message": "no expiry metadata stored",
            }
            continue

        try:
            expires_at = datetime.fromisoformat(expires_at_str)
            # Ensure timezone-aware
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            org_results[service_key] = {
                "status": "unknown",
                "message": "invalid expiry metadata format",
            }
            continue

        remaining = expires_at - now

        if expires_at <= now:
            # Token is expired
            org_results[service_key] = {
                "status": "expired",
                "expired_at": expires_at.isoformat(),
                "expired_hours_ago": round(abs(remaining.total_seconds()) / 3600, 1),
            }
            summary["critical"] += 1
            logger.warning(
                "token_expired: org=%s service=%s expired_at=%s",
                org_key, service_key, expires_at.isoformat(),
            )
        elif expires_at <= alert_cutoff:
            # Critical: expiring within 1 hour
            org_results[service_key] = {
                "status": "critical",
                "expires_at": expires_at.isoformat(),
                "remaining_minutes": round(remaining.total_seconds() / 60, 1),
            }
            summary["critical"] += 1
            logger.warning(
                "token_expiring_critical: org=%s service=%s expires_at=%s remaining_min=%.1f",
                org_key, service_key, expires_at.isoformat(), remaining.total_seconds() / 60,
            )
        elif expires_at <= warning_cutoff:
            # Warning: expiring within 24 hours
            org_results[service_key] = {
                "status": "warning",
                "expires_at": expires_at.isoformat(),
                "remaining_hours": round(remaining.total_seconds() / 3600, 1),
            }
            summary["warning"] += 1
            logger.info(
                "token_expiring_warning: org=%s service=%s expires_at=%s remaining_hours=%.1f",
                org_key, service_key, expires_at.isoformat(), remaining.total_seconds() / 3600,
            )
        else:
            # Healthy
            org_results[service_key] = {
                "status": "healthy",
                "expires_at": expires_at.isoformat(),
                "remaining_hours": round(remaining.total_seconds() / 3600, 1),
            }
            summary["healthy"] += 1

    # Overall determination
    if summary["critical"] > 0:
        summary["overall"] = "critical"
    elif summary["warning"] > 0:
        summary["overall"] = "warning"
    else:
        summary["overall"] = "healthy"

    return summary
