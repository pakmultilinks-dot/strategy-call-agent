"""Meeting provider abstraction (Phase 6B.4 — FUTURE-FACING).

Defines the abstract interface that meeting providers (Google Meet,
Zoom, etc.) must implement. This is NOT an implementation — it is
the contract that the calendar_service.py and pipeline will use.

DESIGN:
  - Protocol-based (typing.Protocol) for structural subtyping
  - No abstract base class needed — any object with matching methods works
  - GoogleMeetProvider is the current default implementation
  - ZoomMeetingProvider implements the Zoom integration (Phase 6B.5)

CURRENT STATUS (Phase 6B.5):
  - ZoomMeetingProvider is implemented and uses the Zoom Meeting API
  - resolve_meeting_provider() checks for Zoom credentials, falls back
    to Google Meet as default
  - The pipeline can now use the provider abstraction for both backends

FUTURE:
  - The pipeline can be fully migrated to use MeetingProvider directly
  - CalendarService may delegate to GoogleMeetProvider as well
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from app.services.org_context import OrganizationContext

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MeetingDetails:
    """Result of creating a meeting — provider-agnostic."""
    meeting_id: str
    meeting_link: str | None = None
    provider: str = "google_meet"


@runtime_checkable
class MeetingProvider(Protocol):
    """Abstract protocol for meeting providers.

    Any class that implements these methods can serve as a meeting
    provider. The pipeline code can accept any MeetingProvider without
    knowing the underlying implementation.

    This is the contract that will be used when Zoom is added:

        provider: ZoomMeetingProvider = resolve_meeting_provider(org_ctx)
        details = provider.create_meeting(...)
        link = provider.get_meeting_link(details.meeting_id)
        provider.cancel_meeting(details.meeting_id)
    """

    def create_meeting(
        self,
        summary: str,
        description: str,
        start_utc: datetime,
        duration_minutes: int,
        attendees: list[str],
        idempotency_key: str,
        timezone: str = "UTC",
    ) -> MeetingDetails:
        """Create a new meeting and return its details.

        Args:
            summary: Meeting title/subject.
            description: Meeting description/notes.
            start_utc: Start time as a timezone-aware datetime.
            duration_minutes: Meeting duration in minutes.
            attendees: List of attendee email addresses.
            idempotency_key: Unique key to prevent duplicate creation.
            timezone: IANA timezone name for display purposes.

        Returns:
            MeetingDetails with the meeting ID and link.
        """
        ...  # pragma: no cover

    def get_meeting_link(self, meeting_id: str) -> str | None:
        """Return the join link for an existing meeting.

        Args:
            meeting_id: The provider-specific meeting ID.

        Returns:
            The meeting join URL, or None if the meeting was cancelled/deleted.
        """
        ...  # pragma: no cover

    def cancel_meeting(self, meeting_id: str) -> None:
        """Cancel/delete an existing meeting.

        Args:
            meeting_id: The provider-specific meeting ID.
        """
        ...  # pragma: no cover

    def get_meeting(self, meeting_id: str) -> dict | None:
        """Retrieve meeting details by ID.

        Args:
            meeting_id: The provider-specific meeting ID.

        Returns:
            Meeting metadata dict, or None if not found.
        """
        ...  # pragma: no cover


# ---------------------------------------------------------------------------
# Duration configuration
# ---------------------------------------------------------------------------

# Default meeting duration. The current business rule is 30 minutes
# (Phase 6B.5+ requirement). This is a module-level constant that can
# be made organization-configurable in the future via OrgScheduleConfig.
DEFAULT_MEETING_DURATION_MINUTES: int = 30


# ---------------------------------------------------------------------------
# Future: Provider resolution
# ---------------------------------------------------------------------------

def resolve_meeting_provider(
    org_context: OrganizationContext | None = None,
    db: Session | None = None,
) -> MeetingProvider:
    """Resolve the appropriate meeting provider for an organization.

    Resolution logic (no schema changes):
      1. If the org has Zoom OAuth credentials → ZoomMeetingProvider
      2. Otherwise → fall back to Google Meet (CalendarService pattern)

    This function is used by the pipeline to select the meeting backend
    at runtime based on the org's configured integrations.

    Args:
        org_context: Organization context for provider selection.
        db: Database session for credential lookup.

    Returns:
        A MeetingProvider implementation.

    Raises:
        ZoomAPIError: If Zoom is selected but credentials are invalid.
    """
    # Step 8: Check if org has Zoom credentials configured
    if org_context is not None and db is not None:
        from app.services.credential_vault import CredentialVault

        has_zoom = CredentialVault.has_credentials(
            db,
            org_context.organization_id,
            "zoom",
            "zoom_oauth",
        )
        if has_zoom:
            # Check if the Zoom integration is in an ERROR state (e.g.
            # refresh token revoked / invalid_grant).  In that case,
            # fall back to Google Meet instead of repeatedly failing.
            from app.models_multi_tenant import IntegrationStatus, OrgIntegration
            zoom_row = db.query(OrgIntegration).filter(
                OrgIntegration.organization_id == org_context.organization_id,
                OrgIntegration.provider == "zoom",
                OrgIntegration.integration_type == "zoom_oauth",
            ).first()
            if zoom_row is not None and zoom_row.status == IntegrationStatus.ERROR:
                logger.warning(
                    "[MEETING_PROVIDER] Zoom integration in ERROR state for "
                    "org %s — falling back to Google Meet. last_error=%s",
                    org_context.organization_id,
                    zoom_row.last_error or "(none)",
                )
                return _GoogleMeetProviderShim()

            logger.info(
                "[MEETING_PROVIDER] Resolved Zoom for org %s",
                org_context.organization_id,
            )
            return ZoomMeetingProvider(
                org_context=org_context,
                db=db,
            )

    # Default: Google Meet (no provider object — pipeline uses CalendarService)
    logger.debug(
        "[MEETING_PROVIDER] Defaulting to Google Meet (org=%s)",
        org_context.organization_id if org_context else "none",
    )
    # Return a marker that tells the pipeline to use CalendarService.
    # We use GoogleMeetProvider (a thin shim) for structural consistency.
    return _GoogleMeetProviderShim()


# ---------------------------------------------------------------------------
# Google Meet shim (delegates to CalendarService in the pipeline)
# ---------------------------------------------------------------------------


class _GoogleMeetProviderShim:
    """Shim for the default Google Meet provider.

    This is NOT a full MeetingProvider implementation — it is a
    sentinel that the pipeline checks to decide whether to use
    CalendarService directly.  The actual Google Meet meeting creation
    remains in CalendarService (unchanged).
    """

    provider_name: str = "google_meet"

    def __repr__(self) -> str:
        return "<GoogleMeetProviderShim (uses CalendarService)>"


# ---------------------------------------------------------------------------
# Zoom Meeting Provider (Phase 6B.5 — Step 7)
# ---------------------------------------------------------------------------


class ZoomMeetingProvider:
    """MeetingProvider implementation backed by the Zoom Meeting API.

    This class implements the ``MeetingProvider`` protocol using Zoom's
    REST API for meeting CRUD.  Token management is handled via the
    encrypted vault — this class never holds long-lived token state.

    SECURITY:
      - Access tokens are refreshed automatically before each API call
      - Tokens are stored in encrypted vault (CredentialVault)
      - Tokens are NEVER logged

    Usage:
        provider = ZoomMeetingProvider(org_context=org_ctx, db=db)
        details = provider.create_meeting(
            summary="Strategy Call",
            description="Quarterly review",
            start_utc=datetime(2026, 9, 1, 14, 0, tzinfo=timezone.utc),
            duration_minutes=30,
            attendees=["user@example.com"],
            idempotency_key="lead-123-abc",
        )
        # details.meeting_link → "https://zoom.us/j/..."
    """

    provider_name: str = "zoom"

    def __init__(
        self,
        org_context: OrganizationContext,
        db: Session,
    ):
        self._org_context = org_context
        self._db = db

    def _get_access_token(self) -> str:
        """Get a valid Zoom access token, refreshing if necessary.

        Delegates to ZoomOAuthFlow.refresh_token_if_needed() which
        checks token_expires_at and refreshes transparently.
        """
        from app.services.zoom_oauth_flow import ZoomOAuthFlow

        return ZoomOAuthFlow.refresh_token_if_needed(
            self._db,
            self._org_context.organization_id,
        )

    # ------------------------------------------------------------------
    # MeetingProvider protocol methods
    # ------------------------------------------------------------------

    def create_meeting(
        self,
        summary: str,
        description: str,
        start_utc: datetime,
        duration_minutes: int,
        attendees: list[str],
        idempotency_key: str,
        timezone: str = "UTC",
    ) -> MeetingDetails:
        """Create a new Zoom meeting.

        Args:
            summary: Meeting topic.
            description: Meeting description.
            start_utc: Start time (UTC, timezone-aware).
            duration_minutes: Duration in minutes.
            attendees: List of attendee emails (Zoom invites them via
                       the meeting join URL — Zoom API doesn't accept
                       attendee emails for direct invite).
            idempotency_key: Unique key (logged, not sent to Zoom).
            timezone: IANA timezone for display.

        Returns:
            MeetingDetails with Zoom meeting ID and join URL.
        """
        from app.services.zoom_api_client import ZoomAPIClient, ZoomMeetingError

        access_token = self._get_access_token()

        logger.info(
            "[ZOOM_PROVIDER] Creating meeting",
            extra={
                "org_id": str(self._org_context.organization_id),
                "idempotency_key": idempotency_key,
                "start_utc": start_utc.isoformat(),
                "duration": duration_minutes,
            },
        )

        try:
            result = ZoomAPIClient.create_meeting(
                access_token=access_token,
                topic=summary,
                start_time=start_utc,
                duration_minutes=duration_minutes,
                description=description,
                timezone=timezone,
            )
        except ZoomMeetingError:
            logger.exception(
                "[ZOOM_PROVIDER] Failed to create meeting (org=%s)",
                self._org_context.organization_id,
            )
            raise

        meeting_id = result["id"]
        join_url = result.get("join_url")

        logger.info(
            "[ZOOM_PROVIDER] Meeting created: id=%s",
            meeting_id,
            extra={"org_id": str(self._org_context.organization_id)},
        )

        return MeetingDetails(
            meeting_id=meeting_id,
            meeting_link=join_url,
            provider="zoom",
        )

    def get_meeting_link(self, meeting_id: str) -> str | None:
        """Return the join link for an existing Zoom meeting.

        Args:
            meeting_id: The Zoom meeting ID (numeric string).

        Returns:
            The meeting join URL, or None if the meeting was
            cancelled/deleted.
        """
        from app.services.zoom_api_client import ZoomAPIClient

        access_token = self._get_access_token()
        result = ZoomAPIClient.get_meeting(access_token, meeting_id)

        if result is None:
            return None

        return result.get("join_url")

    def cancel_meeting(self, meeting_id: str) -> None:
        """Cancel/delete an existing Zoom meeting.

        Args:
            meeting_id: The Zoom meeting ID (numeric string).
        """
        from app.services.zoom_api_client import ZoomAPIClient

        access_token = self._get_access_token()

        logger.info(
            "[ZOOM_PROVIDER] Cancelling meeting: id=%s",
            meeting_id,
            extra={"org_id": str(self._org_context.organization_id)},
        )

        ZoomAPIClient.delete_meeting(access_token, meeting_id)

    def get_meeting(self, meeting_id: str) -> dict | None:
        """Retrieve Zoom meeting details by ID.

        Args:
            meeting_id: The Zoom meeting ID (numeric string).

        Returns:
            Meeting metadata dict, or None if not found.
        """
        from app.services.zoom_api_client import ZoomAPIClient

        access_token = self._get_access_token()
        return ZoomAPIClient.get_meeting(access_token, meeting_id)
