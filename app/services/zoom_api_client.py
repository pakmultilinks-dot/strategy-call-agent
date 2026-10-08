"""Zoom REST API client (Phase 6B.5 — Step 2).

Thin HTTP client wrapping the Zoom Meeting APIs.  Uses httpx with
timeouts and the shared ``external_call_retry`` decorator for
transient-failure resilience.

SECURITY:
  - Access / refresh tokens are NEVER logged.
  - All external calls go through ``external_call_retry`` with
    exponential back-off.
  - Client secrets are read from the encrypted vault (or platform
    defaults) — never from environment variables at call time.

Zoom OAuth2 endpoints (Web Application flow):
  Authorization:  https://zoom.us/oauth/authorize
  Token:          https://zoom.us/oauth/token

Zoom Meeting API (v2):
  Base URL:       https://api.zoom.us/v2
  Create meeting: POST   /v2/users/me/meetings
  Get meeting:    GET    /v2/meetings/{meetingId}
  Delete meeting: DELETE /v2/meetings/{meetingId}
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.services.retry import external_call_retry

logger = logging.getLogger(__name__)

# ── Zoom endpoints ────────────────────────────────────────────────────

ZOOM_OAUTH_AUTHORIZE = "https://zoom.us/oauth/authorize"
ZOOM_OAUTH_TOKEN = "https://zoom.us/oauth/token"
ZOOM_API_BASE = "https://api.zoom.us/v2"

# Request timeouts (seconds)
_TIMEOUT_CONNECT = 10.0
_TIMEOUT_READ = 30.0

# Buffer before actual expiry to trigger proactive refresh (seconds).
_TOKEN_EXPIRY_BUFFER_SECONDS = 300  # 5 minutes


# ── Exceptions ────────────────────────────────────────────────────────


class ZoomAPIError(Exception):
    """Base exception for Zoom API errors."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_code: str = "zoom_api_error",
    ):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


class ZoomTokenExchangeError(ZoomAPIError):
    """Token exchange with Zoom failed."""

    def __init__(self, message: str):
        super().__init__(message, error_code="zoom_token_exchange_failed")


class ZoomTokenRefreshError(ZoomAPIError):
    """Token refresh with Zoom failed."""

    def __init__(self, message: str):
        super().__init__(message, error_code="zoom_token_refresh_failed")


class ZoomMeetingError(ZoomAPIError):
    """Meeting API call failed."""

    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message, status_code=status_code, error_code="zoom_meeting_error")


# ── Client ────────────────────────────────────────────────────────────


class ZoomAPIClient:
    """Stateless helper for Zoom OAuth + Meeting API calls.

    Every method accepts explicit credentials so the client is
    re-entrant and does not hold mutable token state — the vault is
    the single source of truth.
    """

    # ----------------------------------------------------------------
    # Authorization URL
    # ----------------------------------------------------------------

    @staticmethod
    def build_authorization_url(
        client_id: str,
        redirect_uri: str,
        state_token: str,
    ) -> str:
        """Build the Zoom OAuth2 authorization URL.

        Args:
            client_id: Zoom app Client ID.
            redirect_uri: Must match the value registered in Zoom Marketplace.
            state_token: CSRF state token.

        Returns:
            Full authorization URL to redirect the user to.
        """
        from urllib.parse import urlencode

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state_token,
        }
        return f"{ZOOM_OAUTH_AUTHORIZE}?{urlencode(params)}"

    # ----------------------------------------------------------------
    # Token exchange (authorization code → tokens)
    # ----------------------------------------------------------------

    @staticmethod
    @external_call_retry
    def exchange_code(
        code: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        """Exchange an authorization code for access + refresh tokens.

        Uses HTTP Basic Auth per Zoom OAuth2 spec.

        Returns:
            Dict with keys: access_token, refresh_token, token_type,
            expires_in, account_id, account_email.
        """
        try:
            response = httpx.post(
                ZOOM_OAUTH_TOKEN,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
                auth=(client_id, client_secret),
                timeout=httpx.Timeout(_TIMEOUT_CONNECT, read=_TIMEOUT_READ),
            )
        except httpx.RequestError as exc:
            raise ZoomTokenExchangeError(
                "Failed to connect to Zoom's token endpoint."
            ) from exc

        if response.status_code != 200:
            error_data = (
                response.json()
                if "application/json" in response.headers.get("content-type", "")
                else {}
            )
            error_msg = error_data.get("error", "unknown_error")
            error_desc = error_data.get("error_description", "")
            logger.error(
                "[ZOOM_API] Token exchange failed: status=%s error=%s",
                response.status_code,
                error_msg,
            )
            raise ZoomTokenExchangeError(
                f"Zoom token exchange failed: {error_msg}"
                + (f" — {error_desc}" if error_desc else "")
            )

        data = response.json()

        # Zoom returns the account info inline for Server-to-Server but
        # for Web Application flow it may not include account_id/email
        # in the token response — those are fetched separately if needed.
        return {
            "access_token": data["access_token"],
            "refresh_token": data.get("refresh_token", ""),
            "token_type": data.get("token_type", "Bearer"),
            "expires_in": data.get("expires_in", 3600),
            "scope": data.get("scope", ""),
        }

    # ----------------------------------------------------------------
    # Token refresh
    # ----------------------------------------------------------------

    @staticmethod
    @external_call_retry
    def refresh_access_token(
        refresh_token: str,
        client_id: str,
        client_secret: str,
    ) -> dict[str, Any]:
        """Refresh an expired access token.

        Returns:
            Dict with keys: access_token, refresh_token (new, rotated),
            expires_in.
        """
        try:
            response = httpx.post(
                ZOOM_OAUTH_TOKEN,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                },
                auth=(client_id, client_secret),
                timeout=httpx.Timeout(_TIMEOUT_CONNECT, read=_TIMEOUT_READ),
            )
        except httpx.RequestError as exc:
            raise ZoomTokenRefreshError(
                "Failed to connect to Zoom's token endpoint for refresh."
            ) from exc

        if response.status_code != 200:
            error_data = (
                response.json()
                if "application/json" in response.headers.get("content-type", "")
                else {}
            )
            error_msg = error_data.get("error", "unknown_error")
            logger.error(
                "[ZOOM_API] Token refresh failed: status=%s error=%s",
                response.status_code,
                error_msg,
            )
            raise ZoomTokenRefreshError(
                f"Zoom token refresh failed: {error_msg}"
            )

        data = response.json()
        return {
            "access_token": data["access_token"],
            "refresh_token": data.get("refresh_token", refresh_token),
            "expires_in": data.get("expires_in", 3600),
        }

    # ----------------------------------------------------------------
    # Fetch account info (used after initial token exchange)
    # ----------------------------------------------------------------

    @staticmethod
    @external_call_retry
    def get_account_info(access_token: str) -> dict[str, Any]:
        """Fetch the authenticated user's Zoom account info.

        Returns:
            Dict with keys: id, account_id, email.
        """
        try:
            response = httpx.get(
                f"{ZOOM_API_BASE}/users/me",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=httpx.Timeout(_TIMEOUT_CONNECT, read=_TIMEOUT_READ),
            )
        except httpx.RequestError as exc:
            raise ZoomAPIError(
                "Failed to connect to Zoom API for account info."
            ) from exc

        if response.status_code != 200:
            error_data = (
                response.json()
                if "application/json" in response.headers.get("content-type", "")
                else {}
            )
            zoom_code = error_data.get("code", "unknown")
            zoom_message = error_data.get("message", "no message")
            logger.warning(
                "[ZOOM_API] Account info fetch failed: status=%s zoom_code=%s message=%s",
                response.status_code,
                zoom_code,
                zoom_message,
            )
            raise ZoomAPIError(
                f"Failed to fetch Zoom account info: HTTP {response.status_code} — "
                f"Zoom code={zoom_code}: {zoom_message}",
                status_code=response.status_code,
            )

        data = response.json()
        return {
            "id": data.get("id"),
            "account_id": data.get("account_id"),
            "email": data.get("email"),
            "first_name": data.get("first_name"),
            "last_name": data.get("last_name"),
        }

    # ----------------------------------------------------------------
    # Meeting CRUD
    # ----------------------------------------------------------------

    @staticmethod
    def create_meeting(
        access_token: str,
        *,
        topic: str,
        start_time: datetime,
        duration_minutes: int,
        description: str = "",
        timezone: str = "UTC",
        settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new Zoom meeting.

        NOTE: No retry decorator — meeting creation is NOT idempotent.
        A timeout after Zoom creates the meeting but before the client
        receives the response would create duplicate meetings on retry.
        Transient failures are recorded as FailedJob for manual recovery.

        Args:
            access_token: Valid Zoom access token.
            topic: Meeting topic / subject.
            start_time: Start time (UTC, timezone-aware).
            duration_minutes: Duration in minutes.
            description: Meeting description.
            timezone: IANA timezone name for display.
            settings: Optional meeting settings override.

        Returns:
            Dict with keys: id, join_url, start_time, topic, etc.
        """
        # Zoom API expects ISO 8601 without trailing Z — just the
        # offset-free local representation tagged with tz parameter.
        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S")

        body: dict[str, Any] = {
            "topic": topic,
            "type": 2,  # 2 = scheduled meeting
            "start_time": start_str,
            "duration": duration_minutes,
            "timezone": timezone,
            "description": description,
        }

        # Default: enable waiting room, join before host disabled.
        default_settings: dict[str, Any] = {
            "waiting_room": True,
            "join_before_host": False,
            "host_video": True,
            "participant_video": False,
        }
        if settings:
            default_settings.update(settings)
        body["settings"] = default_settings

        try:
            response = httpx.post(
                f"{ZOOM_API_BASE}/users/me/meetings",
                json=body,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=httpx.Timeout(_TIMEOUT_CONNECT, read=_TIMEOUT_READ),
            )
        except httpx.RequestError as exc:
            raise ZoomMeetingError(
                "Failed to connect to Zoom Meeting API."
            ) from exc

        if response.status_code not in (200, 201):
            error_data = (
                response.json()
                if "application/json" in response.headers.get("content-type", "")
                else {}
            )
            error_msg = error_data.get("message", "Unknown error")
            logger.error(
                "[ZOOM_API] Create meeting failed: status=%s error=%s",
                response.status_code,
                error_msg,
            )
            raise ZoomMeetingError(
                f"Failed to create Zoom meeting: {error_msg}",
                status_code=response.status_code,
            )

        data = response.json()
        return {
            "id": str(data.get("id", "")),
            "join_url": data.get("join_url"),
            "start_time": data.get("start_time"),
            "topic": data.get("topic"),
            "duration": data.get("duration"),
            "password": data.get("password"),
            "h323_password": data.get("h323_password"),
            "pstn_password": data.get("pstn_password"),
            "status": data.get("status"),
        }

    @staticmethod
    @external_call_retry
    def get_meeting(access_token: str, meeting_id: str) -> dict[str, Any] | None:
        """Retrieve meeting details by ID.

        Returns:
            Meeting dict, or None if not found.
        """
        try:
            response = httpx.get(
                f"{ZOOM_API_BASE}/meetings/{meeting_id}",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=httpx.Timeout(_TIMEOUT_CONNECT, read=_TIMEOUT_READ),
            )
        except httpx.RequestError as exc:
            raise ZoomMeetingError(
                "Failed to connect to Zoom Meeting API."
            ) from exc

        if response.status_code == 404:
            return None

        if response.status_code != 200:
            logger.warning(
                "[ZOOM_API] Get meeting failed: status=%s meeting_id=%s",
                response.status_code,
                meeting_id,
            )
            raise ZoomMeetingError(
                f"Failed to get Zoom meeting: HTTP {response.status_code}",
                status_code=response.status_code,
            )

        data = response.json()
        return {
            "id": str(data.get("id", "")),
            "join_url": data.get("join_url"),
            "start_time": data.get("start_time"),
            "topic": data.get("topic"),
            "duration": data.get("duration"),
            "status": data.get("status"),
        }

    @staticmethod
    @external_call_retry
    def delete_meeting(access_token: str, meeting_id: str) -> bool:
        """Cancel/delete an existing Zoom meeting.

        Returns:
            True if deleted successfully.
        """
        try:
            response = httpx.delete(
                f"{ZOOM_API_BASE}/meetings/{meeting_id}",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=httpx.Timeout(_TIMEOUT_CONNECT, read=_TIMEOUT_READ),
            )
        except httpx.RequestError as exc:
            raise ZoomMeetingError(
                "Failed to connect to Zoom Meeting API."
            ) from exc

        if response.status_code == 204:
            return True

        if response.status_code == 404:
            # Already deleted or doesn't exist — idempotent.
            logger.info(
                "[ZOOM_API] Meeting already absent: meeting_id=%s",
                meeting_id,
            )
            return True

        logger.warning(
            "[ZOOM_API] Delete meeting failed: status=%s meeting_id=%s",
            response.status_code,
            meeting_id,
        )
        raise ZoomMeetingError(
            f"Failed to delete Zoom meeting: HTTP {response.status_code}",
            status_code=response.status_code,
        )


# ── Token freshness helper ────────────────────────────────────────────


def is_token_expired(expires_at: datetime | None) -> bool:
    """Check whether a Zoom access token is expired or about to expire.

    Args:
        expires_at: UTC datetime when the token expires, or None.

    Returns:
        True if the token should be refreshed.
    """
    if expires_at is None:
        return True
    now = datetime.now(timezone.utc)
    return now >= (expires_at - timedelta(seconds=_TOKEN_EXPIRY_BUFFER_SECONDS))
