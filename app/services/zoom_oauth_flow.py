"""Zoom OAuth2 Web Application flow management.

Mirrors the ``GoogleOAuthFlow`` pattern exactly:
  1. State generation (CSRF protection)
  2. Authorization URL construction
  3. Token exchange (authorization code → access + refresh tokens)
  4. Account info fetch
  5. Token storage via CredentialVault
  6. State validation and consumption
  7. Token refresh (before each API call)
  8. Connection status + disconnect

SECURITY:
  - State tokens are cryptographically random (secrets.token_urlsafe)
  - State tokens are single-use (consumed on callback)
  - State tokens expire (configurable TTL, default 10 minutes)
  - Access tokens are stored in encrypted vault only
  - All credential storage is encrypted via CredentialVault
  - Error messages are sanitized to prevent token leakage
  - Tokens are NEVER logged

Usage:
    from app.services.zoom_oauth_flow import ZoomOAuthFlow

    # Step 1: Generate state + auth URL
    state_row = ZoomOAuthFlow.create_authorization_url(
        db=db, org_id=org_id, user_id=user_id,
    )
    # Redirect user to state_row → build_authorization_url()

    # Step 2: Handle callback
    result = ZoomOAuthFlow.exchange_code(
        db=db, code=authorization_code, state=state_token,
    )
"""
from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models_multi_tenant import IntegrationStatus, ZoomOAuthState
from app.services.zoom_api_client import ZoomTokenExchangeError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ZoomOAuthError(Exception):
    """Base exception for Zoom OAuth flow errors."""

    def __init__(self, message: str, error_code: str = "zoom_oauth_error"):
        super().__init__(message)
        self.error_code = error_code


class ZoomOAuthStateError(ZoomOAuthError):
    """Raised when OAuth state validation fails."""

    def __init__(self, message: str):
        super().__init__(message, error_code="zoom_invalid_state")


class ZoomOAuthTokenExchangeError(ZoomOAuthError):
    """Raised when token exchange with Zoom fails."""

    def __init__(self, message: str):
        super().__init__(message, error_code="zoom_token_exchange_failed")


class ZoomOAuthDenialError(ZoomOAuthError):
    """Raised when user denies access at Zoom consent screen."""

    def __init__(self):
        super().__init__(
            "Authorization was denied by the user.",
            error_code="zoom_access_denied",
        )


# ---------------------------------------------------------------------------
# Platform-owned credential resolution
# ---------------------------------------------------------------------------


def resolve_client_credentials(db: Session, org_id: Any) -> tuple[str, str, str]:
    """Resolve the Zoom OAuth client_id/client_secret/redirect_uri to use.

    Delegates to ``IntegrationConfigResolver.resolve_zoom_config`` - the
    single source of truth - which implements the PLATFORM-OWNED MODEL
    (one-click connect):
      1. Legacy first: an org that stored its own Zoom app in the vault
         keeps using it.  Refresh tokens are bound to the app that issued
         them, so such an org MUST keep its own client for token refresh.
      2. Platform credentials from server settings (.env ZOOM_CLIENT_ID /
         ZOOM_CLIENT_SECRET / ZOOM_REDIRECT_URI) - set ONCE by the app
         owner in the Zoom Marketplace.  Every other organization shares
         this single OAuth app; end users just click "Connect".

    Returns:
        (client_id, client_secret, redirect_uri)

    Raises:
        ZoomOAuthError: If no client credentials are configured.
    """
    from app.services.credential_vault import (
        CredentialCorruptError,
        CredentialNotFoundError,
    )
    from app.services.integration_config_resolver import IntegrationConfigResolver

    try:
        zoom_cfg = IntegrationConfigResolver.resolve_zoom_config(db, org_id)
    except (CredentialNotFoundError, CredentialCorruptError) as exc:
        raise ZoomOAuthError(
            "Zoom connect is not set up on this server yet. "
            "The platform administrator must set ZOOM_CLIENT_ID, "
            "ZOOM_CLIENT_SECRET and ZOOM_REDIRECT_URI (one-time setup in "
            "the Zoom Marketplace).",
            error_code="zoom_client_not_configured",
        ) from exc

    if not (zoom_cfg.client_id and zoom_cfg.client_secret and zoom_cfg.redirect_uri):
        raise ZoomOAuthError(
            "Zoom connect is not set up on this server yet. "
            "The platform administrator must set ZOOM_CLIENT_ID, "
            "ZOOM_CLIENT_SECRET and ZOOM_REDIRECT_URI (one-time setup in "
            "the Zoom Marketplace).",
            error_code="zoom_client_not_configured",
        )

    return zoom_cfg.client_id, zoom_cfg.client_secret, zoom_cfg.redirect_uri


# ---------------------------------------------------------------------------
# Flow class
# ---------------------------------------------------------------------------


class ZoomOAuthFlow:
    """Manages the complete Zoom OAuth2 Web Application flow."""

    # ------------------------------------------------------------------
    # Step 1: Create authorization URL
    # ------------------------------------------------------------------

    @staticmethod
    def create_authorization_url(
        db: Session,
        org_id: Any,
        user_id: Any,
        *,
        scopes: list[str] | None = None,
    ) -> ZoomOAuthState:
        """Generate a state token and build the Zoom authorization URL.

        Args:
            db: Database session
            org_id: Organization UUID
            user_id: User UUID
            scopes: Optional scopes (informational - Zoom scopes are
                    configured in Marketplace, not in the URL).

        Returns:
            ZoomOAuthState row with state_token.

        Raises:
            ZoomOAuthError: If Zoom client is not configured.
        """
        # PLATFORM-OWNED MODEL: one Zoom Marketplace app for the whole
        # platform (set once by the app owner).  The end user just clicks
        # Connect - no developer console, no pasting credentials.
        try:
            _, _, redirect_uri = resolve_client_credentials(db, org_id)
        except ZoomOAuthError:
            logger.warning(
                "[ZOOM_OAUTH] Zoom OAuth not configured for org=%s - "
                "no platform or org Zoom credentials found.",
                str(org_id)[:8],
            )
            raise

        # Convert string IDs to UUIDs if needed
        org_uuid = (
            uuid.UUID(str(org_id))
            if not isinstance(org_id, uuid.UUID)
            else org_id
        )
        user_uuid = (
            uuid.UUID(str(user_id))
            if not isinstance(user_id, uuid.UUID)
            else user_id
        )

        # Generate cryptographically random state token
        state_token = secrets.token_urlsafe(32)

        # Calculate expiry
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(
            minutes=settings.zoom_oauth_state_ttl_minutes
        )

        # redirect_uri already resolved from org vault above

        # Persist state in database
        state_row = ZoomOAuthState(
            organization_id=org_uuid,
            user_id=user_uuid,
            state_token=state_token,
            redirect_uri=redirect_uri,
            scopes=scopes or ["meeting:write"],
            expires_at=expires_at,
            used=False,
        )
        db.add(state_row)

        # Purge expired states for this org (housekeeping)
        _purge_expired_states(db, org_uuid)

        db.commit()
        db.refresh(state_row)

        logger.info(
            "[ZOOM_OAUTH] Created authorization state",
            extra={
                "org_id": str(org_uuid),
                "user_id": str(user_uuid),
                "expires_at": expires_at.isoformat(),
            },
        )
        return state_row

    @staticmethod
    def build_authorization_url(
        state_token: str,
        redirect_uri: str,
        client_id: str | None = None,
    ) -> str:
        """Build the Zoom OAuth2 authorization URL.

        Args:
            state_token: The CSRF state token.
            redirect_uri: Where Zoom redirects after auth.
            client_id: Optional client_id override. If None, uses platform default.

        Returns:
            Full authorization URL string.
        """
        from app.services.zoom_api_client import ZoomAPIClient

        resolved_client_id = client_id or (settings.zoom_client_id or "").strip()
        if not resolved_client_id:
            raise ZoomOAuthError(
                "Zoom client_id is required to build authorization URL. "
                "The platform administrator must complete the one-time "
                "Zoom Marketplace setup.",
                error_code="zoom_client_not_configured",
            )

        return ZoomAPIClient.build_authorization_url(
            client_id=resolved_client_id,
            redirect_uri=redirect_uri,
            state_token=state_token,
        )

    # ------------------------------------------------------------------
    # Step 2: Exchange authorization code for tokens
    # ------------------------------------------------------------------

    @staticmethod
    def exchange_code(
        db: Session,
        code: str,
        state: str,
    ) -> dict[str, Any]:
        """Validate state and exchange authorization code for tokens.

        Args:
            db: Database session
            code: Authorization code from Zoom callback
            state: State token from Zoom callback

        Returns:
            Dict with refresh_token, email, account_id, organization_id.

        Raises:
            ZoomOAuthStateError: If state is invalid/expired/reused.
            ZoomOAuthTokenExchangeError: If token exchange fails.
            ZoomOAuthDenialError: If user denied access.
        """
        from app.services.credential_vault import CredentialVault
        from app.services.integration_config_resolver import IntegrationConfigResolver
        from app.services.zoom_api_client import ZoomAPIClient

        # --- Validate state ---
        state_row = _validate_state(db, state)

        # Mark state as used (single-use) BEFORE exchange to prevent race
        # conditions where two concurrent callbacks both pass validation.
        state_row.used = True
        db.flush()  # flush only - commit happens after successful exchange

        # --- Resolve Zoom client credentials (platform-owned) ---
        # Org-owned model: credentials MUST come from org vault
        try:
            (
                resolved_client_id,
                resolved_client_secret,
                resolved_redirect_uri,
            ) = resolve_client_credentials(db, state_row.organization_id)
        except ZoomOAuthError as exc:
            db.rollback()
            raise ZoomOAuthTokenExchangeError(
                "Zoom connect is not set up on this server yet. "
                "The platform administrator must configure the Zoom "
                "OAuth app (one-time setup)."
            ) from exc

        try:
            # --- Exchange code for tokens ---
            token_data = ZoomAPIClient.exchange_code(
                code=code,
                client_id=resolved_client_id,
                client_secret=resolved_client_secret,
                redirect_uri=resolved_redirect_uri,
            )

            # --- Fetch account info ---
            account_info = ZoomAPIClient.get_account_info(
                access_token=token_data["access_token"]
            )
        except ZoomTokenExchangeError:
            # Rollback state marking so user can retry without re-initiating
            db.rollback()
            raise ZoomOAuthTokenExchangeError(
                "Failed to exchange authorization code with Zoom. "
                "Please verify your Zoom OAuth credentials and try again."
            )
        except Exception:
            # Rollback state marking so user can retry without re-initiating
            db.rollback()
            raise

        # --- Compute token expiry ---
        now = datetime.now(timezone.utc)
        token_expires_at = now + timedelta(
            seconds=token_data.get("expires_in", 3600)
        )

        # --- Store credentials in vault (org-scoped, encrypted) ---
        # PLATFORM-OWNED MODEL: client_id/client_secret live in the server
        # .env - the vault keeps only the end user's own tokens.
        #
        # LEGACY PRESERVATION: if the vault already holds org-owned client
        # creds, keep them - refresh tokens are bound to the client that
        # issued them, so wiping them would break future token refreshes
        # for that org.
        credentials = {
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token", ""),
            "redirect_uri": resolved_redirect_uri,
        }
        try:
            _existing = CredentialVault.get_credentials(
                db, state_row.organization_id, "zoom", "zoom_oauth"
            ) or {}
            _existing_id = (_existing.get("client_id") or "").strip()
            _existing_secret = (_existing.get("client_secret") or "").strip()
            if _existing_id and _existing_secret:
                credentials["client_id"] = _existing["client_id"]
                credentials["client_secret"] = _existing["client_secret"]
        except Exception:
            pass
        metadata = {
            "account_id": account_info.get("account_id", ""),
            "account_email": account_info.get("email", ""),
            "connected_at": now.isoformat(),
            "token_expires_at": token_expires_at.isoformat(),
            "scopes": token_data.get("scope", "meeting:write").split(),
        }

        CredentialVault.save_credentials(
            db=db,
            org_id=state_row.organization_id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials=credentials,
            metadata=metadata,
            status=IntegrationStatus.CONNECTED,
        )

        email = account_info.get("email", "")

        logger.info(
            "[ZOOM_OAUTH] OAuth flow completed successfully",
            extra={
                "org_id": str(state_row.organization_id),
                "email": email,
            },
        )

        return {
            "refresh_token": token_data.get("refresh_token", ""),
            "email": email,
            "account_id": account_info.get("account_id", ""),
            "organization_id": str(state_row.organization_id),
        }

    # ------------------------------------------------------------------
    # Step 3: Check connection status
    # ------------------------------------------------------------------

    @staticmethod
    def get_connection_status(db: Session, org_id: Any) -> dict[str, Any]:
        """Get Zoom OAuth connection status for an organization.

        Args:
            db: Database session
            org_id: Organization UUID

        Returns:
            Dict with connected status, metadata, never credentials.

        SECURITY: Never returns credentials, tokens, or secrets.
        """
        from app.services.credential_vault import CredentialVault

        org_uuid = (
            uuid.UUID(str(org_id))
            if not isinstance(org_id, uuid.UUID)
            else org_id
        )

        has_creds = CredentialVault.has_credentials(
            db, org_uuid, "zoom", "zoom_oauth"
        )
        metadata = CredentialVault.get_safe_metadata(
            db, org_uuid, "zoom", "zoom_oauth"
        ) or {}

        return {
            "provider": "zoom",
            "integration_type": "zoom_oauth",
            "connected": has_creds,
            "account_id": metadata.get("account_id") if has_creds else None,
            "account_email": metadata.get("account_email") if has_creds else None,
            "connected_at": metadata.get("connected_at") if has_creds else None,
        }

    # ------------------------------------------------------------------
    # Step 4: Disconnect
    # ------------------------------------------------------------------

    @staticmethod
    def disconnect(db: Session, org_id: Any) -> dict[str, Any]:
        """Disconnect Zoom OAuth for an organization.

        Clears credentials, metadata, and sets status to DISCONNECTED.

        Args:
            db: Database session
            org_id: Organization UUID

        Returns:
            Dict with disconnect status.
        """
        from app.services.credential_vault import CredentialVault

        org_uuid = (
            uuid.UUID(str(org_id))
            if not isinstance(org_id, uuid.UUID)
            else org_id
        )

        result = CredentialVault.disconnect(
            db, org_uuid, "zoom", "zoom_oauth"
        )

        logger.info(
            "[ZOOM_OAUTH] Zoom OAuth disconnected",
            extra={"org_id": str(org_uuid)},
        )

        return {
            "provider": "zoom",
            "integration_type": "zoom_oauth",
            "connected": False,
            "disconnected": result is not None,
        }

    # ------------------------------------------------------------------
    # Step 6: Token refresh
    # ------------------------------------------------------------------

    @staticmethod
    def refresh_token_if_needed(db: Session, org_id: Any) -> str:
        """Ensure a valid access token exists, refreshing if necessary.

        This is called before every Zoom API interaction.  It checks the
        ``token_expires_at`` metadata field and, if the token is expired
        or about to expire, uses the stored refresh token to obtain a
        new access token.  The new tokens are persisted in the vault.

        Args:
            db: Database session
            org_id: Organization UUID

        Returns:
            A valid access token string.

        Raises:
            ZoomTokenRefreshError: If refresh fails.
            ZoomOAuthError: If no credentials exist.
        """
        from app.services.credential_vault import CredentialVault
        from app.services.zoom_api_client import (
            ZoomAPIClient,
            ZoomTokenRefreshError,
            is_token_expired,
        )

        org_uuid = (
            uuid.UUID(str(org_id))
            if not isinstance(org_id, uuid.UUID)
            else org_id
        )

        # Get current credentials
        credentials = CredentialVault.get_credentials(
            db, org_uuid, "zoom", "zoom_oauth"
        )

        access_token = credentials.get("access_token", "")
        refresh_token = credentials.get("refresh_token", "")

        # Check metadata for expiry
        metadata = CredentialVault.get_safe_metadata(
            db, org_uuid, "zoom", "zoom_oauth"
        ) or {}
        expires_at_str = metadata.get("token_expires_at")
        expires_at = None
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
            except (ValueError, TypeError):
                expires_at = None

        if not is_token_expired(expires_at):
            return access_token

        # Token is expired or about to expire - a refresh token is required
        # before we even look at client credentials.
        if not refresh_token:
            raise ZoomOAuthError(
                "Zoom refresh token not available. "
                "Please reconnect Zoom OAuth.",
                error_code="zoom_no_refresh_token",
            )

        # PLATFORM-OWNED MODEL: client credentials come from the vault
        # (legacy org-owned app) when present, else from the platform
        # (server .env).  Token refresh does not need the redirect URI.
        _vault_client_id = (credentials.get("client_id") or "").strip()
        _vault_client_secret = (credentials.get("client_secret") or "").strip()
        if _vault_client_id and _vault_client_secret:
            client_id, client_secret = _vault_client_id, _vault_client_secret
        else:
            try:
                client_id, client_secret, _ = resolve_client_credentials(
                    db, org_uuid
                )
            except ZoomOAuthError as exc:
                raise ZoomOAuthError(
                    "Zoom credentials incomplete: platform Zoom OAuth app is "
                    "not configured. Please ask the platform administrator to "
                    "complete the one-time Zoom Marketplace setup.",
                    error_code="zoom_credentials_incomplete",
                ) from exc

        logger.info(
            "[ZOOM_OAUTH] Refreshing Zoom access token",
            extra={"org_id": str(org_uuid)},
        )

        try:
            token_data = ZoomAPIClient.refresh_access_token(
                refresh_token=refresh_token,
                client_id=client_id,
                client_secret=client_secret,
            )
        except ZoomTokenRefreshError as exc:
            # ── invalid_grant / permanently revoked token ─────────────
            # Mark the integration as ERROR so:
            #  • has_credentials() consumers see the error state
            #  • the dashboard shows "reconnect needed"
            #  • we don't silently retry a permanently invalid token
            #
            # We do NOT clear credentials - the client_id/client_secret
            # are still valid; only the refresh token is revoked.  The
            # user can reconnect via /auth/zoom/start without re-entering
            # client credentials.
            logger.warning(
                "[ZOOM_OAUTH] Zoom token refresh failed - "
                "marking integration as ERROR for org %s",
                str(org_uuid),
            )
            try:
                CredentialVault.mark_error(
                    db=db,
                    org_id=org_uuid,
                    provider="zoom",
                    integration_type="zoom_oauth",
                    error_message=str(exc),
                )
            except Exception:
                # Non-fatal - vault write failure shouldn't mask the
                # original Zoom error.
                logger.exception(
                    "[ZOOM_OAUTH] Failed to mark integration error for org %s",
                    str(org_uuid),
                )
            raise

        # Compute new expiry
        now = datetime.now(timezone.utc)
        new_expires_at = now + timedelta(
            seconds=token_data.get("expires_in", 3600)
        )

        # Update stored credentials - user tokens only (client creds are
        # platform-owned and live in the server .env, not the vault).
        # Preserve legacy org-owned client creds if present (token binding).
        redirect_uri = credentials.get("redirect_uri", "")
        new_credentials = {
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token", refresh_token),
            "redirect_uri": redirect_uri,
        }
        _legacy_id = (credentials.get("client_id") or "").strip()
        _legacy_secret = (credentials.get("client_secret") or "").strip()
        if _legacy_id and _legacy_secret:
            new_credentials["client_id"] = credentials["client_id"]
            new_credentials["client_secret"] = credentials["client_secret"]
        new_metadata = dict(metadata)
        new_metadata["token_expires_at"] = new_expires_at.isoformat()
        new_metadata["connected_at"] = metadata.get(
            "connected_at", now.isoformat()
        )

        CredentialVault.save_credentials(
            db=db,
            org_id=org_uuid,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials=new_credentials,
            metadata=new_metadata,
            status=IntegrationStatus.CONNECTED,
        )

        # Refresh succeeded - ensure integration is marked CONNECTED
        # (in case it was previously marked ERROR by a failed refresh).
        try:
            CredentialVault.mark_connected(
                db=db,
                org_id=org_uuid,
                provider="zoom",
                integration_type="zoom_oauth",
            )
        except Exception:
            logger.debug(
                "[ZOOM_OAUTH] Could not mark_connected for org %s",
                str(org_uuid),
            )

        logger.info(
            "[ZOOM_OAUTH] Zoom access token refreshed successfully",
            extra={"org_id": str(org_uuid)},
        )

        return token_data["access_token"]


# =====================================================================
# Internal helpers
# =====================================================================


def _validate_state(db: Session, state_token: str) -> ZoomOAuthState:
    """Validate and return a state token.

    Checks:
      1. State exists in database
      2. State has not been used
      3. State has not expired

    Returns:
        ZoomOAuthState row

    Raises:
        ZoomOAuthStateError: If any validation check fails.
    """
    stmt = select(ZoomOAuthState).where(
        ZoomOAuthState.state_token == state_token
    )
    state_row = db.execute(stmt).scalar_one_or_none()

    if state_row is None:
        raise ZoomOAuthStateError("Invalid OAuth state parameter.")

    if state_row.used:
        logger.warning(
            "[ZOOM_OAUTH] Reused OAuth state detected",
            extra={
                "org_id": str(state_row.organization_id),
                "state_id": str(state_row.id),
            },
        )
        raise ZoomOAuthStateError(
            "OAuth state has already been used. Please try connecting again."
        )

    now = datetime.now(timezone.utc)
    # SQLite strips timezone info on storage; re-attach for comparison
    expires_at = state_row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        logger.warning(
            "[ZOOM_OAUTH] Expired OAuth state",
            extra={
                "org_id": str(state_row.organization_id),
                "state_id": str(state_row.id),
                "expired_at": state_row.expires_at.isoformat(),
            },
        )
        raise ZoomOAuthStateError(
            "OAuth state has expired. Please try connecting again."
        )

    return state_row


def _purge_expired_states(db: Session, org_id: uuid.UUID) -> None:
    """Delete expired OAuth states for an org (housekeeping).

    Mirrors the Google OAuth pattern.
    """
    from sqlalchemy import delete as sa_delete

    # Use tz-naive UTC for SQLAlchemy comparison (SQLite stores naive datetimes)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    db.execute(
        sa_delete(ZoomOAuthState).where(
            ZoomOAuthState.organization_id == org_id,
            ZoomOAuthState.expires_at < now,
        )
    )
