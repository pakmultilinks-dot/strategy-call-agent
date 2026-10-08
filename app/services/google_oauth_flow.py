"""Google OAuth2 Web Application flow management.

Handles the full OAuth2 authorization code flow:
  1. State generation (CSRF protection)
  2. Authorization URL construction
  3. Token exchange (authorization code → refresh token)
  4. Token storage via CredentialVault
  5. State validation and consumption

SECURITY:
  - State tokens are cryptographically random (secrets.token_urlsafe)
  - State tokens are single-use (consumed on callback)
  - State tokens expire (configurable TTL, default 10 minutes)
  - Access tokens are NEVER stored - only refresh tokens
  - All credential storage is encrypted via CredentialVault
  - Error messages are sanitized to prevent token leakage

Usage:
    from app.services.google_oauth_flow import GoogleOAuthFlow

    # Step 1: Generate state + auth URL
    state_row = await GoogleOAuthFlow.create_authorization_url(
        db=db, org_id=org_id, user_id=user_id,
    )
    # Redirect user to state_row.authorization_url

    # Step 2: Handle callback
    tokens = await GoogleOAuthFlow.exchange_code(
        db=db, code=authorization_code, state=state_token,
    )
    # tokens = {"refresh_token": "...", "email": "...", "scopes": [...]}
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models_multi_tenant import GoogleOAuthState

logger = logging.getLogger(__name__)

# Google OAuth2 endpoints
GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URI = "https://www.googleapis.com/oauth2/v3/userinfo"

# Default scopes for the integration
DEFAULT_SCOPES = [
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
]

# Maximum retries for token exchange
# (TOKEN_EXCHANGE_MAX_RETRIES removed - L3: it was defined but never used.)


def resolve_oauth_client(
    db: Session, org_id: Any
) -> tuple[str, str, str]:
    """Resolve the Google OAuth client_id/client_secret/redirect_uri to use.

    Delegates to ``IntegrationConfigResolver.resolve_google_oauth`` - the
    single source of truth - which implements the PLATFORM-OWNED MODEL
    (one-click connect):
      1. Legacy first: an org that stored its own OAuth client in the
         vault keeps using it (with its own redirect URI).  Refresh tokens
         are bound to the client that issued them, so such an org MUST
         keep its own client for token refresh.
      2. Platform credentials from server settings (.env
         GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REDIRECT_URI) -
         set ONCE by the app owner in Google Cloud Console.  Every other
         organization shares this single OAuth client; end users just
         click "Connect".

    Returns:
        (client_id, client_secret, redirect_uri)

    Raises:
        GoogleOAuthError: If no client credentials are configured.
    """
    from app.services.integration_config_resolver import (
        ConfigurationError,
        IntegrationConfigResolver,
    )

    try:
        google_cfg = IntegrationConfigResolver.resolve_google_oauth(db, org_id)
    except ConfigurationError as exc:
        raise GoogleOAuthError(
            "Google sign-in is not set up on this server yet. "
            "The platform administrator must set GOOGLE_CLIENT_ID and "
            "GOOGLE_CLIENT_SECRET (one-time setup in Google Cloud Console).",
            error_code="client_not_configured",
        ) from exc

    return google_cfg.client_id, google_cfg.client_secret, google_cfg.redirect_uri


def resolve_client_credentials(
    db: Session, org_id: Any
) -> tuple[str, str]:
    """Resolve the Google OAuth client_id/client_secret to use.

    Thin wrapper over :func:`resolve_oauth_client` for callers that only
    need the client pair (e.g. building the authorization URL).
    """
    client_id, client_secret, _ = resolve_oauth_client(db, org_id)
    return client_id, client_secret


class GoogleOAuthError(Exception):
    """Base exception for Google OAuth flow errors."""

    def __init__(self, message: str, error_code: str = "oauth_error"):
        super().__init__(message)
        self.error_code = error_code


class OAuthStateError(GoogleOAuthError):
    """Raised when OAuth state validation fails."""

    def __init__(self, message: str):
        super().__init__(message, error_code="invalid_state")


class OAuthTokenExchangeError(GoogleOAuthError):
    """Raised when token exchange with Google fails."""

    def __init__(self, message: str):
        super().__init__(message, error_code="token_exchange_failed")


class OAuthDenialError(GoogleOAuthError):
    """Raised when user denies access at Google consent screen."""

    def __init__(self):
        super().__init__(
            "Authorization was denied by the user.",
            error_code="access_denied",
        )


class GoogleOAuthFlow:
    """Manages the complete Google OAuth2 Web Application flow."""

    # -----------------------------------------------------------------------
    # Step 1: Create authorization URL
    # -----------------------------------------------------------------------

    @staticmethod
    def create_authorization_url(
        db: Session,
        org_id: Any,
        user_id: Any,
        *,
        scopes: list[str] | None = None,
    ) -> GoogleOAuthState:
        """Generate a state token and build the Google authorization URL.

        Args:
            db: Database session
            org_id: Organization UUID
            user_id: User UUID
            scopes: Optional override for OAuth scopes

        Returns:
            GoogleOAuthState row with state_token and authorization_url

        Raises:
            GoogleOAuthError: If Google client is not configured
        """
        import uuid

        # Convert string IDs to UUIDs if needed
        org_uuid = uuid.UUID(str(org_id)) if not isinstance(org_id, uuid.UUID) else org_id
        user_uuid = uuid.UUID(str(user_id)) if not isinstance(user_id, uuid.UUID) else user_id

        # PLATFORM-OWNED MODEL: one OAuth client for the whole platform
        # (set once by the app owner).  The end user just clicks Connect -
        # no console, no pasting credentials.  Legacy orgs keep their own
        # client (and its redirect URI) via the resolver.
        resolved_client_id, resolved_client_secret, redirect_uri = (
            resolve_oauth_client(db, org_uuid)
        )

        # Diagnostic logging - sanitized client config (never log secrets)
        _cid = resolved_client_id
        _cid_prefix = _cid[:12] if _cid else "(empty)"
        _cid_suffix = _cid[-8:] if len(_cid) > 20 else ""
        _has_secret = bool(resolved_client_secret)
        logger.info(
            "[OAUTH_FLOW] Creating authorization URL",
            extra={
                "org_id": str(org_uuid)[:8],
                "client_id_prefix": _cid_prefix,
                "client_id_suffix": _cid_suffix,
                "has_client_secret": _has_secret,
                "redirect_uri": redirect_uri,
            },
        )

        # Generate cryptographically random state token
        state_token = secrets.token_urlsafe(32)

        # Calculate expiry
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=settings.google_oauth_state_ttl_minutes)

        # Use configured scopes or defaults (excluding userinfo.email - internal use)
        request_scopes = scopes or DEFAULT_SCOPES

        # Persist state in database
        state_row = GoogleOAuthState(
            organization_id=org_uuid,
            user_id=user_uuid,
            state_token=state_token,
            redirect_uri=redirect_uri,
            scopes=request_scopes,
            expires_at=expires_at,
            used=False,
        )
        db.add(state_row)

        # Purge expired states for this org (housekeeping)
        _purge_expired_states(db, org_uuid)

        db.commit()
        db.refresh(state_row)

        logger.info(
            "[OAUTH_FLOW] Created authorization state",
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
        scopes: list[str] | None = None,
        client_id: str | None = None,
    ) -> str:
        """Build the Google OAuth2 authorization URL.

        Args:
            state_token: The CSRF state token
            redirect_uri: Where Google redirects after auth
            scopes: OAuth scopes to request
            client_id: Google OAuth client ID. If None, falls back to
                       settings.google_client_id for backwards compatibility.

        Returns:
            Full authorization URL string
        """
        from urllib.parse import urlencode

        resolved_client_id = client_id or settings.google_client_id
        if not resolved_client_id:
            raise GoogleOAuthError(
                "Google client_id is required to build authorization URL. "
                "Configure your Google credentials in Integrations.",
                error_code="client_not_configured",
            )

        params = {
            "client_id": resolved_client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes or DEFAULT_SCOPES),
            "access_type": "offline",  # ensures refresh_token is returned
            # select_account: always show the Google account chooser popup
            # consent: force the consent screen so a refresh_token is issued
            "prompt": "select_account consent",
            "state": state_token,
        }
        return f"{GOOGLE_AUTH_URI}?{urlencode(params)}"

    # -----------------------------------------------------------------------
    # Step 2: Exchange authorization code for tokens
    # -----------------------------------------------------------------------

    @staticmethod
    def exchange_code(
        db: Session,
        code: str,
        state: str,
    ) -> dict[str, Any]:
        """Validate state and exchange authorization code for tokens.

        Args:
            db: Database session
            code: Authorization code from Google callback
            state: State token from Google callback

        Returns:
            Dict with refresh_token, email, scopes

        Raises:
            OAuthStateError: If state is invalid, expired, or reused
            OAuthTokenExchangeError: If token exchange fails
            OAuthDenialError: If user denied access
        """
        # --- Validate state ---
        state_row = _validate_state(db, state)

        # Mark state as used (single-use)
        state_row.used = True
        db.commit()

        # --- Resolve Google client credentials (platform-owned) ---
        try:
            resolved_client_id, resolved_client_secret, _ = resolve_oauth_client(
                db, state_row.organization_id
            )
        except GoogleOAuthError as exc:
            db.rollback()
            raise OAuthTokenExchangeError(
                "Google sign-in is not set up on this server yet. "
                "The platform administrator must configure the Google "
                "OAuth client (one-time setup)."
            ) from exc

        # --- Exchange code for tokens ---
        token_data = _do_token_exchange(
            code,
            state_row.redirect_uri,
            client_id=resolved_client_id,
            client_secret=resolved_client_secret,
        )

        # --- Fetch user email ---
        email = _fetch_user_email(token_data["access_token"])

        # --- Store credentials in vault (user tokens only) ---
        _store_credentials(
            db=db,
            org_id=state_row.organization_id,
            refresh_token=token_data["refresh_token"],
            scopes=state_row.scopes,
            email=email,
        )

        logger.info(
            "[OAUTH_FLOW] OAuth flow completed successfully",
            extra={
                "org_id": str(state_row.organization_id),
                "email": email,
            },
        )

        return {
            "refresh_token": token_data["refresh_token"],
            "email": email,
            "scopes": state_row.scopes or DEFAULT_SCOPES,
            "organization_id": str(state_row.organization_id),
        }

    # -----------------------------------------------------------------------
    # Step 3: Check connection status
    # -----------------------------------------------------------------------

    @staticmethod
    def get_connection_status(db: Session, org_id: Any) -> dict[str, Any]:
        """Get Google OAuth connection status for an organization.

        Args:
            db: Database session
            org_id: Organization UUID

        Returns:
            Dict with connected status, metadata, never credentials

        Connected semantics:
            An integration is reported as connected ONLY when:
            1. The credential vault row exists with encrypted credentials.
            2. The stored status is not DISCONNECTED.
            3. The decrypted credentials contain a non-empty refresh_token.

            This prevents a false "connected" status when the DB status
            column says connected but the refresh token is missing or
            empty (e.g. after a partial OAuth callback or data corruption).
        """
        import uuid

        from app.services.credential_vault import (
            CredentialCorruptError,
            CredentialNotFoundError,
            CredentialVault,
        )

        org_uuid = uuid.UUID(str(org_id)) if not isinstance(org_id, uuid.UUID) else org_id

        has_creds = CredentialVault.has_credentials(
            db, org_uuid, "google", "google_oauth"
        )
        metadata = CredentialVault.get_safe_metadata(
            db, org_uuid, "google", "google_oauth"
        ) or {}

        # FIX A: Validate that the refresh_token is actually present and
        # non-empty.  The DB status column alone is insufficient - a row
        # can be marked "connected" with an empty or missing refresh_token
        # after a partial OAuth callback, manual DB edit, or data migration.
        connected = has_creds
        if has_creds:
            try:
                creds = CredentialVault.get_credentials(
                    db, org_uuid, "google", "google_oauth"
                )
                if not creds.get("refresh_token"):
                    connected = False
                    logger.warning(
                        "[OAUTH_FLOW] Integration marked connected but "
                        "refresh_token is missing or empty - reporting "
                        "disconnected",
                        extra={"org_id": str(org_uuid)},
                    )
            except (CredentialNotFoundError, CredentialCorruptError):
                connected = False

        return {
            "provider": "google",
            "integration_type": "google_oauth",
            "connected": connected,
            "scopes": metadata.get("scopes", []) if connected else [],
            "connected_at": metadata.get("connected_at") if connected else None,
            "email": metadata.get("email") if connected else None,
        }

    # -----------------------------------------------------------------------
    # Step 4: Disconnect
    # -----------------------------------------------------------------------

    @staticmethod
    def disconnect(db: Session, org_id: Any) -> dict[str, Any]:
        """Disconnect Google OAuth for an organization.

        Clears credentials, metadata, and sets status to DISCONNECTED.

        Args:
            db: Database session
            org_id: Organization UUID

        Returns:
            Dict with disconnect status
        """
        import uuid

        from app.services.credential_vault import CredentialVault

        org_uuid = uuid.UUID(str(org_id)) if not isinstance(org_id, uuid.UUID) else org_id

        # Clear credentials
        result = CredentialVault.disconnect(
            db, org_uuid, "google", "google_oauth"
        )

        # Also clear email config since it was auto-configured during OAuth flow
        CredentialVault.disconnect(
            db, org_uuid, "google", "email"
        )

        logger.info(
            "[OAUTH_FLOW] Google OAuth disconnected",
            extra={"org_id": str(org_uuid)},
        )

        return {
            "provider": "google",
            "integration_type": "google_oauth",
            "connected": False,
            "disconnected": result is not None,
        }


# ======================================================================
# Internal helpers
# ======================================================================


def _resolve_redirect_uri(db: Session, org_id: Any) -> str | None:
    """Resolve the redirect_uri for an organization.

    Checks the org's google_oauth vault for a stored redirect_uri.
    Looks in both the credentials blob and metadata, since:
    - Dashboard CRUD saves redirect_uri in credentials
    - _store_credentials() saves redirect_uri in credentials
    - Older entries may have it in metadata only

    Returns None if not found (caller falls back to
    settings.google_redirect_uri).
    """
    import uuid

    from app.services.credential_vault import (
        CredentialCorruptError,
        CredentialNotFoundError,
        CredentialVault,
    )

    org_uuid = uuid.UUID(str(org_id)) if not isinstance(org_id, uuid.UUID) else org_id
    try:
        creds = CredentialVault.get_credentials(
            db, org_uuid, "google", "google_oauth"
        )
        redirect_uri = creds.get("redirect_uri", "")
        if redirect_uri:
            return redirect_uri
        # Also check metadata (older entries or alternate storage patterns)
        metadata = CredentialVault.get_safe_metadata(
            db, org_uuid, "google", "google_oauth"
        ) or {}
        redirect_uri = metadata.get("redirect_uri", "")
        if redirect_uri:
            return redirect_uri
    except (CredentialNotFoundError, CredentialCorruptError):
        pass
    except Exception as exc:
        logger.warning(
            "failed to read Google redirect_uri from vault: %s", exc
        )
    return None


def _validate_state(db: Session, state_token: str) -> GoogleOAuthState:
    """Validate and return a state token.

    Checks:
      1. State exists in database
      2. State has not been used
      3. State has not expired

    Returns:
        GoogleOAuthState row

    Raises:
        OAuthStateError: If any validation check fails
    """
    stmt = select(GoogleOAuthState).where(
        GoogleOAuthState.state_token == state_token
    )
    state_row = db.execute(stmt).scalar_one_or_none()

    if state_row is None:
        raise OAuthStateError("Invalid OAuth state parameter.")

    if state_row.used:
        logger.warning(
            "[OAUTH_FLOW] Reused OAuth state detected",
            extra={
                "org_id": str(state_row.organization_id),
                "state_id": str(state_row.id),
            },
        )
        raise OAuthStateError(
            "OAuth state has already been used. Please try connecting again."
        )

    now = datetime.now(timezone.utc)
    # SQLite strips timezone info on storage; re-attach for comparison
    expires_at = state_row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        logger.warning(
            "[OAUTH_FLOW] Expired OAuth state",
            extra={
                "org_id": str(state_row.organization_id),
                "state_id": str(state_row.id),
                "expired_at": state_row.expires_at.isoformat(),
            },
        )
        raise OAuthStateError(
            "OAuth state has expired. Please try connecting again."
        )

    return state_row


def _do_token_exchange(
    code: str,
    redirect_uri: str,
    *,
    client_id: str | None = None,
    client_secret: str | None = None,
) -> dict[str, str]:
    """Exchange authorization code for tokens with Google.

    Args:
        code: Authorization code
        redirect_uri: Must match the redirect URI used in the auth request
        client_id: Google OAuth client ID. If None, falls back to settings.
        client_secret: Google OAuth client secret. If None, falls back to settings.

    Returns:
        Dict with access_token, refresh_token, token_type, expiry

    Raises:
        OAuthTokenExchangeError: If the exchange fails
        OAuthDenialError: If user denied access
    """
    resolved_client_id = client_id or settings.google_client_id
    resolved_client_secret = client_secret or settings.google_client_secret

    if not resolved_client_id or not resolved_client_secret:
        raise OAuthTokenExchangeError(
            "Google credentials not configured. "
            "The platform administrator must complete the one-time "
            "Google Cloud Console setup."
        )

    # Diagnostic logging - sanitized (never log the full secret)
    _cid_prefix = resolved_client_id[:12] if resolved_client_id else "(empty)"
    _cid_suffix = resolved_client_id[-8:] if len(resolved_client_id) > 20 else ""
    _has_secret = bool(resolved_client_secret)
    logger.info(
        "[OAUTH_FLOW] Token exchange request",
        extra={
            "client_id_prefix": _cid_prefix,
            "client_id_suffix": _cid_suffix,
            "has_client_secret": _has_secret,
            "redirect_uri": redirect_uri,
        },
    )

    payload = {
        "code": code,
        "client_id": resolved_client_id,
        "client_secret": resolved_client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    try:
        response = httpx.post(
            GOOGLE_TOKEN_URI,
            data=payload,
            timeout=30.0,
        )
    except httpx.RequestError as exc:
        raise OAuthTokenExchangeError(
            "Failed to connect to Google's token endpoint. "
            "Please try again later."
        ) from exc

    if response.status_code != 200:
        error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        error_msg = error_data.get("error_description", error_data.get("error", "Unknown error"))
        error_code = error_data.get("error", "")

        # Log the raw error for debugging (server-side only) with client_id prefix
        logger.error(
            "[OAUTH_FLOW] Token exchange failed",
            extra={
                "status_code": response.status_code,
                "error": error_msg,
                "error_code": error_code,
                "client_id_prefix": _cid_prefix,
                "client_id_suffix": _cid_suffix,
                "has_client_secret": _has_secret,
            },
        )

        # Map known error codes to user-friendly messages.
        combined = f"{error_msg} {error_code}".lower()

        if "access_denied" in combined or "denied" in combined:
            raise OAuthDenialError()
        if "invalid_grant" in combined:
            raise OAuthTokenExchangeError(
                "The authorization code is invalid or has expired. "
                "Please try connecting again."
            )
        if "invalid_client" in combined:
            # 401 + invalid_client = mismatched client_id / client_secret pair.
            # This is the exact symptom of using the wrong GOOGLE_CLIENT_SECRET.
            logger.critical(
                "[OAUTH_FLOW] invalid_client - Client ID and Client Secret "
                "are not a matching pair.",
                extra={
                    "client_id_prefix": _cid_prefix,
                    "client_id_suffix": _cid_suffix,
                },
            )
            raise OAuthTokenExchangeError(
                "Google rejected the saved OAuth credentials (invalid_client). "
                "Please verify that the Client ID and Client Secret belong to "
                "the same Web Application OAuth client in Google Cloud Console."
            )

        raise OAuthTokenExchangeError(
            "Failed to exchange authorization code for tokens. "
            "Please try connecting again."
        )

    token_data = response.json()

    if "refresh_token" not in token_data:
        raise OAuthTokenExchangeError(
            "Google did not return a refresh token. "
            "Please ensure you granted offline access and try again."
        )

    return {
        "access_token": token_data["access_token"],
        "refresh_token": token_data["refresh_token"],
        "token_type": token_data.get("token_type", "Bearer"),
        "expiry": token_data.get("expires_in"),
    }


def _fetch_user_email(access_token: str) -> str:
    """Fetch the authenticated user's email from Google.

    Args:
        access_token: Valid access token

    Returns:
        User's email address

    Raises:
        OAuthTokenExchangeError: If email fetch fails
    """
    try:
        response = httpx.get(
            GOOGLE_USERINFO_URI,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15.0,
        )
    except httpx.RequestError as exc:
        raise OAuthTokenExchangeError(
            "Failed to fetch user information from Google."
        ) from exc

    if response.status_code != 200:
        logger.warning(
            "[OAUTH_FLOW] Failed to fetch user email",
            extra={"status_code": response.status_code},
        )
        raise OAuthTokenExchangeError(
            "Failed to fetch user email from Google."
        )

    userinfo = response.json()
    email = userinfo.get("email")
    if not email:
        raise OAuthTokenExchangeError(
            "Google did not return an email address."
        )

    return email


def _store_credentials(
    db: Session,
    org_id: Any,
    refresh_token: str,
    scopes: list[str] | None,
    email: str,
) -> None:
    """Store Google OAuth user credentials in the encrypted vault.

    PLATFORM-OWNED MODEL: only the end user's refresh_token is stored
    per-org.  The OAuth client_id/client_secret belong to the platform
    (server .env) and are never duplicated into the vault.

    Args:
        db: Database session
        org_id: Organization UUID
        refresh_token: Google refresh token
        scopes: Granted OAuth scopes
        email: Authenticated user's email
    """
    from app.services.credential_vault import CredentialVault

    # PLATFORM-OWNED MODEL: client_id/client_secret live in the server
    # .env - they are NOT stored per-org anymore.  The vault keeps only
    # the end user's own tokens (refresh_token) plus metadata.
    #
    # LEGACY PRESERVATION: if the vault already holds org-owned client
    # creds, keep them - refresh tokens are bound to the client that
    # issued them, so wiping them would break future token refreshes
    # for that org.
    # Resolve redirect_uri: platform setting first, then legacy vault value.
    redirect_uri = (settings.google_redirect_uri or "").strip() or _resolve_redirect_uri(
        db, org_id
    )

    credentials = {
        "refresh_token": refresh_token,
        "redirect_uri": redirect_uri,
    }
    try:
        existing = CredentialVault.get_credentials(
            db, org_id, "google", "google_oauth"
        ) or {}
        _existing_id = (existing.get("client_id") or "").strip()
        _existing_secret = (existing.get("client_secret") or "").strip()
        if _existing_id and _existing_secret:
            credentials["client_id"] = existing["client_id"]
            credentials["client_secret"] = existing["client_secret"]
    except Exception:
        pass
    metadata = {
        "scopes": scopes or DEFAULT_SCOPES,
        "provider": "google",
        "email": email,
        "connected_at": datetime.now(timezone.utc).isoformat(),
    }

    CredentialVault.save_credentials(
        db=db,
        org_id=org_id,
        provider="google",
        integration_type="google_oauth",
        credentials=credentials,
        metadata=metadata,
    )

    # Also store email config for Gmail integration
    # Phase 6D: Use the organization's actual name instead of hardcoded branding.
    from app.models_multi_tenant import Organization
    from app.services.credential_vault import CredentialVault as CV
    org = db.query(Organization).filter(Organization.id == org_id).first()
    org_name = org.name if org else "Strategy Call Agent"

    email_credentials = {"sender_email": email}
    email_metadata = {
        "sender_name": org_name,
        "company_name": org_name,
        "auto_configured": True,
        "auto_configured_at": datetime.now(timezone.utc).isoformat(),
    }

    CV.save_credentials(
        db=db,
        org_id=org_id,
        provider="google",
        integration_type="email",
        credentials=email_credentials,
        metadata=email_metadata,
    )


def _purge_expired_states(db: Session, org_id: Any) -> int:
    """Remove expired or used OAuth states for an organization.

    Args:
        db: Database session
        org_id: Organization UUID

    Returns:
        Number of states purged
    """
    # Use tz-aware UTC so the in-memory comparison (synchronize_session='evaluate')
    # works correctly with both aware and naive expires_at values stored in the
    # session identity map.  SQLite stores naive datetimes but handles string
    # comparison correctly regardless.
    now = datetime.now(timezone.utc)
    stmt = delete(GoogleOAuthState).where(
        GoogleOAuthState.organization_id == org_id,
        (GoogleOAuthState.expires_at < now) | (GoogleOAuthState.used == True),
    )
    result = db.execute(stmt)
    count = result.rowcount
    if count > 0:
        logger.info(
            "[OAUTH_FLOW] Purged expired OAuth states",
            extra={"org_id": str(org_id), "count": count},
        )
    return count
