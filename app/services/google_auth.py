"""Google OAuth2 credential loading for Calendar and Gmail services.

Supports two credential sources:
  1. Organization-specific credentials (from credential vault / org_integrations)
     — PREFERRED: Used in all environments via IntegrationConfigResolver
  2. Platform defaults (token.json file produced by scripts/authorize_google.py)
     — DEVELOPMENT ONLY: Deprecated, will emit warnings in non-dev environments

Never hardcoded, never committed. API keys are never logged.

Phase 6C: token.json is now a development-only fallback. Production
deployments MUST use the OAuth2 Web Application flow to obtain and
store credentials in the encrypted credential vault.
"""
import logging
import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

from app.config import settings

logger = logging.getLogger(__name__)

# Both Calendar event management and Gmail send.
SCOPES = [
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/gmail.send",
]


class GoogleAuthError(RuntimeError):
    """Raised when Google credentials are missing/invalid, with a clear
    instruction to re-run scripts/authorize_google.py."""


def _auth_hint() -> str:
    if settings.app_env == "production":
        return (
            "Google credentials missing or invalid. In production, use the "
            "Google OAuth2 flow: GET /auth/google/start to connect your "
            "Google account via the web application OAuth2 flow."
        )
    if settings.app_env == "test":
        return (
            "Google credentials missing or invalid. In test environment, "
            "this is expected when no mock credentials are configured."
        )
    return (
        "Google credentials missing or invalid. For development, re-run the "
        "one-time auth script:  python scripts/authorize_google.py  "
        f"(expected token file: {settings.google_token_file}). "
        "For production, use the OAuth2 flow: GET /auth/google/start"
    )


def get_google_credentials(
    client_id: str | None = None,
    client_secret: str | None = None,
    refresh_token: str | None = None,
) -> Credentials:
    """Load OAuth2 credentials, auto-refreshing if expired.

    PRIORITY ORDER:
      1. Organization-specific credentials (from IntegrationConfigResolver /
         credential vault) — used when explicit values are provided.
      2. Platform-default token.json — DEPRECATED dev-only fallback.

    When explicit credential values are provided (from the integration config
    resolver for an organization), those are used directly to construct the
    Credentials object — no token file needed.

    When no explicit credentials are provided, falls back to reading from
    the platform-default token.json file (with deprecation warnings).

    Raises GoogleAuthError with a clear remediation message if credentials
    are missing or cannot be refreshed.
    """
    # Organization-specific path: build Credentials directly from values.
    if refresh_token:
        return _build_credentials_from_values(
            client_id=client_id or settings.google_client_id,
            client_secret=client_secret or settings.google_client_secret,
            refresh_token=refresh_token,
        )

    # Platform default path: read from token file (DEPRECATED).
    return _load_credentials_from_file()


def _build_credentials_from_values(
    client_id: str,
    client_secret: str,
    refresh_token: str,
) -> Credentials:
    """Build Google OAuth2 Credentials from explicit values.

    No token file is read or written. The credentials are constructed
    in-memory and auto-refreshed on first use.
    """
    creds = Credentials(
        token=None,  # access token will be fetched on first API call
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=client_id,
        client_secret=client_secret,
        scopes=SCOPES,
    )
    # NOTE: We intentionally skip the immediate refresh here.
    # The Credentials object will auto-refresh on first API call,
    # which avoids the performance overhead of refreshing on every
    # credential instantiation. Revoked/invalid tokens will be caught
    # on the first actual API use (Calendar, Gmail, etc.).
    return creds


def _load_credentials_from_file() -> Credentials:
    """Load OAuth2 credentials from the platform token file.

    DEPRECATED: This function is for development use only. Production
    deployments MUST use the OAuth2 Web Application flow (GET /auth/google/start)
    which stores credentials in the encrypted credential vault.

    Backward-compatible with the original single-tenant approach.
    """
    # Emit deprecation warning only in production (not dev or test)
    if settings.app_env == "production":
        # In production, token.json is NOT a valid credential source.
        # Production MUST use the OAuth2 Web Application flow which stores
        # credentials in the encrypted vault (CredentialVault / OrgIntegration).
        # Falling back to token.json in production is a configuration error
        # that will lead to wrong client_id/secret pairs and 401 errors.
        raise GoogleAuthError(
            "Google credentials not found in the organization's credential vault. "
            "In production, you MUST use the OAuth2 Web Application flow to connect: "
            "click 'Connect Google' in the dashboard integrations page, or call "
            "GET /auth/google/start. The legacy token.json file is NOT used in "
            "production and must not be relied upon."
        )
    elif settings.app_env == "test":
        logger.debug(
            "[GOOGLE_AUTH] Loading credentials from token.json (test mode). "
            "Expected in test environment.",
        )
    else:
        logger.info(
            "[GOOGLE_AUTH] Loading credentials from token.json (dev mode). "
            "Consider migrating to OAuth2 Web Application flow.",
        )

    token_file = settings.google_token_file
    if not token_file or not os.path.exists(token_file):
        raise GoogleAuthError(_auth_hint())

    try:
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    except Exception as exc:  # corrupt/unreadable token file
        raise GoogleAuthError(f"{_auth_hint()}  (could not parse token file: {exc})") from exc

    if not creds.valid:
        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as exc:  # e.g. invalid_grant / revoked -> 401
                raise GoogleAuthError(f"{_auth_hint()}  (token refresh failed: {exc})") from exc
            # Persist the refreshed access token for next time.
            try:
                with open(token_file, "w", encoding="utf-8") as fh:
                    fh.write(creds.to_json())
            except OSError:
                pass  # non-fatal: creds work in-memory even if we can't persist
        else:
            raise GoogleAuthError(_auth_hint())

    return creds
