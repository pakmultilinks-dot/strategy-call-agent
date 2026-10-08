"""Integration Configuration Resolver - credential resolution for services.

Resolves external service credentials for a specific organization with
the following precedence:

    1. Organization-specific credential (from credential vault / org_integrations)
    2. Platform default credential (from .env / settings)
    3. Clear configuration error

This module is the single source of truth for "what credentials should
service X use for organization Y?".

DESIGN:
  - All methods are stateless classmethods
  - Never exposes raw credentials in return types (only dataclass fields)
  - Never logs credential values
  - Falls back gracefully to platform defaults
  - Returns descriptive errors when nothing is configured

SECURITY:
  - This resolver never logs API keys, OAuth tokens, or other secrets
  - Return values are used only within the service layer
  - API responses must NOT expose these values
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.config import settings
from app.services.credential_vault import (
    CredentialCorruptError,
    CredentialNotFoundError,
    CredentialVault,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Resolved configuration dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GoogleOAuthConfig:
    """Resolved Google OAuth2 credentials for an organization.

    Used by CalendarService and EmailService to build Google API
    credentials without depending on a token.json file.

    redirect_uri is the OAuth callback URL for the client in use:
    the legacy org-specific URI when the org brought its own client,
    otherwise the platform redirect URI.
    """
    client_id: str
    client_secret: str
    refresh_token: str
    redirect_uri: str = ""


@dataclass(frozen=True)
class GoogleCalendarConfig:
    """Resolved Google Calendar configuration."""
    calendar_id: str


@dataclass(frozen=True)
class GmailConfig:
    """Resolved Gmail sender configuration."""
    sender_email: str


@dataclass(frozen=True)
class AIProviderConfig:
    """Resolved AI provider configuration for one provider (primary or fallback)."""
    api_key: str
    base_url: str
    model: str
    provider_id: str = "openai"


@dataclass(frozen=True)
class AIConfig:
    """Resolved AI configuration - primary + optional fallback provider.

    The primary config is always present (may come from platform defaults).
    The fallback is only populated when all three fields (key, url, model)
    are configured.
    """
    primary: AIProviderConfig
    fallback: AIProviderConfig | None = None


@dataclass(frozen=True)
class BrandingConfig:
    """Resolved organization branding for emails, calendar events, and AI.

    All fields have safe defaults so callers never need to handle None.
    When an organization has not configured branding, defaults are derived
    from the platform settings.
    """
    company_name: str = "Strategy Call Agent"
    sender_name: str = "Strategy Call Agent"
    brand_color: str = "#1a73e8"
    tagline: str = ""


@dataclass(frozen=True)
class MeetingConfig:
    """Resolved meeting configuration for an organization."""
    duration_minutes: int = 30


@dataclass(frozen=True)
class ZoomOAuthConfig:
    """Resolved Zoom OAuth2 credentials for an organization.

    Used by ZoomMeetingService to authenticate with the Zoom API.
    client_id and client_secret are always required.
    redirect_uri is organization-specific (each org configures their own).
    account_id is optional - populated after OAuth callback from Zoom API.
    """
    account_id: str
    client_id: str
    client_secret: str
    redirect_uri: str = ""


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


class ConfigurationError(RuntimeError):
    """Raised when an organization's integration credentials are missing or
    incomplete in the credential vault.

    In production, services MUST use vault-stored credentials. This error
    replaces the previous silent .env fallback which masked missing
    org-level configuration.
    """


class IntegrationConfigResolver:
    """Resolves integration credentials for a specific organization.

    Every method follows the same pattern:
      1. Try to load org-specific credentials from the credential vault
      2. If found and valid, return them
      3. Otherwise, fall back to platform defaults from settings/.env
      4. If nothing is configured at all, raise a clear error

    All methods are classmethods - no instance state, no database
    connections held. Each call opens a vault lookup via the provided db
    session.
    """

    # ─── Google OAuth ────────────────────────────────────────────────

    @staticmethod
    def resolve_google_oauth(
        db: Session, org_id: uuid.UUID
    ) -> GoogleOAuthConfig:
        """Resolve Google OAuth2 tokens for an organization.

        PLATFORM-OWNED MODEL (one-click connect):
          - client_id / client_secret come from the PLATFORM (server
            .env: GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET), set once by
            the app owner.  Every org shares this single OAuth client.
          - refresh_token comes from the ORG's vault row - each org's own
            user token, obtained when the org owner clicks "Connect".
          - Legacy: orgs that stored their own client_id/client_secret in
            the vault keep working (vault values win for those orgs).

        Raises ConfigurationError when no usable client credentials exist.
        """
        # 1. Legacy org-owned client credentials in the vault win if present
        #    (backward compatibility for orgs configured before the platform
        #    model).  Otherwise fall through to the platform client.
        legacy_client_id = ""
        legacy_client_secret = ""
        legacy_redirect_uri = ""
        try:
            creds = CredentialVault.get_credentials(
                db, org_id, "google", "google_oauth"
            )
            if creds:
                legacy_client_id = (creds.get("client_id") or "").strip()
                legacy_client_secret = (creds.get("client_secret") or "").strip()
                refresh_token = (creds.get("refresh_token") or "").strip()
                if legacy_client_id or legacy_client_secret:
                    if not (legacy_client_id and legacy_client_secret):
                        # Partial legacy record: do NOT silently fall through
                        # to the platform client - the org's existing tokens
                        # (if any) are bound to this client.
                        raise ConfigurationError(
                            f"Google OAuth credentials for organization "
                            f"{str(org_id)[:8]}… are incomplete in the vault "
                            f"(client_id={'set' if legacy_client_id else 'missing'}, "
                            f"client_secret={'set' if legacy_client_secret else 'missing'}). "
                            f"Please remove the partial record or complete it."
                        )
                    # Legacy org-owned client: its redirect URI is the one
                    # registered in the org's own Google Cloud Console.
                    legacy_redirect_uri = (creds.get("redirect_uri") or "").strip()
                    if not legacy_redirect_uri:
                        try:
                            meta = CredentialVault.get_safe_metadata(
                                db, org_id, "google", "google_oauth"
                            ) or {}
                            legacy_redirect_uri = (
                                meta.get("redirect_uri") or ""
                            ).strip()
                        except Exception:
                            pass
                    logger.debug(
                        "resolved Google OAuth from legacy org vault client "
                        "for org=%s (has_refresh_token=%s)",
                        str(org_id)[:8],
                        bool(refresh_token),
                    )
                    return GoogleOAuthConfig(
                        client_id=legacy_client_id,
                        client_secret=legacy_client_secret,
                        refresh_token=refresh_token,
                        redirect_uri=legacy_redirect_uri
                        or (settings.google_redirect_uri or "").strip(),
                    )
        except ConfigurationError:
            raise
        except (CredentialNotFoundError, CredentialCorruptError):
            pass
        except Exception as exc:
            logger.warning(
                "failed to read org Google OAuth from vault: %s", exc
            )

        # 2. Platform-owned client credentials (the normal path now).
        platform_id = (settings.google_client_id or "").strip()
        platform_secret = (settings.google_client_secret or "").strip()
        if not platform_id or not platform_secret:
            raise ConfigurationError(
                "Google sign-in is not set up on this server. The platform "
                "administrator must set GOOGLE_CLIENT_ID and "
                "GOOGLE_CLIENT_SECRET (one-time Google Cloud Console setup)."
            )

        # 3. The org's own user token (empty until the org clicks Connect).
        refresh_token = ""
        try:
            creds = CredentialVault.get_credentials(
                db, org_id, "google", "google_oauth"
            )
            if creds:
                refresh_token = (creds.get("refresh_token") or "").strip()
        except (CredentialNotFoundError, CredentialCorruptError):
            pass
        except Exception as exc:
            logger.warning(
                "failed to read org Google refresh token from vault: %s", exc
            )

        return GoogleOAuthConfig(
            client_id=platform_id,
            client_secret=platform_secret,
            refresh_token=refresh_token,
            redirect_uri=(settings.google_redirect_uri or "").strip(),
        )

    # ─── Google Calendar ────────────────────────────────────────────

    @staticmethod
    def resolve_calendar_config(
        db: Session, org_id: uuid.UUID
    ) -> GoogleCalendarConfig:
        """Resolve calendar_id for an organization.

        Checks org-specific calendar config in vault first,
        then falls back to platform default (settings.calendar_id).
        """
        try:
            creds = CredentialVault.get_credentials(
                db, org_id, "google", "calendar"
            )
            cal_id = creds.get("calendar_id", "")
            if cal_id:
                logger.debug(
                    "resolved calendar config from org vault for org=%s",
                    str(org_id)[:8],
                )
                return GoogleCalendarConfig(calendar_id=cal_id)
        except (CredentialNotFoundError, CredentialCorruptError):
            pass
        except Exception as exc:
            logger.warning(
                "failed to read org calendar config from vault: %s", exc
            )

        return GoogleCalendarConfig(
            calendar_id=settings.calendar_id or "primary"
        )

    # ─── Gmail ──────────────────────────────────────────────────────

    @staticmethod
    def resolve_gmail_config(
        db: Session, org_id: uuid.UUID
    ) -> GmailConfig:
        """Resolve Gmail sender email for an organization."""
        try:
            creds = CredentialVault.get_credentials(
                db, org_id, "google", "email"
            )
            sender = creds.get("sender_email", "")
            if sender:
                logger.debug(
                    "resolved Gmail config from org vault for org=%s",
                    str(org_id)[:8],
                )
                return GmailConfig(sender_email=sender)
        except (CredentialNotFoundError, CredentialCorruptError):
            pass
        except Exception as exc:
            logger.warning(
                "failed to read org Gmail config from vault: %s", exc
            )

        return GmailConfig(sender_email=settings.gmail_sender)

    # ─── AI Provider ────────────────────────────────────────────────

    @staticmethod
    def resolve_ai_config(
        db: Session, org_id: uuid.UUID
    ) -> AIConfig:
        """Resolve AI provider configuration for an organization.

        Org-specific API key/model/base_url take precedence over platform
        defaults. The fallback provider always comes from platform defaults
        (customers are not expected to configure a separate fallback).

        Raises RuntimeError if neither org nor platform has a valid
        primary AI configuration.
        """
        # 1. Try org-specific AI credentials
        primary = IntegrationConfigResolver._resolve_ai_primary(db, org_id)
        if primary is not None:
            # Org has its own AI config - use platform fallback
            fallback = IntegrationConfigResolver._get_platform_fallback()
            return AIConfig(primary=primary, fallback=fallback)

        # 2. Fall back to platform defaults
        platform_primary = IntegrationConfigResolver._get_platform_primary()
        if platform_primary is not None:
            fallback = IntegrationConfigResolver._get_platform_fallback()
            return AIConfig(primary=platform_primary, fallback=fallback)

        # 3. Nothing configured
        raise RuntimeError(
            "AI provider not configured: no organization-specific or "
            "platform AI credentials found. Set AI_BASE_URL, AI_API_KEY, "
            "and AI_MODEL in .env, or configure via the organization API."
        )

    @staticmethod
    def _resolve_ai_primary(
        db: Session, org_id: uuid.UUID
    ) -> AIProviderConfig | None:
        """Try to load org-specific AI primary provider from vault.

        Reads credentials from the vault key ("openai", "ai_provider").
        Supports both new-style (metadata has provider_id) and old-style
        (no provider_id = legacy OpenAI) configurations.
        """
        try:
            creds = CredentialVault.get_credentials(
                db, org_id, "openai", "ai_provider"
            )
            meta = CredentialVault.get_safe_metadata(
                db, org_id, "openai", "ai_provider"
            ) or {}

            api_key = creds.get("api_key", "")
            if api_key:
                # New-style: provider_id stored in metadata
                # Old-style: no provider_id means legacy "openai"
                provider_id = meta.get("provider_id", "openai")
                return AIProviderConfig(
                    api_key=api_key,
                    base_url=creds.get("base_url", settings.ai_base_url),
                    model=meta.get("model", settings.ai_model),
                    provider_id=provider_id,
                )
        except (CredentialNotFoundError, CredentialCorruptError):
            pass
        except Exception as exc:
            logger.warning(
                "failed to read org AI credentials from vault: %s", exc
            )
        return None

    @staticmethod
    def _get_platform_primary() -> AIProviderConfig | None:
        """Return the platform default AI primary provider, or None."""
        if settings.ai_api_key and settings.ai_base_url and settings.ai_model:
            return AIProviderConfig(
                api_key=settings.ai_api_key,
                base_url=settings.ai_base_url,
                model=settings.ai_model,
            )
        return None

    @staticmethod
    def _get_platform_fallback() -> AIProviderConfig | None:
        """Return the platform default AI fallback provider, or None."""
        if (
            settings.ai_fallback_api_key
            and settings.ai_fallback_base_url
            and settings.ai_fallback_model
        ):
            return AIProviderConfig(
                api_key=settings.ai_fallback_api_key,
                base_url=settings.ai_fallback_base_url,
                model=settings.ai_fallback_model,
            )
        return None

    # ─── Timezone ───────────────────────────────────────────────────

    @staticmethod
    def resolve_timezone(
        db: Session, org_id: uuid.UUID
    ) -> str:
        """Resolve the business timezone for an organization.

        Checks the Organization model first, falls back to the platform
        default from settings.
        """
        from app.models_multi_tenant import Organization

        org = db.query(Organization).filter(Organization.id == org_id).first()
        if org and org.timezone:
            return org.timezone
        return settings.business_timezone

    # ─── Branding ───────────────────────────────────────────────────

    @staticmethod
    def resolve_branding(
        db: Session, org_id: uuid.UUID
    ) -> BrandingConfig:
        """Resolve organization branding for emails, calendar, and AI.

        Checks the Organization model fields (sender_name, brand_color,
        tagline) and falls back to platform defaults when not set.

        The company_name is taken from Organization.name - every org
        always has a name, so no fallback is needed for that field.
        """
        from app.models_multi_tenant import Organization

        org = db.query(Organization).filter(Organization.id == org_id).first()
        if org is None:
            return BrandingConfig()

        return BrandingConfig(
            company_name=org.name or "Strategy Call Agent",
            sender_name=org.sender_name or org.name or "Strategy Call Agent",
            brand_color=org.brand_color or "#1a73e8",
            tagline=org.tagline or "",
        )

    # ─── Meeting Duration ───────────────────────────────────────────

    @staticmethod
    def resolve_meeting_config(
        db: Session, org_id: uuid.UUID
    ) -> MeetingConfig:
        """Resolve meeting duration for an organization.

        Checks OrgScheduleConfig.meeting_duration_minutes first,
        falls back to the platform default (30 minutes).
        """
        from app.models_multi_tenant import OrgScheduleConfig

        cfg = db.query(OrgScheduleConfig).filter(
            OrgScheduleConfig.organization_id == org_id
        ).first()
        if cfg and cfg.meeting_duration_minutes is not None:
            return MeetingConfig(duration_minutes=cfg.meeting_duration_minutes)
        return MeetingConfig()

    # ─── Zoom OAuth ────────────────────────────────────────────────

    @staticmethod
    def resolve_zoom_config(
        db: Session, org_id: uuid.UUID
    ) -> ZoomOAuthConfig:
        """Resolve Zoom OAuth2 credentials for an organization.

        PLATFORM-OWNED MODEL (one-click connect):
          - client_id / client_secret / redirect_uri come from the PLATFORM
            (server .env: ZOOM_CLIENT_ID / ZOOM_CLIENT_SECRET /
            ZOOM_REDIRECT_URI), set once by the app owner in the Zoom
            Marketplace.  Every org shares this single OAuth app.
          - account_id comes from the org's vault metadata after connect.
          - Legacy: orgs that stored their own Zoom app credentials in the
            vault keep working (vault values win for those orgs).

        Raises CredentialNotFoundError if no usable credentials exist.
        """
        # 1. Legacy org-owned Zoom app in the vault wins if present
        #    (backward compatibility).
        try:
            creds = CredentialVault.get_credentials(
                db, org_id, "zoom", "zoom_oauth"
            )
            client_id = (creds.get("client_id") or "").strip()
            client_secret = (creds.get("client_secret") or "").strip()
            redirect_uri = (creds.get("redirect_uri") or "").strip()
            if client_id and client_secret and redirect_uri:
                meta = CredentialVault.get_safe_metadata(
                    db, org_id, "zoom", "zoom_oauth"
                ) or {}
                logger.debug(
                    "resolved Zoom OAuth from legacy org vault app for org=%s",
                    str(org_id)[:8],
                )
                # account_id may live in the credentials dict (legacy) or in
                # safe metadata (new saves); check both.
                account_id = (creds.get("account_id") or "").strip() or meta.get(
                    "account_id", ""
                )
                return ZoomOAuthConfig(
                    account_id=account_id,
                    client_id=client_id,
                    client_secret=client_secret,
                    redirect_uri=redirect_uri,
                )
        except (CredentialNotFoundError, CredentialCorruptError):
            pass
        except Exception as exc:
            logger.warning(
                "failed to read org Zoom OAuth from vault: %s", exc
            )

        # 2. Platform-owned Zoom app (the normal path now).
        platform_client_id = (settings.zoom_client_id or "").strip()
        platform_client_secret = (settings.zoom_client_secret or "").strip()
        platform_redirect_uri = (settings.zoom_redirect_uri or "").strip()

        if platform_client_id and platform_client_secret and platform_redirect_uri:
            meta: dict = {}
            creds_account_id = ""
            try:
                meta = CredentialVault.get_safe_metadata(
                    db, org_id, "zoom", "zoom_oauth"
                ) or {}
                # account_id may be in the credentials dict (from OAuth flow)
                # or in metadata; check both.
                try:
                    _creds = CredentialVault.get_credentials(
                        db, org_id, "zoom", "zoom_oauth"
                    )
                    creds_account_id = (_creds.get("account_id") or "").strip()
                except Exception:
                    pass
            except Exception:
                pass
            logger.debug(
                "resolved Zoom OAuth from platform app for org=%s",
                str(org_id)[:8],
            )
            return ZoomOAuthConfig(
                account_id=creds_account_id or meta.get("account_id", ""),
                client_id=platform_client_id,
                client_secret=platform_client_secret,
                redirect_uri=platform_redirect_uri,
            )

        # 3. Nothing configured at all
        raise CredentialNotFoundError(
            "Zoom connect is not set up on this server: no platform Zoom "
            "app configured. The platform administrator must set "
            "ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET and ZOOM_REDIRECT_URI "
            "(one-time Zoom Marketplace setup)."
        )
