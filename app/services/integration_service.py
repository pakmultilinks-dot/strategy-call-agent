"""Integration Service — business logic for managing organization integrations.

Layer between the dashboard API endpoints and the CredentialVault.
Adds:
  - RBAC enforcement (owner/admin can manage, member can read only)
  - Structured audit logging for every integration mutation
  - Secret-safe API response formatting
  - Input validation against known provider schemas

SECURITY:
  - Never returns decrypted credentials through normal API responses
  - Never logs decrypted credentials
  - All operations require organization context
  - Role-based access control enforced server-side
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.models_multi_tenant import IntegrationStatus, OrgIntegration
from app.services.credential_vault import (
    CredentialCorruptError,
    CredentialNotFoundError,
    CredentialVault,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known integration types and their expected credential fields
# ---------------------------------------------------------------------------

# Integration types that represent OAuth *app configuration* (Client ID, Secret,
# Redirect URI) — NOT OAuth authentication.  Saving credentials for these types
# means the admin has configured the OAuth app but no user has completed the
# OAuth flow yet.  Status stays PENDING until a successful token exchange.
_OAUTH_CONFIG_TYPES: set[tuple[str, str]] = {
    ("zoom", "zoom_oauth"),
    ("google", "google_oauth"),
}


KNOWN_PROVIDERS: dict[str, dict[str, dict[str, Any]]] = {
    "google": {
        "google_oauth": {
            # NOTE: refresh_token is NOT required at configuration time — it is
            # only obtained AFTER a successful OAuth callback.  The Dashboard
            # saves client_id + client_secret + redirect_uri; the refresh_token
            # is added later by _store_credentials() in google_oauth_flow.py.
            "required_fields": {"client_id", "client_secret"},
            "optional_fields": {"redirect_uri", "refresh_token"},
            "label": "Google OAuth2",
            "description": "Google account credentials for Calendar, Gmail, and Forms",
        },
        "calendar": {
            "required_fields": {"calendar_id"},
            "label": "Google Calendar",
            "description": "Google Calendar configuration",
        },
        "email": {
            "required_fields": {"sender_email"},
            "label": "Gmail Sending",
            "description": "Gmail sender configuration",
        },
    },
    "openai": {
        "ai_provider": {
            "required_fields": {"api_key"},
            "label": "AI Provider (Legacy OpenAI)",
            "description": "AI model API key for personalization",
        },
    },
    "ai_openai": {
        "ai_provider": {
            "required_fields": {"api_key"},
            "label": "OpenAI",
            "description": "OpenAI API key for AI personalization",
        },
    },
    "ai_anthropic": {
        "ai_provider": {
            "required_fields": {"api_key"},
            "label": "Anthropic / Claude",
            "description": "Anthropic API key (adapter pending)",
        },
    },
    "ai_gemini": {
        "ai_provider": {
            "required_fields": {"api_key"},
            "label": "Google Gemini",
            "description": "Google Gemini API key (adapter pending)",
        },
    },
    "ai_xai": {
        "ai_provider": {
            "required_fields": {"api_key"},
            "label": "xAI / Grok",
            "description": "xAI API key for Grok models",
        },
    },
    "ai_moonshot": {
        "ai_provider": {
            "required_fields": {"api_key"},
            "label": "Moonshot / Kimi",
            "description": "Moonshot API key for Kimi models",
        },
    },
    "ai_openrouter": {
        "ai_provider": {
            "required_fields": {"api_key"},
            "label": "OpenRouter",
            "description": "OpenRouter API key for multi-model access",
        },
    },
    "ai_tokenrouter": {
        "ai_provider": {
            "required_fields": {"api_key"},
            "label": "TokenRouter",
            "description": "TokenRouter API key for AI models",
        },
    },
    "ai_custom_openai_compatible": {
        "ai_provider": {
            "required_fields": {"api_key", "base_url"},
            "label": "Custom OpenAI-Compatible",
            "description": "Any OpenAI-compatible endpoint",
        },
    },
    "zoom": {
        "zoom_oauth": {
            "required_fields": {"client_id", "client_secret", "redirect_uri"},
            "label": "Zoom OAuth2",
            "description": "Zoom OAuth2 connection for meeting scheduling",
        },
    },
}

# Safe metadata keys that are OK to expose in API responses
_SAFE_METADATA_KEYS = {
    "scopes", "calendar_id", "sender_email", "model", "base_url",
    "label", "display_name", "sender_name", "company_name",
    "provider_name", "timezone", "provider_id",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class IntegrationServiceError(Exception):
    """Base exception for integration service errors."""


class IntegrationNotFoundError(IntegrationServiceError):
    """Raised when an integration does not exist."""


class IntegrationValidationError(IntegrationServiceError):
    """Raised when integration input fails validation."""


class InsufficientPermissionsError(IntegrationServiceError):
    """Raised when the user lacks required permissions."""


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class IntegrationService:
    """Business logic layer for organization integration management.

    All methods require:
      - db: database session
      - org_id: organization UUID (derived from authenticated user)
      - role: user role string (owner/admin/member)

    Role enforcement:
      - OWNER/ADMIN: full CRUD on integrations
      - MEMBER: read-only (list, get status)
    """

    # ─── Generic / All integrations ──────────────────────────────────────

    @staticmethod
    def list_integrations(
        db: Session,
        org_id: uuid.UUID,
    ) -> list[dict[str, Any]]:
        """List all integrations for an organization.

        Returns safe-for-API response dicts. Never includes credentials.
        """
        integrations = CredentialVault.list_integrations(db, org_id)

        # Enrich with provider labels
        enriched = []
        for item in integrations:
            provider = item.get("provider", "")
            integration_type = item.get("integration_type", "")
            item["label"] = _get_integration_label(provider, integration_type)
            item["description"] = _get_integration_description(provider, integration_type)
            item["metadata"] = _sanitize_metadata(item.get("metadata", {}))
            enriched.append(item)

        return enriched

    @staticmethod
    def get_integration_status(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
    ) -> dict[str, Any]:
        """Get the status of all integration types for a given provider.

        Returns safe API response. Never returns credentials.
        """
        from sqlalchemy import select

        stmt = select(OrgIntegration).where(
            OrgIntegration.organization_id == org_id,
            OrgIntegration.provider == provider,
        )
        integrations = db.execute(stmt).scalars().all()

        items = []
        for integration in integrations:
            items.append({
                "id": str(integration.id),
                "integration_type": integration.integration_type,
                "status": integration.status.value,
                "has_credentials": integration.credentials_encrypted is not None,
                "connected_at": (
                    integration.connected_at.isoformat()
                    if integration.connected_at
                    else None
                ),
                "last_error": integration.last_error,
                "label": _get_integration_label(provider, integration.integration_type),
                "metadata": _sanitize_metadata(integration.metadata_json or {}),
                "created_at": (
                    integration.created_at.isoformat()
                    if integration.created_at
                    else None
                ),
                "updated_at": (
                    integration.updated_at.isoformat()
                    if integration.updated_at
                    else None
                ),
            })

        return {
            "provider": provider,
            "integrations": items,
        }

    @staticmethod
    def save_integration(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
        credentials: dict[str, Any],
        metadata: dict[str, Any] | None = None,
        *,
        role: str,
    ) -> dict[str, Any]:
        """Save credentials for an integration.

        Requires owner/admin role. Validates input, encrypts credentials,
        records an audit log entry, and returns a safe API response.

        NEVER returns the stored credentials in the response.
        """
        _require_management_role(role)
        _validate_credentials(provider, integration_type, credentials)

        # Sanitize AI provider metadata — prevent invalid provider_id
        if metadata and integration_type == "ai_provider":
            provider_id = metadata.get("provider_id", "")
            if not provider_id or provider_id in ("undefined", "null", "none", ""):
                metadata = {**metadata, "provider_id": "openai"}
            else:
                # Validate against registry
                from app.services.ai_provider_registry import get_provider
                if get_provider(provider_id) is None:
                    logger.warning(
                        "[INTEGRATION_SERVICE] Unknown AI provider_id '%s' — defaulting to 'openai'",
                        provider_id,
                    )
                    metadata = {**metadata, "provider_id": "openai"}

        # OAuth app config (client_id/secret/redirect_uri) → PENDING
        # until the OAuth flow completes.  All other integrations
        # (API keys, OAuth tokens) → CONNECTED immediately.
        is_oauth_config = (provider, integration_type) in _OAUTH_CONFIG_TYPES
        vault_status = IntegrationStatus.PENDING if is_oauth_config else IntegrationStatus.CONNECTED

        integration = CredentialVault.save_credentials(
            db=db,
            org_id=org_id,
            provider=provider,
            integration_type=integration_type,
            credentials=credentials,
            metadata=metadata,
            status=vault_status,
        )

        _record_audit(
            org_id=org_id,
            event_type="integration.connected" if vault_status == IntegrationStatus.CONNECTED else "integration.pending",
            provider=provider,
            integration_type=integration_type,
        )

        return _safe_response(integration)

    @staticmethod
    def update_integration(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
        credentials: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        *,
        role: str,
    ) -> dict[str, Any]:
        """Update an existing integration.

        Requires owner/admin role. Only updates provided fields.
        Records an audit log entry.

        NEVER returns the stored credentials in the response.
        """
        _require_management_role(role)

        # Sanitize AI provider metadata on update too
        if metadata and integration_type == "ai_provider":
            provider_id = metadata.get("provider_id", "")
            if not provider_id or provider_id in ("undefined", "null", "none", ""):
                metadata = {**metadata, "provider_id": "openai"}
            elif provider_id:
                from app.services.ai_provider_registry import get_provider
                if get_provider(provider_id) is None:
                    metadata = {**metadata, "provider_id": "openai"}

        if credentials is not None:
            _validate_credentials(provider, integration_type, credentials)
            is_oauth_config = (provider, integration_type) in _OAUTH_CONFIG_TYPES
            vault_status = IntegrationStatus.PENDING if is_oauth_config else IntegrationStatus.CONNECTED
            integration = CredentialVault.save_credentials(
                db=db,
                org_id=org_id,
                provider=provider,
                integration_type=integration_type,
                credentials=credentials,
                metadata=metadata,
                status=vault_status,
            )
        elif metadata is not None:
            integration = CredentialVault.update_metadata(
                db=db,
                org_id=org_id,
                provider=provider,
                integration_type=integration_type,
                metadata=metadata,
            )
        else:
            raise IntegrationValidationError(
                "No credentials or metadata provided for update"
            )

        _record_audit(
            org_id=org_id,
            event_type="integration.updated",
            provider=provider,
            integration_type=integration_type,
        )

        return _safe_response(integration)

    @staticmethod
    def disconnect_integration(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
        *,
        role: str,
    ) -> dict[str, Any]:
        """Disconnect an integration: clear credentials and set DISCONNECTED.

        Requires owner/admin role. Records an audit log entry.
        """
        _require_management_role(role)

        integration = CredentialVault.disconnect(
            db=db,
            org_id=org_id,
            provider=provider,
            integration_type=integration_type,
        )

        if integration is None:
            raise IntegrationNotFoundError(
                f"No integration found for provider={provider}, "
                f"type={integration_type}"
            )

        _record_audit(
            org_id=org_id,
            event_type="integration.disconnected",
            provider=provider,
            integration_type=integration_type,
        )

        return _safe_response(integration)

    @staticmethod
    def record_error(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
        error_message: str,
    ) -> dict[str, Any]:
        """Record an error on an integration without requiring user role.

        Called by service layers (not user-facing) when an integration
        call fails (e.g., Google token refresh failure).
        """
        integration = CredentialVault.mark_error(
            db=db,
            org_id=org_id,
            provider=provider,
            integration_type=integration_type,
            error_message=error_message,
        )

        _record_audit(
            org_id=org_id,
            event_type="integration.error",
            provider=provider,
            integration_type=integration_type,
        )

        return _safe_response(integration)

    # ─── Typed convenience methods ───────────────────────────────────────

    @staticmethod
    def save_google_oauth(
        db: Session,
        org_id: uuid.UUID,
        refresh_token: str,
        client_id: str,
        client_secret: str,
        scopes: list[str] | None = None,
        *,
        role: str = "owner",
    ) -> dict[str, Any]:
        """Store Google OAuth2 credentials for an org."""
        credentials = {
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        metadata = {
            "scopes": scopes or ["calendar", "gmail.send"],
            "provider": "google",
        }
        return IntegrationService.save_integration(
            db=db,
            org_id=org_id,
            provider="google",
            integration_type="google_oauth",
            credentials=credentials,
            metadata=metadata,
            role=role,
        )

    @staticmethod
    def get_google_oauth_status(
        db: Session,
        org_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Get Google OAuth status (no credentials exposed)."""
        metadata = CredentialVault.get_safe_metadata(db, org_id, "google", "google_oauth")
        has = CredentialVault.has_credentials(db, org_id, "google", "google_oauth")
        return {
            "provider": "google",
            "integration_type": "google_oauth",
            "has_credentials": has,
            "metadata": metadata or {},
        }

    @staticmethod
    def save_ai_provider(
        db: Session,
        org_id: uuid.UUID,
        api_key: str,
        base_url: str,
        model: str,
        provider_name: str = "openai",
        *,
        role: str = "owner",
    ) -> dict[str, Any]:
        """Store AI provider credentials for an org.

        Always saves under the canonical vault key ("openai", "ai_provider")
        regardless of provider_name.  The actual provider identity is stored
        in metadata as ``provider_id`` so the resolver can find it.
        """
        credentials = {
            "api_key": api_key,
            "base_url": base_url,
        }
        metadata = {
            "model": model,
            "provider_name": provider_name,
            "provider_id": provider_name,
        }
        return IntegrationService.save_integration(
            db=db,
            org_id=org_id,
            provider="openai",
            integration_type="ai_provider",
            credentials=credentials,
            metadata=metadata,
            role=role,
        )

    @staticmethod
    def get_ai_provider_status(
        db: Session,
        org_id: uuid.UUID,
        provider_name: str = "openai",
    ) -> dict[str, Any]:
        """Get AI provider status (no credentials exposed).

        Always reads from the canonical vault key ("openai", "ai_provider").
        """
        metadata = CredentialVault.get_safe_metadata(
            db, org_id, "openai", "ai_provider"
        )
        has = CredentialVault.has_credentials(db, org_id, "openai", "ai_provider")
        return {
            "provider": provider_name,
            "integration_type": "ai_provider",
            "has_credentials": has,
            "metadata": metadata or {},
        }

    @staticmethod
    def save_zoom_oauth(
        db: Session,
        org_id: uuid.UUID,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        *,
        role: str = "owner",
    ) -> dict[str, Any]:
        """Store Zoom OAuth2 credentials for an organization.

        Each organization configures their own Zoom OAuth app.
        Credentials are encrypted at rest via CredentialVault.
        """
        credentials = {
            "client_id": client_id.strip(),
            "client_secret": client_secret.strip(),
            "redirect_uri": redirect_uri.strip(),
        }
        metadata = {
            "label": "Zoom OAuth2",
            "configured_at": datetime.now(timezone.utc).isoformat(),
        }
        return IntegrationService.save_integration(
            db=db,
            org_id=org_id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials=credentials,
            metadata=metadata,
            role=role,
        )

    @staticmethod
    def get_zoom_oauth_status(
        db: Session,
        org_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Get Zoom OAuth status (no credentials exposed).

        Returns configured status, masked client_id, and redirect_uri.
        """
        has = CredentialVault.has_credentials(db, org_id, "zoom", "zoom_oauth")
        metadata = CredentialVault.get_safe_metadata(
            db, org_id, "zoom", "zoom_oauth"
        ) or {}

        result: dict[str, Any] = {
            "provider": "zoom",
            "integration_type": "zoom_oauth",
            "has_credentials": has,
            "configured": False,
            "masked_client_id": None,
            "redirect_uri": None,
            "connected_at": metadata.get("connected_at"),
            "account_email": metadata.get("account_email"),
        }

        if has:
            try:
                creds = CredentialVault.get_credentials(
                    db, org_id, "zoom", "zoom_oauth"
                )
                client_id = creds.get("client_id", "")
                client_secret = creds.get("client_secret", "")
                redirect_uri = creds.get("redirect_uri", "")
                result["configured"] = bool(client_id and client_secret)
                if client_id and len(client_id) > 8:
                    result["masked_client_id"] = (
                        client_id[:4] + "..." + client_id[-4:]
                    )
                elif client_id:
                    result["masked_client_id"] = client_id
                result["redirect_uri"] = redirect_uri or None
            except (CredentialNotFoundError, CredentialCorruptError):
                pass

        return result

    @staticmethod
    def save_email_config(
        db: Session,
        org_id: uuid.UUID,
        sender_email: str,
        sender_name: str,
        company_name: str,
        *,
        role: str = "owner",
    ) -> dict[str, Any]:
        """Store email sender configuration for an org."""
        credentials = {"sender_email": sender_email}
        metadata = {"sender_name": sender_name, "company_name": company_name}
        return IntegrationService.save_integration(
            db=db,
            org_id=org_id,
            provider="google",
            integration_type="email",
            credentials=credentials,
            metadata=metadata,
            role=role,
        )

    @staticmethod
    def get_email_config(
        db: Session,
        org_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Get email configuration (no credentials exposed)."""
        metadata = CredentialVault.get_safe_metadata(db, org_id, "google", "email")
        has = CredentialVault.has_credentials(db, org_id, "google", "email")
        return {
            "provider": "google",
            "integration_type": "email",
            "has_credentials": has,
            "metadata": metadata or {},
        }

    @staticmethod
    def save_calendar_config(
        db: Session,
        org_id: uuid.UUID,
        calendar_id: str,
        company_name: str,
        *,
        role: str = "owner",
    ) -> dict[str, Any]:
        """Store calendar configuration for an org."""
        credentials = {"calendar_id": calendar_id}
        metadata = {"company_name": company_name}
        return IntegrationService.save_integration(
            db=db,
            org_id=org_id,
            provider="google",
            integration_type="calendar",
            credentials=credentials,
            metadata=metadata,
            role=role,
        )

    @staticmethod
    def get_calendar_config(
        db: Session,
        org_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Get calendar configuration (no credentials exposed)."""
        metadata = CredentialVault.get_safe_metadata(db, org_id, "google", "calendar")
        has = CredentialVault.has_credentials(db, org_id, "google", "calendar")
        return {
            "provider": "google",
            "integration_type": "calendar",
            "has_credentials": has,
            "metadata": metadata or {},
        }

    @staticmethod
    def delete_integration(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
        *,
        hard_delete: bool = False,
        role: str = "owner",
    ) -> bool:
        """Remove an integration's credentials (soft or hard delete)."""
        _require_management_role(role)
        return CredentialVault.delete_credentials(
            db, org_id, provider, integration_type, hard_delete=hard_delete
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_management_role(role: str) -> None:
    """Raise InsufficientPermissionsError if the role cannot manage integrations."""
    if role not in ("owner", "admin"):
        raise InsufficientPermissionsError(
            "Insufficient permissions. Required: owner or admin role."
        )


def _validate_credentials(
    provider: str,
    integration_type: str,
    credentials: dict[str, Any],
) -> None:
    """Validate that credentials contain the required fields for the provider."""
    known = KNOWN_PROVIDERS.get(provider, {}).get(integration_type)
    if known is None:
        logger.warning(
            "[INTEGRATION_SERVICE] Unknown provider/type: %s/%s",
            provider,
            integration_type,
        )
        return

    required = known.get("required_fields", set())
    missing = required - set(credentials.keys())
    if missing:
        raise IntegrationValidationError(
            f"Missing required fields for {provider}/{integration_type}: "
            f"{', '.join(sorted(missing))}"
        )

    for field in required:
        value = credentials.get(field)
        if isinstance(value, str) and not value.strip():
            raise IntegrationValidationError(
                f"Field '{field}' cannot be empty"
            )

    # Phase 6: Prevent mixed credentials — client_id and client_secret must
    # always come from the same configuration.  If one is provided, the other
    # must be too.
    if "client_id" in credentials and "client_secret" in credentials:
        cid = credentials.get("client_id", "")
        cs = credentials.get("client_secret", "")
        if (isinstance(cid, str) and cid.strip()) and (isinstance(cs, str) and not cs.strip()):
            raise IntegrationValidationError(
                "client_id is provided but client_secret is empty. "
                "Both must be provided together."
            )
        if (isinstance(cs, str) and cs.strip()) and (isinstance(cid, str) and not cid.strip()):
            raise IntegrationValidationError(
                "client_secret is provided but client_id is empty. "
                "Both must be provided together."
            )


def _get_integration_label(provider: str, integration_type: str) -> str:
    """Get a human-readable label for an integration."""
    known = KNOWN_PROVIDERS.get(provider, {}).get(integration_type)
    if known:
        return known.get("label", f"{provider}/{integration_type}")
    return f"{provider}/{integration_type}"


def _get_integration_description(provider: str, integration_type: str) -> str:
    """Get a description for an integration."""
    known = KNOWN_PROVIDERS.get(provider, {}).get(integration_type)
    if known:
        return known.get("description", "")
    return ""


def _sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Return only safe, non-secret metadata keys for API exposure."""
    return {k: v for k, v in metadata.items() if k in _SAFE_METADATA_KEYS}


def _record_audit(
    *,
    org_id: uuid.UUID,
    event_type: str,
    provider: str,
    integration_type: str,
) -> None:
    """Record a structured audit log entry for an integration event.

    EventLog requires a lead_id (NOT NULL FK). For integration events
    that aren't tied to a specific lead, we emit a structured log line
    that can be consumed by a future event-ingestion pipeline.
    """
    logger.info(
        "[AUDIT] %s org=%s provider=%s type=%s",
        event_type,
        str(org_id),
        provider,
        integration_type,
        extra={
            "audit_event": True,
            "event_type": event_type,
            "org_id": str(org_id),
            "provider": provider,
            "integration_type": integration_type,
        },
    )


def _safe_response(integration: OrgIntegration) -> dict[str, Any]:
    """Format an OrgIntegration row as a secret-safe API response.

    NEVER includes credentials_encrypted, decrypted credentials,
    or any sensitive data.
    """
    return {
        "id": str(integration.id),
        "provider": integration.provider,
        "integration_type": integration.integration_type,
        "status": integration.status.value,
        "has_credentials": integration.credentials_encrypted is not None,
        "connected_at": (
            integration.connected_at.isoformat()
            if integration.connected_at
            else None
        ),
        "last_error": integration.last_error,
        "metadata": _sanitize_metadata(integration.metadata_json or {}),
        "created_at": (
            integration.created_at.isoformat()
            if integration.created_at
            else None
        ),
        "updated_at": (
            integration.updated_at.isoformat()
            if integration.updated_at
            else None
        ),
    }
