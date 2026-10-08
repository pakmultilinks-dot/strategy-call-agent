"""Credential Vault — encrypted credential storage and retrieval.

Provides a high-level service for storing, retrieving, updating, and
deleting encrypted credentials in the org_integrations table.

All credentials are encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
before being written to the database, and decrypted on read.

This module does NOT implement business logic — it provides a clean
abstraction that the future integration service layer will use.

Design decisions:
  - Credentials are stored as a versioned, encrypted JSON blob
  - Org-scoped: all operations require an organization_id
  - Provider-scoped: each org can have one integration per (provider, type)
  - Metadata (non-secret config) stored separately in metadata_json
  - NEVER returns raw credentials to API responses — use get_safe_metadata()
  - Audit logging for every mutation (save/update/delete)
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models_multi_tenant import IntegrationStatus, OrgIntegration
from app.services.crypto import (
    CryptoError,
    DecryptionError,
    decrypt_secret,
    deserialize_credentials,
    encrypt_secret,
    mask_dict_values,
    serialize_credentials,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CredentialVaultError(Exception):
    """Base exception for credential vault errors."""


class CredentialNotFoundError(CredentialVaultError):
    """Raised when the requested integration row does not exist."""


class CredentialAlreadyExistsError(CredentialVaultError):
    """Raised when trying to create an integration that already exists."""


class CredentialCorruptError(CredentialVaultError):
    """Raised when stored credentials cannot be decrypted (wrong key, corrupt)."""


class InvalidCredentialDataError(CredentialVaultError):
    """Raised when credential data is not a valid dict / JSON."""


# ---------------------------------------------------------------------------
# Vault service
# ---------------------------------------------------------------------------


class CredentialVault:
    """Encrypted credential storage service.

    All methods are classmethods — no instance state needed.
    Every mutation is audit-logged via the logging framework.

    Usage:
        CredentialVault.save_credentials(
            db=db, org_id=org_id,
            provider="google", integration_type="google_oauth",
            credentials={"refresh_token": "...", ...},
            metadata={"scopes": ["calendar", "gmail"]},
        )
        creds = CredentialVault.get_credentials(db, org_id, "google", "google_oauth")
    """

    # -----------------------------------------------------------------------
    # Write operations
    # -----------------------------------------------------------------------

    @staticmethod
    def save_credentials(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
        credentials: dict[str, Any],
        metadata: dict[str, Any] | None = None,
        status: IntegrationStatus = IntegrationStatus.CONNECTED,
    ) -> OrgIntegration:
        """Create or update an integration with encrypted credentials.

        If an integration with the same (org_id, provider, integration_type)
        already exists, it is updated in place (atomic replacement).

        Returns the OrgIntegration row.
        """
        from app.config import settings

        encryption_key = settings.get_credential_encryption_key()

        # Serialize and encrypt the credentials
        try:
            plaintext_json = serialize_credentials(credentials)
            encrypted = encrypt_secret(plaintext_json, encryption_key)
        except CryptoError as exc:
            raise CredentialVaultError(f"Failed to encrypt credentials: {exc}") from exc

        now = datetime.now(timezone.utc)

        # Upsert logic
        existing = _find_integration(db, org_id, provider, integration_type)

        if existing is not None:
            existing.credentials_encrypted = encrypted
            existing.metadata_json = metadata
            existing.status = status
            existing.last_error = None  # clear any previous error
            existing.updated_at = now
            if status == IntegrationStatus.CONNECTED:
                existing.connected_at = now

            db.commit()
            db.refresh(existing)

            logger.info(
                "[CREDENTIAL_VAULT] Updated credentials",
                extra={
                    "org_id": str(org_id),
                    "provider": provider,
                    "integration_type": integration_type,
                    "action": "update",
                },
            )
            return existing

        # Create new
        integration = OrgIntegration(
            organization_id=org_id,
            provider=provider,
            integration_type=integration_type,
            status=status,
            credentials_encrypted=encrypted,
            metadata_json=metadata,
            connected_at=now if status == IntegrationStatus.CONNECTED else None,
        )
        db.add(integration)
        db.commit()
        db.refresh(integration)

        logger.info(
            "[CREDENTIAL_VAULT] Saved new credentials",
            extra={
                "org_id": str(org_id),
                "provider": provider,
                "integration_type": integration_type,
                "action": "create",
            },
        )
        return integration

    @staticmethod
    def update_metadata(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
        metadata: dict[str, Any],
    ) -> OrgIntegration:
        """Update only the metadata (non-secret config) for an integration.

        Does not touch credentials.
        """
        integration = _find_integration_or_raise(db, org_id, provider, integration_type)
        integration.metadata_json = metadata
        integration.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(integration)

        logger.info(
            "[CREDENTIAL_VAULT] Updated metadata",
            extra={
                "org_id": str(org_id),
                "provider": provider,
                "integration_type": integration_type,
                "action": "update_metadata",
            },
        )
        return integration

    # -----------------------------------------------------------------------
    # Read operations
    # -----------------------------------------------------------------------

    @staticmethod
    def get_credentials(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
    ) -> dict[str, Any]:
        """Decrypt and return the stored credentials dict.

        Raises:
            CredentialNotFoundError: If no integration row exists.
            CredentialCorruptError: If decryption fails (wrong key, corrupt data).
        """
        integration = _find_integration_or_raise(db, org_id, provider, integration_type)

        if not integration.credentials_encrypted:
            return {}

        from app.config import settings

        encryption_key = settings.get_credential_encryption_key()

        try:
            plaintext_json = decrypt_secret(integration.credentials_encrypted, encryption_key)
            return deserialize_credentials(plaintext_json)
        except DecryptionError as exc:
            raise CredentialCorruptError(
                f"Cannot decrypt credentials for {provider}/{integration_type}: {exc}"
            ) from exc
        except CryptoError as exc:
            raise CredentialCorruptError(
                f"Corrupt credential data for {provider}/{integration_type}: {exc}"
            ) from exc

    @staticmethod
    def get_safe_metadata(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
    ) -> dict[str, Any] | None:
        """Return the metadata_json for an integration, safe for API exposure.

        Returns None if the integration does not exist.
        Never returns credentials — only metadata.
        """
        integration = _find_integration(db, org_id, provider, integration_type)
        if integration is None:
            return None
        return integration.metadata_json or {}

    @staticmethod
    def has_credentials(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
    ) -> bool:
        """Check if credentials exist for this org/provider/type combination."""
        integration = _find_integration(db, org_id, provider, integration_type)
        return (
            integration is not None
            and integration.credentials_encrypted is not None
            and integration.status != IntegrationStatus.DISCONNECTED
        )

    @staticmethod
    def list_integrations(
        db: Session,
        org_id: uuid.UUID,
        include_metadata: bool = True,
    ) -> list[dict[str, Any]]:
        """List all integrations for an org WITHOUT exposing credentials.

        Returns a list of dicts with: provider, integration_type, status,
        metadata (if requested), created_at, updated_at.

        NEVER includes credentials_encrypted.
        """
        stmt = select(OrgIntegration).where(
            OrgIntegration.organization_id == org_id
        )
        integrations = db.execute(stmt).scalars().all()

        result = []
        for integration in integrations:
            item = {
                "id": str(integration.id),
                "provider": integration.provider,
                "integration_type": integration.integration_type,
                "status": integration.status.value,
                "has_credentials": integration.credentials_encrypted is not None,
                "connected_at": integration.connected_at.isoformat() if integration.connected_at else None,
                "last_error": integration.last_error,
                "created_at": integration.created_at.isoformat() if integration.created_at else None,
                "updated_at": integration.updated_at.isoformat() if integration.updated_at else None,
            }
            if include_metadata:
                item["metadata"] = integration.metadata_json or {}
            result.append(item)

        return result

    # -----------------------------------------------------------------------
    # Delete operations
    # -----------------------------------------------------------------------

    @staticmethod
    def delete_credentials(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
        *,
        hard_delete: bool = False,
    ) -> bool:
        """Remove credentials from an integration.

        By default, clears credentials_encrypted and sets status to DISCONNECTED
        (soft delete). The row remains for audit trail.

        If hard_delete=True, removes the entire row from the database.

        Returns True if something was deleted/cleared, False if not found.
        """
        integration = _find_integration(db, org_id, provider, integration_type)

        if integration is None:
            return False

        if hard_delete:
            db.delete(integration)
            db.commit()
            logger.info(
                "[CREDENTIAL_VAULT] Hard-deleted integration",
                extra={
                    "org_id": str(org_id),
                    "provider": provider,
                    "integration_type": integration_type,
                    "action": "hard_delete",
                },
            )
        else:
            integration.credentials_encrypted = None
            integration.status = IntegrationStatus.DISCONNECTED
            integration.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(integration)
            logger.info(
                "[CREDENTIAL_VAULT] Soft-deleted credentials (set to DISCONNECTED)",
                extra={
                    "org_id": str(org_id),
                    "provider": provider,
                    "integration_type": integration_type,
                    "action": "soft_delete",
                },
            )

        return True

    # -----------------------------------------------------------------------
    # Status transition helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def mark_connected(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
    ) -> OrgIntegration:
        """Mark an integration as connected, recording connected_at timestamp.

        Raises CredentialNotFoundError if the integration does not exist.
        """
        integration = _find_integration_or_raise(db, org_id, provider, integration_type)
        now = datetime.now(timezone.utc)
        integration.status = IntegrationStatus.CONNECTED
        integration.connected_at = now
        integration.last_error = None
        integration.updated_at = now
        db.commit()
        db.refresh(integration)
        logger.info(
            "[CREDENTIAL_VAULT] Marked connected",
            extra={
                "org_id": str(org_id),
                "provider": provider,
                "integration_type": integration_type,
                "action": "mark_connected",
            },
        )
        return integration

    @staticmethod
    def mark_error(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
        error_message: str,
    ) -> OrgIntegration:
        """Mark an integration as error state, recording the error.

        Sanitizes the error_message to ensure no tokens/secrets are stored.
        Raises CredentialNotFoundError if the integration does not exist.
        """
        integration = _find_integration_or_raise(db, org_id, provider, integration_type)
        now = datetime.now(timezone.utc)
        integration.status = IntegrationStatus.ERROR
        integration.last_error = _sanitize_error(error_message)
        integration.updated_at = now
        db.commit()
        db.refresh(integration)
        logger.warning(
            "[CREDENTIAL_VAULT] Marked error",
            extra={
                "org_id": str(org_id),
                "provider": provider,
                "integration_type": integration_type,
                "action": "mark_error",
                # NEVER log the actual error if it might contain tokens
            },
        )
        return integration

    @staticmethod
    def disconnect(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
    ) -> OrgIntegration | None:
        """Disconnect an integration: clear credentials, set DISCONNECTED status.

        Returns the updated OrgIntegration row, or None if not found.
        """
        integration = _find_integration(db, org_id, provider, integration_type)
        if integration is None:
            return None

        now = datetime.now(timezone.utc)
        integration.credentials_encrypted = None
        integration.status = IntegrationStatus.DISCONNECTED
        integration.connected_at = None
        integration.last_error = None
        integration.updated_at = now
        db.commit()
        db.refresh(integration)
        logger.info(
            "[CREDENTIAL_VAULT] Disconnected integration",
            extra={
                "org_id": str(org_id),
                "provider": provider,
                "integration_type": integration_type,
                "action": "disconnect",
            },
        )
        return integration

    # -----------------------------------------------------------------------
    # Masked display
    # -----------------------------------------------------------------------

    @staticmethod
    def get_masked_credentials(
        db: Session,
        org_id: uuid.UUID,
        provider: str,
        integration_type: str,
    ) -> dict[str, str] | None:
        """Return decrypted credentials with all values masked for display.

        Useful for admin UIs that need to show "your API key ends in ...ef456".
        Returns None if no credentials exist.
        """
        integration = _find_integration(db, org_id, provider, integration_type)
        if integration is None or not integration.credentials_encrypted:
            return None

        try:
            creds = CredentialVault.get_credentials(db, org_id, provider, integration_type)
        except CredentialCorruptError:
            return None

        if not creds:
            return None
        return mask_dict_values(creds)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sanitize_error(error_message: str, max_length: int = 500) -> str:
    """Sanitize an error message to ensure it contains no secrets.

    Strips common patterns that might leak tokens, API keys, or other
    credentials. Truncates to max_length.
    """
    import re

    # Common patterns that might appear in error messages
    secret_patterns = [
        r'(access_token["\':=\s]+)[\w\-._~+/]+=*',
        r'(refresh_token["\':=\s]+)[\w\-._~+/]+=*',
        r'(api_key["\':=\s]+)[\w\-._~+/]+=*',
        r'(client_secret["\':=\s]+)[\w\-._~+/]+=*',
        r'(Bearer\s+)[\w\-._~+/]+=*',
    ]
    sanitized = error_message
    for pattern in secret_patterns:
        sanitized = re.sub(pattern, r"\1[REDACTED]", sanitized, flags=re.IGNORECASE)

    return sanitized[:max_length]


def _find_integration(
    db: Session,
    org_id: uuid.UUID,
    provider: str,
    integration_type: str,
) -> OrgIntegration | None:
    """Find an integration row by (org_id, provider, integration_type)."""
    stmt = select(OrgIntegration).where(
        OrgIntegration.organization_id == org_id,
        OrgIntegration.provider == provider,
        OrgIntegration.integration_type == integration_type,
    )
    return db.execute(stmt).scalar_one_or_none()


def _find_integration_or_raise(
    db: Session,
    org_id: uuid.UUID,
    provider: str,
    integration_type: str,
) -> OrgIntegration:
    """Find an integration row, raising CredentialNotFoundError if missing."""
    integration = _find_integration(db, org_id, provider, integration_type)
    if integration is None:
        raise CredentialNotFoundError(
            f"No integration found for org {org_id} / "
            f"provider={provider} / type={integration_type}"
        )
    return integration
