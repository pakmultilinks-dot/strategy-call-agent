"""Symmetric encryption service for customer credentials.

Provides Fernet-based encryption/decryption for credential blobs stored
in the org_integrations.credentials_encrypted column.

Design decisions:
  - Fernet (AES-128-CBC + HMAC-SHA256) from the `cryptography` library
  - Key format: Fernet-generated 32-byte URL-safe base64 key
  - Version prefix ("v1:") on all ciphertext for future key rotation
  - All operations are stateless (no class instances needed)
  - Decryption failures raise a dedicated CryptoError so callers can
    distinguish bad key from corrupt data vs. bad input.

SECURITY:
  - Never log, print, or expose the encryption key or decrypted secrets
  - The encryption key MUST be set via CREDENTIAL_ENCRYPTION_KEY env var
  - In production, a missing/invalid key causes an app start-up error
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Final

from cryptography.fernet import Fernet, InvalidToken

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CIPHERTEXT_VERSION: Final[str] = "v1"
_VERSION_PREFIX: Final[str] = f"{CIPHERTEXT_VERSION}:"
_FERNET_KEY_LENGTH: Final[int] = 44  # Fernet keys are 44 chars (32 bytes base64-encoded)
_SALT_LENGTH: Final[int] = 16
_MAX_KEY_ATTEMPTS: Final[int] = 100  # key derivation attempts


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CryptoError(Exception):
    """Raised when encryption/decryption fails."""


class InvalidKeyError(CryptoError):
    """Raised when the encryption key is invalid or missing."""


class DecryptionError(CryptoError):
    """Raised when ciphertext cannot be decrypted (wrong key, corrupt data)."""


# ---------------------------------------------------------------------------
# Key validation & derivation
# ---------------------------------------------------------------------------


def validate_key(key: str | None) -> str:
    """Validate that a Fernet key is well-formed.

    Returns the key if valid, raises InvalidKeyError otherwise.
    """
    if not key or not key.strip():
        raise InvalidKeyError(
            "CREDENTIAL_ENCRYPTION_KEY is not set. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        )

    key = key.strip()

    try:
        # Fernet.__init__ validates the key format internally
        Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise InvalidKeyError(
            f"CREDENTIAL_ENCRYPTION_KEY is not a valid Fernet key: {exc}. "
            "Generate a new one with: python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        ) from exc

    return key


def generate_key() -> str:
    """Generate a new Fernet encryption key.

    Returns the key as a UTF-8 string (44 characters, URL-safe base64).
    """
    return Fernet.generate_key().decode()


def derive_key_from_password(password: str, salt: bytes | None = None) -> tuple[str, bytes]:
    """Derive a Fernet-compatible key from a password + salt using PBKDF2.

    Returns (fernet_key_str, salt) where fernet_key_str is a 44-char
    Fernet key string suitable for encrypt_secret/decrypt_secret.
    """
    import base64 as _b64

    if salt is None:
        salt = secrets.token_bytes(_SALT_LENGTH)

    key_material = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _MAX_KEY_ATTEMPTS,
        dklen=32,
    )
    fernet_key = _b64.urlsafe_b64encode(key_material).decode("ascii")
    # Validate it works
    Fernet(fernet_key.encode())
    return fernet_key, salt


def base64_encode(data: bytes) -> bytes:
    """URL-safe base64 encode (no padding)."""
    import base64
    return base64.urlsafe_b64encode(data)


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------


def encrypt_secret(plaintext: str, key: str) -> str:
    """Encrypt a plaintext string using the given Fernet key.

    Returns ciphertext with a version prefix: "v1:<fernet_ciphertext>".

    Args:
        plaintext: The secret value to encrypt (API key, token, etc.)
        key: A valid Fernet key (44-char URL-safe base64 string).

    Raises:
        InvalidKeyError: If the key is not a valid Fernet key.
        CryptoError: If encryption fails for any other reason.
    """
    validated_key = validate_key(key)

    if not plaintext:
        raise CryptoError("Cannot encrypt an empty string")

    try:
        f = Fernet(validated_key.encode())
        ciphertext = f.encrypt(plaintext.encode("utf-8"))
        return f"{_VERSION_PREFIX}{ciphertext.decode('ascii')}"
    except Exception as exc:
        raise CryptoError(f"Encryption failed: {exc}") from exc


def decrypt_secret(ciphertext: str, key: str) -> str:
    """Decrypt a versioned ciphertext string.

    Expects ciphertext in the format "v1:<fernet_ciphertext>".

    Args:
        ciphertext: The versioned ciphertext to decrypt.
        key: The Fernet key used to encrypt.

    Returns:
        The decrypted plaintext string.

    Raises:
        InvalidKeyError: If the key is not a valid Fernet key.
        DecryptionError: If decryption fails (wrong key, corrupt data).
    """
    validated_key = validate_key(key)

    if not ciphertext:
        raise DecryptionError("Cannot decrypt an empty string")

    # M16 fix: the DB column is Text - corruption, manual edits, or driver
    # quirks can hand us bytes (or other types).  Coerce safely and wrap
    # everything in DecryptionError so callers see CredentialCorruptError,
    # not a raw TypeError.
    if isinstance(ciphertext, bytes):
        try:
            ciphertext = ciphertext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecryptionError(
                "Ciphertext bytes are not valid UTF-8"
            ) from exc
    if not isinstance(ciphertext, str):
        raise DecryptionError(
            f"Cannot decrypt ciphertext of type {type(ciphertext).__name__}"
        )

    # Strip version prefix
    raw_ciphertext = ciphertext
    if ciphertext.startswith(_VERSION_PREFIX):
        raw_ciphertext = ciphertext[len(_VERSION_PREFIX):]

    try:
        f = Fernet(validated_key.encode())
        plaintext = f.decrypt(raw_ciphertext.encode("ascii"))
        return plaintext.decode("utf-8")
    except InvalidToken:
        raise DecryptionError(
            "Decryption failed - wrong key or corrupt ciphertext"
        )
    except Exception as exc:
        raise DecryptionError(f"Decryption failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Masking utilities
# ---------------------------------------------------------------------------


def mask_secret(plaintext: str, visible_chars: int = 4, mask_char: str = "*") -> str:
    """Return a masked version of a secret for display purposes.

    Shows the last `visible_chars` characters and masks the rest.

    Examples:
        mask_secret("sk-abc123def456") → "***********ef456"
        mask_secret("short")            → "*****"
        mask_secret("")                 → ""
        mask_secret("ab", visible_chars=4) → "ab"
    """
    if not plaintext:
        return ""
    if len(plaintext) <= visible_chars:
        return plaintext
    masked_length = len(plaintext) - visible_chars
    return mask_char * masked_length + plaintext[-visible_chars:]


def mask_dict_values(data: dict, keys_to_mask: list[str] | None = None) -> dict:
    """Return a copy of a dict with sensitive values masked.

    If keys_to_mask is provided, only those keys are masked.
    Otherwise, common secret key names are masked automatically.
    """
    if keys_to_mask is None:
        keys_to_mask = {
            "api_key", "api_secret", "secret", "password", "token",
            "refresh_token", "access_token", "client_secret",
            "credentials", "private_key", "secret_key",
        }

    masked = {}
    for k, v in data.items():
        if isinstance(v, str) and k.lower() in {k.lower() for k in keys_to_mask}:
            masked[k] = mask_secret(v)
        elif isinstance(v, dict):
            masked[k] = mask_dict_values(v, keys_to_mask)
        else:
            masked[k] = v
    return masked


# ---------------------------------------------------------------------------
# Credential blob serialization (JSON-safe)
# ---------------------------------------------------------------------------


def serialize_credentials(credentials: dict) -> str:
    """Serialize a credentials dict to a JSON string for encryption.

    Validates that the result is valid JSON before returning.
    """
    import json
    try:
        serialized = json.dumps(credentials, separators=(",", ":"))
        # Validate round-trip
        json.loads(serialized)
        return serialized
    except (TypeError, ValueError) as exc:
        raise CryptoError(f"Failed to serialize credentials: {exc}") from exc


def deserialize_credentials(json_string: str) -> dict:
    """Deserialize a JSON string to a credentials dict.

    Raises CryptoError if the string is not valid JSON or not a dict.
    """
    import json
    try:
        data = json.loads(json_string)
        if not isinstance(data, dict):
            raise CryptoError(f"Expected a JSON object, got {type(data).__name__}")
        return data
    except json.JSONDecodeError as exc:
        raise CryptoError(f"Invalid credential JSON: {exc}") from exc
