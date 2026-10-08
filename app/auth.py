"""Authentication and authorization module (Phase 6B.3).

Provides:
  - Password hashing (bcrypt via passlib)
  - JWT token creation and validation
  - FastAPI dependencies: get_current_user(), get_current_organization()
  - Role-based permission checks
  - Token revocation (P1-D: blocklist-based logout)

SECURITY RULES:
  - Passwords are NEVER stored in plaintext
  - password_hash is NEVER returned in any API response
  - JWT tokens contain ONLY: sub, org_id, role, exp, iat, jti
  - organization_id is NEVER trusted from client-supplied parameters
  - All protected routes use get_current_user() dependency
  - Revoked tokens are checked on every request via TokenBlocklist
"""
from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal, get_db
from app.models_multi_tenant import (
    Organization,
    TokenBlocklist,
    User,
    UserRole,
    UserStatus,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Password Hashing
# ---------------------------------------------------------------------------

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Minimum password length (configurable)
MIN_PASSWORD_LENGTH = 8


def hash_password(password: str) -> str:
    """Hash a password using bcrypt. NEVER log the password.

    Args:
        password: The plaintext password to hash.

    Returns:
        The bcrypt hash string.
    """
    return _pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash.

    Args:
        plain_password: The plaintext password to check.
        hashed_password: The stored bcrypt hash.

    Returns:
        True if the password matches.
    """
    return _pwd_context.verify(plain_password, hashed_password)


def validate_password_strength(password: str) -> None:
    """Validate password meets minimum requirements.

    Args:
        password: The plaintext password to validate.

    Raises:
        HTTPException 422 if the password is too short.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters long",
        )


# ---------------------------------------------------------------------------
# JWT Token Creation
# ---------------------------------------------------------------------------

_bearer_scheme = HTTPBearer(auto_error=False)


def create_access_token(
    user_id: uuid.UUID,
    organization_id: uuid.UUID,
    role: str,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT access token.

    The token payload contains ONLY:
      - sub: user_id (subject)
      - org_id: organization_id
      - role: user role (owner/admin/member)
      - exp: expiration timestamp
      - iat: issued-at timestamp
      - jti: unique token identifier (for revocation)

    NEVER include: passwords, API keys, OAuth tokens, credentials, secrets.

    Args:
        user_id: The user's UUID.
        organization_id: The user's organization UUID.
        role: The user's role string (owner/admin/member).
        expires_delta: Custom expiration period. Defaults to configured value.

    Returns:
        The encoded JWT string.
    """
    secret_key = settings.get_jwt_secret_key()
    algorithm = settings.jwt_algorithm

    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.jwt_access_token_expire_minutes)

    now = datetime.now(timezone.utc)
    expire = now + expires_delta

    payload = {
        "sub": str(user_id),
        "org_id": str(organization_id),
        "role": role,
        "exp": expire,
        "iat": now,
        "jti": str(uuid.uuid4()),
    }

    return jwt.encode(payload, secret_key, algorithm=algorithm)


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token.

    Args:
        token: The JWT string to decode.

    Returns:
        The decoded payload dict with sub, org_id, role, exp, iat, jti.

    Raises:
        HTTPException 401 if the token is expired, malformed, or invalid.
    """
    secret_key = settings.get_jwt_secret_key()
    algorithm = settings.jwt_algorithm

    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
    except JWTError as exc:
        logger.info("JWT decode failed: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    # Validate required fields
    user_id = payload.get("sub")
    org_id = payload.get("org_id")
    role = payload.get("role")
    jti = payload.get("jti")

    if not user_id or not org_id or not role or not jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


# ---------------------------------------------------------------------------
# Token Revocation (Phase 28 — P1-D)
# ---------------------------------------------------------------------------


def _is_token_revoked(jti: str, db: Session) -> bool:
    """Check if a token's jti is in the blocklist.

    Only checks non-expired blocklist entries for efficiency.
    Expired entries are cleaned up by ``cleanup_expired_blocklist()``.
    """
    now = datetime.now(timezone.utc)
    return (
        db.query(TokenBlocklist.id)
        .filter(
            TokenBlocklist.jti == jti,
            TokenBlocklist.expires_at > now,
        )
        .first()
        is not None
    )


def revoke_token(jti: str, user_id: uuid.UUID, organization_id: uuid.UUID,
                  reason: str = "logout", expires_at: datetime | None = None,
                  db: Session | None = None) -> None:
    """Add a single token jti to the blocklist.

    Args:
        jti: The token's unique identifier.
        user_id: The token owner's user ID.
        organization_id: The token owner's org ID.
        reason: Why the token was revoked (for audit logging).
        expires_at: When the original token expires (for cleanup). Defaults to
            now + jwt_expire_minutes.
        db: Database session. If None, a new one is created.
    """
    if expires_at is None:
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=settings.jwt_access_token_expire_minutes
        )

    own_session = db is None
    if own_session:
        db = SessionLocal()

    try:
        # Check for duplicate (idempotent revocation)
        existing = db.query(TokenBlocklist.id).filter(TokenBlocklist.jti == jti).first()
        if existing is None:
            entry = TokenBlocklist(
                jti=jti,
                user_id=user_id,
                organization_id=organization_id,
                reason=reason,
                expires_at=expires_at,
            )
            db.add(entry)
            db.commit()
    except Exception:
        if own_session:
            db.rollback()
        raise
    finally:
        if own_session:
            db.close()


def revoke_all_user_tokens(user_id: uuid.UUID, organization_id: uuid.UUID,
                           reason: str = "password_change",
                           db: Session | None = None) -> int:
    """Revoke ALL active tokens for a user by marking them in the blocklist.

    This is a BULK revocation — we use a sentinel jti pattern to invalidate
    all tokens.  The ``get_current_user()`` function checks both the blocklist
    table AND the user's ``token_version`` to handle bulk revocations.

    Instead of a token_version approach (which requires a DB column), we insert
    a single "bulk revoke" marker that ``_is_all_user_tokens_revoked()`` checks.

    The sentinel jti is the first 36 chars of a deterministic string so it
    fits in the ``jti`` column (VARCHAR(36)).

    Returns:
        The number of blocklist entries created (0 or 1 for the bulk marker).
    """
    own_session = db is None
    if own_session:
        db = SessionLocal()

    try:
        # Use first 36 chars of a deterministic sentinel — fits VARCHAR(36)
        sentinel_jti = f"BR:{uuid.uuid5(uuid.NAMESPACE_URL, str(user_id))}"[:36]
        existing = db.query(TokenBlocklist.id).filter(TokenBlocklist.jti == sentinel_jti).first()
        if existing is None:
            # Use a far-future expiry for the sentinel so it persists until cleanup
            far_future = datetime.now(timezone.utc) + timedelta(days=365)
            entry = TokenBlocklist(
                jti=sentinel_jti,
                user_id=user_id,
                organization_id=organization_id,
                reason=reason,
                expires_at=far_future,
            )
            db.add(entry)
            db.commit()
            return 1
        return 0
    except Exception:
        if own_session:
            db.rollback()
        raise
    finally:
        if own_session:
            db.close()


def _is_all_user_tokens_revoked(user_id: uuid.UUID, db: Session) -> bool:
    """Check if a bulk revocation sentinel exists for the user."""
    sentinel_jti = f"BR:{uuid.uuid5(uuid.NAMESPACE_URL, str(user_id))}"[:36]
    now = datetime.now(timezone.utc)
    return (
        db.query(TokenBlocklist.id)
        .filter(
            TokenBlocklist.jti == sentinel_jti,
            TokenBlocklist.expires_at > now,
        )
        .first()
        is not None
    )


def _clear_bulk_revocation(user_id: uuid.UUID, db: Session) -> None:
    """Remove the bulk revocation sentinel for a user.

    Called on successful login so that newly-issued tokens are not rejected.
    """
    sentinel_jti = f"BR:{uuid.uuid5(uuid.NAMESPACE_URL, str(user_id))}"[:36]
    deleted = (
        db.query(TokenBlocklist)
        .filter(TokenBlocklist.jti == sentinel_jti)
        .delete(synchronize_session="fetch")
    )
    if deleted > 0:
        db.commit()
        logger.info("Cleared bulk revocation sentinel for user=%s", user_id)


def cleanup_expired_blocklist(db: Session) -> int:
    """Remove expired entries from the token blocklist.

    Should be called periodically (e.g. by the scheduler) to prevent
    unbounded table growth.

    Returns:
        The number of entries deleted.
    """
    now = datetime.now(timezone.utc)
    count = (
        db.query(TokenBlocklist)
        .filter(TokenBlocklist.expires_at <= now)
        .delete(synchronize_session="fetch")
    )
    if count > 0:
        db.commit()
        logger.info("Cleaned up %d expired token_blocklist entries", count)
    return count


# ---------------------------------------------------------------------------
# Context variable for current request's organization_id
# ---------------------------------------------------------------------------

_current_org_id: ContextVar[uuid.UUID | None] = ContextVar("current_org_id", default=None)


def set_current_org_id(org_id: uuid.UUID) -> None:
    """Set the current request's organization ID in context."""
    _current_org_id.set(org_id)


def get_current_org_id_from_context() -> uuid.UUID | None:
    """Get the current request's organization ID from context."""
    return _current_org_id.get()


# ---------------------------------------------------------------------------
# FastAPI Dependencies
# ---------------------------------------------------------------------------


def _extract_token(credentials: HTTPAuthorizationCredentials | None) -> str | None:
    """Extract the Bearer token from the Authorization header."""
    if credentials and credentials.credentials:
        return credentials.credentials
    return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency: extract and validate the current user from JWT.

    Usage:
        @router.get("/protected")
        def my_route(current_user: User = Depends(get_current_user)):
            ...

    Returns:
        The authenticated User ORM instance.

    Raises:
        HTTPException 401 if no token, invalid token, revoked token, or user not found/disabled.
    """
    token = _extract_token(credentials)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)

    try:
        user_id = uuid.UUID(payload["sub"])
        org_id = uuid.UUID(payload["org_id"])
    except (ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    # Check token blocklist — single token revocation
    jti = payload.get("jti")
    if jti and _is_token_revoked(jti, db):
        logger.info("Token jti=%s is revoked (logout)", jti)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check bulk revocation sentinel (password change / forced logout all)
    if _is_all_user_tokens_revoked(user_id, db):
        logger.info("All tokens revoked for user=%s (bulk revoke)", user_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="All sessions have been invalidated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Look up the user
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check user is active
    if user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify org_id in token matches user's actual org (defense-in-depth)
    if user.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Set context variable for background tasks / non-request code
    set_current_org_id(org_id)

    return user


async def get_current_organization(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Organization:
    """FastAPI dependency: get the current user's organization.

    Usage:
        @router.get("/org-info")
        def my_route(org: Organization = Depends(get_current_organization)):
            ...

    Returns:
        The Organization ORM instance.
    """
    org = db.query(Organization).filter(Organization.id == current_user.organization_id).first()
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    return org


# ---------------------------------------------------------------------------
# Role-Based Access Control
# ---------------------------------------------------------------------------


def require_role(*allowed_roles: UserRole):
    """Create a dependency that requires the current user to have one of the specified roles.

    Usage:
        @router.delete("/users/{user_id}")
        def delete_user(
            current_user: User = Depends(get_current_user),
            _=Depends(require_role(UserRole.OWNER)),
        ):
            ...

    Args:
        *allowed_roles: The UserRole values that are permitted.

    Returns:
        A FastAPI dependency function.
    """

    async def _check_role(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {', '.join(r.value for r in allowed_roles)}",
            )
        return current_user

    return _check_role


# ---------------------------------------------------------------------------
# Slug Generation
# ---------------------------------------------------------------------------


def generate_organization_slug(name: str, db: Session) -> str:
    """Generate a URL-safe slug from an organization name, handling collisions.

    Examples:
        "ACME Training Ltd." → "acme-training-ltd"
        "ACME Training" (exists) → "acme-training-2"

    Args:
        name: The organization name.
        db: Database session for uniqueness check.

    Returns:
        A unique URL-safe slug string.
    """
    import re

    # Convert to lowercase, replace non-alphanumeric with hyphens
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")

    if not slug:
        slug = "org"

    # Check for collision and append suffix if needed
    base_slug = slug
    counter = 2
    while True:
        existing = db.query(Organization).filter(Organization.slug == slug).first()
        if existing is None:
            break
        slug = f"{base_slug}-{counter}"
        counter += 1

    return slug
