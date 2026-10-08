"""Authentication router - registration, login, /auth/me (Phase 6B.3).

Endpoints:
  POST /auth/register  - Create organization + owner atomically
  POST /auth/login     - Email + password → JWT access token
  GET  /auth/me        - Current user info

SECURITY:
  - Passwords are hashed with bcrypt, never stored or logged
  - password_hash is NEVER returned in any response
  - Login uses generic error to prevent account enumeration
  - Rate limiting applied via middleware
  - Phase 10B: Login brute-force protection via per-email rate limiting
"""
import logging
import time
import uuid
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import (
    create_access_token,
    generate_organization_slug,
    get_current_user,
    hash_password,
    validate_password_strength,
    verify_password,
)
from app.config import settings
from app.database import get_db
from app.models_multi_tenant import (
    OrgScheduleConfig,
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)
from app.schemas_auth import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserInfo,
    build_safe_user_info,
)
from app.services.audit_service import log_audit_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# ── Login brute-force protection (Phase 10B) ──────────────────────────────
# In-memory sliding window rate limiter for failed login attempts.
# Limits per-email: max attempts within a time window before lockout.
# Resilient: if the server restarts, counters reset (acceptable trade-off
# vs. external dependency like Redis for this application's scale).

_LOGIN_MAX_ATTEMPTS = 10       # max failed attempts per email
_LOGIN_WINDOW_SECONDS = 300    # 5-minute sliding window
_login_failures: dict[str, list[float]] = defaultdict(list)  # email → [timestamps]

# M14: per-IP bucket against distributed credential stuffing (many emails
# from one IP).  Generous enough not to hit real users behind NAT.
_LOGIN_IP_MAX_ATTEMPTS = 60
_login_ip_failures: dict[str, list[float]] = defaultdict(list)  # ip → [timestamps]


def _check_login_ip_rate_limit(client_ip: str) -> None:
    """Per-IP login brake. Raises 429 when one IP fails too often."""
    now = time.monotonic()
    _login_ip_failures[client_ip] = [
        t for t in _login_ip_failures[client_ip]
        if now - t < _LOGIN_WINDOW_SECONDS
    ]
    if len(_login_ip_failures[client_ip]) >= _LOGIN_IP_MAX_ATTEMPTS:
        logger.warning(
            "login rate limited: ip=%s attempts=%d window=%ds",
            client_ip, len(_login_ip_failures[client_ip]), _LOGIN_WINDOW_SECONDS,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
        )


def _record_login_ip_failure(client_ip: str) -> None:
    _login_ip_failures[client_ip].append(time.monotonic())


def _check_login_rate_limit(email: str) -> None:
    """Check if the email has exceeded the login rate limit.

    Raises HTTPException 429 if too many failed attempts within the window.
    Clears the counter on success (caller must call _reset_login_rate_limit).
    """
    now = time.monotonic()
    # Prune old timestamps outside the window
    _login_failures[email] = [
        t for t in _login_failures[email]
        if now - t < _LOGIN_WINDOW_SECONDS
    ]
    if len(_login_failures[email]) >= _LOGIN_MAX_ATTEMPTS:
        logger.warning(
            "login rate limited: email=%s attempts=%d window=%ds",
            email, len(_login_failures[email]), _LOGIN_WINDOW_SECONDS,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
        )


def _record_login_failure(email: str) -> None:
    """Record a failed login attempt for rate limiting."""
    _login_failures[email].append(time.monotonic())


def _reset_login_rate_limit(email: str) -> None:
    """Clear the rate limit counter on successful login."""
    _login_failures.pop(email, None)


# ── Registration rate limiting (Phase 20 - P2-A) ────────────────────────
# Per-IP sliding window to prevent registration spam.
_REGISTER_MAX_ATTEMPTS = 5       # max registrations per IP
_REGISTER_WINDOW_SECONDS = 300   # 5-minute sliding window
_register_hits: dict[str, list[float]] = defaultdict(list)


def _check_register_rate_limit(request) -> None:
    """Check if the IP has exceeded the registration rate limit.

    Raises HTTPException 429 if too many registrations within the window.
    Uses the client IP from the request for identification.
    """
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    _register_hits[client_ip] = [
        t for t in _register_hits[client_ip]
        if now - t < _REGISTER_WINDOW_SECONDS
    ]
    if len(_register_hits[client_ip]) >= _REGISTER_MAX_ATTEMPTS:
        logger.warning(
            "register rate limited: ip=%s attempts=%d window=%ds",
            client_ip, len(_register_hits[client_ip]), _REGISTER_WINDOW_SECONDS,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Please try again later.",
        )
    _register_hits[client_ip].append(now)


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Register a new organization and owner user.

    Creates the Organization and User atomically in a single transaction.
    If either creation fails, both are rolled back.

    Returns a JWT access token on success.
    """
    _check_register_rate_limit(request)
    validate_password_strength(payload.password)

    # Check if email already exists in any organization
    existing_user = db.query(User).filter(User.email == payload.email.lower()).first()
    if existing_user is not None:
        # Email exists - but could be in a different org. For now, reject
        # to keep things simple. In the future, multi-org users can be supported.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    slug = generate_organization_slug(payload.organization_name, db)
    password_hash = hash_password(payload.password)

    try:
        # Create organization
        org = Organization(
            name=payload.organization_name,
            slug=slug,
            status=OrganizationStatus.ACTIVE,
            timezone="America/Chicago",
        )
        db.add(org)
        db.flush()  # Get the org.id without committing

        # Create default schedule config for the new org
        # This ensures APScheduler can register per-org jobs immediately.
        sched_config = OrgScheduleConfig(
            organization_id=org.id,
            timezone=org.timezone,
            reminder_enabled=True,
            reminder_hour=8,
            reminder_minute=0,
            rsvp_poll_interval_minutes=10,
            scheduler_enabled=True,
        )
        db.add(sched_config)

        # Create owner user
        user = User(
            organization_id=org.id,
            email=payload.email.lower(),
            full_name=payload.name,
            password_hash=password_hash,
            role=UserRole.OWNER,
            status=UserStatus.ACTIVE,
        )
        db.add(user)
        db.commit()
        db.refresh(org)
        db.refresh(user)

        logger.info(
            "registration successful: org=%s user=%s email=%s role=owner",
            org.id,
            user.id,
            user.email,
        )
        log_audit_event(db, event_type="audit.registration_success",
                        user_id=user.id, organization_id=org.id,
                        detail={"email": user.email, "org_name": org.name})
        db.commit()

        # Register per-org scheduler jobs immediately so the new org's
        # daily_reminder and rsvp_poll jobs are live without a restart.
        # Lazy import avoids circular dependency (main imports this router).
        try:
            from app import main as _main_mod
            _main_mod.reschedule_org_scheduler_jobs(org.id)
        except Exception:
            logger.warning("could not register scheduler jobs for new org %s", org.id)

        # Create and return JWT
        token = create_access_token(
            user_id=user.id,
            organization_id=org.id,
            role=user.role.value,
        )
        return TokenResponse(access_token=token, token_type="bearer")

    except IntegrityError:
        db.rollback()
        logger.warning("registration failed: integrity error for email=%s", payload.email)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )
    except Exception:
        db.rollback()
        logger.exception("registration failed for email=%s", payload.email)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed. Please try again.",
        )


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate with email + password and receive a JWT access token.

    Returns a generic error for invalid credentials to prevent account enumeration.
    Phase 10B: Rate-limited to prevent brute-force attacks.
    """
    # Generic error message - never reveal whether the email exists
    generic_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Phase 10B: Check rate limit BEFORE querying the database.
    # This prevents both enumeration-based and password-based brute force.
    email_lower = payload.email.lower()
    client_ip = request.client.host if request.client else "unknown"
    _check_login_rate_limit(email_lower)
    _check_login_ip_rate_limit(client_ip)

    user = db.query(User).filter(User.email == email_lower).first()
    if user is None:
        # Log at info level only - no password involved.
        # Cannot write audit event: no org to attribute (email doesn't exist).
        logger.info("login failed: email not found")
        _record_login_failure(email_lower)
        _record_login_ip_failure(client_ip)
        db.commit()
        raise generic_error

    if user.password_hash is None:
        # User was created without a password (legacy/OAuth-only)
        logger.info("login failed: user %s has no password hash", user.id)
        _record_login_failure(email_lower)
        _record_login_ip_failure(client_ip)
        log_audit_event(db, event_type="audit.login_failure",
                        user_id=user.id, organization_id=user.organization_id,
                        detail={"reason": "no_password_hash"})
        db.commit()
        raise generic_error

    if not verify_password(payload.password, user.password_hash):
        logger.info("login failed: wrong password for user %s", user.id)
        _record_login_failure(email_lower)
        _record_login_ip_failure(client_ip)
        log_audit_event(db, event_type="audit.login_failure",
                        user_id=user.id, organization_id=user.organization_id,
                        detail={"reason": "wrong_password"})
        db.commit()
        raise generic_error

    if user.status != UserStatus.ACTIVE:
        logger.info("login failed: user %s is disabled", user.id)
        _record_login_failure(email_lower)
        _record_login_ip_failure(client_ip)
        log_audit_event(db, event_type="audit.login_failure",
                        user_id=user.id, organization_id=user.organization_id,
                        detail={"reason": "account_disabled"})
        db.commit()
        raise generic_error

    if user.organization_id is None:
        # Cannot write audit event: user has no org to attribute.
        logger.warning("login failed: user %s has no organization", user.id)
        _record_login_failure(email_lower)
        _record_login_ip_failure(client_ip)
        db.commit()
        raise generic_error

    # Phase 20 P0-B: Check organization status.
    # A suspended/disabled organization must not allow any user to log in.
    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    if org is None or org.status != OrganizationStatus.ACTIVE:
        logger.info(
            "login failed: organization %s is not active (status=%s)",
            user.organization_id,
            org.status.value if org else "missing",
        )
        _record_login_failure(email_lower)
        _record_login_ip_failure(client_ip)
        log_audit_event(db, event_type="audit.login_failure",
                        user_id=user.id, organization_id=user.organization_id,
                        detail={"reason": "organization_inactive",
                                "org_status": org.status.value if org else "missing"})
        db.commit()
        raise generic_error

    # Success - clear the rate limit counter
    _reset_login_rate_limit(email_lower)

    # Phase 28 P1-D: Clear any bulk revocation sentinel from previous
    # password changes/resets.  Without this, newly-issued tokens would
    # still be rejected by _is_all_user_tokens_revoked().
    from app.auth import _clear_bulk_revocation
    _clear_bulk_revocation(user.id, db)

    token = create_access_token(
        user_id=user.id,
        organization_id=user.organization_id,
        role=user.role.value,
    )

    logger.info("login successful: user=%s email=%s role=%s", user.id, user.email, user.role.value)
    log_audit_event(db, event_type="audit.login_success",
                    user_id=user.id, organization_id=user.organization_id,
                    detail={"email": user.email, "role": user.role.value})
    db.commit()
    return TokenResponse(access_token=token, token_type="bearer")


@router.get("/me", response_model=UserInfo)
def me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> UserInfo:
    """Return the current authenticated user's safe profile information.

    Includes organization info. NEVER returns password_hash or credentials.
    """
    org = db.query(Organization).filter(
        Organization.id == current_user.organization_id
    ).first()
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    # Phase 20 P0-B: Reject requests for suspended/disabled organizations.
    if org.status != OrganizationStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization is suspended",
        )
    return build_safe_user_info(current_user, org)


# ══════════════════════════════════════════════════════════════════════════════
# PASSWORD RESET (Phase 20 P1-A)
# ══════════════════════════════════════════════════════════════════════════════

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from app.models_multi_tenant import PasswordResetToken

# Token configuration
_TOKEN_EXPIRY_MINUTES = 30
_TOKEN_BYTE_LENGTH = 32  # 32 bytes = 256 bits of entropy


def _hash_token(token: str) -> str:
    """Hash a reset token with SHA-256 for storage.

    We use SHA-256 (not bcrypt) for the token hash because:
    1. We need exact-match lookup (bcrypt is designed for slow comparison).
    2. The token itself already has high entropy (256 bits).
    3. This is a one-time-use token, not a user-chosen password.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _generate_reset_token() -> tuple[str, str]:
    """Generate a cryptographically secure reset token and its hash.

    Returns:
        (plaintext_token, token_hash) - plaintext is sent via email,
        hash is stored in the database.
    """
    token = secrets.token_urlsafe(_TOKEN_BYTE_LENGTH)
    token_hash = _hash_token(token)
    return token, token_hash


def _invalidate_old_tokens(user_id: uuid.UUID, db: Session) -> None:
    """Mark all unused tokens for a user as used (invalidate)."""
    from sqlalchemy import update

    db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user_id,
            PasswordResetToken.used == False,
        )
        .values(used=True)
    )


def _build_reset_url(token: str) -> str:
    """Build the full password reset URL for email.

    Uses the dashboard base URL with a query parameter containing the token.
    """
    base_url = settings.dashboard_base_url.rstrip("/")
    return f"{base_url}/auth/reset-password?token={token}"


# In-memory rate limiter for forgot-password requests (per email)
_FORGOT_MAX_ATTEMPTS = 5
_FORGOT_WINDOW_SECONDS = 300  # 5 minutes
_forgot_rate_limits: dict[str, list[float]] = defaultdict(list)


def _check_forgot_rate_limit(email: str) -> None:
    """Rate-limit forgot-password requests per email."""
    now = time.monotonic()
    _forgot_rate_limits[email] = [
        t for t in _forgot_rate_limits[email]
        if now - t < _FORGOT_WINDOW_SECONDS
    ]
    if len(_forgot_rate_limits[email]) >= _FORGOT_MAX_ATTEMPTS:
        logger.warning(
            "forgot-password rate limited: email=%s attempts=%d",
            email, len(_forgot_rate_limits[email]),
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset requests. Please try again later.",
        )
    _forgot_rate_limits[email].append(now)


@router.post("/forgot-password", status_code=status.HTTP_200_OK)
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)) -> dict:
    """Request a password reset link.

    SECURITY:
    - Always returns a generic response regardless of whether the email exists
      (prevents account enumeration).
    - Rate-limited to prevent abuse.
    - Only sends emails to ACTIVE users with ACTIVE organizations.
    - Invalidates any previous unused tokens for the user.
    """
    email_lower = payload.email.lower()

    # Rate limit check
    _check_forgot_rate_limit(email_lower)

    generic_response = {
        "message": "If an account exists with that email, a password reset link has been sent.",
    }

    # Look up user - always return the same response
    user = db.query(User).filter(User.email == email_lower).first()
    if user is None:
        logger.info("forgot-password: email not found (returning generic response)")
        return generic_response

    if user.password_hash is None:
        logger.info("forgot-password: user %s has no password hash", user.id)
        return generic_response

    if user.status != UserStatus.ACTIVE:
        logger.info("forgot-password: user %s is not active", user.id)
        return generic_response

    if user.organization_id is None:
        logger.info("forgot-password: user %s has no organization", user.id)
        return generic_response

    # Check organization is active
    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    if org is None or org.status != OrganizationStatus.ACTIVE:
        logger.info("forgot-password: organization for user %s is not active", user.id)
        return generic_response

    # Invalidate old tokens
    _invalidate_old_tokens(user.id, db)

    # Generate new token
    plaintext_token, token_hash = _generate_reset_token()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=_TOKEN_EXPIRY_MINUTES)

    reset_token = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(reset_token)
    db.commit()

    # Phase 28 P1-E: Log audit event BEFORE email attempt so we always
    # record the request, even if email delivery fails.
    log_audit_event(db, event_type="audit.forgot_password_email_sent",
                    user_id=user.id, organization_id=user.organization_id,
                    detail={"email": user.email, "status": "requested"})
    db.commit()

    # Send email (best-effort - don't fail the endpoint if email fails)
    try:
        from app.services.email_service import EmailService as _EmailService
        from app.services.email_templates import (
            build_password_reset_html,
            build_password_reset_subject,
            build_password_reset_text,
        )
        from app.services.integration_config_resolver import IntegrationConfigResolver
        from app.services.org_context import OrganizationContext

        org_ctx = OrganizationContext(organization_id=user.organization_id)
        email_svc = _EmailService(org_context=org_ctx, db=db)

        branding = IntegrationConfigResolver.resolve_branding(db, user.organization_id)

        reset_url = _build_reset_url(plaintext_token)
        subject = build_password_reset_subject()
        html_body = build_password_reset_html(reset_url, branding, _TOKEN_EXPIRY_MINUTES)
        text_body = build_password_reset_text(reset_url, branding, _TOKEN_EXPIRY_MINUTES)

        email_svc.send_email(
            to=user.email,
            subject=subject,
            plain_body=text_body,
            db=db,
            html_body=html_body,
        )
        logger.info("forgot-password: reset email sent to user=%s", user.id)
    except Exception:
        # M10 fix: don't fail SILENTLY.  The client still gets the generic
        # response (anti-enumeration), but the failure is now loud in the
        # logs and recorded on the audit event so an org admin can see
        # that password resets are broken (usually: Gmail not connected).
        logger.exception(
            "forgot-password: FAILED to send reset email to user=%s (org=%s). "
            "The user cannot reset their password until the org's Gmail "
            "integration is connected.",
            user.id, user.organization_id,
        )
        try:
            log_audit_event(db, event_type="audit.forgot_password_email_failed",
                            user_id=user.id, organization_id=user.organization_id,
                            detail={"email": user.email, "status": "email_failed",
                                    "hint": "connect the org Gmail integration"})
            db.commit()
        except Exception:
            db.rollback()

    return generic_response


@router.post("/reset-password", status_code=status.HTTP_200_OK)
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)) -> dict:
    """Reset a user's password using a valid token.

    SECURITY:
    - Token is validated: exists, not expired, not used.
    - Password strength is validated.
    - Old tokens are invalidated after successful reset.
    - Generic response on any failure (prevents token enumeration).
    """
    # Validate password strength first
    validate_password_strength(payload.new_password)

    token_hash = _hash_token(payload.token)

    generic_error = {
        "message": "If a valid reset request exists, your password has been updated.",
    }

    # Look up the token
    reset_token = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == token_hash
    ).first()

    if reset_token is None:
        logger.info("reset-password: token not found")
        return generic_error

    if reset_token.used:
        logger.info("reset-password: token already used (user=%s)", reset_token.user_id)
        return generic_error

    if reset_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        logger.info("reset-password: token expired (user=%s)", reset_token.user_id)
        return generic_error

    # Verify user is still active
    user = db.query(User).filter(User.id == reset_token.user_id).first()
    if user is None or user.status != UserStatus.ACTIVE:
        logger.info("reset-password: user %s not found or inactive", reset_token.user_id)
        return generic_error

    # Verify organization is active
    if user.organization_id is not None:
        org = db.query(Organization).filter(
            Organization.id == user.organization_id
        ).first()
        if org is None or org.status != OrganizationStatus.ACTIVE:
            logger.info("reset-password: org for user %s is not active", user.id)
            return generic_error

    # Mark token as used
    reset_token.used = True

    # Update password
    user.password_hash = hash_password(payload.new_password)

    # Invalidate all other tokens for this user
    _invalidate_old_tokens(user.id, db)

    # Revoke all active JWTs for this user (P1-D: token revocation on password reset)
    from app.auth import revoke_all_user_tokens
    revoke_all_user_tokens(
        user_id=user.id,
        organization_id=user.organization_id,
        reason="password_reset",
        db=db,
    )

    db.commit()

    logger.info("reset-password: password reset successful for user=%s", user.id)
    log_audit_event(db, event_type="audit.password_reset",
                    user_id=user.id, organization_id=user.organization_id,
                    detail={"reason": "token_based_reset"})
    db.commit()
    return generic_error


# ══════════════════════════════════════════════════════════════════════════════
# LOGOUT & PASSWORD CHANGE (Phase 28 - P1-D / P1-C)
# ══════════════════════════════════════════════════════════════════════════════

from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer_scheme = HTTPBearer(auto_error=False)

from app.auth import (
    decode_access_token,
    revoke_all_user_tokens,
    revoke_token,
)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    """Logout the current user by revoking the active JWT.

    SECURITY:
    - Adds the token's jti to the blocklist so it can no longer be used.
    - Subsequent requests with this token will receive 401.
    - The user must log in again to get a new token.
    - Returns 204 No Content on success (idempotent).
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(credentials.credentials)
    except HTTPException:
        # Token already invalid - this is effectively a no-op logout
        return

    jti = payload.get("jti")
    if jti:
        try:
            exp_ts = payload.get("exp")
            expires_at = None
            if exp_ts:
                from datetime import datetime as _dt
                expires_at = _dt.fromtimestamp(exp_ts, tz=timezone.utc)
            revoke_token(
                jti=jti,
                user_id=current_user.id,
                organization_id=current_user.organization_id,
                reason="logout",
                expires_at=expires_at,
                db=db,
            )
            logger.info("logout: token revoked jti=%s user=%s", jti, current_user.id)
            log_audit_event(db, event_type="audit.logout",
                            user_id=current_user.id, organization_id=current_user.organization_id,
                            detail={"jti": jti})
            db.commit()
        except Exception:
            # Log but don't fail the logout - the token will expire naturally
            logger.exception("logout: failed to revoke token jti=%s", jti)


@router.post("/change-password", status_code=status.HTTP_200_OK)
def change_password(
    body: "ChangePasswordRequest",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Change the current user's password (requires current password).

    SECURITY:
    - Validates current password before allowing change.
    - Validates new password meets strength requirements.
    - Invalidates ALL existing tokens for the user (forced re-login).
    - Returns a generic message regardless of outcome details.
    """
    from app.auth import verify_password

    # Verify current password
    if not verify_password(body.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    # Validate new password strength
    validate_password_strength(body.new_password)

    # Prevent reuse of current password
    if body.current_password == body.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password",
        )

    # Update password
    current_user.password_hash = hash_password(body.new_password)

    # Invalidate ALL tokens for this user (bulk revocation)
    revoke_all_user_tokens(
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        reason="password_change",
        db=db,
    )

    db.commit()

    logger.info(
        "change-password: password changed for user=%s org=%s",
        current_user.id, current_user.organization_id,
    )
    log_audit_event(db, event_type="audit.password_change",
                    user_id=current_user.id, organization_id=current_user.organization_id,
                    detail={"reason": "user_initiated"})
    db.commit()
    return {"message": "Password updated successfully. Please log in again."}
