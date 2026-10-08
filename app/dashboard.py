"""Read-only admin dashboard (Phase 4 + 6B.3 + 6B.6).

Pure observability - ZERO new business logic. No state transitions, no
emails, no Calendar calls. It only reads what already exists in the DB.

Auth: Supports BOTH:
  1. HTTP Basic (DASHBOARD_USERNAME / DASHBOARD_PASSWORD) - platform admin
  2. Bearer JWT - customer users (organization-scoped data)

Both mechanisms are validated in constant-time where applicable.

Phase 6B.6: Full multi-tenant isolation.  Every endpoint derives
org_id from the authenticated identity - never from client input.
Role-based access control enforced on write endpoints (settings, triggers).
"""
from __future__ import annotations

import base64 as _b64
import json
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
)
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.events import publish_event
from app.models import (
    ALLOWED_FOLLOWUP_TRANSITIONS,
    CallOutcome,
    EventLog,
    FailedJob,
    FollowUp,
    FollowUpPriority,
    FollowUpStatus,
    Lead,
    LeadStatus,
)
from app.models_multi_tenant import Organization, OrganizationStatus, User, UserStatus
from app.schemas import (
    ALLOWED_STATUS_TRANSITIONS,
    CancelCallRequest,
    CreateFollowUpRequest,
    EditLeadRequest,
    FollowUpStatusRequest,
    ManualLeadRequest,
    RescheduleCallRequest,
    UpdateCallRequest,
    UpdateFollowUpRequest,
    UpdateStatusRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
_security = HTTPBasic(auto_error=False)
_bearer = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# AuthContext - carries identity + role + org for downstream authorization
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthContext:
    """Rich auth context returned by _auth_context().

    Carries both the org scope AND the user's role so that downstream
    endpoints can enforce role-based access control without a second DB
    round-trip.

    Attributes:
        org_id:    Organization UUID for the authenticated user (customer).
                   None for platform admin (sees all data).
        user_id:   User UUID.  None for platform admin.
        role:      User role string ("owner", "admin", "member", "platform").
                   "platform" for HTTP Basic admin.
        is_platform_admin: True when authenticated via HTTP Basic.
    """
    org_id: uuid.UUID | None
    user_id: uuid.UUID | None
    role: str
    is_platform_admin: bool = False


def _auth(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(_security),
    bearer: HTTPAuthorizationCredentials = Depends(_bearer),
) -> uuid.UUID | None:
    """Combined auth dependency supporting both HTTP Basic (platform admin)
    and Bearer JWT (customer users).

    Returns:
        - None if authenticated via HTTP Basic (platform admin - no org scope)
        - organization_id if authenticated via JWT (customer user)

    Platform admin sees ALL data (backward compatible).
    Customer user sees ONLY their organization's data.
    """
    ctx = _resolve_auth_context(request, credentials, bearer)
    return ctx.org_id


def _auth_context(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(_security),
    bearer: HTTPAuthorizationCredentials = Depends(_bearer),
) -> AuthContext:
    """Rich auth dependency returning an AuthContext with org_id, role, etc.

    Use this in endpoints that need role-based access control (settings
    write, trigger execution, user management).
    """
    return _resolve_auth_context(request, credentials, bearer)


def _resolve_auth_context(
    request: Request,
    credentials: HTTPBasicCredentials | None,
    bearer: HTTPAuthorizationCredentials | None,
) -> AuthContext:
    """Core auth resolution - shared by _auth() and _auth_context().

    Tries JWT Bearer first, then HTTP Basic.  Returns AuthContext.
    Raises HTTPException 401 on failure.
    """
    # Try JWT Bearer first (customer users)
    if bearer and bearer.credentials:
        from app.auth import (
            _is_all_user_tokens_revoked,
            _is_token_revoked,
            decode_access_token,
        )
        try:
            payload = decode_access_token(bearer.credentials)
            org_id = uuid.UUID(payload["org_id"])
            user_id = uuid.UUID(payload["sub"])
            jti = payload.get("jti")
            role = payload.get("role", "member")
            # Validate user exists and is active
            from app.database import SessionLocal
            db = SessionLocal()
            try:
                # P0-C: Check token blocklist - revoked tokens must not
                # grant dashboard access.  Matches get_current_user() logic.
                if jti and _is_token_revoked(jti, db):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Token has been revoked",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                if _is_all_user_tokens_revoked(user_id, db):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="All sessions have been invalidated",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

                user = db.query(User).filter(User.id == user_id).first()
                if user is None or user.status != UserStatus.ACTIVE:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or expired token",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                if user.organization_id != org_id:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid token payload",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                # Use the canonical role from the DB, not the token
                # (defense-in-depth against role escalation via token tampering).
                role = user.role.value if user.role else "member"

                # Phase 20 P0-B: Check organization status.
                # A suspended/disabled organization blocks all API access.
                org = db.query(Organization).filter(
                    Organization.id == user.organization_id
                ).first()
                if org is None or org.status != OrganizationStatus.ACTIVE:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Organization is suspended",
                    )
            finally:
                db.close()
            return AuthContext(org_id=org_id, user_id=user_id, role=role)
        except HTTPException:
            raise
        except Exception:
            # JWT failed, fall through to try Basic auth
            pass

    # Fallback: HTTP Basic auth (platform admin)
    if credentials:
        ok = bool(settings.dashboard_username and settings.dashboard_password) and (
            secrets.compare_digest(credentials.username, settings.dashboard_username)
            and secrets.compare_digest(credentials.password, settings.dashboard_password)
        )
        if ok:
            return AuthContext(
                org_id=None,
                user_id=None,
                role="platform",
                is_platform_admin=True,
            )

    # Neither auth method succeeded
    # Determine which WWW-Authenticate to use
    if bearer and bearer.credentials:
        # Had a Bearer token but it was invalid
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # No auth at all or wrong Basic credentials
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Basic"},
    )


def _require_owner_or_admin(ctx: AuthContext) -> None:
    """Raise 403 if the user is not an owner, admin, or platform admin."""
    if ctx.is_platform_admin:
        return  # Platform admins can do everything
    if ctx.role not in ("owner", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Required: owner or admin",
        )


def _fmt_local(dt_utc: datetime | None, tz: ZoneInfo) -> str | None:
    """Human-readable local time, or None if the timestamp is missing."""
    if dt_utc is None:
        return None
    local = dt_utc.astimezone(tz)
    hour = local.hour % 12 or 12
    ampm = "AM" if local.hour < 12 else "PM"
    return f"{local.year}-{local.month:02d}-{local.day:02d} {hour}:{local.minute:02d} {ampm} {local.tzname()}"


def _lead_row(lead: Lead, tz: ZoneInfo) -> dict:
    """Build a safe API response row for a lead.

    Phase 9: Null-safe - every field is guarded against None values
    that could cause downstream errors in the frontend or API consumers.
    Phase 10: Added appt_datetime_raw for edit form support.
    """
    return {
        "id": str(lead.id) if lead.id else None,
        "prospect_name": str(lead.name) if lead.name else "Unknown",
        "company_address": str(lead.company_address) if lead.company_address else None,
        "email": str(lead.email) if lead.email else None,
        "phone_number": str(lead.phone_number) if lead.phone_number else None,
        "direct_number": str(lead.direct_number) if lead.direct_number else None,
        "courses": str(lead.courses) if lead.courses else None,
        "status": lead.status.value if lead.status else "unknown",
        "appt_datetime_raw": str(lead.appt_datetime_raw) if lead.appt_datetime_raw else None,
        "appt_datetime_utc": lead.appt_datetime_utc.isoformat() if lead.appt_datetime_utc else None,
        "appt_local": _fmt_local(lead.appt_datetime_utc, tz) if lead.appt_datetime_utc else None,
        "customer_timezone": str(lead.customer_timezone) if lead.customer_timezone else None,
        "calendar_event_id": str(lead.calendar_event_id) if lead.calendar_event_id else None,
        "reminder_sent_at": lead.reminder_sent_at.isoformat() if lead.reminder_sent_at else None,
        "processing_started_at": lead.processing_started_at.isoformat() if lead.processing_started_at else None,
        # Phase 12: Call management fields
        "call_outcome": lead.call_outcome.value if lead.call_outcome else None,
        "call_notes": str(lead.call_notes) if lead.call_notes else None,
        "call_duration_minutes": lead.call_duration_minutes,
        "cancelled_at": lead.cancelled_at.isoformat() if lead.cancelled_at else None,
        "reschedule_count": lead.reschedule_count or 0,
        "assigned_to": str(lead.assigned_to) if lead.assigned_to else None,
        "created_at": lead.created_at.isoformat() if lead.created_at else None,
        "updated_at": lead.updated_at.isoformat() if lead.updated_at else None,
        "organization_id": str(lead.organization_id) if lead.organization_id else None,
    }


@router.post("/api/leads", status_code=201)
def create_lead(
    body: ManualLeadRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Create a manual lead from the dashboard UI.

    Owner and admin roles can create leads. Members are rejected with 403.
    Organization is derived from the authenticated JWT - never from client input.
    The lead enters the same pipeline as webhook-submitted leads.
    """
    # RBAC: only owner, admin, or platform admin can create leads
    if not ctx.is_platform_admin and ctx.role not in ("owner", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Required: owner or admin",
        )
    if ctx.org_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization context required",
        )

    # ── Phase 23: Entitlement check - lead limit ───────────────────────

    import dateparser as _dateparser
    from sqlalchemy.exc import IntegrityError

    # M9 fix: parse in the ORG's timezone, exactly like the webhook path
    # (_parse_appt_utc with business_tz).  The old code parsed naive
    # input as UTC, so "tomorrow 2pm" landed hours off for manual leads.
    from app.main import _parse_appt_utc, _resolve_customer_tz
    from app.models_multi_tenant import Organization as _Organization

    _org_row = (
        db.query(_Organization)
        .filter(_Organization.id == ctx.org_id)
        .first()
    )
    _business_tz = (
        _org_row.timezone
        if _org_row and getattr(_org_row, "timezone", None)
        else None
    )

    # Parse appointment datetime
    appt_utc = _parse_appt_utc(body.appt_datetime_raw, business_tz=_business_tz)
    customer_tz = None
    if body.appt_datetime_raw:
        # Resolve IANA timezone for storage
        customer_tz = _resolve_customer_tz(body.appt_datetime_raw, business_tz=_business_tz) or None

    # Build dedupe key (M8: org-scoped; M11: normalized instant)
    dedupe_key = body.compute_dedupe_key(
        organization_id=str(ctx.org_id),
        appt_utc=appt_utc,
    )

    # Create lead
    lead = Lead(
        name=body.name,
        email=str(body.email),
        phone_number=body.phone_number,
        company_address=body.company_address,
        appt_datetime_raw=body.appt_datetime_raw,
        appt_datetime_utc=appt_utc,
        customer_timezone=customer_tz,
        dedupe_key=dedupe_key,
        status=LeadStatus.PENDING,
        organization_id=ctx.org_id,
        assigned_to=body.assigned_to,
    )
    db.add(lead)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A lead with this email and appointment time already exists",
        )
    db.refresh(lead)

    # Log event
    from app.main import _log_event
    _log_event(
        db, lead.id, "manual_lead_created",
        {"name": body.name, "email": str(body.email)},
        organization_id=ctx.org_id,
    )

    # Publish SSE event
    publish_event(
        "lead.created",
        {"lead_id": str(lead.id), "name": body.name},
        organization_id=ctx.org_id,
    )

    # Kick off pipeline in background
    from app.main import run_pipeline
    background_tasks.add_task(run_pipeline, lead.id)

    tz = ZoneInfo(settings.business_timezone)
    return {
        "status": "created",
        "lead": _lead_row(lead, tz),
    }


@router.patch("/api/leads/{lead_id}")
def edit_lead(
    lead_id: uuid.UUID,
    body: EditLeadRequest,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Edit lead information. Only owner/admin may edit.

    Editable fields: name, email, phone_number, company_address,
    appt_datetime_raw. All are optional (partial update).
    Protected fields (id, org_id, dedupe_key, status, calendar_event_id,
    timestamps, pipeline fields) are NOT editable here.
    """
    _require_owner_or_admin(ctx)

    if ctx.org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required")

    lead = db.get(Lead, lead_id)
    if lead is None:
        raise HTTPException(status_code=404, detail="lead not found")
    if lead.organization_id != ctx.org_id:
        raise HTTPException(status_code=404, detail="lead not found")

    # Track what changed for audit event
    changes: dict[str, dict] = {}
    fields_to_update = body.model_dump(exclude_unset=True)
    if not fields_to_update:
        raise HTTPException(status_code=400, detail="No fields to update")

    for field, new_value in fields_to_update.items():
        old_value = getattr(lead, field, None)
        # Normalize for comparison
        old_cmp = str(old_value) if old_value is not None else None
        new_cmp = str(new_value) if new_value is not None else None
        if old_cmp != new_cmp:
            changes[field] = {"old": old_value, "new": new_value}
            setattr(lead, field, new_value)

    if not changes:
        raise HTTPException(status_code=400, detail="No changes detected")

    # If email or appt_datetime_raw changed, rebuild dedupe_key
    if "email" in changes or "appt_datetime_raw" in changes:
        import re as _re
        email = str(lead.email).strip().lower()
        appt = _re.sub(r"\s+", " ", lead.appt_datetime_raw.strip().lower())
        prefix = lead.dedupe_key.split("|")[0] + "|" if "|" in lead.dedupe_key else ""
        new_dedupe_key = f"{prefix}{email}|{appt}"
        if new_dedupe_key != lead.dedupe_key:
            lead.dedupe_key = new_dedupe_key

    # If appt_datetime_raw changed, re-parse the UTC timestamp
    if "appt_datetime_raw" in changes:
        import dateparser as _dateparser
        parsed = _dateparser.parse(
            lead.appt_datetime_raw,
            settings={"RETURN_AS_TIMEZONE_AWARE": True},
        )
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            lead.appt_datetime_utc = parsed.astimezone(timezone.utc)
        else:
            lead.appt_datetime_utc = None
        # Re-resolve the customer timezone from the updated raw string
        from app.main import _resolve_customer_tz
        lead.customer_timezone = _resolve_customer_tz(lead.appt_datetime_raw) or None

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=409, detail="Update failed - possible duplicate email/appointment")

    db.refresh(lead)

    # Audit event
    from app.main import _log_event
    _log_event(
        db, lead.id, "lead_updated",
        {"changes": {k: {"old": str(v["old"]), "new": str(v["new"])} for k, v in changes.items()}},
        organization_id=ctx.org_id,
    )

    publish_event(
        "lead.updated",
        {"lead_id": str(lead.id), "changes": list(changes.keys())},
        organization_id=ctx.org_id,
    )

    tz = ZoneInfo(settings.business_timezone)
    return {"status": "updated", "lead": _lead_row(lead, tz)}


@router.patch("/api/leads/{lead_id}/status")
def update_lead_status(
    lead_id: uuid.UUID,
    body: UpdateStatusRequest,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Change lead status through validated transitions.

    Only owner/admin may change status. Transitions are validated against
    the business rules defined in ALLOWED_STATUS_TRANSITIONS.
    """
    _require_owner_or_admin(ctx)

    if ctx.org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required")

    lead = db.get(Lead, lead_id)
    if lead is None:
        raise HTTPException(status_code=404, detail="lead not found")
    if lead.organization_id != ctx.org_id:
        raise HTTPException(status_code=404, detail="lead not found")

    current_status = lead.status.value
    new_status = body.status.value

    if current_status == new_status:
        raise HTTPException(status_code=400, detail="Lead is already in that status")

    allowed = ALLOWED_STATUS_TRANSITIONS.get(current_status, set())
    if new_status not in allowed:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid transition: {current_status} → {new_status}. "
                   f"Allowed from {current_status}: {', '.join(sorted(allowed)) if allowed else 'none (terminal state)'}",
        )

    old_status = current_status
    lead.status = body.status

    # Phase 7 Part 3: Auto-cancellation cascade - when a lead enters a
    # terminal state, cancel all pending follow-ups to prevent the scheduler
    # from contacting a lead that is no longer eligible for outreach.
    # Cascade runs BEFORE commit so status change + cancellation are atomic.
    from app.services.followup_cancellation import (
        cancel_pending_followups_for_lead,
        is_terminal_lead_status,
    )
    if is_terminal_lead_status(new_status):
        cancel_pending_followups_for_lead(db, lead.id, ctx.org_id)

    # Phase 28+: Release Google Calendar event when a lead enters a
    # terminal state.  Follows the same pattern as cancel_call() - the
    # release is best-effort; a Google API failure is logged but does not
    # prevent the DB status change from committing.
    if is_terminal_lead_status(new_status) and lead.calendar_event_id:
        try:
            from app.services.calendar_service import CalendarService
            from app.services.org_context import OrganizationContext
            org_ctx = OrganizationContext.from_id(ctx.org_id)
            svc = CalendarService(org_context=org_ctx, db=db)
            svc.release_calendar_event(
                lead.calendar_event_id,
                lead.name,
                db,
            )
        except Exception as exc:
            from app.main import _log_event
            _log_event(
                db, lead.id, "calendar_cancel_error",
                {"error": str(exc)},
                organization_id=ctx.org_id,
            )

    db.commit()
    db.refresh(lead)

    # Audit event
    from app.main import _log_event
    _log_event(
        db, lead.id, "lead_status_changed",
        {"old_status": old_status, "new_status": new_status},
        organization_id=ctx.org_id,
    )

    publish_event(
        "lead.status_changed",
        {"lead_id": str(lead.id), "old_status": old_status, "new_status": new_status},
        organization_id=ctx.org_id,
    )

    tz = ZoneInfo(settings.business_timezone)
    return {"status": "updated", "lead": _lead_row(lead, tz)}


# ── Phase 12: Call Management Endpoints ──────────────────────────────


@router.patch("/api/leads/{lead_id}/call")
def update_call(
    lead_id: uuid.UUID,
    body: UpdateCallRequest,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Update call outcome, notes, and/or duration for a lead.

    Owner and admin roles can update call details.
    Validates that the lead exists and belongs to the user's organization.
    """
    _require_owner_or_admin(ctx)
    if ctx.org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required")

    lead = db.get(Lead, lead_id)
    if lead is None:
        raise HTTPException(status_code=404, detail="lead not found")
    if lead.organization_id != ctx.org_id:
        raise HTTPException(status_code=404, detail="lead not found")

    fields = body.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")

    # Track changes for audit
    changes: dict[str, dict] = {}
    for field, new_value in fields.items():
        old_value = getattr(lead, field, None)
        old_cmp = str(old_value) if old_value is not None else None
        new_cmp = str(new_value) if new_value is not None else None
        if old_cmp != new_cmp:
            changes[field] = {"old": old_value, "new": new_value}
            setattr(lead, field, new_value)

    if not changes:
        raise HTTPException(status_code=400, detail="No changes detected")

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update call details")
    db.refresh(lead)

    # Audit event
    from app.main import _log_event
    _log_event(
        db, lead.id, "call_updated",
        {"changes": {k: {"old": str(v["old"]), "new": str(v["new"])} for k, v in changes.items()}},
        organization_id=ctx.org_id,
    )

    # Phase 23: Auto-create follow-up when call_outcome is set
    if "call_outcome" in changes and lead.call_outcome is not None:
        try:
            from app.services.auto_followup_service import create_post_call_followups
            create_post_call_followups(db, lead, lead.call_outcome, ctx.org_id)
        except Exception as exc:
            logger.warning("auto follow-up creation failed for lead %s: %s", lead.id, exc)

    publish_event(
        "call.updated",
        {"lead_id": str(lead.id), "changes": list(changes.keys())},
        organization_id=ctx.org_id,
    )

    tz = ZoneInfo(settings.business_timezone)
    return {"status": "updated", "lead": _lead_row(lead, tz)}


@router.post("/api/leads/{lead_id}/cancel")
def cancel_call(
    lead_id: uuid.UUID,
    body: CancelCallRequest,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Cancel a scheduled call.

    Sets lead status to DECLINED, records cancelled_at timestamp,
    sets call_outcome to CANCELLED, and optionally patches the
    Google Calendar event.
    """
    _require_owner_or_admin(ctx)
    if ctx.org_id is None and not ctx.is_platform_admin:
        raise HTTPException(status_code=400, detail="Organization context required")

    lead = db.get(Lead, lead_id)
    if lead is None:
        raise HTTPException(status_code=404, detail="lead not found")
    if not ctx.is_platform_admin and lead.organization_id != ctx.org_id:
        raise HTTPException(status_code=404, detail="lead not found")

    # Validate: can only cancel if not already terminal
    terminal = {"completed", "declined", "not_interested", "error"}
    if lead.status.value in terminal:
        raise HTTPException(
            status_code=422,
            detail=f"Cannot cancel a call in '{lead.status.value}' status",
        )

    old_status = lead.status.value
    now_utc = datetime.now(timezone.utc)

    # Derive org_id from the lead (always non-nullable) rather than from
    # ctx.org_id which is None for platform-admin requests.  After the
    # authorization checks above this is guaranteed to be the correct
    # tenant scope.
    org_id = lead.organization_id

    # Update lead fields
    lead.status = LeadStatus.DECLINED
    lead.call_outcome = CallOutcome.CANCELLED
    lead.cancelled_at = now_utc

    # Phase 7 Part 3: Auto-cancellation cascade - lead is entering DECLINED
    # (terminal).  Cancel pending follow-ups now, before other work.
    from app.services.followup_cancellation import cancel_pending_followups_for_lead
    cancel_pending_followups_for_lead(db, lead.id, org_id)

    # Phase 28: Release calendar event using org-scoped credentials.
    # Uses release_calendar_event() for idempotent, tenant-safe release.
    if lead.calendar_event_id:
        try:
            from app.services.calendar_service import CalendarService
            from app.services.org_context import OrganizationContext
            org_ctx = OrganizationContext.from_id(org_id)
            svc = CalendarService(org_context=org_ctx, db=db)
            svc.release_calendar_event(
                lead.calendar_event_id,
                lead.name,
                db,
            )
        except Exception as exc:
            # Log but don't fail the cancel - the DB state is updated
            from app.main import _log_event
            _log_event(
                db, lead.id, "calendar_cancel_error",
                {"error": str(exc)},
                organization_id=org_id,
            )

    # Phase 6B.5: Cancel Zoom meeting if the lead has one.
    if lead.zoom_meeting_id:
        try:
            from app.services.meeting_provider import (
                ZoomMeetingProvider,
                resolve_meeting_provider,
            )
            from app.services.org_context import OrganizationContext
            org_ctx = OrganizationContext.from_id(org_id)
            provider = resolve_meeting_provider(org_context=org_ctx, db=db)
            if isinstance(provider, ZoomMeetingProvider):
                provider.cancel_meeting(lead.zoom_meeting_id)
        except Exception as exc:
            from app.main import _log_event
            _log_event(
                db, lead.id, "zoom_cancel_error",
                {"error": str(exc)[:200], "meeting_id": lead.zoom_meeting_id},
                organization_id=org_id,
            )

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to cancel call")
    db.refresh(lead)

    # Audit event
    from app.main import _log_event
    _log_event(
        db, lead.id, "call_cancelled",
        {
            "old_status": old_status,
            "reason": body.reason,
        },
        organization_id=org_id,
    )

    publish_event(
        "call.cancelled",
        {
            "lead_id": str(lead.id),
            "old_status": old_status,
            "reason": body.reason,
        },
        organization_id=org_id,
    )

    tz = ZoneInfo(settings.business_timezone)
    return {"status": "cancelled", "lead": _lead_row(lead, tz)}


@router.post("/api/leads/{lead_id}/reschedule")
def reschedule_call(
    lead_id: uuid.UUID,
    body: RescheduleCallRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Reschedule a call to a new date/time.

    Updates appt_datetime_raw, re-parses the UTC timestamp,
    increments reschedule_count, and optionally re-patches the
    Google Calendar event.
    """
    _require_owner_or_admin(ctx)
    if ctx.org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required")

    lead = db.get(Lead, lead_id)
    if lead is None:
        raise HTTPException(status_code=404, detail="lead not found")
    if lead.organization_id != ctx.org_id:
        raise HTTPException(status_code=404, detail="lead not found")

    # Validate: can only reschedule if not already terminal
    terminal = {"completed", "declined", "not_interested", "error"}
    if lead.status.value in terminal:
        raise HTTPException(
            status_code=422,
            detail=f"Cannot reschedule a call in '{lead.status.value}' status",
        )

    import dateparser as _dateparser
    old_appt = lead.appt_datetime_raw

    # Parse new appointment datetime
    parsed = _dateparser.parse(
        body.appt_datetime_raw,
        settings={"RETURN_AS_TIMEZONE_AWARE": True},
    )
    if parsed is not None:
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        new_appt_utc = parsed.astimezone(timezone.utc)
    else:
        new_appt_utc = None

    # Resolve customer timezone from the new raw string
    from app.main import _resolve_customer_tz
    new_customer_tz = _resolve_customer_tz(body.appt_datetime_raw) or None

    lead.appt_datetime_raw = body.appt_datetime_raw
    lead.appt_datetime_utc = new_appt_utc
    lead.customer_timezone = new_customer_tz
    lead.reschedule_count = (lead.reschedule_count or 0) + 1

    # Update dedupe key (email stays same, appt changes)
    import re as _re
    email = str(lead.email).strip().lower()
    appt_norm = _re.sub(r"\s+", " ", body.appt_datetime_raw.strip().lower())
    prefix = lead.dedupe_key.split("|")[0] + "|" if "|" in lead.dedupe_key else ""
    new_dedupe_key = f"{prefix}{email}|{appt_norm}"
    lead.dedupe_key = new_dedupe_key

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=409, detail="Reschedule failed - possible duplicate")
    db.refresh(lead)

    # Audit event
    from app.main import _log_event
    _log_event(
        db, lead.id, "call_rescheduled",
        {
            "old_appt": old_appt,
            "new_appt": body.appt_datetime_raw,
            "reason": body.reason,
            "reschedule_count": lead.reschedule_count,
        },
        organization_id=ctx.org_id,
    )

    publish_event(
        "call.rescheduled",
        {
            "lead_id": str(lead.id),
            "old_appt": old_appt,
            "new_appt": body.appt_datetime_raw,
            "reschedule_count": lead.reschedule_count,
        },
        organization_id=ctx.org_id,
    )

    # Phase 28: Patch calendar event with new start/end time using org-scoped credentials.
    if lead.calendar_event_id and new_appt_utc is not None:
        try:
            from app.services.calendar_service import CalendarService
            from app.services.org_context import OrganizationContext
            org_ctx = OrganizationContext.from_id(ctx.org_id)
            svc = CalendarService(org_context=org_ctx, db=db)
            svc.update_event_reschedule(
                lead.calendar_event_id,
                new_appt_utc,
                svc._meeting_duration,
                f"Strategy Call: {lead.name}",
                db,
            )
        except Exception as exc:
            # Log but don't fail the reschedule - the DB state is updated
            _log_event(
                db, lead.id, "calendar_reschedule_error",
                {"error": str(exc), "new_appt_utc": new_appt_utc.isoformat()},
                organization_id=ctx.org_id,
            )

    # Phase 6B.5: Reschedule Zoom meeting - cancel old + create new with updated time.
    if lead.zoom_meeting_id and new_appt_utc is not None:
        try:
            from app.services.meeting_provider import (
                DEFAULT_MEETING_DURATION_MINUTES,
                ZoomMeetingProvider,
                resolve_meeting_provider,
            )
            from app.services.org_context import OrganizationContext
            org_ctx = OrganizationContext.from_id(ctx.org_id)
            provider = resolve_meeting_provider(org_context=org_ctx, db=db)
            if isinstance(provider, ZoomMeetingProvider):
                # Cancel the old meeting
                try:
                    provider.cancel_meeting(lead.zoom_meeting_id)
                except Exception:
                    pass  # best-effort: old meeting may already be gone
                # Create a new meeting at the new time
                details = provider.create_meeting(
                    summary=f"Strategy Call: {lead.name}",
                    description=f"Rescheduled strategy call for {lead.name}",
                    start_utc=new_appt_utc,
                    duration_minutes=DEFAULT_MEETING_DURATION_MINUTES,
                    attendees=[lead.email] if lead.email else [],
                    idempotency_key=f"reschedule-{lead.id}-{lead.reschedule_count}",
                    timezone=settings.business_timezone,
                )
                lead.zoom_meeting_id = details.meeting_id
                lead.zoom_join_url = details.meeting_link
        except Exception as exc:
            _log_event(
                db, lead.id, "zoom_reschedule_error",
                {"error": str(exc)[:200], "old_meeting_id": lead.zoom_meeting_id},
                organization_id=ctx.org_id,
            )

    tz = ZoneInfo(settings.business_timezone)
    return {"status": "rescheduled", "lead": _lead_row(lead, tz)}


@router.get("/api/leads")
def list_leads(
    status: str | None = Query(default=None),
    exclude_status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    org_id: uuid.UUID | None = Depends(_auth),
) -> dict:
    """All leads, most recent first. Optional ?status= filter + pagination.

    Customer users (org_id set) see only their organization's leads.
    Platform admins (org_id=None) see all leads.

    Query params:
      ?status=X           – only return leads with this status
      ?exclude_status=X,Y – exclude leads with these statuses (comma-separated)
    """
    tz = ZoneInfo(settings.business_timezone)
    q = db.query(Lead)
    if org_id is not None:
        q = q.filter(Lead.organization_id == org_id)
    if status:
        # Validate status value to avoid DataError from invalid enum
        valid_statuses = {s.value for s in LeadStatus}
        if status not in valid_statuses:
            return {
                "total": 0,
                "limit": limit,
                "offset": offset,
                "leads": [],
                "error": f"Invalid status '{status}'. Valid: {', '.join(sorted(valid_statuses))}",
            }
        q = q.filter(Lead.status == status)
    if exclude_status:
        valid_statuses = {s.value for s in LeadStatus}
        exclude_list = [s.strip() for s in exclude_status.split(',') if s.strip()]
        invalid = [s for s in exclude_list if s not in valid_statuses]
        if invalid:
            return {
                "total": 0,
                "limit": limit,
                "offset": offset,
                "leads": [],
                "error": f"Invalid exclude_status value(s): {', '.join(invalid)}. Valid: {', '.join(sorted(valid_statuses))}",
            }
        if exclude_list:
            q = q.filter(Lead.status.notin_(exclude_list))
    total = q.count()
    leads = q.order_by(Lead.created_at.desc()).limit(limit).offset(offset).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "leads": [_lead_row(lead, tz) for lead in leads],
    }


@router.get("/api/leads/export")
def export_leads_csv(
    status: str | None = Query(default=None),
    db: Session = Depends(get_db),
    org_id: uuid.UUID | None = Depends(_auth),
):
    """Export all leads as a CSV download.

    Customer users (org_id set) see only their organization's leads.
    Platform admins (org_id=None) see all leads.
    Optional ?status= filter. Streams CSV for large datasets.
    """
    import csv
    import io

    tz = ZoneInfo(settings.business_timezone)
    q = db.query(Lead)
    if org_id is not None:
        q = q.filter(Lead.organization_id == org_id)
    if status:
        valid_statuses = {s.value for s in LeadStatus}
        if status not in valid_statuses:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status '{status}'. Valid: {', '.join(sorted(valid_statuses))}",
            )
        q = q.filter(Lead.status == status)
    leads = q.order_by(Lead.created_at.desc()).all()

    # CSV columns (human-readable headers)
    fieldnames = [
        "id", "prospect_name", "email", "phone_number", "direct_number",
        "company_address", "courses", "status", "appt_datetime_raw",
        "appt_datetime_utc", "appt_local", "calendar_event_id",
        "reminder_sent_at", "processing_started_at", "call_outcome",
        "call_notes", "call_duration_minutes", "cancelled_at",
        "reschedule_count", "created_at", "updated_at", "organization_id",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for lead in leads:
        row = _lead_row(lead, tz)
        writer.writerow({k: row.get(k, "") for k in fieldnames})

    from fastapi.responses import StreamingResponse

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=leads_export.csv"},
    )


@router.get("/api/leads/upcoming")
def upcoming_leads(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    org_id: uuid.UUID | None = Depends(_auth),
) -> dict:
    """Leads with future appointments, ordered by appointment time."""
    tz = ZoneInfo(settings.business_timezone)
    now_utc = datetime.now(timezone.utc)
    q = (
        db.query(Lead)
        .filter(Lead.appt_datetime_utc.isnot(None))
        .filter(Lead.appt_datetime_utc >= now_utc)
        .filter(Lead.status.in_(["scheduled", "accepted", "tentative"]))
    )
    if org_id is not None:
        q = q.filter(Lead.organization_id == org_id)
    leads = q.order_by(Lead.appt_datetime_utc.asc()).limit(limit).all()
    return {
        "count": len(leads),
        "leads": [_lead_row(lead, tz) for lead in leads],
    }


@router.get("/api/activity/recent")
def recent_activity(
    limit: int = Query(default=15, ge=1, le=50),
    db: Session = Depends(get_db),
    org_id: uuid.UUID | None = Depends(_auth),
) -> dict:
    """Recent activity feed - single query, replaces N+1 lead detail calls."""
    eq = db.query(EventLog)
    if org_id is not None:
        eq = eq.filter(EventLog.organization_id == org_id)
    events = eq.order_by(EventLog.created_at.desc()).limit(limit).all()
    # Batch-load lead names for all referenced lead_ids
    lead_ids = list({e.lead_id for e in events if e.lead_id})
    lead_names: dict[uuid.UUID, str] = {}
    if lead_ids:
        rows = db.query(Lead.id, Lead.name).filter(Lead.id.in_(lead_ids)).all()
        lead_names = {r.id: r.name for r in rows}
    return {
        "events": [
            {
                "event_type": e.event_type,
                "created_at": e.created_at.isoformat() if e.created_at else None,
                "payload": json.loads(e.payload) if e.payload else None,
                "lead_name": lead_names.get(e.lead_id, "Unknown"),
            }
            for e in events
        ],
    }


@router.get("/api/leads/{lead_id}")
def lead_detail(
    lead_id: uuid.UUID,
    db: Session = Depends(get_db),
    org_id: uuid.UUID | None = Depends(_auth),
) -> dict:
    """Single lead + its full EventLog history (chronological).

    Phase 6B.6: EventLog query also filtered by organization_id for
    defense-in-depth (prevents cross-org event leakage if an event
    were ever mis-associated).
    """
    tz = ZoneInfo(settings.business_timezone)
    lead = db.get(Lead, lead_id)
    if lead is None:
        raise HTTPException(status_code=404, detail="lead not found")
    # Tenant isolation: customer users can only see their own org's leads
    if org_id is not None and lead.organization_id != org_id:
        raise HTTPException(status_code=404, detail="lead not found")
    eq = db.query(EventLog).filter(EventLog.lead_id == lead.id)
    # Defense-in-depth: also filter events by org_id if customer user
    if org_id is not None:
        eq = eq.filter(EventLog.organization_id == org_id)
    events = eq.order_by(EventLog.created_at.asc()).all()
    return {
        "lead": _lead_row(lead, tz),
        "events": [
            {
                "event_type": e.event_type,
                "payload": json.loads(e.payload) if e.payload else None,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in events
        ],
    }


@router.get("/api/failed-jobs")
def failed_jobs(
    db: Session = Depends(get_db),
    org_id: uuid.UUID | None = Depends(_auth),
) -> dict:
    """All unresolved FailedJob rows, most recent first."""
    q = db.query(FailedJob).filter(FailedJob.resolved.is_(False))
    if org_id is not None:
        q = q.filter(FailedJob.organization_id == org_id)
    jobs = q.order_by(FailedJob.created_at.desc()).all()
    return {
        "count": len(jobs),
        "failed_jobs": [
            {
                "id": str(j.id),
                "job_type": j.job_type,
                "payload": json.loads(j.payload) if j.payload else None,
                "error": j.error,
                "retry_count": j.retry_count,
                "created_at": j.created_at.isoformat() if j.created_at else None,
            }
            for j in jobs
        ],
    }


@router.get("/api/summary")
def summary(
    db: Session = Depends(get_db),
    org_id: uuid.UUID | None = Depends(_auth),
) -> dict:
    """Counts grouped by status + total leads + total unresolved failed jobs."""
    lead_q = db.query(Lead)
    failed_q = db.query(FailedJob).filter(FailedJob.resolved.is_(False))
    if org_id is not None:
        lead_q = lead_q.filter(Lead.organization_id == org_id)
        failed_q = failed_q.filter(FailedJob.organization_id == org_id)
    rows = lead_q.with_entities(Lead.status, func.count()).group_by(Lead.status).all()
    by_status = {(s.value if s else "unknown"): c for s, c in rows}
    total_leads = lead_q.count()
    unresolved = failed_q.count()
    return {
        "by_status": by_status,
        "total_leads": total_leads,
        "unresolved_failed_jobs": unresolved,
    }


# --- SSE (Server-Sent Events) for real-time dashboard updates (Phase 6) ---
# EventSource (browser) doesn't support Authorization headers, so auth is
# passed as a base64-encoded query parameter: ?token=<base64(user:pass)>.
# Phase 6B.6: Also supports JWT tokens - try Basic credentials first,
# then fall back to JWT decode.  This lets customer users (JWT holders)
# receive SSE events on their organization's data.

from app.events import event_stream, subscribe


def _validate_sse_token(token: str) -> uuid.UUID | None:
    """Validate the base64-encoded credentials from the SSE query param.

    Phase 6B.6: Supports two formats:
      1. base64(username:password) - platform admin (HTTP Basic)
      2. plain JWT string - customer user (Bearer JWT)

    Returns:
        None for platform admin (Basic auth) - sees all events.
        uuid.UUID for customer user (JWT auth) - sees only their org's events.

    Raises:
        HTTPException 401 if authentication fails.
    """
    # Try HTTP Basic credentials first (backward compatible)
    try:
        decoded = _b64.b64decode(token).decode("utf-8")
        username, password = decoded.split(":", 1)
        if bool(
            settings.dashboard_username
            and settings.dashboard_password
            and secrets.compare_digest(username, settings.dashboard_username)
            and secrets.compare_digest(password, settings.dashboard_password)
        ):
            return None  # platform admin - no org filter
    except Exception:
        pass

    # Try JWT token (customer user)
    try:
        from app.auth import (
            _is_all_user_tokens_revoked,
            _is_token_revoked,
            decode_access_token,
        )
        from app.database import SessionLocal
        from app.models_multi_tenant import (
            Organization,
            OrganizationStatus,
            User,
            UserStatus,
        )

        payload = decode_access_token(token)
        org_id_str = payload.get("org_id")
        user_id_str = payload.get("sub")
        jti = payload.get("jti")
        if not org_id_str or not user_id_str:
            raise ValueError("missing org_id/sub")
        org_id = uuid.UUID(org_id_str)
        user_id = uuid.UUID(user_id_str)

        # M3 fix: replicate the revocation + status checks from
        # _resolve_auth_context - a logged-out/disabled user's token
        # must not open a live event stream.
        db = SessionLocal()
        try:
            if jti and _is_token_revoked(jti, db):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                )
            if _is_all_user_tokens_revoked(user_id, db):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="All sessions have been invalidated",
                )
            user = db.query(User).filter(User.id == user_id).first()
            if user is None or user.status != UserStatus.ACTIVE:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token",
                )
            if user.organization_id != org_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token payload",
                )
            org = db.query(Organization).filter(Organization.id == org_id).first()
            if org is None or org.status != OrganizationStatus.ACTIVE:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Organization is not active",
                )
        finally:
            db.close()
        return org_id
    except HTTPException:
        raise
    except Exception:
        pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid SSE token",
        headers={"WWW-Authenticate": "Basic"},
    )


# ── M2: short-lived single-use SSE tickets ─────────────────────────────────
# EventSource can't send Authorization headers, so the dashboard first
# obtains a ticket via an authenticated POST, then opens the stream with
# ?ticket=<single-use>.  Tickets live 60 seconds and are bound to the
# requester's org - unlike long-lived JWTs they are useless if leaked
# into access logs or browser history.
_sse_tickets: dict[str, tuple[uuid.UUID | None, float]] = {}
_sse_ticket_lock = None  # initialized lazily (threading.Lock)


def _get_sse_ticket_lock():
    global _sse_ticket_lock
    if _sse_ticket_lock is None:
        import threading
        _sse_ticket_lock = threading.Lock()
    return _sse_ticket_lock


def _issue_sse_ticket(org_id: uuid.UUID | None) -> str:
    import secrets as _secrets
    import time as _time

    ticket = _secrets.token_urlsafe(32)
    with _get_sse_ticket_lock():
        now = _time.monotonic()
        # Prune expired tickets
        expired = [t for t, (_, exp) in _sse_tickets.items() if exp < now]
        for t in expired:
            del _sse_tickets[t]
        _sse_tickets[ticket] = (org_id, now + 60.0)
    return ticket


def _redeem_sse_ticket(ticket: str) -> tuple[bool, uuid.UUID | None]:
    """Redeem a single-use ticket. Returns (found, org_id)."""
    import time as _time

    with _get_sse_ticket_lock():
        entry = _sse_tickets.pop(ticket, None)
    if entry is None:
        return False, None
    org_id, expires_at = entry
    if _time.monotonic() > expires_at:
        return False, None
    return True, org_id


@router.post("/api/events/ticket")
def create_sse_ticket(
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Issue a short-lived single-use SSE ticket (M2).

    Authenticated via the normal Authorization header.  The dashboard
    then opens EventSource with ?ticket=... instead of putting a
    long-lived JWT in the URL (which lands in access logs).
    """
    return {"ticket": _issue_sse_ticket(ctx.org_id)}


@router.get("/api/events")
async def sse_events(
    token: str | None = Query(default=None),
    ticket: str | None = Query(default=None),
):
    """Server-Sent Events stream for real-time dashboard updates.

    M2: prefers ?ticket= (short-lived, single-use, issued by
    POST /api/events/ticket).  ?token= (long-lived JWT/Basic) is still
    accepted for backward compatibility but the dashboard no longer
    sends it.

    Platform admins see all events; customer users see only their org's.
    Sends a keepalive comment every 30s.

    Phase 10B: JWT-authenticated customers are now scoped to their
    organization's events only (prevents cross-tenant event leakage).
    """
    org_id: uuid.UUID | None | str = "unset"

    if ticket:
        found, redeemed_org = _redeem_sse_ticket(ticket)
        if not found and not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or expired SSE ticket",
            )
        if found:
            org_id = redeemed_org

    if org_id == "unset" and token:
        org_id = _validate_sse_token(token)

    if org_id == "unset":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SSE ticket or token required",
        )

    queue = subscribe(organization_id=org_id)  # type: ignore[arg-type]
    return StreamingResponse(
        event_stream(queue),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# --- Analytics endpoints (Phase 7) ---


@router.get("/api/analytics/leads-over-time")
def leads_over_time(
    days: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_db),
    org_id: uuid.UUID | None = Depends(_auth),
) -> dict:
    """Leads grouped by creation date for the last N days (for charting)."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = db.query(
        func.date(Lead.created_at),
        func.count(Lead.id),
    ).filter(Lead.created_at >= since)
    if org_id is not None:
        q = q.filter(Lead.organization_id == org_id)
    rows = q.group_by(func.date(Lead.created_at)).order_by(func.date(Lead.created_at)).all()
    return {
        "days": days,
        "data": [{"date": str(r[0]), "count": r[1]} for r in rows],
    }


@router.get("/api/analytics/appointments-over-time")
def appointments_over_time(
    days: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_db),
    org_id: uuid.UUID | None = Depends(_auth),
) -> dict:
    """Appointments (leads with parsed UTC time) grouped by date."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = db.query(
        func.date(Lead.appt_datetime_utc),
        func.count(Lead.id),
    ).filter(Lead.appt_datetime_utc >= since)
    if org_id is not None:
        q = q.filter(Lead.organization_id == org_id)
    rows = q.group_by(func.date(Lead.appt_datetime_utc)).order_by(func.date(Lead.appt_datetime_utc)).all()
    return {
        "days": days,
        "data": [{"date": str(r[0]), "count": r[1]} for r in rows],
    }


# --- Audit Log endpoint (Phase 6F) ---


@router.get("/api/audit-log")
def audit_log(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    event_type: str | None = Query(default=None),
    db: Session = Depends(get_db),
    org_id: uuid.UUID | None = Depends(_auth),
) -> dict:
    """Organization-scoped audit log (EventLog entries).

    Returns safe metadata only - never passwords, tokens, or secrets.
    Customer users see only their org's events.
    Platform admins see all events.

    Phase 9: Deep redaction for nested payloads. Event type summary counts.
    """
    from sqlalchemy import func as sqlfunc

    q = db.query(EventLog)
    if org_id is not None:
        q = q.filter(EventLog.organization_id == org_id)
    if event_type:
        q = q.filter(EventLog.event_type == event_type)
    total = q.count()
    events = q.order_by(EventLog.created_at.desc()).limit(limit).offset(offset).all()

    # Phase 9: Event type summary counts (all events, not just this page)
    summary_q = db.query(
        EventLog.event_type, sqlfunc.count(EventLog.id)
    )
    if org_id is not None:
        summary_q = summary_q.filter(EventLog.organization_id == org_id)
    event_type_counts = dict(summary_q.group_by(EventLog.event_type).all())

    # Build safe response - redact sensitive fields from payload
    # Phase 9: Recursive redaction for nested dicts/lists
    _SENSITIVE_KEYS = {
        "password", "token", "secret", "api_key", "access_token",
        "refresh_token", "client_secret", "credentials", "credential_ciphertext",
        "credential_encryption_key", "jwt_secret_key", "webhook_secret",
    }

    def _safe_payload(raw: str | None) -> dict | None:
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {"_raw": "[unreadable]"}
        return _deep_redact(data, _SENSITIVE_KEYS)

    def _deep_redact(data, sensitive_keys: set) -> any:
        """Recursively redact sensitive keys in nested dicts/lists."""
        if isinstance(data, dict):
            return {
                k: "[REDACTED]" if k.lower() in sensitive_keys else _deep_redact(v, sensitive_keys)
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [_deep_redact(item, sensitive_keys) for item in data]
        else:
            return data

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "event_type_counts": event_type_counts,
        "events": [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "payload": _safe_payload(e.payload),
                "lead_id": str(e.lead_id) if e.lead_id else None,
                "organization_id": str(e.organization_id) if e.organization_id else None,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in events
        ],
    }


# ── Phase 18: Follow-Up Endpoints ──────────────────────────────────────


def _follow_up_response(fu: FollowUp, db: Session) -> dict:
    """Build a safe API response dict for a follow-up.

    Resolves user names and lead name for display.
    """
    lead = db.get(Lead, fu.lead_id)
    created_by_user = db.get(User, fu.created_by)
    assigned_user = db.get(User, fu.assigned_to) if fu.assigned_to else None
    completed_by_user = db.get(User, fu.completed_by) if fu.completed_by else None
    cancelled_by_user = db.get(User, fu.cancelled_by) if fu.cancelled_by else None

    return {
        "id": str(fu.id),
        "organization_id": str(fu.organization_id),
        "lead_id": str(fu.lead_id),
        "lead_name": str(lead.name) if lead else None,
        "created_by": str(fu.created_by),
        "created_by_name": str(created_by_user.full_name) if created_by_user else None,
        "assigned_to": str(fu.assigned_to) if fu.assigned_to else None,
        "assigned_to_name": str(assigned_user.full_name) if assigned_user else None,
        "title": str(fu.title) if fu.title else None,
        "notes": str(fu.notes) if fu.notes else None,
        "priority": fu.priority.value if fu.priority else "medium",
        "status": fu.status.value if fu.status else "pending",
        "due_at": fu.due_at.isoformat() if fu.due_at else None,
        "completed_at": fu.completed_at.isoformat() if fu.completed_at else None,
        "completed_by": str(fu.completed_by) if fu.completed_by else None,
        "completed_by_name": str(completed_by_user.full_name) if completed_by_user else None,
        "cancelled_at": fu.cancelled_at.isoformat() if fu.cancelled_at else None,
        "cancelled_by": str(fu.cancelled_by) if fu.cancelled_by else None,
        "cancelled_by_name": str(cancelled_by_user.full_name) if cancelled_by_user else None,
        "created_at": fu.created_at.isoformat() if fu.created_at else None,
        "updated_at": fu.updated_at.isoformat() if fu.updated_at else None,
    }


@router.post("/api/follow-ups", status_code=201)
def create_follow_up(
    body: CreateFollowUpRequest,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Create a new follow-up task for a lead.

    Owner/Admin only. organization_id and created_by derived from auth context.
    """
    _require_owner_or_admin(ctx)
    if ctx.org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required")
    if ctx.user_id is None:
        raise HTTPException(status_code=400, detail="User context required")

    # Validate lead exists and belongs to this org
    lead = db.get(Lead, body.lead_id)
    if lead is None:
        raise HTTPException(status_code=404, detail="lead not found")
    if lead.organization_id != ctx.org_id:
        raise HTTPException(status_code=404, detail="lead not found")

    # Phase 7 Part 4 - Guard: reject follow-up creation for terminal leads
    from app.services.followup_cancellation import is_terminal_lead_status
    if is_terminal_lead_status(lead.status):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot create follow-up: lead is in terminal status '{lead.status.value}'",
        )

    # Validate assigned_to user exists in same org if provided
    if body.assigned_to is not None:
        assignee = db.get(User, body.assigned_to)
        if assignee is None:
            raise HTTPException(status_code=400, detail="assigned_to user not found")
        if assignee.organization_id != ctx.org_id:
            raise HTTPException(status_code=400, detail="assigned_to user not found")

    fu = FollowUp(
        organization_id=ctx.org_id,
        lead_id=body.lead_id,
        created_by=ctx.user_id,
        assigned_to=body.assigned_to,
        title=body.title,
        notes=body.notes,
        priority=body.priority,
        status=FollowUpStatus.PENDING,
        due_at=body.due_at,
    )
    db.add(fu)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create follow-up")
    db.refresh(fu)

    # Audit event + SSE
    from app.main import _log_event
    _log_event(
        db, fu.lead_id, "follow_up_created",
        {"follow_up_id": str(fu.id), "title": fu.title, "priority": fu.priority.value},
        organization_id=ctx.org_id,
    )
    publish_event(
        "follow_up.created",
        {"follow_up_id": str(fu.id), "lead_id": str(fu.lead_id), "title": fu.title},
        organization_id=ctx.org_id,
    )

    return {"status": "created", "follow_up": _follow_up_response(fu, db)}


@router.get("/api/follow-ups")
def list_follow_ups(
    lead_id: uuid.UUID | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    priority: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """List follow-ups for the authenticated organization.

    Supports optional filters: lead_id, status, priority.
    Paginated with limit/offset (default limit=100, max=500).
    Platform admin (org_id=None) can query follow-ups across all orgs.
    """
    q = db.query(FollowUp)
    if ctx.org_id is not None:
        q = q.filter(FollowUp.organization_id == ctx.org_id)

    if lead_id is not None:
        # lead_id may already be a UUID (from FastAPI Query conversion) or a string
        if isinstance(lead_id, uuid.UUID):
            lead_uuid = lead_id
        else:
            try:
                lead_uuid = uuid.UUID(lead_id)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid lead_id format")
        q = q.filter(FollowUp.lead_id == lead_uuid)

    if status_filter is not None:
        try:
            s = FollowUpStatus(status_filter)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status: {status_filter}. Must be one of: {', '.join(e.value for e in FollowUpStatus)}",
            )
        q = q.filter(FollowUp.status == s)

    if priority is not None:
        try:
            p = FollowUpPriority(priority)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid priority: {priority}. Must be one of: {', '.join(e.value for e in FollowUpPriority)}",
            )
        q = q.filter(FollowUp.priority == p)

    total = q.count()
    follow_ups = q.order_by(FollowUp.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "follow_ups": [_follow_up_response(fu, db) for fu in follow_ups],
    }


@router.get("/api/follow-ups/stats")
def follow_up_stats(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Aggregate statistics for follow-ups in the authenticated organization.

    Returns total/active/completed/cancelled counts, average time-to-completion,
    and overdue count.  All queries are scoped to ctx.org_id.
    Platform admin (org_id=None) sees stats across all organizations.
    """
    if ctx.org_id is not None:
        org_filter = FollowUp.organization_id == ctx.org_id
    else:
        org_filter = True

    # ── Counts (single query) ──────────────────────────────────────
    counts = db.query(
        func.count(FollowUp.id).label("total"),
        func.count(
            case(
                (FollowUp.status.in_([FollowUpStatus.PENDING, FollowUpStatus.IN_PROGRESS]), 1),
            )
        ).label("active"),
        func.count(
            case((FollowUp.status == FollowUpStatus.COMPLETED, 1))
        ).label("completed"),
        func.count(
            case((FollowUp.status == FollowUpStatus.CANCELLED, 1))
        ).label("cancelled"),
    ).filter(org_filter).one()

    # ── Overdue count ──────────────────────────────────────────────
    now_utc = datetime.now(timezone.utc)
    overdue_count = (
        db.query(func.count(FollowUp.id))
        .filter(
            org_filter,
            FollowUp.status.in_([FollowUpStatus.PENDING, FollowUpStatus.IN_PROGRESS]),
            FollowUp.due_at.isnot(None),
            FollowUp.due_at < now_utc,
        )
        .scalar()
    )

    # ── Average time-to-completion ─────────────────────────────────
    # Computed in Python for SQLite/PostgreSQL portability.
    completed_rows = (
        db.query(FollowUp.created_at, FollowUp.completed_at)
        .filter(
            org_filter,
            FollowUp.status == FollowUpStatus.COMPLETED,
            FollowUp.completed_at.isnot(None),
        )
        .all()
    )
    avg_hours = None
    if completed_rows:
        total_seconds = sum(
            (row.completed_at - row.created_at).total_seconds()
            for row in completed_rows
        )
        avg_hours = round(total_seconds / len(completed_rows) / 3600.0, 2)

    return {
        "total": counts.total,
        "active": counts.active,
        "completed": counts.completed,
        "cancelled": counts.cancelled,
        "avg_time_to_completion_hours": avg_hours,
        "overdue": overdue_count,
    }


@router.get("/api/follow-ups/{follow_up_id}")
def get_follow_up(
    follow_up_id: uuid.UUID,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Get a single follow-up by ID."""
    if ctx.org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required")

    fu = db.get(FollowUp, follow_up_id)
    if fu is None:
        raise HTTPException(status_code=404, detail="follow-up not found")
    if fu.organization_id != ctx.org_id:
        raise HTTPException(status_code=404, detail="follow-up not found")

    return {"follow_up": _follow_up_response(fu, db)}


@router.patch("/api/follow-ups/{follow_up_id}")
def update_follow_up(
    follow_up_id: uuid.UUID,
    body: UpdateFollowUpRequest,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Update follow-up details (title, notes, priority, due_at, assigned_to).

    Owner/Admin only. Partial update - only provided fields are changed.
    """
    _require_owner_or_admin(ctx)
    if ctx.org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required")

    fu = db.get(FollowUp, follow_up_id)
    if fu is None:
        raise HTTPException(status_code=404, detail="follow-up not found")
    if fu.organization_id != ctx.org_id:
        raise HTTPException(status_code=404, detail="follow-up not found")

    fields = body.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")

    # Validate assigned_to if changing
    if "assigned_to" in fields and fields["assigned_to"] is not None:
        assignee = db.get(User, fields["assigned_to"])
        if assignee is None:
            raise HTTPException(status_code=400, detail="assigned_to user not found")
        if assignee.organization_id != ctx.org_id:
            raise HTTPException(status_code=400, detail="assigned_to user not found")

    changes: dict[str, dict] = {}
    for field, new_value in fields.items():
        old_value = getattr(fu, field, None)
        if str(old_value) != str(new_value):
            changes[field] = {"old": str(old_value), "new": str(new_value)}
            setattr(fu, field, new_value)

    if not changes:
        raise HTTPException(status_code=400, detail="No changes detected")

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update follow-up")
    db.refresh(fu)

    # Audit event + SSE
    from app.main import _log_event
    _log_event(
        db, fu.lead_id, "follow_up_updated",
        {"follow_up_id": str(fu.id), "changes": {k: {"old": str(v["old"]), "new": str(v["new"])} for k, v in changes.items()}},
        organization_id=ctx.org_id,
    )
    publish_event(
        "follow_up.updated",
        {"follow_up_id": str(fu.id), "changes": list(changes.keys())},
        organization_id=ctx.org_id,
    )

    return {"status": "updated", "follow_up": _follow_up_response(fu, db)}


@router.patch("/api/follow-ups/{follow_up_id}/status")
def update_follow_up_status(
    follow_up_id: uuid.UUID,
    body: FollowUpStatusRequest,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Change follow-up status through validated transitions.

    Owner/Admin only. Transitions validated against ALLOWED_FOLLOWUP_TRANSITIONS.
    Automatically sets completed_at/completed_by or cancelled_at/cancelled_by.
    """
    _require_owner_or_admin(ctx)
    if ctx.org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required")
    if ctx.user_id is None:
        raise HTTPException(status_code=400, detail="User context required")

    fu = db.get(FollowUp, follow_up_id)
    if fu is None:
        raise HTTPException(status_code=404, detail="follow-up not found")
    if fu.organization_id != ctx.org_id:
        raise HTTPException(status_code=404, detail="follow-up not found")

    current_status = fu.status.value
    new_status = body.status.value

    if current_status == new_status:
        raise HTTPException(status_code=400, detail="Follow-up is already in that status")

    allowed = ALLOWED_FOLLOWUP_TRANSITIONS.get(current_status, set())
    if new_status not in allowed:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid transition: {current_status} → {new_status}. "
                   f"Allowed from {current_status}: {', '.join(sorted(allowed)) if allowed else 'none (terminal state)'}",
        )

    old_status = current_status
    now_utc = datetime.now(timezone.utc)

    fu.status = body.status
    if new_status == "completed":
        fu.completed_at = now_utc
        fu.completed_by = ctx.user_id
    elif new_status == "cancelled":
        fu.cancelled_at = now_utc
        fu.cancelled_by = ctx.user_id

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update status")
    db.refresh(fu)

    # Audit event + SSE
    from app.main import _log_event
    _log_event(
        db, fu.lead_id, "follow_up_status_changed",
        {"follow_up_id": str(fu.id), "old_status": old_status, "new_status": new_status},
        organization_id=ctx.org_id,
    )
    publish_event(
        "follow_up.status_changed",
        {"follow_up_id": str(fu.id), "old_status": old_status, "new_status": new_status},
        organization_id=ctx.org_id,
    )

    return {"status": "updated", "follow_up": _follow_up_response(fu, db)}


@router.delete("/api/follow-ups/{follow_up_id}", status_code=204)
def delete_follow_up(
    follow_up_id: uuid.UUID,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> None:
    """Delete a follow-up. Owner/Admin only.

    Soft-delete: sets status to cancelled with timestamp if not already terminal.
    """
    _require_owner_or_admin(ctx)
    if ctx.org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required")
    if ctx.user_id is None:
        raise HTTPException(status_code=400, detail="User context required")

    fu = db.get(FollowUp, follow_up_id)
    if fu is None:
        raise HTTPException(status_code=404, detail="follow-up not found")
    if fu.organization_id != ctx.org_id:
        raise HTTPException(status_code=404, detail="follow-up not found")

    # Cancel if not already terminal
    if fu.status not in (FollowUpStatus.COMPLETED, FollowUpStatus.CANCELLED):
        fu.status = FollowUpStatus.CANCELLED
        fu.cancelled_at = datetime.now(timezone.utc)
        fu.cancelled_by = ctx.user_id
        db.commit()

        from app.main import _log_event
        _log_event(
            db, fu.lead_id, "follow_up_deleted",
            {"follow_up_id": str(fu.id), "title": fu.title},
            organization_id=ctx.org_id,
        )
        publish_event(
            "follow_up.deleted",
            {"follow_up_id": str(fu.id), "lead_id": str(fu.lead_id)},
            organization_id=ctx.org_id,
        )

    return None


# ── Phase 29: Form Field Mapping APIs ────────────────────────────────────────
# Organization-scoped CRUD for Google Form question label → Lead field mapping.
# Only owner and admin roles can modify mappings.


@router.get("/api/form-field-mappings")
def list_form_field_mappings(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """List the organization's form field mappings.

    Returns the current mapping configuration and the default mapping
    for reference. If no custom mapping is configured, the active
    mapping equals the default.
    """
    from app.models_multi_tenant import (
        DEFAULT_FORM_FIELD_MAPPING,
        VALID_LEAD_FIELDS,
        OrgFormFieldMapping,
    )

    if ctx.org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required")

    mappings = (
        db.query(OrgFormFieldMapping)
        .filter(OrgFormFieldMapping.organization_id == ctx.org_id)
        .order_by(OrgFormFieldMapping.display_order, OrgFormFieldMapping.form_label)
        .all()
    )

    return {
        "mappings": [
            {
                "id": str(m.id),
                "form_label": m.form_label,
                "lead_field": m.lead_field,
                "is_required": m.is_required,
                "display_order": m.display_order,
                "created_at": m.created_at.isoformat() if m.created_at else None,
                "updated_at": m.updated_at.isoformat() if m.updated_at else None,
            }
            for m in mappings
        ],
        "default_mapping": DEFAULT_FORM_FIELD_MAPPING,
        "valid_fields": sorted(VALID_LEAD_FIELDS),
        "is_custom": len(mappings) > 0,
    }


@router.put("/api/form-field-mappings")
def replace_form_field_mappings(
    request_body: dict,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Replace the organization's form field mappings.

    Accepts a list of mapping objects. Validates the configuration,
    then replaces all existing mappings atomically.

    Body:
        {
          "mappings": [
            {"form_label": "Full Name", "lead_field": "name", "is_required": true},
            {"form_label": "Email", "lead_field": "email", "is_required": true},
            ...
          ]
        }

    Owner/Admin only.
    """
    from app.models_multi_tenant import (
        OrgFormFieldMapping,
    )
    from app.services.field_mapping_resolver import (
        invalidate_mapping_cache,
        validate_mapping_config,
    )

    _require_owner_or_admin(ctx)
    if ctx.org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required")

    mappings_data = request_body.get("mappings", [])
    if not isinstance(mappings_data, list):
        raise HTTPException(status_code=422, detail="'mappings' must be a list")

    # Validate the proposed configuration
    errors = validate_mapping_config(mappings_data)
    if errors:
        raise HTTPException(
            status_code=422,
            detail={"errors": errors},
        )

    # Check if the proposed mapping is the same as default
    proposed = {}
    for m in mappings_data:
        form_label = m["form_label"].strip()
        lead_field = m["lead_field"].strip()
        proposed[form_label] = lead_field

    # Atomically replace: delete old, insert new
    try:
        db.query(OrgFormFieldMapping).filter(
            OrgFormFieldMapping.organization_id == ctx.org_id
        ).delete()

        for i, m in enumerate(mappings_data):
            mapping = OrgFormFieldMapping(
                organization_id=ctx.org_id,
                form_label=m["form_label"].strip(),
                lead_field=m["lead_field"].strip(),
                is_required=m.get("is_required", False),
                display_order=m.get("display_order", i),
            )
            db.add(mapping)

        db.commit()
    except Exception as exc:
        db.rollback()
        logger.exception("Failed to update form field mappings for org %s", ctx.org_id)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save mappings: {exc}",
        )

    # Invalidate the cache so the webhook picks up the new mapping
    invalidate_mapping_cache(ctx.org_id)

    return {"status": "ok", "count": len(mappings_data)}


@router.post("/api/form-field-mappings/seed")
def seed_form_field_mappings(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Seed the organization's form field mappings with the default values.

    Useful for initializing a new organization's mapping or resetting
    to the default configuration.

    Owner/Admin only.
    """
    from app.models_multi_tenant import (
        DEFAULT_FORM_FIELD_MAPPING,
        OrgFormFieldMapping,
    )
    from app.services.field_mapping_resolver import invalidate_mapping_cache

    _require_owner_or_admin(ctx)
    if ctx.org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required")

    # Check if already has mappings
    existing = db.query(OrgFormFieldMapping).filter(
        OrgFormFieldMapping.organization_id == ctx.org_id
    ).count()
    if existing > 0:
        raise HTTPException(
            status_code=409,
            detail="Organization already has field mappings. Use PUT to replace.",
        )

    # Seed with default mapping
    try:
        for i, (form_label, lead_field) in enumerate(DEFAULT_FORM_FIELD_MAPPING.items()):
            mapping = OrgFormFieldMapping(
                organization_id=ctx.org_id,
                form_label=form_label,
                lead_field=lead_field,
                is_required=lead_field in ("name", "email", "appt_datetime_raw"),
                display_order=i,
            )
            db.add(mapping)
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.exception("Failed to seed form field mappings for org %s", ctx.org_id)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to seed mappings: {exc}",
        )

    invalidate_mapping_cache(ctx.org_id)

    return {"status": "ok", "count": len(DEFAULT_FORM_FIELD_MAPPING)}


@router.delete("/api/form-field-mappings", status_code=200)
def delete_all_form_field_mappings(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Delete all form field mappings for the organization.

    After deletion, the webhook will use the default mapping.

    Owner/Admin only.
    """
    from app.models_multi_tenant import OrgFormFieldMapping
    from app.services.field_mapping_resolver import invalidate_mapping_cache

    _require_owner_or_admin(ctx)
    if ctx.org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required")

    count = db.query(OrgFormFieldMapping).filter(
        OrgFormFieldMapping.organization_id == ctx.org_id
    ).delete()
    db.commit()

    invalidate_mapping_cache(ctx.org_id)

    return {"status": "ok", "deleted": count}


_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Strategy Call Agent</title>
<link rel="preconnect" href="https://api.fontshare.com" crossorigin>
<link rel="preconnect" href="https://cdn.fontshare.com" crossorigin>
<link href="https://api.fontshare.com/v2/css?f[]=general-sans@400,500,600,700&f[]=inter@400,500&f[]=jetbrains-mono@400,500&display=swap" rel="stylesheet">
<style>
/* ===== RESET ===== */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
button,input,select,textarea{font:inherit}

/* ===== DESIGN TOKENS ===== */
:root{
  --bg:#FFFFFF;--bg-alt:#F9FAFB;--surface:#F7F7F8;--surface-hover:#F0F1F3;
  --border:#E4E5E8;--border-light:#F0F1F3;
  --text:#16171A;--text-secondary:#3B3D42;--text-muted:#71757D;--text-faint:#A1A5AC;
  --accent:#0E8A5F;--accent-light:rgba(14,138,95,0.08);--accent-hover:#0C7A53;
  --warning:#B7791F;--warning-light:rgba(183,121,31,0.08);
  --danger:#C0362C;--danger-light:rgba(192,54,44,0.08);
  --info:#2563EB;--info-light:rgba(37,99,235,0.08);
  --shadow-xs:0 1px 2px rgba(16,17,20,0.04);
  --shadow-sm:0 1px 3px rgba(16,17,20,0.06),0 1px 2px rgba(16,17,20,0.04);
  --shadow-md:0 4px 6px rgba(16,17,20,0.04),0 2px 4px rgba(16,17,20,0.03);
  --shadow-lg:0 10px 15px rgba(16,17,20,0.05),0 4px 6px rgba(16,17,20,0.03);
  --radius-sm:6px;--radius:8px;--radius-md:10px;--radius-lg:12px;--radius-xl:16px;
  --sidebar-w:240px;--header-h:64px;
  --font-sans:'General Sans','Inter',system-ui,-apple-system,sans-serif;
  --font-mono:'JetBrains Mono','Space Mono',ui-monospace,monospace;
  --font-inter:'Inter',system-ui,-apple-system,sans-serif;
  --transition:0.2s cubic-bezier(0.4,0,0.2,1);
}

/* ===== BASE ===== */
html{height:100%}
body{background:var(--bg-alt);color:var(--text);font-family:var(--font-sans);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;height:100%;overflow:hidden}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}

/* ===== APP LAYOUT ===== */
.app{display:flex;height:100vh;overflow:hidden}

/* ===== SIDEBAR ===== */
.sidebar{width:var(--sidebar-w);background:var(--bg);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;z-index:100;transition:transform var(--transition)}
.sidebar-brand{padding:20px 20px 16px;border-bottom:1px solid var(--border-light)}
.sidebar-brand h1{font-size:15px;font-weight:700;letter-spacing:-0.02em;color:var(--text);line-height:1.2}
.sidebar-brand p{font-size:11px;color:var(--text-muted);margin-top:3px;line-height:1.3}
.sidebar-nav{flex:1;padding:12px 8px;overflow-y:auto}
.nav-section{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-faint);padding:16px 12px 6px;user-select:none}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:var(--radius);color:var(--text-muted);font-size:13px;font-weight:500;cursor:pointer;transition:all var(--transition);user-select:none;text-decoration:none;border:none;background:none;width:100%;text-align:left}
.nav-item:hover{background:var(--surface-hover);color:var(--text);text-decoration:none}
.nav-item.active{background:var(--surface);color:var(--text);font-weight:600}
.nav-item .icon{width:18px;height:18px;display:flex;align-items:center;justify-content:center;font-size:15px;flex-shrink:0}
.nav-item .badge{margin-left:auto;font-size:11px;font-weight:600;background:var(--danger);color:#fff;padding:1px 6px;border-radius:8px;min-width:18px;text-align:center}
.sidebar-footer{padding:12px 20px;border-top:1px solid var(--border-light);font-size:11px;color:var(--text-faint)}

/* ===== MAIN CONTENT ===== */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}
.main-header{height:var(--header-h);background:var(--bg);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 32px;flex-shrink:0}
.main-header h2{font-size:18px;font-weight:600;letter-spacing:-0.02em}
.header-right{display:flex;align-items:center;gap:12px}
.automation-badge{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:500;padding:5px 12px;border-radius:20px;transition:all var(--transition)}
.automation-badge.live{background:var(--accent-light);color:var(--accent)}
.automation-badge.reconnecting{background:var(--warning-light);color:var(--warning)}
.automation-badge.polling{background:var(--warning-light);color:var(--warning)}
.automation-badge .dot{width:7px;height:7px;border-radius:50%;background:currentColor;flex-shrink:0}
.automation-badge.live .dot{animation:pulse-dot 2s ease-in-out infinite}
@keyframes pulse-dot{0%,100%{opacity:1}50%{opacity:0.4}}

.main-scroll{flex:1;overflow-y:auto;overflow-x:hidden;scroll-behavior:smooth}
.page{display:none;padding:32px;animation:page-in 0.3s ease-out}
.page.active{display:block}
@keyframes page-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

/* ===== MOBILE MENU ===== */
.mobile-toggle{display:none;appearance:none;border:none;background:none;font-size:20px;cursor:pointer;padding:4px;color:var(--text)}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.3);z-index:99}

/* ===== CARDS ===== */
.card{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-lg);padding:24px;box-shadow:var(--shadow-sm);transition:box-shadow var(--transition)}
.card:hover{box-shadow:var(--shadow-md)}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.card-header h3{font-size:14px;font-weight:600;color:var(--text)}
.card-header .subtitle{font-size:12px;color:var(--text-muted)}

/* ===== KPI CARDS ===== */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px}
.kpi{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-md);padding:20px 22px;box-shadow:var(--shadow-xs);transition:all var(--transition);position:relative;overflow:hidden}
.kpi:hover{box-shadow:var(--shadow-sm);transform:translateY(-1px)}
.kpi-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-bottom:8px}
.kpi-value{font-size:28px;font-weight:700;letter-spacing:-0.03em;color:var(--text);line-height:1}
.kpi-sub{font-size:12px;color:var(--text-muted);margin-top:6px}
.kpi-icon{position:absolute;top:16px;right:16px;width:36px;height:36px;border-radius:var(--radius);display:flex;align-items:center;justify-content:center;font-size:16px}
.kpi-icon.green{background:var(--accent-light);color:var(--accent)}
.kpi-icon.blue{background:var(--info-light);color:var(--info)}
.kpi-icon.amber{background:var(--warning-light);color:var(--warning)}
.kpi-icon.red{background:var(--danger-light);color:var(--danger)}

/* ===== PIPELINE ===== */
.pipeline{display:flex;align-items:center;gap:0;margin-bottom:28px;overflow-x:auto;padding:4px 0}
.pipeline-stage{flex:1;min-width:120px;text-align:center;padding:16px 12px;position:relative}
.pipeline-stage::after{content:'';position:absolute;top:24px;right:-8px;width:16px;height:2px;background:var(--border);z-index:0}
.pipeline-stage:last-child::after{display:none}
.pipeline-count{font-size:26px;font-weight:700;letter-spacing:-0.03em;line-height:1;margin-bottom:6px}
.pipeline-count.active{color:var(--accent)}
.pipeline-count.zero{color:var(--text-faint)}
.pipeline-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted)}
.pipeline-dot{width:8px;height:8px;border-radius:50%;background:var(--accent);margin:0 auto 10px;opacity:0.6}
.pipeline-stage:first-child .pipeline-dot{opacity:1}
.pipeline-stage:last-child .pipeline-dot{background:var(--accent)}
.pipeline-connector{width:24px;height:2px;background:var(--border);flex-shrink:0}

/* ===== TABLES ===== */
.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--border-light)}
th{font-family:var(--font-sans);color:var(--text-muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.05em;background:var(--bg-alt);position:sticky;top:0;z-index:1}
td{font-family:var(--font-inter);color:var(--text-secondary)}
tr{transition:background var(--transition)}
tr:hover{background:var(--surface-hover)}
tr.clickable{cursor:pointer}
tr.clickable:focus-visible{outline:2px solid var(--accent);outline-offset:-2px;border-radius:var(--radius-sm)}

/* ===== STATUS BADGES ===== */
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:0.02em;white-space:nowrap}
.badge-dot{width:6px;height:6px;border-radius:50%;background:currentColor;flex-shrink:0}
.badge.scheduled,.badge.accepted,.badge.reminded{background:var(--accent-light);color:var(--accent)}
.badge.scheduled .badge-dot,.badge.accepted .badge-dot,.badge.reminded .badge-dot{background:var(--accent)}
.badge.tentative,.badge.pending{background:var(--warning-light);color:var(--warning)}
.badge.tentative .badge-dot,.badge.pending .badge-dot{background:var(--warning)}
.badge.declined,.badge.error{background:var(--danger-light);color:var(--danger)}
.badge.declined .badge-dot,.badge.error .badge-dot{background:var(--danger)}

/* ===== SEARCH & FILTERS ===== */
.search-bar{display:flex;gap:12px;align-items:center;margin-bottom:20px;flex-wrap:wrap}
.search-input{flex:1;min-width:200px;padding:9px 14px 9px 36px;border:1px solid var(--border);border-radius:var(--radius);font-size:13px;background:var(--bg);color:var(--text);transition:border-color var(--transition);background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='%2371757D' viewBox='0 0 16 16'%3E%3Cpath d='M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85zm-5.242.156a5 5 0 1 1 0-10 5 5 0 0 1 0 10z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:12px center}
.search-input:focus{outline:none;border-color:var(--accent)}
.filter-btn{padding:7px 14px;border:1px solid var(--border);border-radius:var(--radius);font-size:12px;font-weight:500;background:var(--bg);color:var(--text-muted);cursor:pointer;transition:all var(--transition)}
.filter-btn:hover,.filter-btn.active{background:var(--text);color:var(--bg);border-color:var(--text)}
.filter-count{display:inline-block;min-width:18px;height:18px;line-height:18px;text-align:center;border-radius:9px;font-size:10px;font-weight:700;margin-left:4px;background:var(--border);color:var(--text-muted)}
.filter-btn.active .filter-count{background:rgba(255,255,255,0.25);color:inherit}
.time-filter{display:flex;gap:4px;background:var(--surface);border-radius:var(--radius);padding:3px}
.time-filter button{padding:5px 12px;border:none;border-radius:var(--radius-sm);font-size:12px;font-weight:500;background:transparent;color:var(--text-muted);cursor:pointer;transition:all var(--transition)}
.time-filter button.active{background:var(--bg);color:var(--text);box-shadow:var(--shadow-xs)}

/* ===== BUTTONS ===== */
.btn{display:inline-flex;align-items:center;gap:6px;font-family:var(--font-sans);font-size:13px;font-weight:500;padding:8px 16px;border-radius:var(--radius);border:1px solid var(--border);background:var(--bg);color:var(--text);cursor:pointer;transition:all var(--transition);white-space:nowrap}
.btn:hover{background:var(--surface-hover);box-shadow:var(--shadow-xs)}
.btn:active{transform:scale(0.98)}
.btn:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.btn:disabled{opacity:0.5;cursor:not-allowed;transform:none}
.btn-primary{background:var(--text);color:var(--bg);border-color:var(--text)}
.btn-primary:hover{opacity:0.9;background:var(--text)}
.btn-sm{padding:5px 10px;font-size:12px}
.btn-ghost{border-color:transparent;background:transparent}
.btn-ghost:hover{background:var(--surface)}
.btn-danger{color:var(--danger);border-color:var(--danger)}

/* ===== TOAST ===== */
.toast-container{position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none}
.toast{pointer-events:auto;padding:12px 20px;border-radius:var(--radius);font-size:13px;font-weight:500;box-shadow:var(--shadow-lg);animation:toast-in 0.3s ease-out;display:flex;align-items:center;gap:8px;max-width:380px}
.toast.success{background:var(--accent);color:#fff}
.toast.error{background:var(--danger);color:#fff}
.toast.info{background:var(--text);color:var(--bg)}
@keyframes toast-in{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:none}}
@keyframes toast-out{from{opacity:1;transform:none}to{opacity:0;transform:translateX(40px)}}

/* ===== DRAWER ===== */
.drawer-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.3);z-index:200;opacity:0;visibility:hidden;transition:all 0.3s ease}
.drawer-overlay.open{opacity:1;visibility:visible}
.drawer{position:fixed;top:0;right:0;width:520px;max-width:90vw;height:100vh;background:var(--bg);box-shadow:var(--shadow-lg);z-index:201;transform:translateX(100%);transition:transform 0.3s cubic-bezier(0.4,0,0.2,1);display:flex;flex-direction:column}
.drawer.open{transform:translateX(0)}
.drawer-header{display:flex;align-items:center;justify-content:space-between;padding:20px 24px;border-bottom:1px solid var(--border);flex-shrink:0}
.drawer-header h3{font-size:16px;font-weight:600}
.drawer-close{appearance:none;border:none;background:none;font-size:20px;cursor:pointer;color:var(--text-muted);padding:4px;border-radius:var(--radius-sm);transition:all var(--transition)}
.drawer-close:hover{background:var(--surface);color:var(--text)}
.drawer-body{flex:1;overflow-y:auto;padding:24px}
.drawer-meta{display:grid;grid-template-columns:120px 1fr;gap:8px 16px;font-size:13px;margin-bottom:24px}
.drawer-meta dt{color:var(--text-muted);font-weight:500}
.drawer-meta dd{color:var(--text);word-break:break-all}

/* ===== ACTIVITY FEED ===== */
.feed{display:flex;flex-direction:column;gap:0}
.feed-item{display:flex;gap:12px;padding:12px 0;border-bottom:1px solid var(--border-light);align-items:flex-start;animation:feed-in 0.3s ease-out}
.feed-item:last-child{border-bottom:none}
@keyframes feed-in{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.feed-dot{width:8px;height:8px;border-radius:50%;margin-top:6px;flex-shrink:0}
.feed-dot.green{background:var(--accent)}
.feed-dot.blue{background:var(--info)}
.feed-dot.amber{background:var(--warning)}
.feed-dot.red{background:var(--danger)}
.feed-dot.gray{background:var(--text-faint)}
.feed-text{flex:1;font-size:13px;color:var(--text-secondary);line-height:1.4}
.feed-text strong{color:var(--text);font-weight:600}
.feed-time{font-size:11px;color:var(--text-faint);font-family:var(--font-mono);white-space:nowrap;margin-top:2px}

/* ===== AUTOMATION CARDS ===== */
.automation-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
.automation-card{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-lg);padding:22px;box-shadow:var(--shadow-xs);transition:all var(--transition)}
.automation-card:hover{box-shadow:var(--shadow-sm)}
.automation-card-header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px}
.automation-card-header h4{font-size:14px;font-weight:600;color:var(--text)}
.automation-status{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:600;padding:3px 10px;border-radius:20px}
.automation-status.active{background:var(--accent-light);color:var(--accent)}
.automation-status.active .dot{width:6px;height:6px;border-radius:50%;background:var(--accent);animation:pulse-dot 2s ease-in-out infinite}
.automation-card p{font-size:12px;color:var(--text-muted);margin-bottom:12px;line-height:1.5}
.automation-card-footer{display:flex;align-items:center;justify-content:space-between;padding-top:12px;border-top:1px solid var(--border-light);font-size:12px;color:var(--text-muted)}
.automation-config{font-family:var(--font-mono);font-size:12px;color:var(--text-secondary);background:var(--surface);padding:4px 8px;border-radius:var(--radius-sm)}

/* ===== CHARTS (Analytics) ===== */
.chart-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:20px;margin-bottom:28px}
.chart-container{position:relative;height:220px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-md);padding:20px;box-shadow:var(--shadow-xs)}
.chart-container canvas{width:100%!important;height:100%!important}
.chart-title{font-size:13px;font-weight:600;color:var(--text);margin-bottom:12px}

/* ===== SETTINGS ===== */
.settings-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:20px}
.setting-group{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-lg);padding:24px;box-shadow:var(--shadow-xs)}
.setting-group h4{font-size:14px;font-weight:600;margin-bottom:4px}
.setting-group .desc{font-size:12px;color:var(--text-muted);margin-bottom:16px;line-height:1.5}
.setting-field{margin-bottom:16px}
.setting-field:last-child{margin-bottom:0}
.setting-field label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-bottom:6px}
.setting-field input[type="time"],
.setting-field input[type="number"]{font-family:var(--font-mono);font-size:13px;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text);width:100%;max-width:200px;transition:border-color var(--transition)}
.setting-field input:focus{outline:none;border-color:var(--accent)}

/* ===== EMPTY STATE ===== */
.empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:60px 32px;text-align:center}
.empty-state .icon{font-size:48px;margin-bottom:16px;opacity:0.4}
.empty-state h3{font-size:16px;font-weight:600;color:var(--text);margin-bottom:8px}
.empty-state p{font-size:13px;color:var(--text-muted);max-width:360px;line-height:1.6}

/* ===== SKELETON LOADING ===== */
.skeleton{background:linear-gradient(90deg,var(--surface) 25%,var(--border-light) 50%,var(--surface) 75%);background-size:200% 100%;animation:shimmer 1.5s ease-in-out infinite;border-radius:var(--radius-sm)}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
.skeleton-card{height:100px;border-radius:var(--radius-md)}
.skeleton-row{height:16px;margin-bottom:8px}
.skeleton-row.w60{width:60%}
.skeleton-row.w80{width:80%}
.skeleton-row.w40{width:40%}

/* ===== DETAIL META ===== */
.detail-grid{display:grid;grid-template-columns:130px 1fr;gap:8px 16px;font-size:13px;margin-bottom:24px}
.detail-grid dt{color:var(--text-muted);font-weight:500}
.detail-grid dd{color:var(--text);margin:0}

/* ===== TIMELINE ===== */
.timeline{list-style:none;margin:0;padding:0}
.timeline li{position:relative;padding:0 0 20px 28px;border-left:1px solid var(--border)}
.timeline li:last-child{border-left-color:transparent}
.timeline li::before{content:'';position:absolute;left:-4px;top:6px;width:7px;height:7px;border-radius:50%;background:var(--bg);border:2px solid var(--text-muted)}
.timeline li.ev-success::before{border-color:var(--accent)}
.timeline li.ev-danger::before{border-color:var(--danger)}
.timeline li.ev-warn::before{border-color:var(--warning)}
.timeline .t{font-family:var(--font-mono);font-size:11px;color:var(--text-muted)}
.timeline .e{font-weight:600;font-size:12px;margin-left:8px}
.timeline .e.ev-success{color:var(--accent)}
.timeline .e.ev-danger{color:var(--danger)}
.timeline .e.ev-warn{color:var(--warning)}
.timeline .e.ev-neutral{color:var(--text-muted)}
.timeline pre{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 10px;margin:6px 0 0;font-size:11px;overflow-x:auto;font-family:var(--font-mono);color:var(--text-muted);line-height:1.5}

/* ===== TRIGGER ROW ===== */
.trigger-row{display:flex;gap:12px;margin-top:16px;padding-top:16px;border-top:1px solid var(--border-light)}
.trigger-result{font-size:12px;color:var(--text-muted);margin-top:8px;font-family:var(--font-mono)}

/* ===== USER MANAGEMENT TABLE ===== */
.um-table{width:100%;font-size:13px;border-collapse:collapse}
.um-table th{text-align:left;padding:10px 16px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);border-bottom:1px solid var(--border)}
.um-table td{padding:12px 16px;border-bottom:1px solid var(--border-light);vertical-align:middle}
.um-table tr:last-child td{border-bottom:none}
.um-table tr:hover td{background:var(--surface)}
.um-name-cell{font-weight:500;color:var(--text)}
.um-email-cell{font-family:var(--font-mono);font-size:12px;color:var(--text-secondary)}
.um-badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:0.02em;white-space:nowrap}
.um-badge.owner{background:var(--accent-light);color:var(--accent)}
.um-badge.admin{background:var(--info-light);color:var(--info)}
.um-badge.member{background:var(--surface);color:var(--text-muted);border:1px solid var(--border)}
.um-badge.active{background:var(--accent-light);color:var(--accent)}
.um-badge.disabled{background:var(--danger-light);color:var(--danger)}
.um-section{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-lg);padding:24px;box-shadow:var(--shadow-xs);margin-bottom:20px}
.um-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:12px}
.um-header h4{font-size:14px;font-weight:600}
.um-header .desc{font-size:12px;color:var(--text-muted);margin-top:2px}
.um-actions{display:flex;gap:8px;align-items:center}
.um-total{font-size:12px;color:var(--text-muted);font-weight:500}
.um-self-tag{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--accent);background:var(--accent-light);padding:2px 6px;border-radius:4px;margin-left:6px}
/* ===== USER MANAGEMENT MODAL ===== */
.um-modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:500;display:flex;align-items:center;justify-content:center;padding:20px}
.um-modal{background:var(--bg);border-radius:var(--radius-xl);box-shadow:var(--shadow-lg);width:100%;max-width:440px;max-height:90vh;overflow-y:auto}
.um-modal-header{padding:24px 24px 0;display:flex;align-items:center;justify-content:space-between}
.um-modal-header h3{font-size:16px;font-weight:600;margin:0}
.um-modal-close{background:none;border:none;font-size:20px;cursor:pointer;color:var(--text-muted);padding:4px 8px;border-radius:var(--radius);transition:all var(--transition);line-height:1}
.um-modal-close:hover{background:var(--surface);color:var(--text)}
.um-modal-body{padding:20px 24px 24px}
.um-form-field{margin-bottom:16px}
.um-form-field:last-child{margin-bottom:0}
.um-form-field label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-bottom:6px}
.um-form-field input,.um-form-field select{width:100%;padding:8px 12px;font-size:13px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text);transition:border-color var(--transition)}
.um-form-field input:focus,.um-form-field select:focus{outline:none;border-color:var(--accent)}
.um-form-field input.field-error{border-color:var(--danger)}
.um-field-error{color:var(--danger);font-size:11px;margin-top:4px;display:none}
.um-field-error.visible{display:block}
.um-form-actions{display:flex;gap:10px;margin-top:20px;justify-content:flex-end}
.um-delete-warning{font-size:13px;color:var(--text-secondary);margin-bottom:16px;line-height:1.5}
.um-delete-warning strong{color:var(--danger);font-weight:600}
.um-delete-info{font-size:12px;color:var(--text-muted);margin-top:8px;padding:10px 12px;background:var(--surface);border-radius:var(--radius);border:1px solid var(--border-light)}
.um-self-warning{font-size:12px;color:var(--warning);margin-top:8px;padding:8px 12px;background:var(--warning-light);border-radius:var(--radius);border:1px solid rgba(183,121,31,0.15)}
/* ===== RESPONSIVE ===== */
@media(max-width:1024px){
  .kpi-grid{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
  .chart-grid{grid-template-columns:1fr}
}
@media(max-width:768px){
  .sidebar{position:fixed;top:0;left:0;height:100%;transform:translateX(-100%);z-index:200;box-shadow:var(--shadow-lg)}
  .sidebar.open{transform:translateX(0)}
  .sidebar-overlay.open{display:block}
  .mobile-toggle{display:block}
  .main-header{padding:0 16px 0 8px}
  .page{padding:20px 16px}
  .kpi-grid{grid-template-columns:repeat(2,1fr);gap:10px}
  .kpi{padding:14px 16px}
  .kpi-value{font-size:22px}
  .pipeline{flex-wrap:wrap;justify-content:center}
  .pipeline-connector{display:none}
  .pipeline-stage::after{display:none}
  .automation-grid{grid-template-columns:1fr}
  .settings-grid{grid-template-columns:1fr}
  .um-header{flex-direction:column;align-items:flex-start}
  .um-table th:nth-child(4),.um-table td:nth-child(4){display:none}
  .drawer{width:100%;max-width:100%}
  .detail-grid{grid-template-columns:1fr}
  .detail-grid dt{font-weight:600}
  .search-bar{flex-direction:column}
  .search-input{min-width:unset;width:100%}
}
@media(max-width:480px){
  .kpi-grid{grid-template-columns:1fr}
}

/* ===== REDUCED MOTION ===== */
@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:0.01ms!important;animation-iteration-count:1!important;transition-duration:0.01ms!important}
  .page{animation:none;opacity:1}
  .feed-item{animation:none}
  .toast{animation:none}
}

/* ===== LOGIN PAGE (Phase 6F) ===== */
.login-page{display:flex;align-items:center;justify-content:center;min-height:100vh;background:var(--bg-alt);padding:20px}
.login-card{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-xl);padding:40px;width:100%;max-width:400px;box-shadow:var(--shadow-md)}
.login-card h1{font-size:22px;font-weight:700;text-align:center;margin-bottom:4px;letter-spacing:-0.02em}
.login-card .subtitle{text-align:center;font-size:13px;color:var(--text-muted);margin-bottom:28px}
.login-field{margin-bottom:16px}
.login-field label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-bottom:6px}
.login-field input{width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:var(--radius);font-size:14px;background:var(--bg);color:var(--text);transition:border-color var(--transition)}
.login-field input:focus{outline:none;border-color:var(--accent)}
.login-error{color:var(--danger);font-size:12px;margin-bottom:12px;display:none}
.login-btn{width:100%;padding:11px;border:none;border-radius:var(--radius);font-size:14px;font-weight:600;background:var(--text);color:var(--bg);cursor:pointer;transition:all var(--transition)}
.login-btn:hover{opacity:0.9}
.login-btn:disabled{opacity:0.5;cursor:not-allowed}
.login-footer{text-align:center;margin-top:20px;font-size:12px;color:var(--text-muted)}
.login-footer a{color:var(--accent);font-weight:500}

/* ===== INTEGRATION CARDS (Phase 6F) ===== */
.integration-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px}
.integration-card{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-lg);padding:22px;box-shadow:var(--shadow-xs);transition:all var(--transition)}
.integration-card:hover{box-shadow:var(--shadow-sm)}
.integration-card-header{display:flex;align-items:center;gap:12px;margin-bottom:14px}
.integration-icon{width:40px;height:40px;border-radius:var(--radius);display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.integration-icon.google{background:rgba(66,133,244,0.1);color:#4285F4}
.integration-icon.ai{background:rgba(16,185,129,0.1);color:#10B981}
.integration-icon.zoom{background:rgba(45,143,234,0.1);color:#2D8FEA}
.integration-icon.calendar{background:rgba(52,168,83,0.1);color:#34A853}
.integration-icon.email{background:rgba(234,67,53,0.1);color:#EA4335}
.integration-status-badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}
.integration-status-badge.connected{background:var(--accent-light);color:var(--accent)}
.integration-status-badge.pending{background:var(--warning-light);color:var(--warning)}
.integration-status-badge.disconnected{background:var(--surface);color:var(--text-muted)}
.integration-status-badge.error{background:var(--danger-light);color:var(--danger)}
.integration-meta{font-size:12px;color:var(--text-muted);margin-bottom:14px;line-height:1.5}
.integration-actions{display:flex;gap:8px;flex-wrap:wrap}

/* ===== PHASE 18: FOLLOW-UP BADGES ===== */
.status-badge{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:0.02em;white-space:nowrap}
.status-badge.status-pending{background:var(--warning-light);color:var(--warning)}
.status-badge.status-scheduled,.status-badge.status-in-progress{background:var(--info-light);color:var(--info)}
.status-badge.status-completed{background:var(--accent-light);color:var(--accent)}
.status-badge.status-cancelled,.status-badge.status-declined{background:var(--danger-light);color:var(--danger)}
.btn-xs{padding:3px 8px;font-size:11px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--bg);color:var(--text);cursor:pointer;transition:all var(--transition)}
.btn-xs:hover{background:var(--surface);border-color:var(--text-muted)}
.btn-xs.btn-primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn-xs.btn-success{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn-xs.btn-danger{background:var(--danger);color:#fff;border-color:var(--danger)}

/* ===== WEBHOOK PAGE (Phase 6F) ===== */
.webhook-url-box{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;font-family:var(--font-mono);font-size:13px;color:var(--text-secondary);word-break:break-all;margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;gap:12px}
.webhook-url-box .copy-btn{flex-shrink:0}
.secret-box{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;font-family:var(--font-mono);font-size:13px;color:var(--text-secondary);margin-bottom:16px}
.secret-warning{background:var(--warning-light);border:1px solid rgba(183,121,31,0.2);border-radius:var(--radius);padding:12px 16px;font-size:12px;color:var(--warning);margin-bottom:16px;line-height:1.5}
.secret-warning strong{font-weight:600}

/* ===== AUDIT LOG (Phase 6F) ===== */
.audit-list{display:flex;flex-direction:column;gap:0}
.audit-item{display:flex;gap:12px;padding:12px 0;border-bottom:1px solid var(--border-light);align-items:flex-start}
.audit-item:last-child{border-bottom:none}
.audit-dot{width:8px;height:8px;border-radius:50%;margin-top:6px;flex-shrink:0}
.audit-dot.green{background:var(--accent)}
.audit-dot.blue{background:var(--info)}
.audit-dot.amber{background:var(--warning)}
.audit-dot.red{background:var(--danger)}
.audit-dot.gray{background:var(--text-faint)}
.audit-text{flex:1;font-size:13px;color:var(--text-secondary);line-height:1.4}
.audit-text strong{color:var(--text);font-weight:600}
.audit-time{font-size:11px;color:var(--text-faint);font-family:var(--font-mono);white-space:nowrap;margin-top:2px}

/* ===== SETTINGS FORM (Phase 6F) ===== */
.settings-form .setting-field input[type="text"],
.settings-form .setting-field input[type="color"],
.settings-form .setting-field select{font-size:13px;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text);width:100%;max-width:300px;transition:border-color var(--transition)}
.settings-form .setting-field input:focus,
.settings-form .setting-field select:focus{outline:none;border-color:var(--accent)}
.color-input-wrap{display:flex;align-items:center;gap:10px}
.color-input-wrap input[type="color"]{width:40px;height:36px;padding:2px;border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer}
.color-input-wrap .color-hint{font-size:12px;color:var(--text-muted);font-family:var(--font-mono)}

/* ===== ONBOARDING WIZARD (Phase 7) ===== */
.onboarding-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:500;display:flex;align-items:center;justify-content:center;padding:20px}
.onboarding-card{background:var(--bg);border-radius:var(--radius-xl);box-shadow:var(--shadow-lg);width:100%;max-width:560px;max-height:90vh;overflow-y:auto}
.onboarding-header{padding:32px 32px 0;text-align:center}
.onboarding-header h2{font-size:20px;font-weight:700;margin-bottom:4px;letter-spacing:-0.02em}
.onboarding-header p{font-size:13px;color:var(--text-muted);margin-bottom:24px}
.onboarding-progress{display:flex;gap:6px;padding:0 32px;margin-bottom:28px}
.onboarding-progress .step{flex:1;height:4px;border-radius:2px;background:var(--border);transition:background var(--transition)}
.onboarding-progress .step.done{background:var(--accent)}
.onboarding-progress .step.active{background:var(--accent);opacity:0.5}
.onboarding-body{padding:0 32px 32px}
.onboarding-step{display:none}
.onboarding-step.active{display:block}
.onboarding-step h3{font-size:16px;font-weight:600;margin-bottom:4px}
.onboarding-step .desc{font-size:13px;color:var(--text-muted);margin-bottom:20px;line-height:1.5}
.onboarding-checklist{list-style:none;margin:0 0 24px;padding:0}
.onboarding-checklist li{display:flex;align-items:center;gap:12px;padding:12px 16px;background:var(--surface);border-radius:var(--radius);margin-bottom:8px;font-size:13px}
.onboarding-checklist li .check-icon{width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
.onboarding-checklist li .check-icon.pending{background:var(--border-light);color:var(--text-muted)}
.onboarding-checklist li .check-icon.done{background:var(--accent-light);color:var(--accent)}
.onboarding-nav{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:0 32px 28px}
.onboarding-skip{font-size:12px;color:var(--text-muted);cursor:pointer;background:none;border:none;padding:8px}
.onboarding-skip:hover{color:var(--text)}

/* ===== SETUP CHECKLIST WIDGET (Phase 7) ===== */
.setup-checklist{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-lg);padding:20px 24px;margin-bottom:28px;box-shadow:var(--shadow-xs)}
.setup-checklist-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.setup-checklist-header h3{font-size:14px;font-weight:600;display:flex;align-items:center;gap:8px}
.setup-checklist-header .progress-text{font-size:12px;color:var(--text-muted)}
.setup-progress-bar{height:6px;background:var(--border-light);border-radius:3px;margin-bottom:16px;overflow:hidden}
.setup-progress-bar .fill{height:100%;background:var(--accent);border-radius:3px;transition:width 0.4s ease}
.setup-step{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:var(--radius);cursor:pointer;transition:background var(--transition);margin-bottom:4px}
.setup-step:hover{background:var(--surface)}
.setup-step .step-check{width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;flex-shrink:0;border:2px solid var(--border)}
.setup-step .step-check.done{background:var(--accent);border-color:var(--accent);color:#fff}
.setup-step .step-check.pending{border-color:var(--border)}
.setup-step .step-info{flex:1}
.setup-step .step-label{font-size:13px;font-weight:500;color:var(--text)}
.setup-step .step-desc{font-size:11px;color:var(--text-muted)}
.setup-step.done .step-label{color:var(--text-muted)}
.setup-step.done .step-desc{color:var(--text-faint)}

/* ===== PIPELINE HEALTH (Phase 7) ===== */
.pipeline-health{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.pipeline-health-stat{text-align:center;padding:12px;background:var(--surface);border-radius:var(--radius)}
.pipeline-health-stat .val{font-size:20px;font-weight:700}
.pipeline-health-stat .lbl{font-size:11px;color:var(--text-muted);margin-top:2px}
.pipeline-health-stat.green .val{color:var(--accent)}
.pipeline-health-stat.amber .val{color:var(--warning)}
.pipeline-health-stat.red .val{color:var(--danger)}
.pipeline-health-stat.blue .val{color:var(--info)}
@media(max-width:768px){.pipeline-health{grid-template-columns:repeat(2,1fr)}}
.followups-stats{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}
@media(max-width:768px){.followups-stats{grid-template-columns:repeat(3,1fr)}}
</style>
</head>
<body>

<!-- TOAST CONTAINER -->
<div class="toast-container" id="toast-container"></div>

<!-- LOGIN PAGE (Phase 6F) -->
<div class="login-page" id="login-page" style="display:none">
  <div class="login-card">
    <h1>Strategy Call Agent</h1>
    <p class="subtitle">Sign in to your dashboard</p>
    <div class="login-error" id="login-error"></div>
    <form id="login-form" autocomplete="on">
      <div class="login-field">
        <label for="login-email">Email</label>
        <input type="email" id="login-email" placeholder="you@company.com" required autocomplete="email">
      </div>
      <div class="login-field">
        <label for="login-password">Password</label>
        <input type="password" id="login-password" placeholder="••••••••" required autocomplete="current-password">
      </div>
      <button type="submit" class="login-btn" id="login-btn">Sign In</button>
    </form>
    <div class="login-footer">Don't have an account? <a href="#" id="show-register">Create one</a></div>
  </div>
</div>

<!-- REGISTER PAGE (Phase 6F) -->
<div class="login-page" id="register-page" style="display:none">
  <div class="login-card">
    <h1>Strategy Call Agent</h1>
    <p class="subtitle">Create your organization</p>
    <div class="login-error" id="register-error"></div>
    <form id="register-form" autocomplete="on">
      <div class="login-field">
        <label for="reg-org-name">Organization Name</label>
        <input type="text" id="reg-org-name" placeholder="Acme Inc." required>
      </div>
      <div class="login-field">
        <label for="reg-name">Your Name</label>
        <input type="text" id="reg-name" placeholder="John Doe" required>
      </div>
      <div class="login-field">
        <label for="reg-email">Email</label>
        <input type="email" id="reg-email" placeholder="you@company.com" required autocomplete="email">
      </div>
      <div class="login-field">
        <label for="reg-password">Password</label>
        <input type="password" id="reg-password" placeholder="Min 8 characters" required minlength="8" autocomplete="new-password">
      </div>
      <button type="submit" class="login-btn" id="reg-btn">Create Account</button>
    </form>
    <div class="login-footer">Already have an account? <a href="#" id="show-login">Sign in</a></div>
  </div>
</div>

<!-- SIDEBAR OVERLAY (mobile) -->
<div class="sidebar-overlay" id="sidebar-overlay"></div>

<!-- DRAWER OVERLAY -->
<div class="drawer-overlay" id="drawer-overlay"></div>

<!-- LEAD DETAIL DRAWER -->
<div class="drawer" id="lead-drawer">
  <div class="drawer-header">
    <h3 id="drawer-title">Lead Detail</h3>
    <button class="drawer-close" id="drawer-close">&times;</button>
  </div>
  <div class="drawer-body" id="drawer-body">
    <div class="empty-state"><div class="icon">&#128203;</div><p>Select a lead to view details.</p></div>
  </div>
</div>

<!-- ONBOARDING WIZARD (Phase 7) -->
<div class="onboarding-overlay" id="onboarding-overlay" style="display:none">
  <div class="onboarding-card">
    <div class="onboarding-header">
      <h2 id="onboarding-title">Welcome to Strategy Call Agent</h2>
      <p id="onboarding-subtitle">Let's get your account set up in a few quick steps.</p>
    </div>
    <div class="onboarding-progress" id="onboarding-progress">
      <div class="step active"></div><div class="step"></div><div class="step"></div><div class="step"></div>
    </div>
    <div class="onboarding-body" id="onboarding-body">
      <!-- Step 1: Overview -->
      <div class="onboarding-step active" id="onboard-step-1">
        <h3>Get Started</h3>
        <p class="desc">Here's what we'll set up to get your lead pipeline running:</p>
        <ul class="onboarding-checklist" id="onboard-overview-list">
          <li><span class="check-icon pending">&#8943;</span><div><strong>Connect Google</strong><br><span style="font-size:11px;color:var(--text-muted)">Calendar + Gmail integration</span></div></li>
          <li><span class="check-icon pending">&#8943;</span><div><strong>Configure Webhook</strong><br><span style="font-size:11px;color:var(--text-muted)">Set up form submission endpoint</span></div></li>
          <li><span class="check-icon pending">&#8943;</span><div><strong>Schedule Settings</strong><br><span style="font-size:11px;color:var(--text-muted)">Timezone and reminder preferences</span></div></li>
          <li><span class="check-icon pending">&#8943;</span><div><strong>Brand Your Emails</strong><br><span style="font-size:11px;color:var(--text-muted)">Add sender name and brand color</span></div></li>
        </ul>
      </div>
      <!-- Step 2: Google Connect -->
      <div class="onboarding-step" id="onboard-step-2">
        <h3>Connect Google Account</h3>
        <p class="desc">Link your Google account to enable Calendar event creation and Gmail for sending confirmation emails.</p>
        <div id="onboard-google-status" style="padding:16px;background:var(--surface);border-radius:var(--radius);margin-bottom:16px;font-size:13px">
          Checking connection...
        </div>
      </div>
      <!-- Step 3: Quick Settings -->
      <div class="onboarding-step" id="onboard-step-3">
        <h3>Quick Settings</h3>
        <p class="desc">Set your timezone and reminder time. You can change these later.</p>
        <div class="setting-field">
          <label for="onboard-timezone">Timezone</label>
          <select id="onboard-timezone" style="width:100%;max-width:300px;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);font-size:13px">
            <optgroup label="Americas">
              <option value="Pacific/Honolulu">Hawaii Time (Pacific/Honolulu)</option>
              <option value="America/Anchorage">Alaska Time (America/Anchorage)</option>
              <option value="America/Los_Angeles">Pacific Time (America/Los_Angeles)</option>
              <option value="America/Vancouver">Pacific Time (America/Vancouver)</option>
              <option value="America/Denver">Mountain Time (America/Denver)</option>
              <option value="America/Chicago">Central Time (America/Chicago)</option>
              <option value="America/Mexico_City">Central Time (America/Mexico_City)</option>
              <option value="America/New_York">Eastern Time (America/New_York)</option>
              <option value="America/Toronto">Eastern Time (America/Toronto)</option>
              <option value="America/Sao_Paulo">Brasilia Time (America/Sao_Paulo)</option>
              <option value="America/Argentina/Buenos_Aires">Argentina Time (America/Argentina/Buenos_Aires)</option>
            </optgroup>
            <optgroup label="Europe">
              <option value="UTC">UTC</option>
              <option value="Europe/London">Greenwich Mean Time (Europe/London)</option>
              <option value="Europe/Dublin">Irish Standard Time (Europe/Dublin)</option>
              <option value="Europe/Paris">Central European Time (Europe/Paris)</option>
              <option value="Europe/Berlin">Central European Time (Europe/Berlin)</option>
              <option value="Europe/Madrid">Central European Time (Europe/Madrid)</option>
              <option value="Europe/Rome">Central European Time (Europe/Rome)</option>
              <option value="Europe/Amsterdam">Central European Time (Europe/Amsterdam)</option>
              <option value="Europe/Zurich">Central European Time (Europe/Zurich)</option>
              <option value="Europe/Stockholm">Central European Time (Europe/Stockholm)</option>
              <option value="Europe/Warsaw">Central European Time (Europe/Warsaw)</option>
              <option value="Europe/Athens">Eastern European Time (Europe/Athens)</option>
              <option value="Europe/Helsinki">Eastern European Time (Europe/Helsinki)</option>
              <option value="Europe/Istanbul">Turkey Time (Europe/Istanbul)</option>
              <option value="Europe/Moscow">Moscow Time (Europe/Moscow)</option>
            </optgroup>
            <optgroup label="Africa &amp; Middle East">
              <option value="Africa/Casablanca">Western European Time (Africa/Casablanca)</option>
              <option value="Africa/Lagos">West Africa Time (Africa/Lagos)</option>
              <option value="Africa/Cairo">Eastern European Time (Africa/Cairo)</option>
              <option value="Africa/Johannesburg">South Africa Standard Time (Africa/Johannesburg)</option>
              <option value="Africa/Nairobi">East Africa Time (Africa/Nairobi)</option>
              <option value="Asia/Jerusalem">Israel Standard Time (Asia/Jerusalem)</option>
              <option value="Asia/Dubai">Gulf Standard Time (Asia/Dubai)</option>
              <option value="Asia/Riyadh">Arabia Standard Time (Asia/Riyadh)</option>
              <option value="Asia/Qatar">Arabia Standard Time (Asia/Qatar)</option>
              <option value="Asia/Kuwait">Arabia Standard Time (Asia/Kuwait)</option>
              <option value="Asia/Bahrain">Arabia Standard Time (Asia/Bahrain)</option>
              <option value="Asia/Muscat">Gulf Standard Time (Asia/Muscat)</option>
            </optgroup>
            <optgroup label="South Asia">
              <option value="Asia/Karachi">Pakistan Standard Time (Asia/Karachi)</option>
              <option value="Asia/Kolkata">India Standard Time (Asia/Kolkata)</option>
              <option value="Asia/Dhaka">Bangladesh Standard Time (Asia/Dhaka)</option>
              <option value="Asia/Colombo">Sri Lanka Standard Time (Asia/Colombo)</option>
              <option value="Asia/Kathmandu">Nepal Time (Asia/Kathmandu)</option>
            </optgroup>
            <optgroup label="East &amp; Southeast Asia">
              <option value="Asia/Shanghai">China Standard Time (Asia/Shanghai)</option>
              <option value="Asia/Hong_Kong">Hong Kong Time (Asia/Hong_Kong)</option>
              <option value="Asia/Taipei">Taipei Standard Time (Asia/Taipei)</option>
              <option value="Asia/Tokyo">Japan Standard Time (Asia/Tokyo)</option>
              <option value="Asia/Seoul">Korea Standard Time (Asia/Seoul)</option>
              <option value="Asia/Singapore">Singapore Time (Asia/Singapore)</option>
              <option value="Asia/Bangkok">Indochina Time (Asia/Bangkok)</option>
              <option value="Asia/Jakarta">Western Indonesia Time (Asia/Jakarta)</option>
              <option value="Asia/Manila">Philippines Standard Time (Asia/Manila)</option>
            </optgroup>
            <optgroup label="Oceania">
              <option value="Australia/Perth">Australian Western Time (Australia/Perth)</option>
              <option value="Australia/Adelaide">Australian Central Time (Australia/Adelaide)</option>
              <option value="Australia/Darwin">Australian Central Time (Australia/Darwin)</option>
              <option value="Australia/Brisbane">Australian Eastern Time (Australia/Brisbane)</option>
              <option value="Australia/Sydney">Australian Eastern Time (Australia/Sydney)</option>
              <option value="Australia/Melbourne">Australian Eastern Time (Australia/Melbourne)</option>
              <option value="Pacific/Auckland">New Zealand Standard Time (Pacific/Auckland)</option>
            </optgroup>
          </select>
        </div>
        <div class="setting-field" style="margin-top:12px">
          <label for="onboard-reminder-time">Daily Reminder Time</label>
          <input type="time" id="onboard-reminder-time" value="08:00" style="max-width:200px;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);font-size:13px;font-family:var(--font-mono)">
        </div>
      </div>
      <!-- Step 4: Ready -->
      <div class="onboarding-step" id="onboard-step-4">
        <h3>You're All Set!</h3>
        <p class="desc">Your account is configured and ready to start processing leads. You can always adjust these settings from the dashboard.</p>
        <div style="padding:20px;background:var(--accent-light);border-radius:var(--radius);text-align:center;margin-bottom:16px">
          <div style="font-size:32px;margin-bottom:8px">&#10003;</div>
          <div style="font-size:14px;font-weight:600;color:var(--accent)">Setup Complete</div>
        </div>
      </div>
    </div>
    <div class="onboarding-nav" style="flex-direction:column;align-items:center;gap:12px">
      <label class="onboarding-dontshow-label" style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text-muted);cursor:pointer;user-select:none">
        <input type="checkbox" id="onboarding-dont-show-again" style="accent-color:var(--accent);width:14px;height:14px;cursor:pointer;margin:0">
        Don't show again
      </label>
      <div style="display:flex;align-items:center;gap:12px;width:100%;justify-content:space-between">
        <button class="onboarding-skip" id="onboarding-skip" onclick="dismissOnboarding()">Skip for now</button>
        <div style="display:flex;gap:8px">
          <button class="btn" id="onboard-back-btn" onclick="onboardingBack()" style="display:none">Back</button>
          <button class="btn btn-primary" id="onboard-next-btn" onclick="onboardingNext()">Get Started</button>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="app" id="app-main" style="display:none">

<!-- ===== SIDEBAR ===== -->
<aside class="sidebar" id="sidebar">
  <div class="sidebar-brand">
    <h1 id="sidebar-org-name">Strategy Call Agent</h1>
    <p id="sidebar-org-tagline">Turn website leads into booked calls</p>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-section">Main</div>
    <button class="nav-item active" data-page="overview">
      <span class="icon">&#9673;</span>Overview
    </button>
    <button class="nav-item" data-page="leads">
      <span class="icon">&#128100;</span>Leads
      <span class="badge" id="nav-leads-count" style="display:none"></span>
    </button>
    <button class="nav-item" data-page="calls">
      <span class="icon">&#128222;</span>Calls
    </button>
    <button class="nav-item" data-page="follow-ups">
      <span class="icon">&#128203;</span>Follow-ups
      <span class="badge" id="nav-followups-count" style="display:none"></span>
    </button>
    <div class="nav-section">Automation</div>
    <button class="nav-item" data-page="automations">
      <span class="icon">&#9881;</span>Automations
    </button>
    <button class="nav-item" data-page="analytics">
      <span class="icon">&#128200;</span>Analytics
    </button>
    <div class="nav-section">Configure</div>
    <button class="nav-item" data-page="integrations">
      <span class="icon">&#128279;</span>Integrations
    </button>
    <button class="nav-item" data-page="webhook">
      <span class="icon">&#128279;</span>Webhook
    </button>
    <button class="nav-item" data-page="org-settings">
      <span class="icon">&#9881;</span>Organization
    </button>
    <div class="nav-section">System</div>
    <button class="nav-item" data-page="activity">
      <span class="icon">&#128221;</span>Activity
    </button>
    <button class="nav-item" data-page="settings">
      <span class="icon">&#9881;</span>Settings
    </button>
  </nav>
  <div class="sidebar-footer">
    <div id="sidebar-user-info" style="margin-bottom:8px">
      <div style="font-size:12px;font-weight:600;color:var(--text-secondary)" id="sidebar-user-name">-</div>
      <div style="font-size:11px;color:var(--text-faint)" id="sidebar-user-role">-</div>
    </div>
    <button class="nav-item" id="logout-btn" style="padding:6px 0;color:var(--danger);font-size:12px">
      <span class="icon">&#9211;</span>Sign Out
    </button>
    <div style="margin-top:6px">v1.0 &middot; Phase 23</div>
  </div>
</aside>

<!-- ===== MAIN CONTENT ===== -->
<div class="main">
  <header class="main-header">
    <div style="display:flex;align-items:center;gap:12px">
      <button class="mobile-toggle" id="mobile-toggle">&#9776;</button>
      <h2 id="page-title">Overview</h2>
    </div>
    <div class="header-right">
      <div class="automation-badge live" id="sse-badge">
        <span class="dot"></span>
        <span id="sse-text">Connecting</span>
      </div>
    </div>
  </header>

  <div class="main-scroll">

    <!-- ===== OVERVIEW PAGE ===== -->
    <div class="page active" id="page-overview">
      <div style="margin-bottom:28px">
        <p style="font-size:15px;color:var(--text-secondary);margin-bottom:12px">Turn your website leads into booked strategy calls automatically.</p>
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
          <span style="font-size:12px;font-weight:600;color:var(--accent);background:var(--accent-light);padding:4px 10px;border-radius:12px">Capture</span>
          <span style="color:var(--text-faint)">&rarr;</span>
          <span style="font-size:12px;font-weight:600;color:var(--info);background:var(--info-light);padding:4px 10px;border-radius:12px">Qualify</span>
          <span style="color:var(--text-faint)">&rarr;</span>
          <span style="font-size:12px;font-weight:600;color:var(--accent);background:var(--accent-light);padding:4px 10px;border-radius:12px">Book</span>
          <span style="color:var(--text-faint)">&rarr;</span>
          <span style="font-size:12px;font-weight:600;color:var(--info);background:var(--info-light);padding:4px 10px;border-radius:12px">Confirm</span>
          <span style="color:var(--text-faint)">&rarr;</span>
          <span style="font-size:12px;font-weight:600;color:var(--accent);background:var(--accent-light);padding:4px 10px;border-radius:12px">Remind</span>
        </div>
      </div>

      <!-- KPI Cards -->
      <div class="kpi-grid" id="kpi-grid">
        <div class="kpi skeleton skeleton-card"></div>
        <div class="kpi skeleton skeleton-card"></div>
        <div class="kpi skeleton skeleton-card"></div>
        <div class="kpi skeleton skeleton-card"></div>
        <div class="kpi skeleton skeleton-card"></div>
      </div>

      <!-- Pipeline -->
      <div class="card" style="margin-bottom:28px" id="overview-pipeline">
        <div class="card-header"><h3>Pipeline</h3></div>
        <div class="pipeline" id="overview-pipeline-stages">
          <div class="skeleton skeleton-row w80" style="height:60px"></div>
        </div>
      </div>

      <!-- Setup Checklist (Phase 7) - hidden when setup is complete -->
      <div class="setup-checklist" id="setup-checklist" style="display:none">
        <div class="setup-checklist-header">
          <h3>&#128736; Setup Checklist</h3>
          <span class="progress-text" id="setup-progress-text"></span>
        </div>
        <div class="setup-progress-bar"><div class="fill" id="setup-progress-fill" style="width:0%"></div></div>
        <div id="setup-steps-list"></div>
        <div style="margin-top:12px;text-align:right">
          <button class="btn btn-sm" onclick="dismissSetupChecklist()">Dismiss</button>
        </div>
      </div>

      <!-- Pipeline Health (Phase 7) -->
      <div class="card" style="margin-bottom:28px" id="overview-pipeline-health" style="display:none">
        <div class="card-header"><h3>Pipeline Health</h3></div>
        <div class="pipeline-health" id="pipeline-health-grid">
          <div class="pipeline-health-stat"><div class="val">-</div><div class="lbl">Total Leads</div></div>
          <div class="pipeline-health-stat green"><div class="val">-</div><div class="lbl">Completed</div></div>
          <div class="pipeline-health-stat amber"><div class="val">-</div><div class="lbl">Pending</div></div>
          <div class="pipeline-health-stat red"><div class="val">-</div><div class="lbl">Errors (24h)</div></div>
        </div>
      </div>

      <!-- Two-column: Upcoming Calls + Activity -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:28px" id="overview-columns">
        <div class="card" id="overview-upcoming">
          <div class="card-header"><h3>Upcoming Calls</h3></div>
          <div id="upcoming-calls-list">
            <div class="skeleton skeleton-row w80" style="height:40px;margin-bottom:8px"></div>
            <div class="skeleton skeleton-row w60" style="height:40px"></div>
          </div>
        </div>
        <div class="card" id="overview-activity">
          <div class="card-header"><h3>Recent Activity</h3></div>
          <div id="activity-feed">
            <div class="skeleton skeleton-row w80" style="height:36px;margin-bottom:8px"></div>
            <div class="skeleton skeleton-row w60" style="height:36px;margin-bottom:8px"></div>
            <div class="skeleton skeleton-row w80" style="height:36px"></div>
          </div>
        </div>
      </div>

      <!-- Automation Status Bar -->
      <div class="card" id="overview-automations">
        <div class="card-header"><h3>Automation Status</h3></div>
        <div id="overview-auto-status" style="display:flex;gap:16px;flex-wrap:wrap"></div>
      </div>
    </div>

    <!-- ===== LEADS PAGE ===== -->
    <div class="page" id="page-leads">
      <div class="search-bar">
        <input type="text" class="search-input" id="leads-search" placeholder="Search leads by name, email, or company...">
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
          <button class="btn btn-primary" id="cl-create-btn" onclick="showCreateLeadModal()" data-admin-only>+ Create Lead</button>
          <button class="filter-btn active" data-filter="all">All</button>
          <button class="filter-btn" data-filter="pending">Pending</button>
          <button class="filter-btn" data-filter="scheduled">Scheduled</button>
          <button class="filter-btn" data-filter="accepted">Accepted</button>
          <button class="filter-btn" data-filter="declined">Declined</button>
          <button class="filter-btn" data-filter="error">Error</button>
        </div>
      </div>
      <div class="card">
        <div class="table-wrap" id="leads-table-wrap">
          <div class="skeleton skeleton-row w80" style="height:40px;margin-bottom:8px"></div>
          <div class="skeleton skeleton-row w60" style="height:40px;margin-bottom:8px"></div>
          <div class="skeleton skeleton-row w80" style="height:40px"></div>
        </div>
      </div>
    </div>

    <!-- ===== CALLS PAGE ===== -->
    <div class="page" id="page-calls">
      <div style="display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap">
        <button class="filter-btn active" data-call-filter="upcoming">Upcoming <span class="filter-count" id="calls-count-upcoming"></span></button>
        <button class="filter-btn" data-call-filter="today">Today <span class="filter-count" id="calls-count-today"></span></button>
        <button class="filter-btn" data-call-filter="past">Past <span class="filter-count" id="calls-count-past"></span></button>
        <button class="filter-btn" data-call-filter="all">All Booked <span class="filter-count" id="calls-count-all"></span></button>
        <button class="filter-btn" data-call-filter="cancelled">Cancelled <span class="filter-count" id="calls-count-cancelled"></span></button>
      </div>
      <div class="card" id="calls-table-card">
        <div class="table-wrap" id="calls-table-wrap">
          <div class="skeleton skeleton-row w80" style="height:40px;margin-bottom:8px"></div>
          <div class="skeleton skeleton-row w60" style="height:40px"></div>
        </div>
      </div>
    </div>

    <!-- ===== FOLLOW-UPS PAGE (Phase 18 + Phase 7 Part 5) ===== -->
    <div class="page" id="page-follow-ups">
      <!-- Stats cards (Phase 7 Part 5) -->
      <div class="followups-stats" id="followups-stats-grid" style="margin-bottom:20px">
        <div class="pipeline-health-stat blue"><div class="val" id="fu-stat-total">-</div><div class="lbl">Total</div></div>
        <div class="pipeline-health-stat amber"><div class="val" id="fu-stat-active">-</div><div class="lbl">Active</div></div>
        <div class="pipeline-health-stat green"><div class="val" id="fu-stat-completed">-</div><div class="lbl">Completed</div></div>
        <div class="pipeline-health-stat red"><div class="val" id="fu-stat-cancelled">-</div><div class="lbl">Cancelled</div></div>
        <div class="pipeline-health-stat red"><div class="val" id="fu-stat-overdue">-</div><div class="lbl">Overdue</div></div>
        <div class="pipeline-health-stat blue"><div class="val" id="fu-stat-avg">-</div><div class="lbl">Avg Completion</div></div>
      </div>
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:12px">
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="filter-btn active" data-fu-filter="all">All</button>
          <button class="filter-btn" data-fu-filter="pending">Pending</button>
          <button class="filter-btn" data-fu-filter="in_progress">In Progress</button>
          <button class="filter-btn" data-fu-filter="completed">Completed</button>
          <button class="filter-btn" data-fu-filter="cancelled">Cancelled</button>
        </div>
        <button class="btn btn-primary" id="btn-create-followup" data-admin-only>
          + New Follow-up
        </button>
      </div>
      <div class="card" id="followups-table-card">
        <div class="table-wrap" id="followups-table-wrap">
          <div class="skeleton skeleton-row w80" style="height:40px;margin-bottom:8px"></div>
          <div class="skeleton skeleton-row w60" style="height:40px;margin-bottom:8px"></div>
          <div class="skeleton skeleton-row w80" style="height:40px"></div>
        </div>
      </div>
    </div>

    <!-- ===== AUTOMATIONS PAGE ===== -->
    <div class="page" id="page-automations">
      <p style="font-size:13px;color:var(--text-muted);margin-bottom:20px">Manage your automated workflow. Each automation runs independently to process and nurture your leads.</p>
      <div class="automation-grid" id="automations-grid">
        <div class="skeleton skeleton-card" style="height:180px"></div>
        <div class="skeleton skeleton-card" style="height:180px"></div>
        <div class="skeleton skeleton-card" style="height:180px"></div>
      </div>
    </div>

    <!-- ===== ANALYTICS PAGE ===== -->
    <div class="page" id="page-analytics">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
        <p style="font-size:13px;color:var(--text-muted)">Track your lead acquisition and booking performance over time.</p>
        <div class="time-filter" id="analytics-time-filter">
          <button data-days="7">7 Days</button>
          <button data-days="30" class="active">30 Days</button>
          <button data-days="90">90 Days</button>
        </div>
      </div>
      <div class="chart-grid" id="analytics-charts">
        <div class="chart-container">
          <div class="chart-title">Leads Over Time</div>
          <canvas id="chart-leads"></canvas>
        </div>
        <div class="chart-container">
          <div class="chart-title">Appointments Over Time</div>
          <canvas id="chart-appointments"></canvas>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><h3>Pipeline Distribution</h3></div>
        <div id="analytics-pipeline-dist" style="padding:12px 0"></div>
      </div>
    </div>

    <!-- ===== SETTINGS PAGE ===== -->
    <div class="page" id="page-settings">
      <p style="font-size:13px;color:var(--text-muted);margin-bottom:20px">Configure how your automation behaves. Changes take effect immediately.</p>
      <div class="settings-grid">
        <div class="setting-group">
          <h4>Appointment Reminders</h4>
          <p class="desc">Choose when automated reminders are sent to leads with upcoming appointments.</p>
          <div class="setting-field">
            <label for="s-reminder-time">Reminder Time</label>
            <input type="time" id="s-reminder-time" value="08:00">
          </div>
        </div>
        <div class="setting-group">
          <h4>RSVP Monitoring</h4>
          <p class="desc">How often we check for attendee responses and update appointment status.</p>
          <div class="setting-field">
            <label for="s-rsvp-interval">Check Interval (minutes)</label>
            <input type="number" id="s-rsvp-interval" min="1" value="10">
          </div>
        </div>
        <div class="setting-group">
          <h4>Manual Actions</h4>
          <p class="desc">Trigger automations manually for testing or immediate execution.</p>
          <div class="trigger-row" style="border-top:none;padding-top:0;margin-top:0">
            <button class="btn" id="s-trigger-reminders">Send Pending Reminders</button>
            <button class="btn" id="s-trigger-poll">Check RSVPs Now</button>
          </div>
          <div class="trigger-result" id="s-trigger-result"></div>
        </div>
      </div>
      <div style="margin-top:24px;display:flex;gap:12px">
        <button class="btn btn-primary" id="s-save-settings">Save Settings</button>
        <span id="s-settings-msg" style="font-size:12px;display:flex;align-items:center"></span>
      </div>
    </div>

    <!-- ===== INTEGRATIONS PAGE (Phase 6F) ===== -->
    <div class="page" id="page-integrations">
      <p style="font-size:13px;color:var(--text-muted);margin-bottom:12px">Manage your connected services and API integrations.</p>
      <div id="meeting-provider-status" style="margin-bottom:16px"></div>
      <div class="integration-grid" id="integrations-grid">
        <div class="skeleton skeleton-card" style="height:180px"></div>
        <div class="skeleton skeleton-card" style="height:180px"></div>
      </div>

      <!-- Google Form Field Mapping Section -->
      <div id="field-mapping-section" style="margin-top:24px;display:none">
        <div class="setting-group" style="grid-column:1/-1">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
            <div>
              <h4>Google Form Field Mapping</h4>
              <p class="desc" style="margin:0">Map Google Form question labels to lead fields. Customize how incoming form data maps to your lead records.</p>
            </div>
            <div style="display:flex;gap:8px" id="field-mapping-actions">
              <button class="btn btn-sm btn-primary" id="btn-save-mapping" onclick="saveFieldMappings()" style="display:none">Save</button>
              <button class="btn btn-sm btn-danger" id="btn-reset-mapping" onclick="resetFieldMappings()" style="display:none">Reset to Default</button>
            </div>
          </div>
          <div id="field-mapping-status" style="font-size:12px;margin-bottom:12px"></div>
          <div id="field-mapping-table-wrap" style="overflow-x:auto">
            <table id="field-mapping-table" style="width:100%;border-collapse:collapse;font-size:13px">
              <thead>
                <tr style="border-bottom:2px solid var(--border)">
                  <th style="text-align:left;padding:8px 12px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted)">Order</th>
                  <th style="text-align:left;padding:8px 12px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted)">Google Form Label</th>
                  <th style="text-align:left;padding:8px 12px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted)">Maps to Lead Field</th>
                  <th style="text-align:center;padding:8px 12px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted)">Required</th>
                  <th style="text-align:center;padding:8px 12px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted)">Actions</th>
                </tr>
              </thead>
              <tbody id="field-mapping-tbody">
                <tr><td colspan="5" style="padding:20px;text-align:center;color:var(--text-muted)">Loading...</td></tr>
              </tbody>
            </table>
          </div>
          <div id="field-mapping-add-row" style="margin-top:12px;display:none">
            <button class="btn btn-sm" onclick="addFieldMappingRow()">+ Add Field</button>
          </div>
          <div id="field-mapping-defaults" style="margin-top:12px;display:none">
            <details>
              <summary style="cursor:pointer;font-size:12px;color:var(--text-muted);padding:4px 0">Default mapping (IT Training org)</summary>
              <div id="field-mapping-defaults-list" style="margin-top:8px;padding:12px;background:var(--surface);border-radius:var(--radius);font-size:12px"></div>
            </details>
          </div>
        </div>
      </div>
    </div>

    <!-- ===== WEBHOOK PAGE (Phase 6F) ===== -->
    <div class="page" id="page-webhook">
      <p style="font-size:13px;color:var(--text-muted);margin-bottom:20px">Configure your webhook endpoint for receiving form submissions.</p>
      <div class="settings-grid">
        <div class="setting-group" style="grid-column:1/-1">
          <h4>Webhook URL</h4>
          <p class="desc">Use this URL in your Google Apps Script or form integration to send submissions to Strategy Call Agent.</p>
          <div class="webhook-url-box" id="webhook-url-display">
            <span id="webhook-url-text">Loading...</span>
            <button class="btn btn-sm" onclick="copyWebhookUrl()">Copy</button>
          </div>
        </div>
        <div class="setting-group">
          <h4>Webhook Secret</h4>
          <p class="desc">A shared secret used to authenticate incoming webhook requests.</p>
          <div class="secret-box" id="webhook-secret-display">Loading...</div>
          <div class="integration-actions" style="margin-top:12px">
            <button class="btn btn-sm" id="btn-rotate-secret" onclick="rotateWebhookSecret()">Rotate Secret</button>
            <button class="btn btn-sm" id="btn-test-webhook" onclick="testWebhook()">Test Configuration</button>
          </div>
          <div id="webhook-test-result" style="margin-top:12px;font-size:12px"></div>
        </div>
        <div class="setting-group" id="secret-rotation-warning" style="display:none">
          <div class="secret-warning">
            <strong>&#9888; Secret Shown Once</strong><br>
            Copy this secret now. It will not be shown again after you close this page.
          </div>
          <div class="secret-box" id="rotated-secret-value" style="color:var(--accent);font-weight:600"></div>
          <button class="btn btn-sm" onclick="copyRotatedSecret()">Copy Secret</button>
        </div>
      </div>
    </div>

    <!-- ===== ORG SETTINGS PAGE (Phase 6F) ===== -->
    <div class="page" id="page-org-settings">
      <p style="font-size:13px;color:var(--text-muted);margin-bottom:20px">Manage your organization profile, branding, and scheduling configuration.</p>
      <div class="settings-grid settings-form" id="org-settings-form">
        <div class="setting-group">
          <h4>Organization Profile</h4>
          <p class="desc">Basic information about your organization.</p>
          <div class="setting-field">
            <label for="os-name">Organization Name</label>
            <input type="text" id="os-name" placeholder="Acme Inc.">
          </div>
          <div class="setting-field">
            <label for="os-display-name">Display Name</label>
            <input type="text" id="os-display-name" placeholder="Optional display name">
          </div>
          <div class="setting-field">
            <label for="os-timezone">Timezone</label>
            <select id="os-timezone">
              <optgroup label="Americas">
                <option value="Pacific/Honolulu">Hawaii Time (Pacific/Honolulu)</option>
                <option value="America/Anchorage">Alaska Time (America/Anchorage)</option>
                <option value="America/Los_Angeles">Pacific Time (America/Los_Angeles)</option>
                <option value="America/Vancouver">Pacific Time (America/Vancouver)</option>
                <option value="America/Denver">Mountain Time (America/Denver)</option>
                <option value="America/Chicago">Central Time (America/Chicago)</option>
                <option value="America/Mexico_City">Central Time (America/Mexico_City)</option>
                <option value="America/New_York">Eastern Time (America/New_York)</option>
                <option value="America/Toronto">Eastern Time (America/Toronto)</option>
                <option value="America/Sao_Paulo">Brasilia Time (America/Sao_Paulo)</option>
                <option value="America/Argentina/Buenos_Aires">Argentina Time (America/Argentina/Buenos_Aires)</option>
              </optgroup>
              <optgroup label="Europe">
                <option value="UTC">UTC</option>
                <option value="Europe/London">Greenwich Mean Time (Europe/London)</option>
                <option value="Europe/Dublin">Irish Standard Time (Europe/Dublin)</option>
                <option value="Europe/Paris">Central European Time (Europe/Paris)</option>
                <option value="Europe/Berlin">Central European Time (Europe/Berlin)</option>
                <option value="Europe/Madrid">Central European Time (Europe/Madrid)</option>
                <option value="Europe/Rome">Central European Time (Europe/Rome)</option>
                <option value="Europe/Amsterdam">Central European Time (Europe/Amsterdam)</option>
                <option value="Europe/Zurich">Central European Time (Europe/Zurich)</option>
                <option value="Europe/Stockholm">Central European Time (Europe/Stockholm)</option>
                <option value="Europe/Warsaw">Central European Time (Europe/Warsaw)</option>
                <option value="Europe/Athens">Eastern European Time (Europe/Athens)</option>
                <option value="Europe/Helsinki">Eastern European Time (Europe/Helsinki)</option>
                <option value="Europe/Istanbul">Turkey Time (Europe/Istanbul)</option>
                <option value="Europe/Moscow">Moscow Time (Europe/Moscow)</option>
              </optgroup>
              <optgroup label="Africa &amp; Middle East">
                <option value="Africa/Casablanca">Western European Time (Africa/Casablanca)</option>
                <option value="Africa/Lagos">West Africa Time (Africa/Lagos)</option>
                <option value="Africa/Cairo">Eastern European Time (Africa/Cairo)</option>
                <option value="Africa/Johannesburg">South Africa Standard Time (Africa/Johannesburg)</option>
                <option value="Africa/Nairobi">East Africa Time (Africa/Nairobi)</option>
                <option value="Asia/Jerusalem">Israel Standard Time (Asia/Jerusalem)</option>
                <option value="Asia/Dubai">Gulf Standard Time (Asia/Dubai)</option>
                <option value="Asia/Riyadh">Arabia Standard Time (Asia/Riyadh)</option>
                <option value="Asia/Qatar">Arabia Standard Time (Asia/Qatar)</option>
                <option value="Asia/Kuwait">Arabia Standard Time (Asia/Kuwait)</option>
                <option value="Asia/Bahrain">Arabia Standard Time (Asia/Bahrain)</option>
                <option value="Asia/Muscat">Gulf Standard Time (Asia/Muscat)</option>
              </optgroup>
              <optgroup label="South Asia">
                <option value="Asia/Karachi">Pakistan Standard Time (Asia/Karachi)</option>
                <option value="Asia/Kolkata">India Standard Time (Asia/Kolkata)</option>
                <option value="Asia/Dhaka">Bangladesh Standard Time (Asia/Dhaka)</option>
                <option value="Asia/Colombo">Sri Lanka Standard Time (Asia/Colombo)</option>
                <option value="Asia/Kathmandu">Nepal Time (Asia/Kathmandu)</option>
              </optgroup>
              <optgroup label="East &amp; Southeast Asia">
                <option value="Asia/Shanghai">China Standard Time (Asia/Shanghai)</option>
                <option value="Asia/Hong_Kong">Hong Kong Time (Asia/Hong_Kong)</option>
                <option value="Asia/Taipei">Taipei Standard Time (Asia/Taipei)</option>
                <option value="Asia/Tokyo">Japan Standard Time (Asia/Tokyo)</option>
                <option value="Asia/Seoul">Korea Standard Time (Asia/Seoul)</option>
                <option value="Asia/Singapore">Singapore Time (Asia/Singapore)</option>
                <option value="Asia/Bangkok">Indochina Time (Asia/Bangkok)</option>
                <option value="Asia/Jakarta">Western Indonesia Time (Asia/Jakarta)</option>
                <option value="Asia/Manila">Philippines Standard Time (Asia/Manila)</option>
              </optgroup>
              <optgroup label="Oceania">
                <option value="Australia/Perth">Australian Western Time (Australia/Perth)</option>
                <option value="Australia/Adelaide">Australian Central Time (Australia/Adelaide)</option>
                <option value="Australia/Darwin">Australian Central Time (Australia/Darwin)</option>
                <option value="Australia/Brisbane">Australian Eastern Time (Australia/Brisbane)</option>
                <option value="Australia/Sydney">Australian Eastern Time (Australia/Sydney)</option>
                <option value="Australia/Melbourne">Australian Eastern Time (Australia/Melbourne)</option>
                <option value="Pacific/Auckland">New Zealand Standard Time (Pacific/Auckland)</option>
              </optgroup>
            </select>
          </div>
        </div>
        <div class="setting-group">
          <h4>Email Branding</h4>
          <p class="desc">Customize how emails appear to your prospects.</p>
          <div class="setting-field">
            <label for="os-sender-name">Sender Name</label>
            <input type="text" id="os-sender-name" placeholder="e.g. Acme Scheduling">
          </div>
          <div class="setting-field">
            <label for="os-tagline">Tagline</label>
            <input type="text" id="os-tagline" placeholder="e.g. Your success is our priority">
          </div>
          <div class="setting-field">
            <label for="os-brand-color">Brand Color</label>
            <div class="color-input-wrap">
              <input type="color" id="os-brand-color" value="#0E8A5F">
              <span class="color-hint" id="os-brand-color-hint">#0E8A5F</span>
            </div>
          </div>
        </div>
        <div class="setting-group">
          <h4>Scheduling</h4>
          <p class="desc">Configure meeting duration and scheduling behavior.</p>
          <div class="setting-field">
            <label for="os-meeting-duration">Meeting Duration (minutes)</label>
            <input type="number" id="os-meeting-duration" min="15" max="120" value="30">
          </div>
          <div class="setting-field">
            <label for="os-rsvp-interval">RSVP Check Interval (minutes)</label>
            <input type="number" id="os-rsvp-interval" min="1" max="1440" value="10">
          </div>
        </div>
      </div>
      <div style="margin-top:24px;display:flex;gap:12px;align-items:center">
        <button class="btn btn-primary" id="os-save-btn" onclick="saveOrgSettings()">Save Settings</button>
        <span id="os-save-msg" style="font-size:12px"></span>
      </div>

      <!-- ===== USER MANAGEMENT (Phase 1) ===== -->
      <div class="um-section" id="um-section">
        <div class="um-header">
          <div>
            <h4>Team Members</h4>
            <p class="desc">Manage users in your organization.</p>
          </div>
          <div class="um-actions">
            <span class="um-total" id="um-total"></span>
            <button class="btn btn-sm" onclick="loadUsers()">Refresh</button>
            <button class="btn btn-sm btn-primary" id="um-create-btn" onclick="showCreateUserModal()">Add User</button>
          </div>
        </div>
        <div id="um-user-list">
          <div class="skeleton skeleton-row w80" style="height:44px;margin-bottom:8px"></div>
          <div class="skeleton skeleton-row w60" style="height:44px;margin-bottom:8px"></div>
          <div class="skeleton skeleton-row w80" style="height:44px"></div>
        </div>
      </div>
    </div>

    <!-- ===== ACTIVITY / AUDIT PAGE (Phase 6F) ===== -->
    <div class="page" id="page-activity">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
        <p style="font-size:13px;color:var(--text-muted)">View organization-scoped activity and audit events.</p>
        <div style="display:flex;gap:8px;align-items:center">
          <select id="audit-type-filter" style="padding:6px 10px;border:1px solid var(--border);border-radius:var(--radius);font-size:12px;background:var(--bg);color:var(--text)">
            <option value="">All Events</option>
            <option value="form_submitted">Form Submitted</option>
            <option value="calendar_created">Calendar Created</option>
            <option value="email_sent">Email Sent</option>
            <option value="reminder_sent">Reminder Sent</option>
            <option value="rsvp_changed">RSVP Changed</option>
            <option value="webhook_auth_failed">Auth Failed</option>
            <option value="error">Errors</option>
          </select>
          <button class="btn btn-sm" onclick="loadAuditLog()">Refresh</button>
        </div>
      </div>
      <div class="card">
        <div id="audit-log-list">
          <div class="skeleton skeleton-row w80" style="height:36px;margin-bottom:8px"></div>
          <div class="skeleton skeleton-row w60" style="height:36px;margin-bottom:8px"></div>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:16px;padding-top:12px;border-top:1px solid var(--border-light)">
          <span id="audit-count" style="font-size:12px;color:var(--text-muted)"></span>
          <div style="display:flex;gap:8px">
            <button class="btn btn-sm" id="audit-prev" onclick="auditPrevPage()" disabled>Previous</button>
            <button class="btn btn-sm" id="audit-next" onclick="auditNextPage()" disabled>Next</button>
          </div>
        </div>
      </div>
    </div>

  </div><!-- /main-scroll -->
</div><!-- /main -->
</div><!-- /app -->

<script>
/* =========================================
   CORE UTILITIES
   ========================================= */
function esc(s){return(s==null?'':String(s)).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}

function timeAgo(iso){
  if(!iso)return'';
  var d=new Date(iso),now=new Date(),diff=(now-d)/1000;
  if(diff<60)return'just now';
  if(diff<3600)return Math.floor(diff/60)+'m ago';
  if(diff<86400)return Math.floor(diff/3600)+'h ago';
  return Math.floor(diff/86400)+'d ago';
}

function formatDate(iso){
  if(!iso)return'-';
  try{
    var d=new Date(iso);
    return d.toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'});
  }catch(e){return iso}
}

function formatTime(iso){
  if(!iso)return'-';
  try{
    var d=new Date(iso);
    return d.toLocaleTimeString('en-US',{hour:'numeric',minute:'2-digit',hour12:true});
  }catch(e){return iso}
}

async function api(path, options){
  options = options || {};
  var headers = options.headers || {};
  var token = localStorage.getItem('jwt_token');
  if(token){
    headers['Authorization'] = 'Bearer ' + token;
  }
  if(options.body && !headers['Content-Type']){
    headers['Content-Type'] = 'application/json';
  }
  options.headers = headers;
  var r = await fetch(path, options);
  if(r.status === 401){
    // Token expired or invalid - clear and show login
    localStorage.removeItem('jwt_token');
    localStorage.removeItem('jwt_user');
    showLoginPage();
    throw new Error('Session expired');
  }
  if(!r.ok){
    var errBody;try{errBody=await r.json()}catch(x){}
    var msg;
    if(errBody && errBody.detail){
      var d = errBody.detail;
      if(typeof d === 'string'){ msg = d; }
      else if(d.errors && Array.isArray(d.errors)){
        msg = d.errors.map(function(x){return typeof x==='string'?x:JSON.stringify(x)}).join('; ');
      }
      else if(d.message){ msg = typeof d.message==='string'?d.message:JSON.stringify(d.message); }
      else if(d.error){ msg = typeof d.error==='string'?d.error:JSON.stringify(d.error); }
      else { msg = JSON.stringify(d); }
    }
    else if(errBody && errBody.errors && Array.isArray(errBody.errors)){
      msg = errBody.errors.map(function(x){return typeof x==='string'?x:JSON.stringify(x)}).join('; ');
    }
    else if(errBody && errBody.message && typeof errBody.message === 'string'){
      msg = errBody.message;
    }
    throw new Error(msg || path+' -> '+r.status);
  }
  return r.json();
}

/* =========================================
   ONBOARDING WIZARD (Phase 7)
   ========================================= */
var onboardingStep = 1;
var onboardingTotalSteps = 4;

async function checkOnboarding(){
  try{
    if(localStorage.getItem('onboarding_dismissed')==='1') return; // user chose don't show again
    var data = await api('/dashboard/api/setup-status');
    if(data.platform_admin) return; // skip for platform admins
    if(data.setup_complete) return; // already done
    // Show onboarding for new/incomplete orgs
    showOnboarding(data);
  }catch(e){
    // If setup-status fails, skip onboarding
    console.error('Onboarding check failed:', e);
  }
}

function showOnboarding(data){
  var overlay = document.getElementById('onboarding-overlay');
  overlay.style.display = '';
  onboardingStep = 1;
  renderOnboardingStep();
  // Update overview checklist in step 1
  if(data && data.steps){
    var list = document.getElementById('onboard-overview-list');
    var items = list.querySelectorAll('li');
    var keys = ['google_connected','webhook_configured','schedule_configured','branding_configured'];
    for(var i=0;i<items.length&&i<keys.length;i++){
      var step = data.steps[keys[i]];
      if(step && step.done){
        items[i].querySelector('.check-icon').className='check-icon done';
        items[i].querySelector('.check-icon').textContent='\u2713';
      }
    }
  }
}

function renderOnboardingStep(){
  // Show/hide steps
  document.querySelectorAll('.onboarding-step').forEach(function(s){s.classList.remove('active')});
  document.getElementById('onboard-step-'+onboardingStep).classList.add('active');
  // Progress bar
  var steps = document.querySelectorAll('#onboarding-progress .step');
  for(var i=0;i<steps.length;i++){
    steps[i].className = 'step';
    if(i < onboardingStep-1) steps[i].classList.add('done');
    else if(i === onboardingStep-1) steps[i].classList.add('active');
  }
  // Back button
  document.getElementById('onboard-back-btn').style.display = onboardingStep > 1 ? '' : 'none';
  // Next button text
  var nextBtn = document.getElementById('onboard-next-btn');
  if(onboardingStep === onboardingTotalSteps) nextBtn.textContent = 'Go to Dashboard';
  else if(onboardingStep === 1) nextBtn.textContent = 'Get Started';
  else nextBtn.textContent = 'Continue';
  // Load step-specific data
  if(onboardingStep === 2) loadOnboardGoogleStatus();
  if(onboardingStep === 3) loadOnboardSettings();
}

async function loadOnboardGoogleStatus(){
  var el = document.getElementById('onboard-google-status');
  try{
    var data = await api('/dashboard/api/integrations/google');
    var items = data.integrations || data || [];
    var connected = false;
    if(Array.isArray(items)){
      connected = items.some(function(i){return i.status==='connected'});
    }else if(items.status){
      connected = items.status === 'connected';
    }
    if(connected){
      el.innerHTML='<span style="color:var(--accent);font-weight:600">\u2713 Google Connected</span><br><span style="font-size:12px;color:var(--text-muted)">Your Google account is linked. Calendar and Gmail are ready.</span>';
    }else{
      el.innerHTML='<span style="color:var(--text-muted)">Not connected</span><br><span style="font-size:12px;color:var(--text-muted)">You can connect later from the Integrations page.</span>';
    }
  }catch(e){
    el.innerHTML='<span style="color:var(--text-muted)">Unable to check connection status.</span>';
  }
}

async function loadOnboardSettings(){
  try{
    var s = await api('/dashboard/api/settings');
    if(s.reminder_time) document.getElementById('onboard-reminder-time').value = s.reminder_time;
  }catch(e){}
  try{
    var org = await api('/organization/settings');
    if(org.timezone) document.getElementById('onboard-timezone').value = org.timezone;
  }catch(e){}
}

async function onboardingNext(){
  if(onboardingStep < onboardingTotalSteps){
    // Save settings from step 3
    if(onboardingStep === 3){
      try{
        var tz = document.getElementById('onboard-timezone').value;
        var rt = document.getElementById('onboard-reminder-time').value;
        await api('/organization/settings',{method:'PATCH',body:JSON.stringify({timezone:tz})});
        await api('/dashboard/api/settings',{method:'PUT',body:JSON.stringify({reminder_time:rt})});
        showToast('Settings saved','success');
      }catch(e){console.error('Onboarding save failed:',e)}
    }
    onboardingStep++;
    renderOnboardingStep();
  }else{
    dismissOnboarding();
  }
}

function onboardingBack(){
  if(onboardingStep > 1){
    onboardingStep--;
    renderOnboardingStep();
  }
}

function dismissOnboarding(){
  document.getElementById('onboarding-overlay').style.display='none';
  localStorage.setItem('onboarding_done','1');
  var cb = document.getElementById('onboarding-dont-show-again');
  if(cb && cb.checked){
    localStorage.setItem('onboarding_dismissed','1');
  }
}

/* =========================================
   SETUP CHECKLIST WIDGET (Phase 7)
   ========================================= */
async function loadSetupChecklist(){
  try{
    // Don't show if dismissed or "don't show again" was checked
    if(localStorage.getItem('onboarding_done')==='1') return;
    if(localStorage.getItem('onboarding_dismissed')==='1') return;
    var data = await api('/dashboard/api/setup-status');
    if(data.platform_admin || data.setup_complete) return;
    renderSetupChecklist(data);
  }catch(e){}
}

function renderSetupChecklist(data){
  var el = document.getElementById('setup-checklist');
  if(!data.steps || Object.keys(data.steps).length===0) return;
  el.style.display = '';
  var steps = data.steps;
  var total = data.total_steps || Object.keys(steps).length;
  var completed = data.completed_steps || 0;
  var pct = Math.round(completed/total*100);
  document.getElementById('setup-progress-text').textContent = completed+'/'+total+' complete';
  document.getElementById('setup-progress-fill').style.width = pct+'%';
  var html = '';
  Object.keys(steps).forEach(function(key){
    var s = steps[key];
    var cls = s.done ? 'done' : '';
    var icon = s.done ? '\u2713' : '';
    html+='<div class="setup-step '+cls+'" onclick="navigateTo(\''+s.route+'\');dismissSetupChecklist()">'
      +'<div class="step-check '+(s.done?'done':'pending')+'">'+icon+'</div>'
      +'<div class="step-info"><div class="step-label">'+esc(s.label)+'</div>'
      +'<div class="step-desc">'+esc(s.description)+'</div></div></div>';
  });
  document.getElementById('setup-steps-list').innerHTML = html;
}

function dismissSetupChecklist(){
  document.getElementById('setup-checklist').style.display='none';
  localStorage.setItem('onboarding_done','1');
}

/* =========================================
   PIPELINE HEALTH (Phase 7)
   ========================================= */
function renderPipelineHealthFromSummary(data){
  /* Reuses /api/summary data - no extra network call needed */
  try{
    if(!data || data.total_leads === 0){
      document.getElementById('overview-pipeline-health').style.display='none';
      return;
    }
    document.getElementById('overview-pipeline-health').style.display='';
    var bs = data.by_status || {};
    var completed = (bs.scheduled||0)+(bs.accepted||0);
    var pending = bs.pending||0;
    var errors = bs.error||0;
    var grid = document.getElementById('pipeline-health-grid');
    grid.innerHTML=''
      +'<div class="pipeline-health-stat blue"><div class="val">'+data.total_leads+'</div><div class="lbl">Total Leads</div></div>'
      +'<div class="pipeline-health-stat green"><div class="val">'+completed+'</div><div class="lbl">Completed</div></div>'
      +'<div class="pipeline-health-stat amber"><div class="val">'+pending+'</div><div class="lbl">Pending</div></div>'
      +'<div class="pipeline-health-stat red"><div class="val">'+errors+'</div><div class="lbl">Errors (24h)</div></div>';
  }catch(e){
    document.getElementById('overview-pipeline-health').style.display='none';
  }
}

async function loadPipelineHealth(){
  try{
    var r=await api('/dashboard/api/summary');
    renderPipelineHealthFromSummary(r);
  }catch(e){
    document.getElementById('overview-pipeline-health').style.display='none';
  }
}

/* =========================================
   AUTH SYSTEM (Phase 6F)
   ========================================= */
var currentUser = null;

function getToken(){return localStorage.getItem('jwt_token')}
function setToken(t){localStorage.setItem('jwt_token', t)}
function clearToken(){localStorage.removeItem('jwt_token');localStorage.removeItem('jwt_user');currentUser=null}

function showLoginPage(){
  document.getElementById('login-page').style.display='';
  document.getElementById('register-page').style.display='none';
  document.getElementById('app-main').style.display='none';
}

function showRegisterPage(){
  document.getElementById('register-page').style.display='';
  document.getElementById('login-page').style.display='none';
}

function showApp(){
  document.getElementById('login-page').style.display='none';
  document.getElementById('register-page').style.display='none';
  document.getElementById('app-main').style.display='';
}

async function loadCurrentUser(){
  try{
    var data = await api('/auth/me');
    currentUser = data;
    localStorage.setItem('jwt_user', JSON.stringify(data));
    updateUserUI(data);
    return data;
  }catch(e){
    showLoginPage();
    return null;
  }
}

function updateUserUI(data){
  if(!data)return;
  document.getElementById('sidebar-user-name').textContent = data.name || data.email;
  var role = (data.role||'member').charAt(0).toUpperCase() + (data.role||'member').slice(1);
  document.getElementById('sidebar-user-role').textContent = role;
  if(data.organization){
    document.getElementById('sidebar-org-name').textContent = data.organization.name || 'Strategy Call Agent';
  }
  // Apply RBAC: hide admin-only nav items for members
  applyRBAC(data.role);
}

function _applyAdminOnlyVisibility(){
  var isAdmin=(_umCurrentUserRole==='owner'||_umCurrentUserRole==='admin');
  document.querySelectorAll('[data-admin-only]').forEach(function(el){
    el.style.display=isAdmin?'':'none';
  });
}

function applyRBAC(role){
  _umCurrentUserRole=(role||'member').toLowerCase();
  var isAdmin = (role === 'owner' || role === 'admin');
  // Hide admin-only nav items
  _applyAdminOnlyVisibility();
  // Organization Settings: read-only for members
  var osForm = document.getElementById('org-settings-form');
  if(osForm){
    osForm.querySelectorAll('input,select').forEach(function(el){el.disabled=!isAdmin});
    var osSave = document.getElementById('os-save-btn');
    if(osSave)osSave.style.display=isAdmin?'':'none';
  }
  // Webhook: hide write controls for members
  var rotateBtn = document.getElementById('btn-rotate-secret');
  var testBtn = document.getElementById('btn-test-webhook');
  if(rotateBtn)rotateBtn.style.display=isAdmin?'':'none';
  if(testBtn)testBtn.style.display=isAdmin?'':'none';
  // Settings: hide save and trigger buttons for members
  var saveBtn = document.getElementById('s-save-settings');
  var triggerReminders = document.getElementById('s-trigger-reminders');
  var triggerPoll = document.getElementById('s-trigger-poll');
  if(saveBtn)saveBtn.style.display=isAdmin?'':'none';
  if(triggerReminders)triggerReminders.style.display=isAdmin?'':'none';
  if(triggerPoll)triggerPoll.style.display=isAdmin?'':'none';
  // User Management: hide create button for members
  var createBtn = document.getElementById('um-create-btn');
  if(createBtn)createBtn.style.display=isAdmin?'':'none';
}

async function doLogin(email, password){
  var errEl = document.getElementById('login-error');
  var btn = document.getElementById('login-btn');
  errEl.style.display='none';
  btn.disabled=true;
  btn.textContent='Signing in...';
  try{
    var r = await fetch('/auth/login',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({email:email, password:password})
    });
    var data = await r.json();
    if(!r.ok){
      errEl.textContent = data.detail || 'Login failed';
      errEl.style.display='';
      return;
    }
    setToken(data.access_token);
    var user = await loadCurrentUser();
    if(user){
      showApp();
      navigateTo('overview');
      startSse();
      showToast('Welcome back, '+(user.name||user.email),'success');
    }
  }catch(e){
    errEl.textContent='Connection failed. Please try again.';
    errEl.style.display='';
  }finally{
    btn.disabled=false;
    btn.textContent='Sign In';
  }
}

async function doRegister(orgName, name, email, password){
  var errEl = document.getElementById('register-error');
  var btn = document.getElementById('reg-btn');
  errEl.style.display='none';
  btn.disabled=true;
  btn.textContent='Creating...';
  try{
    var r = await fetch('/auth/register',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({organization_name:orgName, name:name, email:email, password:password})
    });
    var data = await r.json();
    if(!r.ok){
      errEl.textContent = data.detail || 'Registration failed';
      errEl.style.display='';
      return;
    }
    setToken(data.access_token);
    var user = await loadCurrentUser();
    if(user){
      showApp();
      navigateTo('overview');
      startSse();
      // Phase 7: Show onboarding wizard for new registrations
      localStorage.removeItem('onboarding_done');
      localStorage.removeItem('onboarding_dismissed');
      setTimeout(function(){checkOnboarding()}, 500);
      showToast('Welcome, '+(user.name||user.email)+'!','success');
    }
  }catch(e){
    errEl.textContent='Connection failed. Please try again.';
    errEl.style.display='';
  }finally{
    btn.disabled=false;
    btn.textContent='Create Account';
  }
}

function doLogout(){
  if(activeEvtSource){activeEvtSource.close();activeEvtSource=null}
  sseConnected=false;
  updateSseIndicator();
  clearToken();
  showLoginPage();
  showToast('Signed out','info');
}

// Login form handler
document.getElementById('login-form').addEventListener('submit',function(e){
  e.preventDefault();
  var email = document.getElementById('login-email').value;
  var password = document.getElementById('login-password').value;
  doLogin(email, password);
});

// Register form handler
document.getElementById('register-form').addEventListener('submit',function(e){
  e.preventDefault();
  var orgName = document.getElementById('reg-org-name').value;
  var name = document.getElementById('reg-name').value;
  var email = document.getElementById('reg-email').value;
  var password = document.getElementById('reg-password').value;
  doRegister(orgName, name, email, password);
});

// Toggle login/register
document.getElementById('show-register').addEventListener('click',function(e){e.preventDefault();showRegisterPage()});
document.getElementById('show-login').addEventListener('click',function(e){e.preventDefault();showLoginPage()});

// Logout
document.getElementById('logout-btn').addEventListener('click',doLogout);

/* =========================================
   TOAST SYSTEM
   ========================================= */
function showToast(msg,type){
  type=type||'info';
  var c=document.getElementById('toast-container');
  var t=document.createElement('div');
  t.className='toast '+type;
  t.textContent=msg;
  c.appendChild(t);
  setTimeout(()=>{t.style.animation='toast-out 0.3s ease-out forwards';setTimeout(()=>t.remove(),300)},3500);
}

/* =========================================
   NAVIGATION
   ========================================= */
var currentPage='overview';
var pageTitles={overview:'Overview',leads:'Leads',calls:'Calls','follow-ups':'Follow-ups',automations:'Automations',analytics:'Analytics',settings:'Settings',integrations:'Integrations',webhook:'Webhook Configuration','org-settings':'Organization Settings',activity:'Activity Log'};

function navigateTo(page){
  if(!page)return;
  currentPage=page;
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  var pageEl=document.getElementById('page-'+page);
  if(pageEl)pageEl.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  var navBtn=document.querySelector('[data-page="'+page+'"]');
  if(navBtn)navBtn.classList.add('active');
  document.getElementById('page-title').textContent=pageTitles[page]||page;
  // Load page data
  if(page==='overview')loadOverview();
  else if(page==='leads')loadLeadsPage();
  else if(page==='calls')loadCallsPage();
  else if(page==='follow-ups')loadFollowUpsPage();
  else if(page==='automations')loadAutomationsPage();
  else if(page==='analytics')loadAnalyticsPage();
  else if(page==='settings')loadSettingsPage();
  else if(page==='integrations')loadIntegrationsPage();
  else if(page==='webhook')loadWebhookPage();
  else if(page==='org-settings')loadOrgSettingsPage();
  else if(page==='activity')loadAuditLog();
  // Close mobile sidebar
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('open');
}

document.querySelectorAll('.nav-item').forEach(function(btn){
  btn.addEventListener('click',function(){
    if(btn.dataset.page)navigateTo(btn.dataset.page);
  });
});
document.getElementById('mobile-toggle').addEventListener('click',function(){
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('sidebar-overlay').classList.add('open');
});
document.getElementById('sidebar-overlay').addEventListener('click',function(){
  document.getElementById('sidebar').classList.remove('open');
  this.classList.remove('open');
});

/* =========================================
   DRAWER
   ========================================= */
function openDrawer(){
  document.getElementById('lead-drawer').classList.add('open');
  document.getElementById('drawer-overlay').classList.add('open');
}
function closeDrawer(){
  document.getElementById('lead-drawer').classList.remove('open');
  document.getElementById('drawer-overlay').classList.remove('open');
}
document.getElementById('drawer-close').addEventListener('click',closeDrawer);
document.getElementById('drawer-overlay').addEventListener('click',closeDrawer);

/* =========================================
   ANIMATIONS
   ========================================= */
function animateCount(el,target){
  if(window.matchMedia('(prefers-reduced-motion: reduce)').matches){el.textContent=target;return}
  var duration=500,start=performance.now();
  function tick(now){
    var p=Math.min((now-start)/duration,1);
    var eased=1-Math.pow(1-p,3);
    el.textContent=Math.round(eased*target);
    if(p<1)requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function animateValue(el,start,end,duration){
  if(window.matchMedia('(prefers-reduced-motion: reduce)').matches){el.textContent=end;return}
  var startTime=performance.now();
  function tick(now){
    var p=Math.min((now-startTime)/duration,1);
    var eased=1-Math.pow(1-p,3);
    if(typeof end==='number')el.textContent=Math.round((start+(end-start)*eased)*10)/10;
    else el.textContent=end;
    if(p<1)requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

/* =========================================
   OVERVIEW PAGE
   ========================================= */
var overviewData={summary:null,upcoming:null,events:null,failedJobs:null};

async function loadOverview(){
  var[summaryRes,upcomingRes,failedRes]=await Promise.allSettled([
    api('/dashboard/api/summary'),
    api('/dashboard/api/leads/upcoming?limit=10'),
    api('/dashboard/api/failed-jobs')
  ]);
  // Render each section independently - one failure does not block others.
  if(summaryRes.status==='fulfilled'){
    overviewData.summary=summaryRes.value;
    renderOverviewKPIs(summaryRes.value);
    renderOverviewPipeline(summaryRes.value);
    renderOverviewAutomations(summaryRes.value);
    // Reuse summary data for pipeline health (avoids redundant /pipeline/status call)
    renderPipelineHealthFromSummary(summaryRes.value);
  }else{console.error('Overview summary failed:',summaryRes.reason)}
  if(upcomingRes.status==='fulfilled'){
    overviewData.upcoming=upcomingRes.value;
    renderUpcomingCalls(upcomingRes.value);
  }else{console.error('Overview upcoming failed:',upcomingRes.reason)}
  if(failedRes.status==='fulfilled'){
    overviewData.failedJobs=failedRes.value;
  }else{console.error('Overview failed-jobs failed:',failedRes.reason)}
  // Independent sections - fire in parallel to save a round-trip.
  Promise.allSettled([loadActivityFeed(), loadSetupChecklist()]);
}

function renderOverviewKPIs(s){
  var bs=s.by_status||{};
  var kpis=[
    {label:'New Leads',value:s.total_leads,icon:'&#128100;',color:'blue',sub:'Total captured'},
    {label:'Calls Booked',value:bs.scheduled||0,icon:'&#128197;',color:'green',sub:'Strategy calls scheduled'},
    {label:'Confirmed',value:bs.accepted||0,icon:'&#10003;',color:'green',sub:'Accepted by prospect'},
    {label:'Pending',value:bs.pending||0,icon:'&#8987;',color:'amber',sub:'Awaiting processing'},
    {label:'Booking Rate',value:s.total_leads>0?Math.round(((bs.scheduled||0)+(bs.accepted||0))/s.total_leads*100)+'%':'-',icon:'&#128200;',color:'green',sub:'Leads to calls'}
  ];
  var html='';
  for(var i=0;i<kpis.length;i++){
    var k=kpis[i];
    html+='<div class="kpi" style="animation-delay:'+(i*0.05)+'s">'
      +'<div class="kpi-icon '+k.color+'">'+k.icon+'</div>'
      +'<div class="kpi-label">'+k.label+'</div>'
      +'<div class="kpi-value" data-target="'+k.value+'">'+k.value+'</div>'
      +'<div class="kpi-sub">'+k.sub+'</div></div>';
  }
  document.getElementById('kpi-grid').innerHTML=html;
}

function renderOverviewPipeline(s){
  var bs=s.by_status||{};
  var stages=[
    {key:'submitted',label:'New Leads',count:s.total_leads},
    {key:'scheduled',label:'Booked',count:bs.scheduled||0},
    {key:'accepted',label:'Confirmed',count:bs.accepted||0},
    {key:'declined',label:'Declined',count:bs.declined||0},
    {key:'reminded',label:'Reminded',count:bs.reminded||0}
  ];
  var html='';
  for(var i=0;i<stages.length;i++){
    var st=stages[i];
    var cls=st.count>0?'active':'zero';
    html+='<div class="pipeline-stage"><div class="pipeline-dot"></div>'
      +'<div class="pipeline-count '+cls+'" data-count="'+st.count+'">'+st.count+'</div>'
      +'<div class="pipeline-label">'+st.label+'</div></div>';
    if(i<stages.length-1)html+='<div class="pipeline-connector"></div>';
  }
  var el=document.getElementById('overview-pipeline-stages');
  el.innerHTML=html;
  el.querySelectorAll('.pipeline-count[data-count]').forEach(function(c){
    animateCount(c,parseInt(c.dataset.count,10));
  });
}

function renderUpcomingCalls(d){
  var el=document.getElementById('upcoming-calls-list');
  if(!d.leads||d.leads.length===0){
    el.innerHTML='<div class="empty-state" style="padding:32px 16px"><div class="icon">&#128222;</div><h3>No upcoming calls</h3><p>Booked strategy calls will appear here.</p></div>';
    return;
  }
  var html='';
  for(var i=0;i<d.leads.length;i++){
    var l=d.leads[i];
    html+='<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border-light)">'
      +'<div><div style="font-size:13px;font-weight:600;color:var(--text)">'+esc(l.prospect_name)+'</div>'
      +'<div style="font-size:12px;color:var(--text-muted)">'+esc(l.company_address||'')+(l.company_address?' &middot; ':'')+esc(l.appt_local||'')+'</div></div>'
      +'<div style="display:flex;align-items:center;gap:8px">'
      +'<span class="badge '+esc(l.status)+'"><span class="badge-dot"></span>'+esc(l.status)+'</span>'
      +(l.calendar_event_id?'<button class="btn btn-sm btn-ghost" onclick="openLeadDetail(\''+l.id+'\',\''+esc(l.prospect_name)+'\')">Open</button>':'')
      +'</div></div>';
  }
  el.innerHTML=html;
}

function renderOverviewAutomations(s){
  var bs=s.by_status||{};
  var items=[
    {name:'Lead Processing',desc:'Captures and qualifies incoming leads',active:true},
    {name:'Calendar Booking',desc:'Creates strategy call appointments',active:true},
    {name:'Confirmation Emails',desc:'Sends booking confirmations',active:true},
    {name:'RSVP Monitoring',desc:'Monitors attendee responses',active:true},
    {name:'Appointment Reminders',desc:'Sends reminders before calls',active:true}
  ];
  var html='';
  for(var i=0;i<items.length;i++){
    var item=items[i];
    html+='<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border-light)">'
      +'<span class="automation-status active"><span class="dot"></span>Active</span>'
      +'<div><div style="font-size:13px;font-weight:500;color:var(--text)">'+item.name+'</div>'
      +'<div style="font-size:11px;color:var(--text-muted)">'+item.desc+'</div></div></div>';
  }
  document.getElementById('overview-auto-status').innerHTML=html;
}

async function loadActivityFeed(){
  try{
    // Single batch endpoint - replaces N+1 individual lead detail calls
    var d=await api('/dashboard/api/activity/recent?limit=15');
    var events=(d.events||[]).map(function(e){
      return {type:e.event_type, created_at:e.created_at, payload:e.payload, lead_name:e.lead_name};
    });
    renderActivityFeed(events);
  }catch(e){console.error('Activity feed load failed:',e)}
}

var EVENT_MESSAGES={
  'form_submitted':{text:'New lead received',dot:'green',prefix:'Lead captured from website form'},
  'calendar_created':{text:'Strategy call booked',dot:'blue',prefix:'Calendar event created'},
  'email_generated':{text:'Confirmation email drafted',dot:'blue',prefix:'AI-generated email ready'},
  'email_sent':{text:'Confirmation email sent',dot:'green',prefix:'Email delivered'},
  'reminder_sent':{text:'Reminder sent',dot:'amber',prefix:'Appointment reminder delivered'},
  'rsvp_changed':{text:'RSVP updated',dot:'amber',prefix:'Attendee response received'},
  'error':{text:'Processing error',dot:'red',prefix:'An error occurred'},
  'declined':{text:'Appointment declined',dot:'red',prefix:'Prospect declined the call'},
  'pipeline.completed':{text:'Lead processed successfully',dot:'green',prefix:'Full pipeline completed'},
  'pipeline.failed':{text:'Lead processing failed',dot:'red',prefix:'Pipeline encountered an error'},
  'call_updated':{text:'Call details updated',dot:'blue',prefix:'Call outcome or notes updated'},
  'call_cancelled':{text:'Call cancelled',dot:'red',prefix:'Scheduled call was cancelled'},
  'call_rescheduled':{text:'Call rescheduled',dot:'amber',prefix:'Appointment moved to new date/time'},
  'manual_lead_created':{text:'Manual lead created',dot:'green',prefix:'Lead added from dashboard'},
  'lead_updated':{text:'Lead info updated',dot:'blue',prefix:'Lead details were edited'},
  'lead_status_changed':{text:'Status changed',dot:'amber',prefix:'Lead status was updated'},
};

function renderActivityFeed(events){
  var el=document.getElementById('activity-feed');
  if(!events||events.length===0){
    el.innerHTML='<div class="empty-state" style="padding:24px 16px"><div class="icon">&#128227;</div><h3>No activity yet</h3><p>Activity will appear here as leads move through your pipeline.</p></div>';
    return;
  }
  var html='<div class="feed">';
  for(var i=0;i<events.length;i++){
    var ev=events[i];
    var msg=EVENT_MESSAGES[ev.type]||{text:ev.type,dot:'gray',prefix:''};
    var time=timeAgo(ev.created_at);
    html+='<div class="feed-item">'
      +'<div class="feed-dot '+msg.dot+'"></div>'
      +'<div><div class="feed-text"><strong>'+esc(ev.lead_name||'Lead')+'</strong> &mdash; '+esc(msg.text)+'</div>'
      +'<div class="feed-time">'+esc(time)+'</div></div></div>';
  }
  html+='</div>';
  el.innerHTML=html;
}

/* =========================================
   LEADS PAGE
   ========================================= */
var allLeads=[];
var leadsFilter='all';
var leadsSearchQuery='';

async function loadLeadsPage(){
  try{
    var d=await api('/dashboard/api/leads?limit=500');
    allLeads=d.leads||[];
    renderLeadsTable();
    // Update nav badge
    var badge=document.getElementById('nav-leads-count');
    if(allLeads.length>0){badge.textContent=allLeads.length;badge.style.display=''}
  }catch(e){console.error('Leads load failed:',e)}
}

function renderLeadsTable(){
  var filtered=allLeads.filter(function(l){
    if(leadsFilter!=='all'&&l.status!==leadsFilter)return false;
    if(leadsSearchQuery){
      var q=leadsSearchQuery.toLowerCase();
      return((l.prospect_name||'').toLowerCase().indexOf(q)>=0
        ||(l.email||'').toLowerCase().indexOf(q)>=0
        ||(l.company_address||'').toLowerCase().indexOf(q)>=0);
    }
    return true;
  });
  var el=document.getElementById('leads-table-wrap');
  if(filtered.length===0){
    el.innerHTML='<div class="empty-state"><div class="icon">&#128100;</div>'
      +'<h3>'+(leadsSearchQuery||leadsFilter!=='all'?'No matching leads':'No leads yet')+'</h3>'
      +'<p>'+(leadsSearchQuery||leadsFilter!=='all'?'Try adjusting your search or filters.':'Connect your website form to start capturing prospects.')+'</p></div>';
    return;
  }
  var html='<table><thead><tr>'
    +'<th>Name</th><th>Company</th><th>Email</th><th>Status</th><th>Appointment</th><th>Reminder</th>'
    +'</tr></thead><tbody>';
  for(var i=0;i<filtered.length;i++){
    var l=filtered[i];
    html+='<tr class="clickable" tabindex="0" data-id="'+l.id+'" data-name="'+esc(l.prospect_name)+'">'
      +'<td style="font-weight:500">'+esc(l.prospect_name)+'</td>'
      +'<td>'+esc(l.company_address||'-')+'</td>'
      +'<td style="font-family:var(--font-mono);font-size:12px">'+esc(l.email)+'</td>'
      +'<td><span class="badge '+esc(l.status)+'"><span class="badge-dot"></span>'+esc(l.status)+'</span></td>'
      +'<td style="font-family:var(--font-mono);font-size:12px">'+(l.appt_local?esc(l.appt_local):'-')+'</td>'
      +'<td>'+(l.reminder_sent_at?'<span style="color:var(--accent)">&#10003; sent</span>':'<span style="color:var(--text-faint)">pending</span>')+'</td>'
      +'</tr>';
  }
  el.innerHTML=html+'</tbody></table>';
  el.querySelectorAll('tr.clickable').forEach(function(tr){
    tr.addEventListener('click',function(){openLeadDetail(tr.dataset.id,tr.dataset.name)});
    tr.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();openLeadDetail(tr.dataset.id,tr.dataset.name)}});
  });
}

// Search
document.getElementById('leads-search').addEventListener('input',function(e){
  leadsSearchQuery=e.target.value;
  renderLeadsTable();
});

// Filter buttons
document.querySelectorAll('[data-filter]').forEach(function(btn){
  btn.addEventListener('click',function(){
    document.querySelectorAll('[data-filter]').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    leadsFilter=btn.dataset.filter;
    renderLeadsTable();
  });
});

// ── Manual Lead Entry (Phase 3) ───────────────────────────────────────
function showCreateLeadModal(){
  _closeModal();
  var ov=document.createElement('div');
  ov.id='um-modal-overlay';
  ov.className='um-modal-overlay';
  ov.onclick=function(e){if(e.target===ov)_closeModal()};
  ov.innerHTML='<div class="um-modal">'
    +'<div class="um-modal-header"><h3>Create Lead</h3><button class="um-modal-close" onclick="_closeModal()">&times;</button></div>'
    +'<div class="um-modal-body">'
    +'<div class="um-form-field"><label for="cl-name">Name *</label><input type="text" id="cl-name" placeholder="Prospect name">'
    +'<div class="um-field-error" id="cl-name-err"></div></div>'
    +'<div class="um-form-field"><label for="cl-email">Email *</label><input type="email" id="cl-email" placeholder="prospect@company.com">'
    +'<div class="um-field-error" id="cl-email-err"></div></div>'
    +'<div class="um-form-field"><label for="cl-phone">Phone</label><input type="tel" id="cl-phone" placeholder="555-123-4567"></div>'
    +'<div class="um-form-field"><label for="cl-company">Company / Address</label><input type="text" id="cl-company" placeholder="123 Main St, City"></div>'
    +'<div class="um-form-field"><label for="cl-appt">Appointment Date &amp; Time *</label><input type="text" id="cl-appt" placeholder="e.g. tomorrow 2pm, next Monday 10:00">'
    +'<div class="um-field-error" id="cl-appt-err"></div></div>'
    +'<div class="um-form-field"><label for="cl-notes">Notes</label><textarea id="cl-notes" rows="3" placeholder="Additional notes about this lead..." style="width:100%;padding:8px 12px;font-size:13px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text);resize:vertical;font-family:inherit"></textarea></div>'
    +'<div class="um-form-actions">'
    +'<button class="btn" onclick="_closeModal()">Cancel</button>'
    +'<button class="btn btn-primary" id="cl-submit" onclick="createLead()">Create Lead</button>'
    +'</div></div></div>';
  document.body.appendChild(ov);
}

async function createLead(){
  var name=document.getElementById('cl-name').value.trim();
  var email=document.getElementById('cl-email').value.trim();
  var phone=document.getElementById('cl-phone').value.trim();
  var company=document.getElementById('cl-company').value.trim();
  var appt=document.getElementById('cl-appt').value.trim();
  var notes=document.getElementById('cl-notes').value.trim();
  var btn=document.getElementById('cl-submit');
  // Clear previous errors
  ['cl-name-err','cl-email-err','cl-appt-err'].forEach(function(id){
    var e=document.getElementById(id);if(e){e.textContent='';e.classList.remove('visible')}
  });
  var ok=true;
  function fe(id,v){var e=document.getElementById(id);e.textContent=v;e.classList.add('visible')}
  var emailRe=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if(!name){fe('cl-name-err','Name is required');ok=false}
  if(!email){fe('cl-email-err','Email is required');ok=false}else if(!emailRe.test(email)){fe('cl-email-err','Please enter a valid email address');ok=false}
  if(!appt){fe('cl-appt-err','Appointment date & time is required');ok=false}
  if(!ok)return;
  btn.disabled=true;btn.textContent='Creating...';
  try{
    var payload={name:name,email:email,appt_datetime_raw:appt};
    if(phone)payload.phone_number=phone;
    if(company)payload.company_address=company;
    if(notes)payload.notes=notes;
    await api('/dashboard/api/leads',{method:'POST',body:JSON.stringify(payload)});
    showToast('Lead created successfully','success');
    _closeModal();
    loadLeadsPage();
  }catch(e){
    var msg=e.message||'';
    if(msg.indexOf('already exists')>=0){
      showToast('Duplicate: a lead with this email and appointment time already exists','error');
    }else{
      showToast('Failed to create lead: '+msg,'error');
    }
  }finally{btn.disabled=false;btn.textContent='Create Lead'}
}

async function openLeadDetail(id,name){
  document.getElementById('drawer-title').textContent=name||'Lead Detail';
  var body=document.getElementById('drawer-body');
  body.innerHTML='<div class="skeleton skeleton-row w80" style="height:20px;margin-bottom:12px"></div><div class="skeleton skeleton-row w60" style="height:20px;margin-bottom:12px"></div><div class="skeleton skeleton-row w80" style="height:20px"></div>';
  openDrawer();
  try{
    var d=await api('/dashboard/api/leads/'+id);
    var l=d.lead;
    var isAdmin=(_umCurrentUserRole==='owner'||_umCurrentUserRole==='admin');
    // Status transition options
    var statusTransitions={
      'pending':['scheduled','error','not_interested'],
      'scheduled':['accepted','tentative','declined','reminded','completed'],
      'accepted':['reminded','declined','completed'],
      'tentative':['accepted','declined','completed'],
      'reminded':['completed','declined'],
      'completed':[],'declined':[],'not_interested':[],'error':['pending']
    };
    var allowed=statusTransitions[l.status]||[];
    var statusOpts='';for(var si=0;si<allowed.length;si++)statusOpts+='<option value="'+esc(allowed[si])+'">'+esc(allowed[si])+'</option>';
    var html='<dl class="detail-grid">'
      +'<dt>Prospect</dt><dd style="font-weight:600">'+esc(l.prospect_name)+'</dd>'
      +'<dt>Email</dt><dd>'+esc(l.email)+'</dd>'
      +'<dt>Phone</dt><dd>'+(l.phone_number?esc(l.phone_number):'-')+'</dd>'
      +'<dt>Company</dt><dd>'+esc(l.company_address||'-')+'</dd>'
      +'<dt>Status</dt><dd id="ld-status-cell"><span class="badge '+esc(l.status)+'"><span class="badge-dot"></span>'+esc(l.status)+'</span>'
      +(isAdmin&&allowed.length>0?' <select id="ld-status-select" class="ld-status-select" onchange="changeLeadStatus(\''+id+'\',this.value)" style="margin-left:8px;padding:2px 6px;font-size:12px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--bg);color:var(--text)">'+statusOpts+'</select>':'')
      +'</dd>'
      +'<dt>Appointment</dt><dd style="font-family:var(--font-mono);font-size:12px">'+(l.appt_local?esc(l.appt_local):'-')+'</dd>'
      +'<dt>Calendar Event</dt><dd style="font-family:var(--font-mono);font-size:12px;word-break:break-all">'+(l.calendar_event_id?esc(l.calendar_event_id):'-')+'</dd>'
      +'<dt>Reminder</dt><dd>'+(l.reminder_sent_at?'<span style="color:var(--accent)">&#10003; Sent</span>':'<span style="color:var(--text-muted)">Pending</span>')+'</dd>'
      +'<dt>Created</dt><dd style="font-family:var(--font-mono);font-size:12px">'+formatDate(l.created_at)+'</dd>'
      +'<dt>Updated</dt><dd style="font-family:var(--font-mono);font-size:12px">'+formatDate(l.updated_at)+'</dd>'
      +'</dl>';
    if(isAdmin){
      html+='<div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border)"><button class="btn btn-primary" onclick="toggleLeadEdit(\''+id+'\')" id="ld-edit-btn">Edit Lead</button></div>';
      html+='<div id="ld-edit-form" style="display:none;margin-top:16px;padding:16px;background:var(--surface);border-radius:var(--radius);border:1px solid var(--border)">'
        +'<h4 style="font-size:14px;font-weight:600;margin-bottom:12px;color:var(--text)">Edit Lead</h4>'
        +'<div class="um-form-field"><label>Name *</label><input type="text" id="ld-edit-name" value="'+esc(l.prospect_name)+'"></div>'
        +'<div class="um-form-field"><label>Email *</label><input type="email" id="ld-edit-email" value="'+esc(l.email)+'"></div>'
        +'<div class="um-form-field"><label>Phone</label><input type="tel" id="ld-edit-phone" value="'+esc(l.phone_number||'')+'"></div>'
        +'<div class="um-form-field"><label>Company / Address</label><input type="text" id="ld-edit-company" value="'+esc(l.company_address||'')+'"></div>'
        +'<div class="um-form-field"><label>Appointment Date &amp; Time *</label><input type="text" id="ld-edit-appt" value="'+esc(l.appt_datetime_raw||'')+'"></div>'
        +'<div id="ld-edit-errors" style="color:var(--danger);font-size:12px;margin-bottom:8px"></div>'
        +'<div style="display:flex;gap:8px;justify-content:flex-end">'
        +'<button class="btn btn-ghost" onclick="toggleLeadEdit(null)">Cancel</button>'
        +'<button class="btn btn-primary" id="ld-edit-submit" onclick="submitLeadEdit(\''+id+'\')">Save Changes</button>'
        +'</div></div>';
    }
    // Activity timeline
    if(d.events&&d.events.length>0){
      html+='<h4 style="font-size:13px;font-weight:600;margin:20px 0 12px;color:var(--text)">Activity Timeline</h4>';
      html+='<ul class="timeline">';
      for(var i=0;i<d.events.length;i++){
        var e=d.events[i];
        var cls=eventClass(e.event_type);
        var humanType=humanEventType(e.event_type);
        html+='<li class="'+cls+'">'
          +'<span class="t">'+formatDate(e.created_at)+' '+formatTime(e.created_at)+'</span>'
          +'<span class="e '+cls+'">'+esc(humanType)+'</span>'
          +(e.payload?'<pre>'+esc(JSON.stringify(e.payload,null,2))+'</pre>':'')
          +'</li>';
      }
      html+='</ul>';
    }
    // ── Follow-ups section (Phase 18) ──
    html+='<h4 style="font-size:13px;font-weight:600;margin:20px 0 12px;color:var(--text)">Follow-ups</h4>';
    html+='<div id="ld-followups-section"><div class="skeleton skeleton-row w80" style="height:20px"></div></div>';
    body.innerHTML=html;
    // Load follow-ups for this lead asynchronously
    _loadLeadFollowUps(id);
  }catch(e){body.innerHTML='<div style="color:var(--danger);padding:16px">Failed to load lead details.</div>'}
}

function toggleLeadEdit(id){
  var form=document.getElementById('ld-edit-form');
  var btn=document.getElementById('ld-edit-btn');
  if(!form)return;
  var visible=form.style.display!=='none';
  form.style.display=visible?'none':'';
  if(btn)btn.textContent=visible?'Edit Lead':'Cancel Edit';
}

async function submitLeadEdit(leadId){
  var btn=document.getElementById('ld-edit-submit');
  var errDiv=document.getElementById('ld-edit-errors');
  var name=document.getElementById('ld-edit-name').value.trim();
  var email=document.getElementById('ld-edit-email').value.trim();
  var phone=document.getElementById('ld-edit-phone').value.trim();
  var company=document.getElementById('ld-edit-company').value.trim();
  var appt=document.getElementById('ld-edit-appt').value.trim();
  errDiv.textContent='';
  if(!name){errDiv.textContent='Name is required';return}
  if(!email){errDiv.textContent='Email is required';return}
  if(!appt){errDiv.textContent='Appointment date & time is required';return}
  btn.disabled=true;btn.textContent='Saving...';
  try{
    var payload={name:name,email:email,phone_number:phone||null,company_address:company||null,appt_datetime_raw:appt};
    var resp=await api('/dashboard/api/leads/'+leadId,{method:'PATCH',body:JSON.stringify(payload)});
    showToast('Lead updated successfully','success');
    toggleLeadEdit(null);
    // Refresh the drawer with updated data
    var nameEl=document.getElementById('ld-edit-name');
    openLeadDetail(leadId,name);
    loadLeadsPage();
  }catch(e){
    var msg=e.message||'';
    if(msg.indexOf('duplicate')>=0||msg.indexOf('Duplicate')>=0){
      errDiv.textContent='A lead with this email and appointment time already exists';
    }else{
      errDiv.textContent='Failed to save: '+msg;
    }
  }finally{btn.disabled=false;btn.textContent='Save Changes'}
}

async function changeLeadStatus(leadId,newStatus){
  var cell=document.getElementById('ld-status-cell');
  if(!cell)return;
  var select=document.getElementById('ld-status-select');
  if(select)select.disabled=true;
  try{
    var resp=await api('/dashboard/api/leads/'+leadId+'/status',{method:'PATCH',body:JSON.stringify({status:newStatus})});
    showToast('Status changed to '+newStatus,'success');
    openLeadDetail(leadId,null);
    loadLeadsPage();
  }catch(e){
    showToast('Failed to change status: '+(e.message||'Unknown error'),'error');
    if(select)select.disabled=false;
  }
}

// ── Phase 18: Follow-ups in Lead Detail ──────────────────────────────
async function _loadLeadFollowUps(leadId){
  var section=document.getElementById('ld-followups-section');
  if(!section)return;
  try{
    var resp=await api('/dashboard/api/follow-ups?lead_id='+leadId);
    var fups=resp.follow_ups||[];
    if(!fups.length){
      section.innerHTML='<p style="font-size:12px;color:var(--text-muted)">No follow-ups for this lead.</p>'
        +(isAdmin()?'<button class="btn btn-xs" style="margin-top:8px" onclick="showCreateFollowUpModal(\''+leadId+'\')" data-admin-only>+ Add Follow-up</button>':'');
      if(isAdmin())_applyAdminOnlyVisibility();
      return;
    }
    var html='<ul style="list-style:none;padding:0;margin:0">';
    fups.forEach(function(f){
      var statusCls=f.status==='completed'?'status-completed':f.status==='cancelled'?'status-cancelled':f.status==='in_progress'?'status-scheduled':'status-pending';
      var dueStr=f.due_at?'Due: '+new Date(f.due_at).toLocaleDateString():'';
      html+='<li style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border-light);font-size:12px">';
      html+='<div><span class="status-badge '+statusCls+'" style="font-size:10px">'+f.status.replace('_',' ')+'</span> '
        +'<strong>'+esc(f.title)+'</strong>'
        +(dueStr?' <span style="color:var(--text-muted);margin-left:8px">'+dueStr+'</span>':'')
        +'</div>';
      html+='<div style="display:flex;gap:4px">';
      if(f.status==='pending'&&isAdmin()){
        html+='<button class="btn btn-xs btn-primary" onclick="followUpAction(\''+f.id+'\',\'in_progress\');setTimeout(function(){_loadLeadFollowUps(\''+leadId+'\')},500)" data-admin-only>&#9654;</button>';
        html+='<button class="btn btn-xs btn-success" onclick="followUpAction(\''+f.id+'\',\'completed\');setTimeout(function(){_loadLeadFollowUps(\''+leadId+'\')},500)" data-admin-only>&#10003;</button>';
      } else if(f.status==='in_progress'&&isAdmin()){
        html+='<button class="btn btn-xs btn-success" onclick="followUpAction(\''+f.id+'\',\'completed\');setTimeout(function(){_loadLeadFollowUps(\''+leadId+'\')},500)" data-admin-only>&#10003;</button>';
      }
      html+='</div></li>';
    });
    html+='</ul>';
    if(isAdmin())html+='<button class="btn btn-xs" style="margin-top:8px" onclick="showCreateFollowUpModal(\''+leadId+'\')" data-admin-only>+ Add Follow-up</button>';
    section.innerHTML=html;
    if(isAdmin())_applyAdminOnlyVisibility();
  }catch(e){console.error('Lead follow-ups load failed:',e);section.innerHTML='<p style="font-size:12px;color:var(--danger)">Failed to load follow-ups. '+(e.message||'')+'</p>'}
}

function isAdmin(){return _umCurrentUserRole==='owner'||_umCurrentUserRole==='admin'}

function showCreateFollowUpModal(leadId){
  _closeModal();
  var ov=document.createElement('div');
  ov.id='um-modal-overlay';
  ov.className='um-modal-overlay';
  ov.onclick=function(e){if(e.target===ov)_closeModal()};
  ov.innerHTML='<div class="um-modal">'
    +'<div class="um-modal-header"><h3>Create Follow-up</h3><button class="um-modal-close" onclick="_closeModal()">&times;</button></div>'
    +'<div class="um-modal-body">'
    +'<div class="um-form-field"><label for="fu-title">Title *</label><input type="text" id="fu-title" placeholder="e.g. Send proposal, Follow-up call">'
    +'<div class="um-field-error" id="fu-title-err"></div></div>'
    +'<div class="um-form-field"><label for="fu-notes">Notes</label><textarea id="fu-notes" rows="3" placeholder="Additional details..." style="width:100%;padding:8px 12px;font-size:13px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text);resize:vertical;font-family:inherit"></textarea></div>'
    +'<div class="um-form-field"><label for="fu-priority">Priority</label><select id="fu-priority"><option value="low">Low</option><option value="medium" selected>Medium</option><option value="high">High</option><option value="urgent">Urgent</option></select></div>'
    +'<div class="um-form-field"><label for="fu-due">Due Date</label><input type="date" id="fu-due"></div>'
    +'<div class="um-form-actions">'
    +'<button class="btn" onclick="_closeModal()">Cancel</button>'
    +'<button class="btn btn-primary" id="fu-submit" onclick="submitCreateFollowUp(\''+leadId+'\')">Create</button>'
    +'</div></div></div>';
  document.body.appendChild(ov);
}

async function submitCreateFollowUp(leadId){
  var title=document.getElementById('fu-title').value.trim();
  var notes=document.getElementById('fu-notes').value.trim();
  var priority=document.getElementById('fu-priority').value;
  var dueDate=document.getElementById('fu-due').value;
  var btn=document.getElementById('fu-submit');
  var errEl=document.getElementById('fu-title-err');
  if(errEl){errEl.textContent='';errEl.classList.remove('visible')}
  if(!title){if(errEl){errEl.textContent='Title is required';errEl.classList.add('visible')}return}
  btn.disabled=true;btn.textContent='Creating...';
  try{
    var payload={lead_id:leadId,title:title,priority:priority};
    if(notes)payload.notes=notes;
    if(dueDate)payload.due_at=new Date(dueDate).toISOString();
    await api('/dashboard/api/follow-ups',{method:'POST',body:JSON.stringify(payload)});
    showToast('Follow-up created','success');
    _closeModal();
    _loadLeadFollowUps(leadId);
  }catch(e){showToast('Failed: '+e.message,'error')}
  finally{btn.disabled=false;btn.textContent='Create'}
}

// Also wire up the global "New Follow-up" button on the follow-ups page
document.getElementById('btn-create-followup').addEventListener('click',function(){
  // Show a lead selector modal for the global button
  showGlobalCreateFollowUpModal();
});

async function showGlobalCreateFollowUpModal(){
  _closeModal();
  // First, load leads to pick from
  var leads=[];
  try{
    var d=await api('/dashboard/api/leads?limit=500');
    leads=d.leads||[];
  }catch(e){showToast('Failed to load leads','error');return}
  var ov=document.createElement('div');
  ov.id='um-modal-overlay';
  ov.className='um-modal-overlay';
  ov.onclick=function(e){if(e.target===ov)_closeModal()};
  var leadOpts='<option value="">Select a lead...</option>';
  leads.forEach(function(l){leadOpts+='<option value="'+l.id+'">'+esc(l.prospect_name)+' ('+esc(l.email||'')+') - '+esc(l.status)+'</option>'});
  ov.innerHTML='<div class="um-modal">'
    +'<div class="um-modal-header"><h3>Create Follow-up</h3><button class="um-modal-close" onclick="_closeModal()">&times;</button></div>'
    +'<div class="um-modal-body">'
    +'<div class="um-form-field"><label for="gfu-lead">Lead *</label><select id="gfu-lead">'+leadOpts+'</select>'
    +'<div class="um-field-error" id="gfu-lead-err"></div></div>'
    +'<div class="um-form-field"><label for="gfu-title">Title *</label><input type="text" id="gfu-title" placeholder="e.g. Send proposal, Follow-up call">'
    +'<div class="um-field-error" id="gfu-title-err"></div></div>'
    +'<div class="um-form-field"><label for="gfu-notes">Notes</label><textarea id="gfu-notes" rows="3" placeholder="Additional details..." style="width:100%;padding:8px 12px;font-size:13px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text);resize:vertical;font-family:inherit"></textarea></div>'
    +'<div class="um-form-field"><label for="gfu-priority">Priority</label><select id="gfu-priority"><option value="low">Low</option><option value="medium" selected>Medium</option><option value="high">High</option><option value="urgent">Urgent</option></select></div>'
    +'<div class="um-form-field"><label for="gfu-due">Due Date</label><input type="date" id="gfu-due"></div>'
    +'<div class="um-form-actions">'
    +'<button class="btn" onclick="_closeModal()">Cancel</button>'
    +'<button class="btn btn-primary" id="gfu-submit" onclick="submitGlobalCreateFollowUp()">Create</button>'
    +'</div></div></div>';
  document.body.appendChild(ov);
}

async function submitGlobalCreateFollowUp(){
  var leadId=document.getElementById('gfu-lead').value;
  var title=document.getElementById('gfu-title').value.trim();
  var notes=document.getElementById('gfu-notes').value.trim();
  var priority=document.getElementById('gfu-priority').value;
  var dueDate=document.getElementById('gfu-due').value;
  var btn=document.getElementById('gfu-submit');
  var leadErr=document.getElementById('gfu-lead-err');
  var titleErr=document.getElementById('gfu-title-err');
  if(leadErr){leadErr.textContent='';leadErr.classList.remove('visible')}
  if(titleErr){titleErr.textContent='';titleErr.classList.remove('visible')}
  var ok=true;
  if(!leadId){if(leadErr){leadErr.textContent='Please select a lead';leadErr.classList.add('visible')}ok=false}
  if(!title){if(titleErr){titleErr.textContent='Title is required';titleErr.classList.add('visible')}ok=false}
  if(!ok)return;
  btn.disabled=true;btn.textContent='Creating...';
  try{
    var payload={lead_id:leadId,title:title,priority:priority};
    if(notes)payload.notes=notes;
    if(dueDate)payload.due_at=new Date(dueDate).toISOString();
    await api('/dashboard/api/follow-ups',{method:'POST',body:JSON.stringify(payload)});
    showToast('Follow-up created','success');
    _closeModal();
    loadFollowUpsPage();
  }catch(e){showToast('Failed: '+e.message,'error')}
  finally{btn.disabled=false;btn.textContent='Create'}
}

function eventClass(t){
  if(['reminder_sent','email_sent','email_generated','pipeline.completed','manual_lead_created'].includes(t))return'ev-success';
  if(['error','declined','pipeline.failed','call_cancelled','follow_up_deleted'].includes(t))return'ev-danger';
  if(['rsvp_changed','lead_updated','lead_status_changed','call_rescheduled','follow_up_status_changed'].includes(t))return'ev-warn';
  if(['call_updated','calendar_created','follow_up_created','follow_up_updated'].includes(t))return'ev-info';
  return'ev-neutral';
}

function humanEventType(t){
  var map={
    'form_submitted':'Form Submitted',
    'calendar_created':'Calendar Booked',
    'email_generated':'Email Drafted',
    'email_sent':'Email Sent',
    'reminder_sent':'Reminder Sent',
    'rsvp_changed':'RSVP Updated',
    'manual_lead_created':'Manually Created',
    'lead_updated':'Lead Updated',
    'lead_status_changed':'Status Changed',
    'call_updated':'Call Details Updated',
    'call_cancelled':'Call Cancelled',
    'call_rescheduled':'Call Rescheduled',
    'follow_up_created':'Follow-up Created',
    'follow_up_updated':'Follow-up Updated',
    'follow_up_status_changed':'Follow-up Status Changed',
    'follow_up_deleted':'Follow-up Deleted',
    'error':'Error',
    'declined':'Declined',
    'pipeline.completed':'Pipeline Completed',
    'pipeline.failed':'Pipeline Failed'
  };
  return map[t]||t;
}

/* =========================================
   CALLS PAGE
   ========================================= */
var callsFilter='upcoming';
var allCallsData=[];

async function loadCallsPage(){
  try{
    // Load actionable leads (server-side excludes not_interested and declined)
    var d=await api('/dashboard/api/leads?limit=500&exclude_status=not_interested,declined');
    var leads=(d.leads||[]).filter(function(l){return l.appt_local});
    // Load cancelled leads separately (not_interested + declined)
    try{
      var nc=await api('/dashboard/api/leads?limit=500&status=not_interested');
      var ncLeads=(nc.leads||[]).filter(function(l){return l.appt_local});
      leads=leads.concat(ncLeads);
    }catch(x){}
    try{
      var dc=await api('/dashboard/api/leads?limit=500&status=declined');
      var dcLeads=(dc.leads||[]).filter(function(l){return l.appt_local});
      leads=leads.concat(dcLeads);
    }catch(x){}
    allCallsData=leads;
    updateCallFilterCounts(leads);
    renderCallsTable(leads);
  }catch(e){console.error('Calls load failed:',e)}
}

function updateCallFilterCounts(leads){
  var now=new Date();
  var todayStart=new Date(now.getFullYear(),now.getMonth(),now.getDate());
  var todayEnd=new Date(todayStart.getTime()+86400000);
  var upcoming=0,today=0,past=0,all=0,cancelled=0;
  for(var i=0;i<leads.length;i++){
    var l=leads[i];
    if(l.status==='declined'||l.status==='not_interested'){
      cancelled++;
      continue;
    }
    all++;
    var appt=l.appt_datetime_utc?new Date(l.appt_datetime_utc):null;
    if(!appt)continue;
    if(appt>=todayEnd)upcoming++;
    else if(appt>=todayStart)today++;
    else past++;
  }
  var e;
  e=document.getElementById('calls-count-upcoming');if(e)e.textContent=upcoming||'';
  e=document.getElementById('calls-count-today');if(e)e.textContent=today||'';
  e=document.getElementById('calls-count-past');if(e)e.textContent=past||'';
  e=document.getElementById('calls-count-all');if(e)e.textContent=all||'';
  e=document.getElementById('calls-count-cancelled');if(e)e.textContent=cancelled||'';
}

function renderCallsTable(allBooked){
  var now=new Date();
  var todayStart=new Date(now.getFullYear(),now.getMonth(),now.getDate());
  var todayEnd=new Date(todayStart.getTime()+86400000);
  var filtered;
  if(callsFilter==='upcoming'){
    filtered=allBooked.filter(function(l){
      return l.appt_datetime_utc&&new Date(l.appt_datetime_utc)>=todayEnd&&l.status!=='declined'&&l.status!=='not_interested';
    });
  }else if(callsFilter==='today'){
    filtered=allBooked.filter(function(l){
      var appt=l.appt_datetime_utc?new Date(l.appt_datetime_utc):null;
      return appt&&appt>=todayStart&&appt<todayEnd&&l.status!=='declined'&&l.status!=='not_interested';
    });
  }else if(callsFilter==='past'){
    filtered=allBooked.filter(function(l){
      var appt=l.appt_datetime_utc?new Date(l.appt_datetime_utc):null;
      return appt&&appt<todayStart&&l.status!=='declined'&&l.status!=='not_interested';
    });
  }else if(callsFilter==='cancelled'){
    filtered=allBooked.filter(function(l){return l.status==='declined'||l.status==='not_interested'});
  }else{
    filtered=allBooked;
  }
  // Sort: upcoming first by appt time asc, past last
  filtered.sort(function(a,b){
    if(!a.appt_datetime_utc)return 1;
    if(!b.appt_datetime_utc)return -1;
    return new Date(a.appt_datetime_utc)-new Date(b.appt_datetime_utc);
  });
  var el=document.getElementById('calls-table-wrap');
  if(filtered.length===0){
    var msgs={
      'upcoming':['No upcoming calls','Booked strategy calls will appear here.'],
      'today':['No calls today','No appointments scheduled for today.'],
      'past':['No past calls','Completed calls will appear here.'],
      'cancelled':['No cancelled calls','Cancelled or declined calls will appear here.'],
      'all':['No booked calls','Booked strategy calls will appear here.']
    };
    var pair=msgs[callsFilter]||msgs.all;
    el.innerHTML='<div class="empty-state"><div class="icon">&#128222;</div><h3>'+pair[0]+'</h3><p>'+pair[1]+'</p></div>';
    return;
  }
  var isAdmin=(_umCurrentUserRole==='owner'||_umCurrentUserRole==='admin');
  var html='<table><thead><tr><th>Lead</th><th>Appointment</th><th>Status</th><th>Outcome</th><th>Duration</th><th>Action</th></tr></thead><tbody>';
  for(var i=0;i<filtered.length;i++){
    var l=filtered[i];
    var outcomeText=l.call_outcome?esc(l.call_outcome.replace(/_/g,' ')):'-';
    var durationText=l.call_duration_minutes?l.call_duration_minutes+' min':'-';
    var rowClass='';
    if(l.status==='declined'||l.status==='not_interested')rowClass=' style="opacity:0.6"';
    html+='<tr class="clickable"'+rowClass+' onclick="openCallDetail(\''+l.id+'\',\''+esc(l.prospect_name)+'\')" data-id="'+l.id+'">'
      +'<td style="font-weight:500">'+esc(l.prospect_name)+(l.company_address?'<br><span style="font-size:11px;color:var(--text-muted)">'+esc(l.company_address)+'</span>':'')+'</td>'
      +'<td style="font-family:var(--font-mono);font-size:12px">'+esc(l.appt_local||'-')+'</td>'
      +'<td><span class="badge '+esc(l.status)+'"><span class="badge-dot"></span>'+esc(l.status)+'</span></td>'
      +'<td>'+(l.call_outcome?'<span style="font-size:12px">'+outcomeText+'</span>':'<span style="color:var(--text-muted);font-size:12px">Pending</span>')+'</td>'
      +'<td style="font-family:var(--font-mono);font-size:12px">'+durationText+'</td>'
      +'<td><button class="btn btn-sm btn-ghost" onclick="event.stopPropagation();openCallDetail(\''+l.id+'\',\''+esc(l.prospect_name)+'\')">View</button></td>'
      +'</tr>';
  }
  el.innerHTML=html+'</tbody></table>';
}

async function openCallDetail(id,name){
  document.getElementById('drawer-title').textContent=name||'Call Detail';
  var body=document.getElementById('drawer-body');
  body.innerHTML='<div class="skeleton skeleton-row w80" style="height:20px;margin-bottom:12px"></div><div class="skeleton skeleton-row w60" style="height:20px;margin-bottom:12px"></div><div class="skeleton skeleton-row w80" style="height:20px"></div>';
  openDrawer();
  try{
    var d=await api('/dashboard/api/leads/'+id);
    var l=d.lead;
    var isAdmin=(_umCurrentUserRole==='owner'||_umCurrentUserRole==='admin');
    // Status transition options
    var statusTransitions={
      'pending':['scheduled','error','not_interested'],
      'scheduled':['accepted','tentative','declined','reminded','completed'],
      'accepted':['reminded','declined','completed'],
      'tentative':['accepted','declined','completed'],
      'reminded':['completed','declined'],
      'completed':[],'declined':[],'not_interested':[],'error':['pending']
    };
    var allowed=statusTransitions[l.status]||[];
    var terminal=['completed','declined','not_interested','error'];
    var isActive=terminal.indexOf(l.status)===-1;
    // Outcome options
    var outcomeOpts='';
    var outcomes=['connected','completed','no_answer','voicemail','busy','wrong_number','rescheduled','cancelled','no_show','not_interested'];
    outcomeOpts='<option value="">- Select outcome -</option>';
    for(var oi=0;oi<outcomes.length;oi++){
      var sel=(l.call_outcome===outcomes[oi])?' selected':'';
      outcomeOpts+='<option value="'+outcomes[oi]+'"'+sel+'>'+outcomes[oi].replace(/_/g,' ')+'</option>';
    }
    var html='<dl class="detail-grid">'
      +'<dt>Prospect</dt><dd style="font-weight:600">'+esc(l.prospect_name)+'</dd>'
      +'<dt>Email</dt><dd>'+esc(l.email)+'</dd>'
      +'<dt>Phone</dt><dd>'+(l.phone_number?esc(l.phone_number):'-')+'</dd>'
      +'<dt>Company</dt><dd>'+esc(l.company_address||'-')+'</dd>'
      +'<dt>Status</dt><dd id="ld-status-cell"><span class="badge '+esc(l.status)+'"><span class="badge-dot"></span>'+esc(l.status)+'</span>'
      +(isAdmin&&allowed.length>0?' <select id="ld-status-select" class="ld-status-select" onchange="changeLeadStatus(\''+id+'\',this.value)" style="margin-left:8px;padding:2px 6px;font-size:12px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--bg);color:var(--text)">'+function(){var opts='';for(var si=0;si<allowed.length;si++)opts+='<option value="'+esc(allowed[si])+'">'+esc(allowed[si])+'</option>';return opts;}()+'</select>':'')
      +'</dd>'
      +'<dt>Appointment</dt><dd style="font-family:var(--font-mono);font-size:12px">'+(l.appt_local?esc(l.appt_local):'-')+'</dd>'
      +'<dt>Calendar Event</dt><dd style="font-family:var(--font-mono);font-size:12px;word-break:break-all">'+(l.calendar_event_id?'<a href="https://calendar.google.com/calendar/event?eid='+encodeURIComponent(btoa(l.calendar_event_id.replace(/-/g,'')+'@google.com'))+'" target="_blank" style="color:var(--accent);text-decoration:none">'+esc(l.calendar_event_id)+'</a>':'-')+'</dd>'
      +'<dt>Reminder</dt><dd>'+(l.reminder_sent_at?'<span style="color:var(--accent)">&#10003; Sent</span>':'<span style="color:var(--text-muted)">Pending</span>')+'</dd>'
      +'<dt>Reschedules</dt><dd>'+(l.reschedule_count?l.reschedule_count+' time'+(l.reschedule_count>1?'s':''):'None')+'</dd>'
      +'</dl>';

    // Call Management Section
    html+='<div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border)">'
      +'<h4 style="font-size:13px;font-weight:600;margin-bottom:12px;color:var(--text)">Call Details</h4>'
      +'<dl class="detail-grid">'
      +'<dt>Outcome</dt><dd>'+(l.call_outcome?'<span class="badge '+esc(l.call_outcome)+'" style="text-transform:capitalize"><span class="badge-dot"></span>'+esc(l.call_outcome.replace(/_/g,' '))+'</span>':'<span style="color:var(--text-muted)">Not recorded</span>')+'</dd>'
      +'<dt>Duration</dt><dd>'+(l.call_duration_minutes?l.call_duration_minutes+' minutes':'<span style="color:var(--text-muted)">Not recorded</span>')+'</dd>'
      +'<dt>Notes</dt><dd>'+(l.call_notes?'<div style="background:var(--surface);padding:8px 12px;border-radius:var(--radius);font-size:13px;white-space:pre-wrap">'+esc(l.call_notes)+'</div>':'<span style="color:var(--text-muted)">No notes</span>')+'</dd>'
      +'</dl></div>';

    // Admin Actions
    if(isAdmin){
      html+='<div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border);display:flex;gap:8px;flex-wrap:wrap">';
      html+='<button class="btn btn-primary" onclick="toggleCallEdit(\''+id+'\')" id="cd-edit-btn">Update Call</button>';
      if(isActive){
        html+='<button class="btn" style="background:var(--accent-light);color:var(--accent)" onclick="toggleRescheduleForm(\''+id+'\')" id="cd-reschedule-btn">Reschedule</button>';
        html+='<button class="btn" style="background:var(--danger-light);color:var(--danger)" onclick="toggleCancelForm(\''+id+'\')" id="cd-cancel-btn">Cancel Call</button>';
      }
      html+='</div>';

      // Edit Call Form
      html+='<div id="cd-edit-form" style="display:none;margin-top:16px;padding:16px;background:var(--surface);border-radius:var(--radius);border:1px solid var(--border)">'
        +'<h4 style="font-size:14px;font-weight:600;margin-bottom:12px;color:var(--text)">Update Call Details</h4>'
        +'<div class="um-form-field"><label>Outcome</label><select id="cd-edit-outcome" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);font-size:13px">'+outcomeOpts+'</select></div>'
        +'<div class="um-form-field"><label>Duration (minutes)</label><input type="number" id="cd-edit-duration" min="0" max="1440" value="'+(l.call_duration_minutes||'')+'" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);font-size:13px"></div>'
        +'<div class="um-form-field"><label>Notes</label><textarea id="cd-edit-notes" rows="4" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);font-size:13px;resize:vertical">'+esc(l.call_notes||'')+'</textarea></div>'
        +'<div id="cd-edit-errors" style="color:var(--danger);font-size:12px;margin-bottom:8px"></div>'
        +'<div style="display:flex;gap:8px;justify-content:flex-end">'
        +'<button class="btn btn-ghost" onclick="toggleCallEdit(null)">Cancel</button>'
        +'<button class="btn btn-primary" id="cd-edit-submit" onclick="submitCallEdit(\''+id+'\')">Save</button>'
        +'</div></div>';

      // Reschedule Form
      html+='<div id="cd-reschedule-form" style="display:none;margin-top:16px;padding:16px;background:var(--surface);border-radius:var(--radius);border:1px solid var(--border)">'
        +'<h4 style="font-size:14px;font-weight:600;margin-bottom:12px;color:var(--text)">Reschedule Call</h4>'
        +'<div class="um-form-field"><label>New Date &amp; Time *</label><input type="text" id="cd-reschedule-appt" placeholder="e.g. tomorrow 2pm, 2026-09-01 3:00 PM CT" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);font-size:13px"></div>'
        +'<div class="um-form-field"><label>Reason (optional)</label><input type="text" id="cd-reschedule-reason" placeholder="Reason for rescheduling" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);font-size:13px"></div>'
        +'<div id="cd-reschedule-errors" style="color:var(--danger);font-size:12px;margin-bottom:8px"></div>'
        +'<div style="display:flex;gap:8px;justify-content:flex-end">'
        +'<button class="btn btn-ghost" onclick="toggleRescheduleForm(null)">Cancel</button>'
        +'<button class="btn btn-primary" id="cd-reschedule-submit" onclick="submitReschedule(\''+id+'\')">Reschedule</button>'
        +'</div></div>';

      // Cancel Call Form
      html+='<div id="cd-cancel-form" style="display:none;margin-top:16px;padding:16px;background:var(--surface);border-radius:var(--radius);border:1px solid var(--border)">'
        +'<h4 style="font-size:14px;font-weight:600;margin-bottom:12px;color:var(--danger)">Cancel Call</h4>'
        +'<p style="font-size:13px;color:var(--text-muted);margin-bottom:12px">This will mark the lead as declined and remove the calendar event.</p>'
        +'<div class="um-form-field"><label>Reason (optional)</label><input type="text" id="cd-cancel-reason" placeholder="Reason for cancellation" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);font-size:13px"></div>'
        +'<div id="cd-cancel-errors" style="color:var(--danger);font-size:12px;margin-bottom:8px"></div>'
        +'<div style="display:flex;gap:8px;justify-content:flex-end">'
        +'<button class="btn btn-ghost" onclick="toggleCancelForm(null)">Keep Call</button>'
        +'<button class="btn" style="background:var(--danger);color:#fff" id="cd-cancel-submit" onclick="submitCancelCall(\''+id+'\')">Confirm Cancel</button>'
        +'</div></div>';
    }

    // Activity Timeline
    if(d.events&&d.events.length>0){
      html+='<h4 style="font-size:13px;font-weight:600;margin:20px 0 12px;color:var(--text)">Activity Timeline</h4>';
      html+='<ul class="timeline">';
      for(var i=0;i<d.events.length;i++){
        var e=d.events[i];
        var cls=eventClass(e.event_type);
        var humanType=humanEventType(e.event_type);
        html+='<li class="'+cls+'">'
          +'<span class="t">'+formatDate(e.created_at)+' '+formatTime(e.created_at)+'</span>'
          +'<span class="e '+cls+'">'+esc(humanType)+'</span>'
          +(e.payload?'<pre>'+esc(typeof e.payload==='string'?e.payload:JSON.stringify(e.payload,null,2))+'</pre>':'')
          +'</li>';
      }
      html+='</ul>';
    }
    body.innerHTML=html;
  }catch(e){body.innerHTML='<div style="color:var(--danger);padding:16px">Failed to load call details.</div>'}
}

function toggleCallEdit(id){
  var form=document.getElementById('cd-edit-form');
  var btn=document.getElementById('cd-edit-btn');
  if(!form)return;
  var visible=form.style.display!=='none';
  form.style.display=visible?'none':'block';
  if(btn)btn.textContent=visible?'Update Call':'Cancel';
}

async function submitCallEdit(leadId){
  var btn=document.getElementById('cd-edit-submit');
  var errDiv=document.getElementById('cd-edit-errors');
  var outcome=document.getElementById('cd-edit-outcome').value||null;
  var duration=document.getElementById('cd-edit-duration').value;
  var notes=document.getElementById('cd-edit-notes').value.trim();
  errDiv.textContent='';
  btn.disabled=true;btn.textContent='Saving...';
  try{
    var payload={};
    if(outcome)payload.call_outcome=outcome;
    if(duration!=='')payload.call_duration_minutes=parseInt(duration);
    payload.call_notes=notes||null;
    await api('/dashboard/api/leads/'+leadId+'/call',{method:'PATCH',body:JSON.stringify(payload)});
    showToast('Call details updated','success');
    toggleCallEdit(null);
    openCallDetail(leadId,null);
    loadCallsPage();
  }catch(e){
    errDiv.textContent='Failed to save: '+(e.message||'Unknown error');
  }finally{btn.disabled=false;btn.textContent='Save'}
}

function toggleCancelForm(id){
  var form=document.getElementById('cd-cancel-form');
  var btn=document.getElementById('cd-cancel-btn');
  if(!form)return;
  var visible=form.style.display!=='none';
  form.style.display=visible?'none':'block';
  if(btn)btn.textContent=visible?'Cancel Call':'Keep Call';
}

async function submitCancelCall(leadId){
  var btn=document.getElementById('cd-cancel-submit');
  var errDiv=document.getElementById('cd-cancel-errors');
  var reason=document.getElementById('cd-cancel-reason').value.trim()||null;
  errDiv.textContent='';
  if(!confirm('Are you sure you want to cancel this call?'))return;
  btn.disabled=true;btn.textContent='Cancelling...';
  try{
    await api('/dashboard/api/leads/'+leadId+'/cancel',{method:'POST',body:JSON.stringify({reason:reason})});
    showToast('Call cancelled','success');
    toggleCancelForm(null);
    openCallDetail(leadId,null);
    loadCallsPage();
  }catch(e){
    var msg=e.message||'';
    if(msg.indexOf('terminal')>=0||msg.indexOf('Terminal')>=0||msg.indexOf('422')>=0){
      errDiv.textContent='This call is already in a terminal state and cannot be cancelled.';
    }else{
      errDiv.textContent=msg||'Failed to cancel call';
    }
  }finally{if(btn){btn.disabled=false;btn.textContent='Confirm Cancel'}}
}

function toggleRescheduleForm(id){
  var form=document.getElementById('cd-reschedule-form');
  var btn=document.getElementById('cd-reschedule-btn');
  if(!form)return;
  var visible=form.style.display!=='none';
  form.style.display=visible?'none':'block';
  if(btn)btn.textContent=visible?'Reschedule':'Cancel';
}

async function submitReschedule(leadId){
  var btn=document.getElementById('cd-reschedule-submit');
  var errDiv=document.getElementById('cd-reschedule-errors');
  var appt=document.getElementById('cd-reschedule-appt').value.trim();
  var reason=document.getElementById('cd-reschedule-reason').value.trim()||null;
  errDiv.textContent='';
  if(!appt){errDiv.textContent='New appointment date & time is required';return}
  btn.disabled=true;btn.textContent='Rescheduling...';
  try{
    await api('/dashboard/api/leads/'+leadId+'/reschedule',{method:'POST',body:JSON.stringify({appt_datetime_raw:appt,reason:reason})});
    showToast('Call rescheduled','success');
    toggleRescheduleForm(null);
    openCallDetail(leadId,null);
    loadCallsPage();
  }catch(e){
    var msg=e.message||'';
    if(msg.indexOf('duplicate')>=0||msg.indexOf('Duplicate')>=0){
      errDiv.textContent='A lead with this email and appointment time already exists';
    }else{
      errDiv.textContent='Failed to reschedule: '+msg;
    }
  }finally{btn.disabled=false;btn.textContent='Reschedule'}
}

document.querySelectorAll('[data-call-filter]').forEach(function(btn){
  btn.addEventListener('click',function(){
    document.querySelectorAll('[data-call-filter]').forEach(function(b){b.classList.remove('active')});
    btn.classList.add('active');
    callsFilter=btn.dataset.callFilter;
    renderCallsTable(allCallsData);
  });
});

/* =========================================
   FOLLOW-UPS PAGE (Phase 18)
   ========================================= */
var allFollowUpsData=[];
var followUpsFilter='all';

function renderFollowUpsTable(fups){
  var filtered=fups;
  if(followUpsFilter!=='all')filtered=fups.filter(f=>f.status===followUpsFilter);
  var wrap=document.getElementById('followups-table-wrap');
  if(!filtered.length){
    wrap.innerHTML='<div class="empty-state"><div class="empty-icon">&#128203;</div><h3>No follow-ups found</h3><p style="font-size:13px;color:var(--text-muted)">'+(followUpsFilter==='all'?'Create your first follow-up to track next steps after calls.':'No follow-ups with status "'+followUpsFilter+'".')+'</p></div>';
    return;
  }
  var html='<table class="leads-table"><thead><tr><th>Title</th><th>Lead</th><th>Priority</th><th>Status</th><th>Due</th><th>Assigned To</th><th style="width:120px">Actions</th></tr></thead><tbody>';
  filtered.forEach(f=>{
    var priorityClass=f.priority==='urgent'?'call-outcome-connected':f.priority==='high'?'call-outcome-completed':'call-outcome-pending';
    var statusClass=f.status==='completed'?'status-completed':f.status==='cancelled'?'status-cancelled':f.status==='in_progress'?'status-scheduled':'status-pending';
    var dueStr=f.due_at?new Date(f.due_at).toLocaleDateString():'<span style="color:var(--text-faint)">-</span>';
    var assigned=f.assigned_to_name||'<span style="color:var(--text-faint)">Unassigned</span>';
    html+='<tr>';
    html+='<td style="font-weight:500">'+esc(f.title||'')+'</td>';
    html+='<td><span style="color:var(--text-secondary)">'+esc(f.lead_name||'-')+'</span></td>';
    html+='<td><span class="call-badge '+priorityClass+'">'+esc(f.priority)+'</span></td>';
    html+='<td><span class="status-badge '+statusClass+'">'+esc(f.status.replace('_',' '))+'</span></td>';
    html+='<td>'+dueStr+'</td>';
    html+='<td>'+assigned+'</td>';
    html+='<td>';
    html+='<div style="display:flex;gap:4px">';
    if(f.status==='pending'){
      html+='<button class="btn btn-xs btn-primary" onclick="followUpAction(\''+f.id+'\',\'in_progress\')" data-admin-only title="Start">&#9654;</button>';
      html+='<button class="btn btn-xs btn-success" onclick="followUpAction(\''+f.id+'\',\'completed\')" data-admin-only title="Complete">&#10003;</button>';
      html+='<button class="btn btn-xs btn-danger" onclick="followUpAction(\''+f.id+'\',\'cancelled\')" data-admin-only title="Cancel">&#10007;</button>';
    } else if(f.status==='in_progress'){
      html+='<button class="btn btn-xs btn-success" onclick="followUpAction(\''+f.id+'\',\'completed\')" data-admin-only title="Complete">&#10003;</button>';
      html+='<button class="btn btn-xs btn-danger" onclick="followUpAction(\''+f.id+'\',\'cancelled\')" data-admin-only title="Cancel">&#10007;</button>';
    }
    html+='</div></td></tr>';
  });
  html+='</tbody></table>';
  wrap.innerHTML=html;
  _applyAdminOnlyVisibility();
}

async function followUpAction(fuId,newStatus){
  try{
    await api('/dashboard/api/follow-ups/'+fuId+'/status',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:newStatus})});
    showToast('Follow-up updated to '+newStatus.replace('_',' '),'success');
    loadFollowUpsPage();
  }catch(e){showToast('Failed: '+e.message,'error')}
}

async function loadFollowUpsPage(){
  var [respRes,statsRes]=await Promise.allSettled([
    api('/dashboard/api/follow-ups'),
    api('/dashboard/api/follow-ups/stats')
  ]);
  // Follow-ups list - independent of stats.
  if(respRes.status==='fulfilled'){
    allFollowUpsData=respRes.value.follow_ups||[];
    renderFollowUpsTable(allFollowUpsData);
  }else{console.error('Follow-ups list failed:',respRes.reason)}
  // Stats (badge + cards) - independent of list.
  if(statsRes.status==='fulfilled'){
    var statsResp=statsRes.value;
    var badge=document.getElementById('nav-followups-count');
    if(badge){
      var activeCount=statsResp.active||0;
      if(activeCount>0){badge.textContent=activeCount;badge.style.display='';}
      else{badge.style.display='none';}
    }
    var setVal=function(id,val){var el=document.getElementById(id);if(el)el.textContent=val;};
    setVal('fu-stat-total',statsResp.total||0);
    setVal('fu-stat-active',statsResp.active||0);
    setVal('fu-stat-completed',statsResp.completed||0);
    setVal('fu-stat-cancelled',statsResp.cancelled||0);
    setVal('fu-stat-overdue',statsResp.overdue||0);
    var avgH=statsResp.avg_time_to_completion_hours;
    setVal('fu-stat-avg',avgH!=null?avgH+'h':'N/A');
  }else{console.error('Follow-ups stats failed:',statsRes.reason)}
}

document.querySelectorAll('[data-fu-filter]').forEach(function(btn){
  btn.addEventListener('click',function(){
    document.querySelectorAll('[data-fu-filter]').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    followUpsFilter=btn.dataset.fuFilter;
    renderFollowUpsTable(allFollowUpsData);
  });
});

/* =========================================
   AUTOMATIONS PAGE
   ========================================= */
async function loadAutomationsPage(){
  var [settingsRes,failedRes]=await Promise.allSettled([
    api('/dashboard/api/settings'),
    api('/dashboard/api/failed-jobs')
  ]);
  var settings=(settingsRes.status==='fulfilled')?settingsRes.value:{};
  if(settingsRes.status==='rejected'){console.error('Automations settings failed:',settingsRes.reason)}
  var failed=(failedRes.status==='fulfilled')?failedRes.value:{count:0,failure_details:[]};
  if(failedRes.status==='rejected'){console.error('Automations failed-jobs failed:',failedRes.reason)}
  renderAutomationsPage(settings,failed);
}

function renderAutomationsPage(settings,failed){
  var cards=[
    {
      title:'Lead Processing',
      desc:'Automatically processes incoming website leads through the qualification and booking pipeline.',
      active:true,
      config:null,
      lastActivity:'Running continuously',
      hasError:false
    },
    {
      title:'Calendar Booking',
      desc:'Creates Google Calendar events and Zoom meeting links for qualified leads.',
      active:true,
      config:null,
      lastActivity:'Runs with each new lead',
      hasError:false
    },
    {
      title:'Confirmation Emails',
      desc:'AI-personalized booking confirmation emails sent via Gmail.',
      active:true,
      config:null,
      lastActivity:'Runs with each new lead',
      hasError:false
    },
    {
      title:'RSVP Monitoring',
      desc:'Monitors attendee responses and updates appointment status automatically.',
      active:true,
      config:'Every '+settings.rsvp_poll_interval_minutes+' minutes',
      lastActivity:'Scheduled',
      hasError:false
    },
    {
      title:'Appointment Reminders',
      desc:'Sends reminder emails to leads with upcoming appointments.',
      active:true,
      config:'Daily at '+formatTime24(settings.reminder_time),
      lastActivity:'Scheduled',
      hasError:false
    }
  ];
  var el=document.getElementById('automations-grid');
  var html='';
  for(var i=0;i<cards.length;i++){
    var c=cards[i];
    html+='<div class="automation-card">'
      +'<div class="automation-card-header"><h4>'+esc(c.title)+'</h4>'
      +'<span class="automation-status '+(c.hasError?'error':'active')+'">'
      +(c.hasError?'&#9888; Error':'<span class="dot"></span> Active')+'</span></div>'
      +'<p>'+esc(c.desc)+'</p>'
      +'<div class="automation-card-footer">'
      +'<span>'+(c.config?'<span class="automation-config">'+esc(c.config)+'</span>':esc(c.lastActivity))+'</span>'
      +'</div></div>';
  }
  // Failed jobs card
  if(failed.count>0){
    html+='<div class="automation-card" style="border-color:var(--danger-light)">'
      +'<div class="automation-card-header"><h4 style="color:var(--danger)">Failed Jobs</h4>'
      +'<span class="badge error"><span class="badge-dot"></span>'+failed.count+' unresolved</span></div>'
      +'<p style="color:var(--danger)">Some operations failed and need attention.</p></div>';
  }
  el.innerHTML=html;
}

function formatTime24(hhmm){
  if(!hhmm)return'-';
  var parts=hhmm.split(':');
  var h=parseInt(parts[0],10);
  var m=parts[1];
  var ampm=h>=12?'PM':'AM';
  var h12=h%12||12;
  return h12+':'+m+' '+ampm;
}

/* =========================================
   ANALYTICS PAGE
   ========================================= */
var analyticsDays=30;

async function loadAnalyticsPage(){
  var [leadsRes,apptsRes,summaryRes]=await Promise.allSettled([
    api('/dashboard/api/analytics/leads-over-time?days='+analyticsDays),
    api('/dashboard/api/analytics/appointments-over-time?days='+analyticsDays),
    api('/dashboard/api/summary')
  ]);
  // Leads chart - independent.
  if(leadsRes.status==='fulfilled'){
    renderChart('chart-leads',leadsRes.value.data,'Leads',getAccentColor());
  }else{console.error('Analytics leads-over-time failed:',leadsRes.reason)}
  // Appointments chart - independent.
  if(apptsRes.status==='fulfilled'){
    renderChart('chart-appointments',apptsRes.value.data,'Appointments',getInfoColor());
  }else{console.error('Analytics appointments-over-time failed:',apptsRes.reason)}
  // Pipeline distribution - independent.
  if(summaryRes.status==='fulfilled'){
    renderPipelineDistribution(summaryRes.value);
  }else{console.error('Analytics summary failed:',summaryRes.reason)}
}

function getAccentColor(){return'#0E8A5F'}
function getInfoColor(){return'#2563EB'}

function renderChart(canvasId,data,label,color){
  var canvas=document.getElementById(canvasId);
  var ctx=canvas.getContext('2d');
  var dpr=window.devicePixelRatio||1;
  var rect=canvas.parentElement.getBoundingClientRect();
  var w=rect.width-40;
  var h=rect.height-50;
  canvas.width=w*dpr;
  canvas.height=h*dpr;
  canvas.style.width=w+'px';
  canvas.style.height=h+'px';
  ctx.scale(dpr,dpr);
  ctx.clearRect(0,0,w,h);

  if(!data||data.length===0){
    ctx.fillStyle='#A1A5AC';
    ctx.font='13px General Sans, Inter, sans-serif';
    ctx.textAlign='center';
    ctx.fillText('No data yet',w/2,h/2);
    return;
  }

  // Generate date range
  var dates=[];
  var now=new Date();
  for(var i=analyticsDays-1;i>=0;i--){
    var d=new Date(now);
    d.setDate(d.getDate()-i);
    dates.push(d.toISOString().slice(0,10));
  }

  // Map data to counts
  var counts={};
  for(var i=0;i<data.length;i++)counts[data[i].date]=data[i].count;
  var values=dates.map(function(d){return counts[d]||0});
  var maxVal=Math.max.apply(null,values)||1;

  var padding={top:10,right:10,bottom:30,left:40};
  var chartW=w-padding.left-padding.right;
  var chartH=h-padding.top-padding.bottom;

  // Grid lines
  ctx.strokeStyle='#F0F1F3';
  ctx.lineWidth=1;
  for(var i=0;i<=4;i++){
    var y=padding.top+chartH*(1-i/4);
    ctx.beginPath();ctx.moveTo(padding.left,y);ctx.lineTo(w-padding.right,y);ctx.stroke();
    ctx.fillStyle='#A1A5AC';
    ctx.font='10px JetBrains Mono, monospace';
    ctx.textAlign='right';
    ctx.fillText(Math.round(maxVal*i/4),padding.left-6,y+3);
  }

  // Bars
  var barW=Math.max(2,chartW/values.length-3);
  var gap=chartW/values.length;
  for(var i=0;i<values.length;i++){
    var barH=chartH*(values[i]/maxVal);
    var x=padding.left+i*gap+(gap-barW)/2;
    var y=padding.top+chartH-barH;
    // Rounded top bar
    var r=Math.min(3,barW/2,barH);
    ctx.fillStyle=color;
    ctx.globalAlpha=0.85;
    ctx.beginPath();
    ctx.moveTo(x,y+r);
    ctx.arcTo(x,y,x+r,y,r);
    ctx.arcTo(x+barW,y,x+barW,y+r,r);
    ctx.lineTo(x+barW,padding.top+chartH);
    ctx.lineTo(x,padding.top+chartH);
    ctx.closePath();
    ctx.fill();
    ctx.globalAlpha=1;
  }

  // X-axis labels (show a few)
  ctx.fillStyle='#A1A5AC';
  ctx.font='10px JetBrains Mono, monospace';
  ctx.textAlign='center';
  var step=Math.max(1,Math.floor(dates.length/6));
  for(var i=0;i<dates.length;i+=step){
    var x=padding.left+i*gap+gap/2;
    var label=dates[i].slice(5); // MM-DD
    ctx.fillText(label,x,h-8);
  }
}

function renderPipelineDistribution(s){
  var bs=s.by_status||{};
  var total=s.total_leads||1;
  var statuses=[
    {key:'pending',label:'Pending',color:'var(--warning)'},
    {key:'scheduled',label:'Scheduled',color:'var(--accent)'},
    {key:'accepted',label:'Accepted',color:'var(--accent)'},
    {key:'declined',label:'Declined',color:'var(--danger)'},
    {key:'reminded',label:'Reminded',color:'var(--info)'},
    {key:'error',label:'Error',color:'var(--danger)'}
  ];
  var html='<div style="display:flex;gap:16px;flex-wrap:wrap">';
  for(var i=0;i<statuses.length;i++){
    var st=statuses[i];
    var count=bs[st.key]||0;
    var pct=Math.round(count/total*100);
    html+='<div style="flex:1;min-width:120px;padding:12px;background:var(--surface);border-radius:var(--radius);text-align:center">'
      +'<div style="font-size:20px;font-weight:700;color:'+st.color+'">'+count+'</div>'
      +'<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-top:2px">'+st.label+'</div>'
      +'<div style="font-size:11px;color:var(--text-faint);margin-top:2px">'+pct+'%</div></div>';
  }
  html+='</div>';
  document.getElementById('analytics-pipeline-dist').innerHTML=html;
}

document.querySelectorAll('[data-days]').forEach(function(btn){
  btn.addEventListener('click',function(){
    document.querySelectorAll('[data-days]').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    analyticsDays=parseInt(btn.dataset.days,10);
    loadAnalyticsPage();
  });
});

/* =========================================
   SETTINGS PAGE
   ========================================= */
async function loadSettingsPage(){
  try{
    var s=await api('/dashboard/api/settings');
    document.getElementById('s-reminder-time').value=s.reminder_time;
    document.getElementById('s-rsvp-interval').value=s.rsvp_poll_interval_minutes;
  }catch(e){console.error('Settings load failed:',e)}
}

async function saveSettings(){
  var msg=document.getElementById('s-settings-msg');
  msg.textContent='';
  var btn=document.getElementById('s-save-settings');
  btn.disabled=true;
  try{
    var payload={
      reminder_time:document.getElementById('s-reminder-time').value,
      rsvp_poll_interval_minutes:parseInt(document.getElementById('s-rsvp-interval').value,10)
    };
    var data=await api('/dashboard/api/settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    msg.style.color='var(--accent)';msg.textContent='Settings saved';
    showToast('Settings saved successfully','success');
    setTimeout(function(){msg.textContent=''},3000);
  }catch(e){msg.style.color='var(--danger)';msg.textContent='Save failed: '+(e.message||'Unknown error');showToast('Failed to save settings','error')}
  finally{btn.disabled=false}
}

async function triggerJob(kind){
  var btn=document.getElementById(kind==='reminders'?'s-trigger-reminders':'s-trigger-poll');
  var out=document.getElementById('s-trigger-result');
  btn.disabled=true;out.textContent='Running...';
  try{
    var data=await api('/dashboard/api/trigger/'+(kind==='reminders'?'reminders':'poll-rsvps'),{method:'POST'});
    if(kind==='reminders'){
      out.textContent='Checked '+data.checked+', sent '+data.sent+', errors '+data.errors
        +(data.sent===0&&data.checked>0?' (already reminded today)':'');
      showToast('Reminders processed: '+data.sent+' sent','success');
    }else{
      out.textContent='Checked '+data.checked+', declined '+data.declined+', updated '+data.updated+', errors '+data.errors;
      showToast('RSVP check complete: '+data.checked+' checked','success');
    }
  }catch(e){out.textContent='Request failed';showToast('Request failed','error')}
  finally{btn.disabled=false}
}

document.getElementById('s-save-settings').addEventListener('click',saveSettings);
document.getElementById('s-trigger-reminders').addEventListener('click',function(){triggerJob('reminders')});
document.getElementById('s-trigger-poll').addEventListener('click',function(){triggerJob('poll')});

/* =========================================
   SSE - Phase 6 preserved
   ========================================= */
var sseConnected=false;
var sseRetries=0;
var MAX_SSE_RETRIES=5;
var fallbackTimer=null;
var activeEvtSource=null;

function updateSseIndicator(){
  var badge=document.getElementById('sse-badge');
  var text=document.getElementById('sse-text');
  if(!badge||!text)return;
  badge.className='automation-badge';
  if(sseConnected){
    text.textContent='Live';
    badge.classList.add('live');
  }else{
    text.textContent='Reconnecting...';
    badge.classList.add('reconnecting');
  }
}

function handleSseEvent(event){
  try{
    var msg=JSON.parse(event.data);
    if(msg.type==='connected')return;
    // Refresh current page data
    if(currentPage==='overview')loadOverview();
    else if(currentPage==='leads')loadLeadsPage();
    else if(currentPage==='calls')loadCallsPage();
  }catch(e){}
}

function startSse(){
  var token=getToken();
  if(!token){return} // No auth, skip SSE
  if(activeEvtSource){activeEvtSource.close();activeEvtSource=null}
  // M2: get a short-lived single-use ticket via authenticated POST, then
  // open the stream with ?ticket= so the long-lived credential never
  // appears in the URL (access logs, browser history).
  var headers={};
  if(token.indexOf('.')>-1){headers['Authorization']='Bearer '+token}
  else{headers['Authorization']='Basic '+token}
  fetch('/dashboard/api/events/ticket',{method:'POST',headers:headers})
    .then(function(r){return r.json()})
    .then(function(data){
      if(!data.ticket){throw new Error('no ticket')}
      openSseStream(data.ticket);
    })
    .catch(function(){
      // Fallback to legacy ?token= (deprecated, still accepted server-side)
      openSseStream(null,token);
    });
}

function openSseStream(ticket,legacyToken){
  var url=ticket
    ? '/dashboard/api/events?ticket='+encodeURIComponent(ticket)
    : '/dashboard/api/events?token='+encodeURIComponent(legacyToken);
  var evtSource=new EventSource(url);
  activeEvtSource=evtSource;

  evtSource.onopen=function(){
    sseConnected=true;
    sseRetries=0;
    updateSseIndicator();
    if(fallbackTimer){clearInterval(fallbackTimer);fallbackTimer=null}
  };

  evtSource.onmessage=handleSseEvent;

  evtSource.onerror=function(){
    sseConnected=false;
    updateSseIndicator();
    evtSource.close();
    sseRetries++;
    if(sseRetries<=MAX_SSE_RETRIES){
      var delay=Math.min(1000*Math.pow(2,sseRetries-1),30000);
      setTimeout(startSse,delay);
    }else{
      // Permanent fallback
      var badge=document.getElementById('sse-badge');
      var text=document.getElementById('sse-text');
      text.textContent='Polling';
      badge.className='automation-badge polling';
      startPollingFallback();
    }
  };
}

function startPollingFallback(){
  if(fallbackTimer)return;
  fallbackTimer=setInterval(function(){
    if(currentPage==='overview')loadOverview();
    else if(currentPage==='leads')loadLeadsPage();
  },30000);
  updateSseIndicator();
}

/* Phase 25: Removed global-scope startSse() call - it is already invoked
   inside the init() IIFE below.  The duplicate caused two SSE connections
   on every page load. */

/* =========================================
   INTEGRATIONS PAGE (Phase 6F)
   ========================================= */
var integrationsData = [];

async function loadIntegrationsPage(){
  var grid = document.getElementById('integrations-grid');
  grid.innerHTML='<div class="skeleton skeleton-card" style="height:180px"></div><div class="skeleton skeleton-card" style="height:180px"></div>';
  loadMeetingProviderStatus();
  try{
    var data = await api('/dashboard/api/integrations');
    integrationsData = data.integrations || [];
    renderIntegrations(integrationsData);
    // After rendering, populate AI provider dropdown and load current status
    setTimeout(function(){
      if(typeof loadAIProvidersList==='function'){
        loadAIProvidersList().then(function(){ if(typeof loadAIStatus==='function') loadAIStatus(); });
      }else if(typeof loadAIStatus==='function'){
        loadAIStatus();
      }
      // Load Zoom credentials status from vault
      if(typeof loadZoomCredentialsStatus==='function'){
        loadZoomCredentialsStatus();
      }
      // Load Google credentials status from vault
      if(typeof loadGoogleCredentialsStatus==='function'){
        loadGoogleCredentialsStatus();
      }
      // Load field mapping configuration
      if(typeof loadFieldMappings==='function'){
        loadFieldMappings();
      }
    }, 150);
  }catch(e){
    grid.innerHTML='<div style="color:var(--danger);padding:16px">Failed to load integrations.</div>';
  }
}

function renderIntegrations(items){
  var grid = document.getElementById('integrations-grid');
  // Group existing integrations by provider
  var providers = {};
  (items || []).forEach(function(item){
    var p = item.provider || 'unknown';
    if(!providers[p])providers[p]=[];
    providers[p].push(item);
  });
  var html = '';
  var providerMeta = {
    google:{icon:'&#128225;',label:'Google Calendar & Gmail',desc:'Connect your Google account to manage meetings and send emails.'},
    openai:{icon:'&#129504;',label:'AI Assistant',desc:'Add your OpenAI API key for personalized email content.'},
    zoom:{icon:'&#128222;',label:'Zoom',desc:'Connect Zoom to create meeting links automatically.'}
  };
  // Always show all known providers, even if no integration records exist yet
  ['google','openai','zoom'].forEach(function(prov){
    var meta = providerMeta[prov] || {icon:'&#128279;',label:prov,desc:'Integration'};
    var provItems = providers[prov] || [];
    // Phase 6D BUG FIX: detect multi-org view (platform admin).  When items
    // span multiple organizations, a single aggregated "Connected" badge is
    // misleading - org A's connected Google integration does NOT mean org B
    // is connected.  Show per-org status instead of one aggregated badge.
    var orgIds = {};
    provItems.forEach(function(i){ if(i.organization_id) orgIds[i.organization_id] = true; });
    var orgCount = Object.keys(orgIds).length;
    var isMultiOrgView = orgCount > 1;
    var hasConnected = provItems.some(function(i){return i.status==='connected'});
    var hasPending = provItems.some(function(i){return i.status==='pending'});
    var hasError = provItems.some(function(i){return i.status==='error'});
    // In multi-org view, use per-org status - never show a blanket "Connected"
    // across all orgs.  In single-org view, aggregate normally.
    var statusClass, statusText;
    if(isMultiOrgView){
      statusClass = 'pending';
      statusText = orgCount + ' orgs';
    }else{
      statusClass = hasError?'error':(hasConnected?'connected':(hasPending?'pending':'disconnected'));
      statusText = hasError?'Error':(hasConnected?'Connected':(hasPending?'Configured':'Disconnected'));
    }
    html+='<div class="integration-card">'
      +'<div class="integration-card-header">'
      +'<div class="integration-icon '+prov+'">'+meta.icon+'</div>'
      +'<div><h4 style="font-size:14px;font-weight:600">'+esc(meta.label)+'</h4>'
      +'<p style="font-size:12px;color:var(--text-muted);margin:0">'+esc(meta.desc)+'</p></div>'
      +'<span class="integration-status-badge '+statusClass+'" style="margin-left:auto">'
      +'<span class="badge-dot"></span>'+statusText+'</span>'
      +'</div>';
    // Show individual integration types (skip for openai - handled separately)
    if(prov!=='openai'){
      provItems.forEach(function(item){
        var typeLabel = item.integration_type.replace(/_/g,' ');
        var connectedAt = item.connected_at ? timeAgo(item.connected_at) : '';
        var orgLabel = (isMultiOrgView && item.organization_name)
          ? ' <span style="color:var(--text-muted);font-size:11px">('+esc(item.organization_name)+')</span>'
          : '';
        html+='<div class="integration-meta">'
          +'<strong>'+esc(typeLabel)+'</strong> - '
          +esc(item.status)
          +orgLabel
          +(connectedAt ? ' &middot; '+esc(connectedAt) : '')
          +(item.last_error ? ' &middot; <span style="color:var(--danger)">'+esc(item.last_error)+'</span>' : '')
          +'</div>';
      });
    }
    // Action buttons
    html+='<div class="integration-actions">';
    if(prov==='google'){
      // Status display (always visible)
      html+='<div id="google-cred-status" style="width:100%;margin-top:12px;font-size:12px"></div>';
      if(hasConnected){
        // Connected: show Disconnect button
        html+='<div style="display:flex;gap:8px;align-items:center;margin-top:8px">';
        html+='<button class="btn btn-sm btn-danger" onclick="disconnectGoogle()">Disconnect</button>';
        html+='</div>';
      }else{
        // Disconnected: one-click connect - no credentials to paste.
        // The platform owns the Google OAuth client; the user just picks
        // their Google account in the popup.
        html+='<div style="display:flex;gap:8px;align-items:center;margin-top:8px">';
        html+='<button class="btn btn-sm btn-primary" onclick="connectGoogle()">Connect Google</button>';
        html+='</div>';
        html+='<div style="width:100%;margin-top:8px;font-size:11px;color:var(--text-muted)">';
        html+='Click Connect, choose your Google account, and approve access. No setup or keys needed.';
        html+='</div>';
      }
    }
    if(prov==='zoom'){
      // Status display (always visible)
      html+='<div id="zoom-cred-status" style="width:100%;margin-top:12px;font-size:12px"></div>';
      if(hasConnected){
        // Connected: show Disconnect button
        html+='<div style="display:flex;gap:8px;align-items:center;margin-top:8px">';
        html+='<button class="btn btn-sm btn-danger" onclick="disconnectZoom()">Disconnect</button>';
        html+='</div>';
      }else{
        // Disconnected: one-click connect - no credentials to paste.
        // The platform owns the Zoom Marketplace app; the user just
        // authorizes it on zoom.us.
        html+='<div style="display:flex;gap:8px;align-items:center;margin-top:8px">';
        html+='<button class="btn btn-sm btn-primary" onclick="connectZoom()">Connect Zoom</button>';
        html+='</div>';
        html+='<div style="width:100%;margin-top:8px;font-size:11px;color:var(--text-muted)">';
        html+='Click Connect, sign in to Zoom, and click Allow. No setup or keys needed.';
        html+='</div>';
      }
    }
    // AI provider: provider-aware credential form (only inside AI Assistant card)
    if(prov==='openai'){
      if(hasConnected){
        // Show compact configured state with Reconfigure button
        html+='<div id="ai-credential-summary" style="width:100%;padding:8px 0">';
        html+='<div style="font-size:13px;color:var(--accent);font-weight:600;margin-bottom:4px">AI provider configured</div>';
        html+='<div style="font-size:12px;color:var(--text-muted);margin-bottom:8px">Key is saved and active. Use Test Connection to verify, or Reconfigure to update.</div>';
        html+='<div style="display:flex;gap:8px;align-items:center">';
        html+='<button class="btn btn-sm" onclick="toggleAIForm(true)">Reconfigure</button>';
        html+='<button class="btn btn-sm" id="btn-test-ai" onclick="testAIConnection()" style="font-size:12px;padding:6px 10px">Test Connection</button>';
        html+='<button class="btn btn-sm btn-danger" onclick="disconnectAI()">Remove Key</button>';
        html+='<span id="ai-test-msg" style="font-size:12px"></span>';
        html+='</div></div>';
        // Hidden form for reconfiguration
        html+='<div id="ai-credential-form" style="width:100%;display:none">';
      }else{
        html+='<div id="ai-credential-form" style="width:100%">';
      }
      // Provider selector
      html+='<div class="setting-field" style="margin-bottom:12px">';
      html+='<label style="display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-bottom:6px">Provider</label>';
      html+='<select id="ai-provider-select" onchange="onAIProviderChange()" style="font-size:13px;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text);width:100%">';
      html+='</select>';
      html+='<div id="ai-provider-help" style="font-size:11px;color:var(--text-muted);margin-top:4px"></div>';
      html+='</div>';
      // Base URL input
      html+='<div class="setting-field" style="margin-bottom:12px">';
      html+='<label style="display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-bottom:6px">Base URL</label>';
      html+='<input type="text" id="ai-base-url" placeholder="https://api.openai.com/v1" style="width:100%;font-size:13px;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text)">';
      html+='</div>';
      // API Key input
      html+='<div class="setting-field" style="margin-bottom:12px">';
      html+='<label style="display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-bottom:6px">API Key</label>';
      html+='<div style="display:flex;gap:8px;align-items:center">';
      html+='<input type="password" id="ai-api-key" placeholder="sk-..." style="flex:1;font-size:13px;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text)">';
      html+='</div></div>';
      // Model input (free text with Load Models suggestion)
      html+='<div class="setting-field" style="margin-bottom:12px">';
      html+='<label style="display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-bottom:6px">Model</label>';
      html+='<div style="display:flex;gap:8px;align-items:center">';
      html+='<input type="text" id="ai-model" placeholder="e.g. gpt-4o" list="ai-model-list" style="flex:1;font-size:13px;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text)">';
      html+='<datalist id="ai-model-list"></datalist>';
      html+='<button class="btn btn-sm" id="btn-load-models" onclick="loadAIModels()" style="white-space:nowrap;font-size:12px;padding:6px 10px">Load Models</button>';
      html+='</div></div>';
      // Test Connection button
      html+='<div class="setting-field" style="margin-bottom:12px">';
      html+='<div style="display:flex;gap:8px;align-items:center">';
      html+='<button class="btn btn-sm" id="btn-test-ai" onclick="testAIConnection()" style="font-size:12px;padding:6px 10px">Test Connection</button>';
      html+='<span id="ai-test-msg" style="font-size:12px"></span>';
      html+='</div></div>';
      // Save / Disconnect buttons
      html+='<div style="display:flex;gap:8px;align-items:center">';
      html+='<button class="btn btn-sm btn-primary" onclick="saveAICredentials()">Save</button>';
      if(hasConnected){
        html+='<button class="btn btn-sm btn-danger" onclick="disconnectAI()">Remove Key</button>';
      }
      html+='<span id="ai-save-msg" style="font-size:12px"></span>';
      html+='</div>';
      html+='</div>';
    }
    html+='</div></div>';
  });
  grid.innerHTML = html;
}

async function connectGoogle(){
  try{
    var data = await api('/auth/google/start');
    if(data.authorization_url){
      window.location.href = data.authorization_url;
    }
  }catch(e){
    showToast('Failed to start Google OAuth: '+e.message,'error');
  }
}

async function disconnectGoogle(){
  if(!confirm('Disconnect Google? This will stop Calendar and Gmail integration.'))return;
  try{
    await api('/auth/google/disconnect',{method:'DELETE'});
    showToast('Google disconnected','success');
    loadIntegrationsPage();
  }catch(e){
    showToast('Failed to disconnect: '+e.message,'error');
  }
}

/* ---- Google Credential Management (Org-owned) ---- */

function toggleGoogleForm(show){
  var form = document.getElementById('google-credential-form');
  if(form) form.style.display = show ? '' : 'none';
}

async function loadGoogleCredentialsStatus(){
  try{
    var data = await api('/auth/google/status');
    var statusEl = document.getElementById('google-cred-status');
    if(statusEl){
      if(data.configured){
        var maskedId = data.masked_client_id || '••••••••';
        statusEl.innerHTML='<span style="color:var(--accent)">✓ Configured</span> - Client ID: '+esc(maskedId)
          +(data.redirect_uri ? ' | Redirect: '+esc(data.redirect_uri) : '');
        // Show connected status
        if(data.connected){
          statusEl.innerHTML+='<br><span style="color:var(--accent)">✓ Connected</span>'
            +(data.email ? ' - '+esc(data.email) : '')
            +(data.connected_at ? ' ('+esc(data.connected_at)+')' : '');
        }
      }else{
        statusEl.innerHTML='<span style="color:var(--text-muted)">Google sign-in is not set up on this server yet - the platform administrator must complete the one-time Google Cloud Console setup.</span>';
      }
    }
    // Pre-fill redirect URI if empty
    var redirectInput = document.getElementById('google-redirect-uri');
    if(redirectInput && !redirectInput.value && data.redirect_uri){
      redirectInput.value = data.redirect_uri;
    }
  }catch(e){}
}

async function saveGoogleCredentials(){
  var clientIdInput = document.getElementById('google-client-id');
  var clientSecretInput = document.getElementById('google-client-secret');
  var redirectInput = document.getElementById('google-redirect-uri');
  var msg = document.getElementById('google-save-msg');
  var clientId = clientIdInput ? clientIdInput.value.trim() : '';
  var clientSecret = clientSecretInput ? clientSecretInput.value.trim() : '';
  var redirectUri = redirectInput ? redirectInput.value.trim() : '';
  if(!clientId || !clientSecret || !redirectUri){
    if(msg) msg.innerHTML='<span style="color:var(--danger)">All fields are required</span>';
    return;
  }
  try{
    await api('/dashboard/api/integrations/google/google_oauth',{
      method:'POST',
      body:JSON.stringify({
        credentials:{
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri
        },
        metadata:{label:'Google OAuth2',source:'dashboard'}
      })
    });
    // Clear secret field (never store in browser)
    if(clientSecretInput) clientSecretInput.value = '';
    if(msg) msg.innerHTML='<span style="color:var(--accent)">Saved</span>';
    showToast('Google credentials saved','success');
    loadIntegrationsPage();
  }catch(e){
    if(msg) msg.innerHTML='<span style="color:var(--danger)">'+esc(e.message)+'</span>';
  }
}

async function removeGoogleCredentials(){
  if(!confirm('Remove Google credentials? You will need to reconfigure to reconnect.'))return;
  try{
    await api('/dashboard/api/integrations/google/google_oauth',{method:'DELETE'});
    showToast('Google credentials removed','success');
    loadIntegrationsPage();
  }catch(e){
    showToast('Failed to remove Google credentials: '+e.message,'error');
  }
}

/* ---- Zoom OAuth (Phase 4) ---- */

async function connectZoom(){
  try{
    var data = await api('/auth/zoom/start');
    if(data.authorization_url){
      window.location.href = data.authorization_url;
    }
  }catch(e){
    showToast('Failed to start Zoom OAuth: '+e.message,'error');
  }
}

async function disconnectZoom(){
  if(!confirm('Disconnect Zoom? This will stop Zoom meeting scheduling.'))return;
  try{
    await api('/auth/zoom/disconnect',{method:'DELETE'});
    showToast('Zoom disconnected','success');
    loadIntegrationsPage();
  }catch(e){
    showToast('Failed to disconnect Zoom: '+e.message,'error');
  }
}

/* ---- Zoom Credential Management (Org-owned) ---- */

function toggleZoomForm(show){
  var form = document.getElementById('zoom-credential-form');
  if(form) form.style.display = show ? '' : 'none';
}

async function loadZoomCredentialsStatus(){
  try{
    var data = await api('/auth/zoom/status');
    var statusEl = document.getElementById('zoom-cred-status');
    if(statusEl){
      if(data.configured){
        var maskedId = data.masked_client_id || '••••••••';
        statusEl.innerHTML='<span style="color:var(--accent)">✓ Configured</span> - Client ID: '+esc(maskedId)
          +(data.redirect_uri ? ' | Redirect: '+esc(data.redirect_uri) : '');
        // Show connected status
        if(data.connected){
          statusEl.innerHTML+='<br><span style="color:var(--accent)">✓ Connected</span>'
            +(data.account_email ? ' - '+esc(data.account_email) : '')
            +(data.connected_at ? ' ('+esc(data.connected_at)+')' : '');
        }
      }else{
        statusEl.innerHTML='<span style="color:var(--text-muted)">Zoom connect is not set up on this server yet - the platform administrator must complete the one-time Zoom Marketplace setup.</span>';
      }
    }
    // Pre-fill redirect URI if empty
    var redirectInput = document.getElementById('zoom-redirect-uri');
    if(redirectInput && !redirectInput.value && data.redirect_uri){
      redirectInput.value = data.redirect_uri;
    }
  }catch(e){}
}

async function saveZoomCredentials(){
  var clientIdInput = document.getElementById('zoom-client-id');
  var clientSecretInput = document.getElementById('zoom-client-secret');
  var redirectInput = document.getElementById('zoom-redirect-uri');
  var msg = document.getElementById('zoom-save-msg');
  var clientId = clientIdInput ? clientIdInput.value.trim() : '';
  var clientSecret = clientSecretInput ? clientSecretInput.value.trim() : '';
  var redirectUri = redirectInput ? redirectInput.value.trim() : '';
  if(!clientId || !clientSecret || !redirectUri){
    if(msg) msg.innerHTML='<span style="color:var(--danger)">All fields are required</span>';
    return;
  }
  try{
    await api('/dashboard/api/integrations/zoom/zoom_oauth',{
      method:'POST',
      body:JSON.stringify({
        credentials:{
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri
        },
        metadata:{label:'Zoom OAuth2',source:'dashboard'}
      })
    });
    // Clear secret field (never store in browser)
    if(clientSecretInput) clientSecretInput.value = '';
    if(msg) msg.innerHTML='<span style="color:var(--accent)">Saved</span>';
    showToast('Zoom credentials saved','success');
    loadIntegrationsPage();
  }catch(e){
    if(msg) msg.innerHTML='<span style="color:var(--danger)">'+esc(e.message)+'</span>';
  }
}

async function removeZoomCredentials(){
  if(!confirm('Remove Zoom credentials? You will need to reconfigure to reconnect.'))return;
  try{
    await api('/dashboard/api/integrations/zoom/zoom_oauth',{method:'DELETE'});
    showToast('Zoom credentials removed','success');
    loadIntegrationsPage();
  }catch(e){
    showToast('Failed to remove Zoom credentials: '+e.message,'error');
  }
}



/* ---- AI Credential Management (Phase 6B.7) ---- */

async function loadAIStatus(){
  try{
    var data = await api('/dashboard/api/ai/status');
    var msg = document.getElementById('ai-save-msg');
    // Select provider in dropdown
    var provSel = document.getElementById('ai-provider-select');
    if(provSel && data.provider_id){
      for(var i=0;i<provSel.options.length;i++){
        if(provSel.options[i].value===data.provider_id){
          provSel.selectedIndex = i;
          break;
        }
      }
      onAIProviderChange();
    }
    // Base URL
    var urlInput = document.getElementById('ai-base-url');
    if(urlInput){
      if(data.base_url) urlInput.value = data.base_url;
      else if(provSel){
        var opt = provSel.options[provSel.selectedIndex];
        if(opt && opt.dataset.baseUrl) urlInput.value = opt.dataset.baseUrl;
      }
    }
    if(data.configured){
      // Show masked key as placeholder
      var keyInput = document.getElementById('ai-api-key');
      if(keyInput && !keyInput.value){
        keyInput.placeholder = data.masked_key || '••••••••';
      }
      // Model input
      var modelInput = document.getElementById('ai-model');
      if(modelInput && data.model){
        modelInput.value = data.model;
      }
      if(msg) msg.innerHTML='<span style="color:var(--accent)">Configured</span>';
    }else{
      if(msg) msg.innerHTML='<span style="color:var(--text-muted)">Not configured</span>';
    }
  }catch(e){}
}

async function saveAICredentials(){
  var provSel = document.getElementById('ai-provider-select');
  var urlInput = document.getElementById('ai-base-url');
  var keyInput = document.getElementById('ai-api-key');
  var modelInput = document.getElementById('ai-model');
  var msg = document.getElementById('ai-save-msg');
  var providerId = (provSel && provSel.value) ? provSel.value : 'openai';
  var baseUrl = urlInput ? urlInput.value.trim() : '';
  var apiKey = keyInput ? keyInput.value.trim() : '';
  var model = modelInput ? modelInput.value.trim() : '';
  if(!apiKey){
    if(msg) msg.innerHTML='<span style="color:var(--danger)">Enter an API key</span>';
    return;
  }
  if(!providerId || providerId === 'undefined' || providerId === 'null'){
    providerId = 'openai';
  }
  try{
    var credentials = {api_key: apiKey, base_url: baseUrl};
    var metadata = {provider_id: providerId};
    if(model) metadata.model = model;
    await api('/dashboard/api/integrations/openai/ai_provider',{method:'POST',body:JSON.stringify({credentials:credentials,metadata:metadata})});
    if(keyInput) keyInput.value = '';
    if(msg) msg.innerHTML='<span style="color:var(--accent)">Saved</span>';
    showToast('AI credentials saved','success');
    loadIntegrationsPage();
  }catch(e){
    if(msg) msg.innerHTML='<span style="color:var(--danger)">'+esc(e.message)+'</span>';
  }
}

async function disconnectAI(){
  if(!confirm('Remove AI provider key? Email personalization will use the platform default.'))return;
  try{
    await api('/dashboard/api/integrations/openai/ai_provider',{method:'DELETE'});
    showToast('AI key removed','success');
    loadIntegrationsPage();
  }catch(e){
    showToast('Failed to remove AI key: '+e.message,'error');
  }
}

/* ---- AI Provider List (Phase 26) ---- */

async function loadAIProvidersList(){
  try{
    var data = await api('/dashboard/api/ai/providers');
    var sel = document.getElementById('ai-provider-select');
    if(!sel) return;
    sel.innerHTML = '';
    (data.providers||[]).forEach(function(p){
      var opt = document.createElement('option');
      opt.value = p.id || p.provider_id;
      opt.textContent = p.display_name;
      opt.dataset.baseUrl = p.default_base_url || '';
      opt.dataset.helpText = p.help_text || '';
      opt.dataset.adapterReady = p.adapter_ready ? '1' : '0';
      sel.appendChild(opt);
    });
  }catch(e){
    console.error('Failed to load AI providers:', e);
  }
}

function onAIProviderChange(){
  var sel = document.getElementById('ai-provider-select');
  var helpDiv = document.getElementById('ai-provider-help');
  var urlInput = document.getElementById('ai-base-url');
  if(!sel) return;
  var opt = sel.options[sel.selectedIndex];
  if(!opt) return;
  // Show provider-specific help text
  if(helpDiv){
    var help = opt.dataset.helpText || '';
    var adapterReady = opt.dataset.adapterReady === '1';
    var html = esc(help);
    if(!adapterReady){
      html += ' <span style="color:var(--warning)">⚠ Not yet supported - custom adapter required.</span>';
    }
    helpDiv.innerHTML = html;
  }
  // Pre-fill base URL if empty or from a known provider
  if(urlInput){
    var defaultUrl = opt.dataset.baseUrl || '';
    if(!urlInput.value || urlInput.value === 'https://api.openai.com/v1'){
      urlInput.value = defaultUrl;
    }
    urlInput.placeholder = defaultUrl || 'https://api.example.com/v1';
  }
}

function toggleAIForm(show){
  var form = document.getElementById('ai-credential-form');
  var summary = document.getElementById('ai-credential-summary');
  if(form) form.style.display = show ? '' : 'none';
  if(summary) summary.style.display = show ? 'none' : '';
}

async function loadAIModels(){
  var btn = document.getElementById('btn-load-models');
  var msg = document.getElementById('ai-test-msg');
  var modelInput = document.getElementById('ai-model');
  var urlInput = document.getElementById('ai-base-url');
  var keyInput = document.getElementById('ai-api-key');
  var baseUrl = urlInput ? urlInput.value.trim() : '';
  var apiKey = keyInput ? keyInput.value.trim() : '';
  if(!baseUrl || !apiKey){
    if(msg) msg.innerHTML='<span style="color:var(--danger)">Enter Base URL and API key first</span>';
    return;
  }
  btn.disabled = true;
  btn.textContent = 'Loading...';
  if(msg) msg.innerHTML='<span style="color:var(--text-muted)">Fetching models...</span>';
  try{
    var data = await api('/dashboard/api/ai/load-models',{method:'POST',body:JSON.stringify({base_url:baseUrl,api_key:apiKey})});
    var models = data.models || [];
    // Populate datalist
    var dl = document.getElementById('ai-model-list');
    if(dl){
      dl.innerHTML = '';
      models.forEach(function(m){
        var opt = document.createElement('option');
        opt.value = m.id || m;
        dl.appendChild(opt);
      });
    }
    if(msg) msg.innerHTML='<span style="color:var(--accent)">Found '+models.length+' models</span>';
  }catch(e){
    if(msg) msg.innerHTML='<span style="color:var(--danger)">'+esc(e.message)+'</span>';
  }finally{
    btn.disabled = false;
    btn.textContent = 'Load Models';
  }
}

async function testAIConnection(){
  var btn = document.getElementById('btn-test-ai');
  var msg = document.getElementById('ai-test-msg');
  var provSel = document.getElementById('ai-provider-select');
  var urlInput = document.getElementById('ai-base-url');
  var keyInput = document.getElementById('ai-api-key');
  var modelInput = document.getElementById('ai-model');
  var providerId = provSel ? provSel.value : 'openai';
  var baseUrl = urlInput ? urlInput.value.trim() : '';
  var apiKey = keyInput ? keyInput.value.trim() : '';
  var model = modelInput ? modelInput.value.trim() : '';
  btn.disabled = true;
  btn.textContent = 'Testing...';
  if(msg) msg.innerHTML='<span style="color:var(--text-muted)">Connecting...</span>';
  try{
    var body = {provider_id:providerId,base_url:baseUrl,api_key:apiKey};
    if(model) body.model = model;
    var data = await api('/dashboard/api/ai/test-connection',{method:'POST',body:JSON.stringify(body)});
    if(data.status === 'connected'){
      if(msg) msg.innerHTML='<span style="color:var(--accent)">✓ Connected</span>';
    }else if(data.status === 'configured'){
      // Provider configured but not yet fully testable (e.g. adapter pending)
      var infoMsg = data.message || data.error || 'Provider configured';
      if(msg) msg.innerHTML='<span style="color:var(--text-muted)">ℹ '+esc(infoMsg)+'</span>';
    }else{
      var errMsg = data.error || data.message || 'Unknown error';
      if(msg) msg.innerHTML='<span style="color:var(--danger)">✗ '+esc(errMsg)+'</span>';
    }
  }catch(e){
    if(msg) msg.innerHTML='<span style="color:var(--danger)">✗ '+esc(e.message)+'</span>';
  }finally{
    btn.disabled = false;
    btn.textContent = 'Test Connection';
  }
}

/* ---- Meeting Provider Status (Phase 4) ---- */

async function loadMeetingProviderStatus(){
  var el = document.getElementById('meeting-provider-status');
  if(!el)return;
  try{
    var data = await api('/dashboard/api/meeting-provider');
    var label = data.provider === 'zoom' ? 'Zoom' : 'Google Meet';
    var color = data.provider === 'zoom' ? '#2D8FEA' : '#4285F4';
    el.innerHTML = '<span style="display:inline-flex;align-items:center;gap:6px">'
      + '<span style="width:8px;height:8px;border-radius:50%;background:'+color+'"></span>'
      + '<span style="font-size:13px;color:var(--text-muted)">Active provider: <strong style="color:var(--text-primary)">'+esc(label)+'</strong></span>'
      + '</span>';
  }catch(e){
    el.innerHTML = '';
  }
}

/* =========================================
   FORM FIELD MAPPING (Phase 29)
   ========================================= */

var _fmCurrentMappings = [];
var _fmDefaultMapping = {};
var _fmValidFields = [];
var _fmHasCustom = false;

async function loadFieldMappings(){
  var section = document.getElementById('field-mapping-section');
  var status = document.getElementById('field-mapping-status');
  if(!section) return;
  section.style.display = '';
  try{
    var data = await api('/dashboard/api/form-field-mappings');
    _fmDefaultMapping = data.default_mapping || {};
    _fmValidFields = data.valid_fields || [];
    _fmHasCustom = data.is_custom || false;
    _fmCurrentMappings = (data.mappings || []).map(function(m){
      return {form_label:m.form_label, lead_field:m.lead_field, is_required:m.is_required, display_order:m.display_order};
    });
    _renderFieldMappingTable();
    _renderFieldMappingDefaults();
    // Show action buttons
    document.getElementById('btn-save-mapping').style.display = 'none';
    document.getElementById('btn-reset-mapping').style.display = _fmHasCustom ? '' : 'none';
    document.getElementById('field-mapping-add-row').style.display = '';
    if(_fmHasCustom){
      status.innerHTML = '<span style="color:var(--accent)">&#10003; Custom mapping active</span> (' + _fmCurrentMappings.length + ' fields)';
    }else{
      status.innerHTML = '<span style="color:var(--text-muted)">Using default mapping (' + _fmCurrentMappings.length + ' fields). Add a custom mapping to customize.</span>';
    }
  }catch(e){
    status.innerHTML = '<span style="color:var(--danger)">Failed to load field mappings: ' + esc(e.message) + '</span>';
  }
}

function _renderFieldMappingTable(){
  var tbody = document.getElementById('field-mapping-tbody');
  if(!tbody) return;
  if(!_fmCurrentMappings.length){
    tbody.innerHTML = '<tr><td colspan="5" style="padding:16px;text-align:center;color:var(--text-muted)">No field mappings configured. Click + Add Field to start.</td></tr>';
    return;
  }
  var html = '';
  _fmCurrentMappings.forEach(function(m, idx){
    var fieldOptions = '<option value="">- Select -</option>';
    _fmValidFields.forEach(function(f){
      var sel = f === m.lead_field ? ' selected' : '';
      fieldOptions += '<option value="'+esc(f)+'"'+sel+'>'+esc(f)+'</option>';
    });
    html += '<tr style="border-bottom:1px solid var(--border-light)" id="fm-row-'+idx+'">'
      + '<td style="padding:8px 12px;color:var(--text-muted);font-size:12px;vertical-align:middle">'
      + '<button class="btn-xs" onclick="fmMoveUp('+idx+')" title="Move up" style="cursor:pointer;margin-right:2px">&#9650;</button>'
      + '<button class="btn-xs" onclick="fmMoveDown('+idx+')" title="Move down" style="cursor:pointer">&#9660;</button>'
      + '</td>'
      + '<td style="padding:8px 12px">'
      + '<input type="text" value="'+esc(m.form_label)+'" class="fm-label-input" data-idx="'+idx+'" '
      + 'style="width:100%;font-size:13px;padding:6px 10px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text)" '
      + 'onchange="fmLabelChanged('+idx+',this.value)" placeholder="e.g. Full Name">'
      + '</td>'
      + '<td style="padding:8px 12px">'
      + '<select class="fm-field-select" data-idx="'+idx+'" '
      + 'style="width:100%;font-size:13px;padding:6px 10px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text)" '
      + 'onchange="fmFieldChanged('+idx+',this.value)">'
      + fieldOptions
      + '</select>'
      + '</td>'
      + '<td style="padding:8px 12px;text-align:center">'
      + '<input type="checkbox"'+(m.is_required ? ' checked' : '')+' onchange="fmRequiredChanged('+idx+',this.checked)" '
      + 'style="width:16px;height:16px;cursor:pointer">'
      + '</td>'
      + '<td style="padding:8px 12px;text-align:center">'
      + '<button class="btn-xs btn-danger" onclick="fmRemoveRow('+idx+')" title="Remove">&#10005;</button>'
      + '</td>'
      + '</tr>';
  });
  tbody.innerHTML = html;
}

function _renderFieldMappingDefaults(){
  var el = document.getElementById('field-mapping-defaults-list');
  var wrap = document.getElementById('field-mapping-defaults');
  if(!el || !wrap) return;
  wrap.style.display = '';
  var html = '<table style="width:100%;border-collapse:collapse;font-size:12px">';
  Object.keys(_fmDefaultMapping).forEach(function(label){
    html += '<tr style="border-bottom:1px solid var(--border-light)">'
      + '<td style="padding:4px 8px;color:var(--text-secondary)">'+esc(label)+'</td>'
      + '<td style="padding:4px 8px;color:var(--accent)">&#8594; '+esc(_fmDefaultMapping[label])+'</td>'
      + '</tr>';
  });
  html += '</table>';
  el.innerHTML = html;
}

function fmLabelChanged(idx, val){
  _fmCurrentMappings[idx].form_label = val;
  _fmMarkDirty();
}
function fmFieldChanged(idx, val){
  _fmCurrentMappings[idx].lead_field = val;
  _fmMarkDirty();
}
function fmRequiredChanged(idx, val){
  _fmCurrentMappings[idx].is_required = val;
  _fmMarkDirty();
}
function fmMoveUp(idx){
  if(idx === 0) return;
  var tmp = _fmCurrentMappings[idx];
  _fmCurrentMappings[idx] = _fmCurrentMappings[idx-1];
  _fmCurrentMappings[idx-1] = tmp;
  _reorderMappings();
  _renderFieldMappingTable();
  _fmMarkDirty();
}
function fmMoveDown(idx){
  if(idx >= _fmCurrentMappings.length - 1) return;
  var tmp = _fmCurrentMappings[idx];
  _fmCurrentMappings[idx] = _fmCurrentMappings[idx+1];
  _fmCurrentMappings[idx+1] = tmp;
  _reorderMappings();
  _renderFieldMappingTable();
  _fmMarkDirty();
}
function fmRemoveRow(idx){
  _fmCurrentMappings.splice(idx, 1);
  _reorderMappings();
  _renderFieldMappingTable();
  _fmMarkDirty();
}
function addFieldMappingRow(){
  _fmCurrentMappings.push({form_label:'', lead_field:'', is_required:false, display_order:_fmCurrentMappings.length});
  _renderFieldMappingTable();
  _fmMarkDirty();
  // Focus the new label input
  var inputs = document.querySelectorAll('.fm-label-input');
  if(inputs.length) inputs[inputs.length-1].focus();
}
function _reorderMappings(){
  _fmCurrentMappings.forEach(function(m, i){ m.display_order = i; });
}
function _fmMarkDirty(){
  document.getElementById('btn-save-mapping').style.display = '';
}

async function saveFieldMappings(){
  var btn = document.getElementById('btn-save-mapping');
  var status = document.getElementById('field-mapping-status');
  btn.disabled = true;
  btn.textContent = 'Saving...';
  try{
    // Validate client-side: no empty labels or fields
    var errors = [];
    _fmCurrentMappings.forEach(function(m, i){
      if(!m.form_label.trim()) errors.push('Row ' + (i+1) + ': Form label is empty');
      if(!m.lead_field) errors.push('Row ' + (i+1) + ': Lead field not selected');
    });
    // Check for duplicate form labels
    var labels = {};
    _fmCurrentMappings.forEach(function(m, i){
      var key = m.form_label.trim().toLowerCase();
      if(labels[key] !== undefined){
        errors.push('Duplicate form label "' + m.form_label + '" (rows ' + (labels[key]+1) + ' and ' + (i+1) + ')');
      }
      labels[key] = i;
    });
    // Check for duplicate lead fields
    var fields = {};
    _fmCurrentMappings.forEach(function(m, i){
      if(m.lead_field && fields[m.lead_field] !== undefined){
        errors.push('Duplicate lead field "' + m.lead_field + '" (rows ' + (fields[m.lead_field]+1) + ' and ' + (i+1) + ')');
      }
      if(m.lead_field) fields[m.lead_field] = i;
    });
    if(errors.length){
      status.innerHTML = '<span style="color:var(--danger)">&#10007; ' + errors.map(esc).join('<br>') + '</span>';
      btn.disabled = false;
      btn.textContent = 'Save';
      return;
    }
    var payload = {mappings: _fmCurrentMappings.map(function(m, i){
      return {form_label:m.form_label.trim(), lead_field:m.lead_field, is_required:m.is_required, display_order:i};
    })};
    await api('/dashboard/api/form-field-mappings', {method:'PUT', body:JSON.stringify(payload)});
    _fmHasCustom = payload.mappings.length > 0;
    status.innerHTML = '<span style="color:var(--accent)">&#10003; Mapping saved successfully</span>';
    btn.style.display = 'none';
    document.getElementById('btn-reset-mapping').style.display = _fmHasCustom ? '' : 'none';
    showToast('Field mapping saved','success');
  }catch(e){
    var msg = e.message || 'Unknown error';
    status.innerHTML = '<span style="color:var(--danger)">&#10007; ' + esc(msg) + '</span>';
  }finally{
    btn.disabled = false;
    btn.textContent = 'Save';
  }
}

async function resetFieldMappings(){
  var status = document.getElementById('field-mapping-status');
  if(!confirm('Remove custom field mapping and revert to default? The existing default mapping will apply to new form submissions.')) return;
  try{
    await api('/dashboard/api/form-field-mappings', {method:'DELETE'});
    _fmHasCustom = false;
    status.innerHTML = '<span style="color:var(--text-muted)">Mapping reset to default.</span>';
    document.getElementById('btn-reset-mapping').style.display = 'none';
    document.getElementById('btn-save-mapping').style.display = 'none';
    showToast('Field mapping reset to default','success');
    // Reload to reflect the change
    loadFieldMappings();
  }catch(e){
    status.innerHTML = '<span style="color:var(--danger)">&#10007; ' + esc(e.message) + '</span>';
  }
}

/* =========================================
   WEBHOOK PAGE (Phase 6F)
   ========================================= */

async function loadWebhookPage(){
  try{
    var data = await api('/organization/webhook/config');
    document.getElementById('webhook-url-text').textContent = data.webhook_url || 'Not configured';
    document.getElementById('webhook-secret-display').textContent = data.secret_masked || 'No secret configured';
  }catch(e){
    document.getElementById('webhook-url-text').textContent = 'Failed to load';
    document.getElementById('webhook-secret-display').textContent = 'Failed to load';
  }
}

function copyWebhookUrl(){
  var text = document.getElementById('webhook-url-text').textContent;
  if(text && text !== 'Loading...' && text !== 'Not configured'){
    navigator.clipboard.writeText(text).then(function(){
      showToast('Webhook URL copied','success');
    });
  }
}

async function rotateWebhookSecret(){
  if(!confirm('Rotate webhook secret? The Apps Script will need the new secret.'))return;
  var btn = document.getElementById('btn-rotate-secret');
  btn.disabled=true;
  try{
    var data = await api('/organization/webhook/rotate-secret',{method:'POST'});
    if(data.webhook_secret){
      document.getElementById('secret-rotation-warning').style.display='';
      document.getElementById('rotated-secret-value').textContent = data.webhook_secret;
      document.getElementById('webhook-secret-display').textContent = data.secret_masked || 'Rotated';
      showToast('Secret rotated - copy it now!','success');
    }
  }catch(e){
    showToast('Failed to rotate secret: '+e.message,'error');
  }finally{
    btn.disabled=false;
  }
}

function copyRotatedSecret(){
  var text = document.getElementById('rotated-secret-value').textContent;
  if(text){
    navigator.clipboard.writeText(text).then(function(){
      showToast('Secret copied','success');
    });
  }
}

async function testWebhook(){
  var btn = document.getElementById('btn-test-webhook');
  var result = document.getElementById('webhook-test-result');
  btn.disabled=true;
  result.textContent='Testing...';
  result.style.color='var(--text-muted)';
  try{
    var data = await api('/organization/webhook/test',{method:'POST'});
    if(data.valid){
      result.style.color='var(--accent)';
      result.textContent='Configuration valid.';
    }else{
      result.style.color='var(--warning)';
      result.textContent='Issues: '+(data.message||'No details available');
    }
  }catch(e){
    result.style.color='var(--danger)';
    result.textContent='Test failed: '+e.message;
  }finally{
    btn.disabled=false;
  }
}

/* =========================================
   USER MANAGEMENT (Phase 1)
   ========================================= */
var _umCurrentUserId=null;
var _umCurrentUserRole='member';

async function loadUsers(){
  var el=document.getElementById('um-user-list');
  var totalEl=document.getElementById('um-total');
  el.innerHTML='<div class="skeleton skeleton-row w80" style="height:44px;margin-bottom:8px"></div><div class="skeleton skeleton-row w60" style="height:44px;margin-bottom:8px"></div><div class="skeleton skeleton-row w80" style="height:44px"></div>';
  try{
    var data=await api('/organization/users');
    var users=data.users||[];
    var me;
    try{me=JSON.parse(localStorage.getItem('jwt_user')||'null')}catch(x){me=null}
    _umCurrentUserId=me?me.id:null;
    totalEl.textContent=users.length+(users.length===1?' member':' members');
    if(users.length===0){
      el.innerHTML='<div class="empty-state" style="padding:32px"><div class="icon">&#128101;</div><h3>No team members</h3><p>Users in your organization will appear here.</p></div>';
      return;
    }
    var roleOrder={owner:0,admin:1,member:2};
    users.sort(function(a,b){return(roleOrder[a.role]||9)-(roleOrder[b.role]||9)});
    var html='<div class="table-wrap"><table class="um-table"><thead><tr>'
      +'<th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th>'
      +'</tr></thead><tbody>';
    for(var i=0;i<users.length;i++){
      var u=users[i];
      var isSelf=u.id===_umCurrentUserId;
      html+='<tr>'
        +'<td class="um-name-cell">'+esc(u.name||'-')+(isSelf?'<span class="um-self-tag">You</span>':'')+'</td>'
        +'<td class="um-email-cell">'+esc(u.email)+'</td>'
        +'<td><span class="um-badge '+esc(u.role)+'">'+esc(u.role.charAt(0).toUpperCase()+u.role.slice(1))+'</span></td>'
        var statusCls=(u.status==='disabled')?'disabled':'active';
        var statusLabel=(u.status==='disabled')?'Disabled':'Active';
        +'<td><span class="um-badge '+esc(statusCls)+'">'+esc(statusLabel)+'</span></td>'
        +'<td>';
      var isAdmin=(_umCurrentUserRole==='owner'||_umCurrentUserRole==='admin');
      if(isAdmin){
        html+='<button class="btn btn-sm btn-ghost" onclick=\'showEditUserModal("'+esc(u.id)+'","'+esc(u.name||'')+'","'+esc(u.email)+'","'+esc(u.role)+'","'+esc(u.status||'active')+'")\'>Edit</button>';
      }
      if(_umCurrentUserRole==='owner'&&!isSelf){
        html+='<button class="btn btn-sm btn-ghost" style="color:var(--danger)" onclick=\'showDeleteUserModal("'+esc(u.id)+'","'+esc(u.name||u.email)+'","'+esc(u.role)+'")\'>Delete</button>';
      }
      html+='</td></tr>';
    }
    html+='</tbody></table></div>';
    el.innerHTML=html;
  }catch(e){
    el.innerHTML='<div style="color:var(--danger);padding:16px">Failed to load team members. <button class="btn btn-sm" onclick="loadUsers()">Retry</button></div>';
    showToast('Failed to load users','error');
  }
}

function _closeModal(){var m=document.getElementById('um-modal-overlay');if(m)m.remove()}

function showCreateUserModal(){
  _closeModal();
  var ov=document.createElement('div');
  ov.id='um-modal-overlay';
  ov.className='um-modal-overlay';
  ov.onclick=function(e){if(e.target===ov)_closeModal()};
  var roleOptions='<option value="member">Member</option><option value="admin">Admin</option>';
  if(_umCurrentUserRole==='owner')roleOptions+='<option value="owner">Owner</option>';
  ov.innerHTML='<div class="um-modal">'
    +'<div class="um-modal-header"><h3>Add Team Member</h3><button class="um-modal-close" onclick="_closeModal()">&times;</button></div>'
    +'<div class="um-modal-body">'
    +'<div class="um-form-field"><label for="um-c-name">Name</label><input type="text" id="um-c-name" placeholder="Full name"></div>'
    +'<div class="um-form-field"><label for="um-c-email">Email *</label><input type="email" id="um-c-email" placeholder="user@example.com">'
    +'<div class="um-field-error" id="um-c-email-err"></div></div>'
    +'<div class="um-form-field"><label for="um-c-password">Password *</label><input type="password" id="um-c-password" placeholder="Min 8 characters">'
    +'<div class="um-field-error" id="um-c-password-err"></div></div>'
    +'<div class="um-form-field"><label for="um-c-role">Role</label>'
    +'<select id="um-c-role">'+roleOptions+'</select></div>'
    +'<div class="um-form-actions">'
    +'<button class="btn" onclick="_closeModal()">Cancel</button>'
    +'<button class="btn btn-primary" id="um-c-submit" onclick="createUser()">Add User</button>'
    +'</div></div></div>';
  document.body.appendChild(ov);
}

async function createUser(){
  var name=document.getElementById('um-c-name').value.trim();
  var email=document.getElementById('um-c-email').value.trim();
  var password=document.getElementById('um-c-password').value;
  var role=document.getElementById('um-c-role').value;
  var btn=document.getElementById('um-c-submit');
  var ok=true;
  function fe(id,v){var e=document.getElementById(id);e.textContent=v;e.classList.add('visible')}
  function fc(id){var e=document.getElementById(id);e.textContent='';e.classList.remove('visible')}
  var emailRe=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if(!email){fe('um-c-email-err','Email is required');ok=false}else if(!emailRe.test(email)){fe('um-c-email-err','Please enter a valid email address');ok=false}else fc('um-c-email-err');
  if(!password){fe('um-c-password-err','Password is required');ok=false}else if(password.length<8){fe('um-c-password-err','Password must be at least 8 characters');ok=false}else fc('um-c-password-err');
  if(!ok)return;
  btn.disabled=true;btn.textContent='Creating...';
  try{
    await api('/organization/users',{method:'POST',body:JSON.stringify({email:email,name:name||null,password:password,role:role})});
    showToast('User created successfully','success');
    _closeModal();
    loadUsers();
  }catch(e){showToast('Failed to create user: '+e.message,'error');}finally{btn.disabled=false;btn.textContent='Add User'}
}

function showEditUserModal(userId,userName,userEmail,currentRole,currentStatus){
  _closeModal();
  currentStatus=currentStatus||'active';
  var ov=document.createElement('div');
  ov.id='um-modal-overlay';
  ov.className='um-modal-overlay';
  ov.onclick=function(e){if(e.target===ov)_closeModal()};
  var roleOptions='';
  var roles=['member','admin','owner'];
  for(var i=0;i<roles.length;i++){
    var r=roles[i];
    if(r==='owner'&&_umCurrentUserRole!=='owner')continue;
    roleOptions+='<option value="'+r+'"'+(r===currentRole?' selected':'')+'>'+r.charAt(0).toUpperCase()+r.slice(1)+'</option>';
  }
  var statusOptions='<option value="active"'+(currentStatus==='active'?' selected':'')+'>Active</option>'
    +'<option value="disabled"'+(currentStatus==='disabled'?' selected':'')+'>Disabled</option>';
  ov.innerHTML='<div class="um-modal">'
    +'<div class="um-modal-header"><h3>Edit User</h3><button class="um-modal-close" onclick="_closeModal()">&times;</button></div>'
    +'<div class="um-modal-body">'
    +'<div class="um-form-field"><label>Email</label><input type="email" value="'+esc(userEmail)+'" disabled style="opacity:0.6;cursor:not-allowed"></div>'
    +'<div class="um-form-field"><label for="um-e-name">Name</label><input type="text" id="um-e-name" value="'+esc(userName)+'" placeholder="Full name"></div>'
    +'<div class="um-form-field"><label for="um-e-role">Role</label><select id="um-e-role">'+roleOptions+'</select></div>'
    +'<div class="um-form-field"><label for="um-e-status">Status</label><select id="um-e-status">'+statusOptions+'</select></div>'
    +'<div class="um-form-actions">'
    +'<button class="btn" onclick="_closeModal()">Cancel</button>'
    +'<button class="btn btn-primary" id="um-e-submit" onclick="updateUser(\''+esc(userId)+'\')">Save Changes</button>'
    +'</div></div></div>';
  document.body.appendChild(ov);
}

async function updateUser(userId){
  var name=document.getElementById('um-e-name').value.trim();
  var role=document.getElementById('um-e-role').value;
  var status=document.getElementById('um-e-status').value;
  var btn=document.getElementById('um-e-submit');
  btn.disabled=true;btn.textContent='Saving...';
  try{
    await api('/organization/users/'+userId,{method:'PATCH',body:JSON.stringify({name:name||null,role:role,status:status})});
    showToast('User updated','success');
    _closeModal();
    loadUsers();
  }catch(e){showToast('Failed to update user: '+e.message,'error');}finally{btn.disabled=false;btn.textContent='Save Changes'}
}

function showDeleteUserModal(userId,userName,currentRole){
  _closeModal();
  var ov=document.createElement('div');
  ov.id='um-modal-overlay';
  ov.className='um-modal-overlay';
  ov.onclick=function(e){if(e.target===ov)_closeModal()};
  var warn='';
  if(currentRole==='owner'){
    warn='<div class="um-self-warning">&#9888; This user has the <strong>Owner</strong> role. If they are the last owner, deletion will be blocked by the server.</div>';
  }
  ov.innerHTML='<div class="um-modal">'
    +'<div class="um-modal-header"><h3>Remove Team Member</h3><button class="um-modal-close" onclick="_closeModal()">&times;</button></div>'
    +'<div class="um-modal-body">'
    +'<div class="um-delete-warning">Are you sure you want to remove <strong>'+esc(userName)+'</strong> from your organization?</div>'
    +'<div class="um-delete-info">This action cannot be undone. The user will lose access to all organization resources.</div>'
    +warn
    +'<div class="um-form-actions">'
    +'<button class="btn" onclick="_closeModal()">Cancel</button>'
    +'<button class="btn btn-danger" id="um-d-submit" onclick="deleteUser(\''+esc(userId)+'\')">Remove User</button>'
    +'</div></div></div>';
  document.body.appendChild(ov);
}

async function deleteUser(userId){
  var btn=document.getElementById('um-d-submit');
  btn.disabled=true;btn.textContent='Removing...';
  try{
    await api('/organization/users/'+userId,{method:'DELETE'});
    showToast('User removed','success');
    _closeModal();
    loadUsers();
  }catch(e){showToast('Failed to remove user: '+e.message,'error');}finally{btn.disabled=false;btn.textContent='Remove User'}
}

/* =========================================
   ORG SETTINGS PAGE (Phase 6F)
   ========================================= */

async function loadOrgSettingsPage(){
  try{
    var data = await api('/organization/settings');
    document.getElementById('os-name').value = data.name || '';
    document.getElementById('os-display-name').value = data.display_name || '';
    document.getElementById('os-timezone').value = data.timezone || 'America/Chicago';
    document.getElementById('os-sender-name').value = data.sender_name || '';
    document.getElementById('os-tagline').value = data.tagline || '';
    if(data.brand_color){
      document.getElementById('os-brand-color').value = data.brand_color;
      document.getElementById('os-brand-color-hint').textContent = data.brand_color;
    }
    if(data.meeting_duration_minutes)document.getElementById('os-meeting-duration').value = data.meeting_duration_minutes;
    if(data.rsvp_poll_interval_minutes)document.getElementById('os-rsvp-interval').value = data.rsvp_poll_interval_minutes;
    // Update sidebar org name
    if(data.name)document.getElementById('sidebar-org-name').textContent = data.name;
    if(data.tagline)document.getElementById('sidebar-org-tagline').textContent = data.tagline;
    loadUsers();
  }catch(e){
    showToast('Failed to load settings','error');
  }
}

// Color input sync
document.getElementById('os-brand-color').addEventListener('input',function(e){
  document.getElementById('os-brand-color-hint').textContent = e.target.value;
});

async function saveOrgSettings(){
  var msg = document.getElementById('os-save-msg');
  var btn = document.getElementById('os-save-btn');
  btn.disabled=true;
  msg.textContent='';
  try{
    var payload = {
      name: document.getElementById('os-name').value || null,
      display_name: document.getElementById('os-display-name').value || null,
      timezone: document.getElementById('os-timezone').value || null,
      sender_name: document.getElementById('os-sender-name').value || null,
      tagline: document.getElementById('os-tagline').value || null,
      brand_color: document.getElementById('os-brand-color').value || null,
      meeting_duration_minutes: parseInt(document.getElementById('os-meeting-duration').value,10) || null,
      rsvp_poll_interval_minutes: parseInt(document.getElementById('os-rsvp-interval').value,10) || null
    };
    var data = await api('/organization/settings',{method:'PATCH',body:JSON.stringify(payload)});
    msg.style.color='var(--accent)';
    msg.textContent='Settings saved successfully';
    showToast('Organization settings saved','success');
    // Update sidebar
    if(data.name)document.getElementById('sidebar-org-name').textContent = data.name;
    if(data.tagline)document.getElementById('sidebar-org-tagline').textContent = data.tagline;
    setTimeout(function(){msg.textContent=''},3000);
  }catch(e){
    msg.style.color='var(--danger)';
    msg.textContent='Save failed: '+e.message;
    showToast('Failed to save settings','error');
  }finally{
    btn.disabled=false;
  }
}

/* =========================================
   ACTIVITY / AUDIT LOG (Phase 6F)
   ========================================= */
var auditOffset=0;
var auditLimit=50;
var auditTotal=0;

async function loadAuditLog(){
  var list = document.getElementById('audit-log-list');
  var typeFilter = document.getElementById('audit-type-filter').value;
  var url = '/dashboard/api/audit-log?limit='+auditLimit+'&offset='+auditOffset;
  if(typeFilter)url += '&event_type='+encodeURIComponent(typeFilter);
  try{
    var data = await api(url);
    auditTotal = data.total || 0;
    renderAuditLog(data.events || []);
    document.getElementById('audit-count').textContent = 'Showing '+(auditOffset+1)+'-'+Math.min(auditOffset+auditLimit,auditTotal)+' of '+auditTotal;
    document.getElementById('audit-prev').disabled = auditOffset <= 0;
    document.getElementById('audit-next').disabled = (auditOffset+auditLimit) >= auditTotal;
  }catch(e){
    list.innerHTML='<div style="color:var(--danger);padding:16px">Failed to load activity log.</div>';
  }
}

function auditNextPage(){auditOffset+=auditLimit;loadAuditLog()}
function auditPrevPage(){auditOffset=Math.max(0,auditOffset-auditLimit);loadAuditLog()}

document.getElementById('audit-type-filter').addEventListener('change',function(){auditOffset=0;loadAuditLog()});

var AUDIT_DOT_MAP={
  'form_submitted':'green','calendar_created':'blue','email_sent':'green',
  'reminder_sent':'amber','rsvp_changed':'amber','error':'red',
  'webhook_auth_failed':'red','pipeline.completed':'green','pipeline.failed':'red',
  'email_generated':'blue','declined':'red',
  'call_updated':'blue','call_cancelled':'red','call_rescheduled':'amber',
  'manual_lead_created':'green','lead_updated':'blue','lead_status_changed':'amber'
};

function renderAuditLog(events){
  var list = document.getElementById('audit-log-list');
  if(!events || events.length===0){
    list.innerHTML='<div class="empty-state" style="padding:32px"><div class="icon">&#128221;</div><h3>No activity recorded</h3><p>Events will appear here as leads move through your pipeline.</p></div>';
    return;
  }
  var html='<div class="audit-list">';
  events.forEach(function(ev){
    var dot = AUDIT_DOT_MAP[ev.event_type] || 'gray';
    var payload = ev.payload || {};
    var detail = '';
    if(ev.event_type==='form_submitted' && payload.name)detail=payload.name;
    else if(ev.event_type==='webhook_auth_failed')detail=(payload.reason||'')+(payload.org_slug?' ('+payload.org_slug+')':'');
    else if(ev.event_type==='error'||ev.event_type==='pipeline.failed')detail=payload.error||payload.detail||'';
    else if(ev.event_type==='email_sent')detail=payload.to||'';
    html+='<div class="audit-item">'
      +'<div class="audit-dot '+dot+'"></div>'
      +'<div><div class="audit-text"><strong>'+esc(ev.event_type)+'</strong>'+(detail?' - '+esc(detail):'')+'</div>'
      +'<div class="audit-time">'+esc(timeAgo(ev.created_at))+'</div></div>'
      +'</div>';
  });
  html+='</div>';
  list.innerHTML = html;
}

/* =========================================
   INIT (Phase 6F + OAuth callback redirect)
   ========================================= */
(function init(){
  var token = getToken();
  if(token){
    loadCurrentUser().then(function(user){
      if(user){
        showApp();
        // Phase 4: honor URL hash for OAuth callback redirects
        var hash = (window.location.hash||'').replace('#','');
        // OAuth callback uses ?tab=integrations query param
        var params = new URLSearchParams(window.location.search);
        var tabParam = params.get('tab');
        var startPage = (tabParam && pageTitles[tabParam]) ? tabParam
                      : (hash && pageTitles[hash]) ? hash : 'overview';
        // Clean URL to remove ?tab= param after reading
        if(tabParam || hash){
          window.history.replaceState({}, '', window.location.pathname);
        }
        navigateTo(startPage);
        startSse();
        // Show OAuth result toast if redirected from callback
        var oauthResult = localStorage.getItem('oauth_result');
        if(oauthResult){
          localStorage.removeItem('oauth_result');
          var parts = oauthResult.split(':');
          var type = parts[0] || 'success';
          var msg = parts.slice(1).join(':') || 'OAuth flow completed';
          showToast(msg, type);
        }
        // Phase 7: Check onboarding status on login
        setTimeout(function(){checkOnboarding()}, 1000);
      }
    });
  }else{
    showLoginPage();
  }
})();
</script>
</body>
</html>"""


@router.get("", response_class=HTMLResponse)
def dashboard_page(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(_security),
    bearer: HTTPAuthorizationCredentials = Depends(_bearer),
) -> HTMLResponse:
    """Serve the single-page dashboard (static HTML + vanilla JS).

    Phase 6F: The HTML page is served without server-side auth gate.
    Client-side JavaScript checks for a JWT token in localStorage and
    shows the login page if not authenticated. API calls are authenticated
    via the Bearer token attached by the JS api() helper.
    """
    resp = HTMLResponse(content=_DASHBOARD_HTML)
    # Prevent browser from caching stale dashboard HTML (performance fix)
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp
