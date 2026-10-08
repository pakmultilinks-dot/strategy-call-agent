"""Follow-up management API (Phase 23).

Endpoints:
  GET    /followups              — List follow-ups (with filtering)
  POST   /followups              — Create a manual follow-up
  PATCH  /followups/{id}         — Update follow-up
  GET    /followups/overdue      — Get overdue follow-ups
  POST   /followups/{id}/complete — Mark follow-up as completed
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.dashboard import AuthContext, _auth_context, _require_owner_or_admin
from app.database import get_db
from app.models import FollowUp, FollowUpStatus, Lead
from app.models_multi_tenant import Organization, User
from app.schemas import (
    CreateFollowUpRequest,
    UpdateFollowUpRequest,
)

logger = logging.getLogger("strategy-call-agent.followup_router")

router = APIRouter(prefix="/followups", tags=["followups"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_followup_org_scoped(
    db: Session, followup_id: uuid.UUID, org_id: uuid.UUID
) -> FollowUp:
    """Fetch a follow-up by ID, scoped to the user's organization.

    Raises 404 if the follow-up doesn't exist or doesn't belong to the org.
    """
    followup = (
        db.query(FollowUp)
        .filter(FollowUp.id == followup_id, FollowUp.organization_id == org_id)
        .first()
    )
    if followup is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Follow-up not found",
        )
    return followup


def _followup_to_dict(followup: FollowUp) -> dict:
    """Serialize a FollowUp ORM instance to a JSON-safe dict."""
    return {
        "id": str(followup.id),
        "organization_id": str(followup.organization_id),
        "lead_id": str(followup.lead_id),
        "created_by": str(followup.created_by),
        "assigned_to": str(followup.assigned_to) if followup.assigned_to else None,
        "title": followup.title,
        "notes": followup.notes,
        "priority": followup.priority.value if followup.priority else None,
        "status": followup.status.value if followup.status else None,
        "due_at": followup.due_at.isoformat() if followup.due_at else None,
        "completed_at": followup.completed_at.isoformat() if followup.completed_at else None,
        "completed_by": str(followup.completed_by) if followup.completed_by else None,
        "cancelled_at": followup.cancelled_at.isoformat() if followup.cancelled_at else None,
        "cancelled_by": str(followup.cancelled_by) if followup.cancelled_by else None,
        "created_at": followup.created_at.isoformat() if followup.created_at else None,
        "updated_at": followup.updated_at.isoformat() if followup.updated_at else None,
    }





@router.get("")
def list_followups(
    status_filter: str | None = Query(None, alias="status", description="Filter by status"),
    priority: str | None = Query(None, description="Filter by priority"),
    lead_id: uuid.UUID | None = Query(None, description="Filter by lead ID"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """List follow-ups for the authenticated organization.

    Supports filtering by status, priority, and lead_id with
    paginated results.
    """
    if ctx.org_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization context required",
        )

    query = db.query(FollowUp).filter(FollowUp.organization_id == ctx.org_id)

    if status_filter:
        try:
            status_val = FollowUpStatus(status_filter)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid status: {status_filter}. "
                       f"Valid values: {[s.value for s in FollowUpStatus]}",
            )
        query = query.filter(FollowUp.status == status_val)

    if priority:
        query = query.filter(FollowUp.priority == priority)

    if lead_id:
        query = query.filter(FollowUp.lead_id == lead_id)

    # Total count before pagination
    total = query.count()

    # Paginate
    followups = (
        query.order_by(FollowUp.created_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "followups": [_followup_to_dict(f) for f in followups],
    }


@router.post("", status_code=status.HTTP_201_CREATED)
def create_followup(
    body: CreateFollowUpRequest,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Create a manual follow-up task.

    Owner and admin roles can create follow-ups. Members are rejected
    with 403. The lead must belong to the same organization.
    """
    _require_owner_or_admin(ctx)

    if ctx.org_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization context required",
        )

    # Validate assigned_to user exists in same org if provided
    # (Validate inputs before business-rule checks for clearer error messages)
    if body.assigned_to is not None:
        assignee = db.get(User, body.assigned_to)
        if assignee is None or assignee.organization_id != ctx.org_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="assigned_to user not found",
            )

    # Validate lead exists and belongs to this org
    lead = (
        db.query(Lead)
        .filter(Lead.id == body.lead_id, Lead.organization_id == ctx.org_id)
        .first()
    )
    if lead is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Lead not found",
        )

    # Phase 7 Part 4 — Guard: reject follow-up creation for terminal leads
    from app.services.followup_cancellation import is_terminal_lead_status
    if is_terminal_lead_status(lead.status):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot create follow-up: lead is in terminal status '{lead.status.value}'",
        )

    followup = FollowUp(
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
    db.add(followup)
    db.commit()
    db.refresh(followup)

    logger.info(
        "Manual follow-up created: id=%s title=%s lead=%s org=%s by=%s",
        followup.id,
        followup.title,
        followup.lead_id,
        ctx.org_id,
        ctx.user_id,
    )

    return _followup_to_dict(followup)


@router.patch("/{followup_id}")
def update_followup(
    followup_id: uuid.UUID,
    body: UpdateFollowUpRequest,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Update a follow-up's details (partial update).

    Owner and admin roles can update follow-ups. Only the fields
    provided in the request body will be updated.
    """
    _require_owner_or_admin(ctx)

    if ctx.org_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization context required",
        )

    followup = _get_followup_org_scoped(db, followup_id, ctx.org_id)

    # Apply partial updates
    update_data = body.model_dump(exclude_unset=True)

    # Validate assigned_to if being updated
    if "assigned_to" in update_data and update_data["assigned_to"] is not None:
        assignee = db.get(User, update_data["assigned_to"])
        if assignee is None or assignee.organization_id != ctx.org_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="assigned_to user not found",
            )

    for field, value in update_data.items():
        setattr(followup, field, value)

    db.commit()
    db.refresh(followup)

    logger.info(
        "Follow-up updated: id=%s fields=%s org=%s by=%s",
        followup.id,
        list(update_data.keys()),
        ctx.org_id,
        ctx.user_id,
    )

    return _followup_to_dict(followup)


@router.get("/overdue")
def list_overdue_followups(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """List overdue follow-ups for the organization.

    Returns follow-ups where due_at is in the past and status is
    PENDING or IN_PROGRESS, scoped to the authenticated org.
    """
    if ctx.org_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization context required",
        )

    now = datetime.now(timezone.utc)

    followups = (
        db.query(FollowUp)
        .filter(
            FollowUp.organization_id == ctx.org_id,
            FollowUp.due_at < now,
            FollowUp.status.in_([FollowUpStatus.PENDING, FollowUpStatus.IN_PROGRESS]),
        )
        .order_by(FollowUp.due_at.asc())
        .all()
    )

    return {
        "total": len(followups),
        "followups": [_followup_to_dict(f) for f in followups],
    }


@router.post("/{followup_id}/complete")
def complete_followup(
    followup_id: uuid.UUID,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Mark a follow-up as completed.

    Sets status to COMPLETED and records the completion timestamp
    and the completing user. Only follow-ups in PENDING or
    IN_PROGRESS status can be completed.
    """
    if ctx.org_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization context required",
        )

    followup = _get_followup_org_scoped(db, followup_id, ctx.org_id)

    if followup.status not in (FollowUpStatus.PENDING, FollowUpStatus.IN_PROGRESS):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot complete follow-up with status '{followup.status.value}'. "
                   f"Must be 'pending' or 'in_progress'.",
        )

    now = datetime.now(timezone.utc)
    followup.status = FollowUpStatus.COMPLETED
    followup.completed_at = now
    followup.completed_by = ctx.user_id

    db.commit()
    db.refresh(followup)

    logger.info(
        "Follow-up completed: id=%s org=%s by=%s",
        followup.id,
        ctx.org_id,
        ctx.user_id,
    )

    return _followup_to_dict(followup)
