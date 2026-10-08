"""CRM Search, Lead Scoring, and Dashboard Stats API (Phase 23).

Endpoints:
  GET  /crm/search              — Full-text search + advanced filtering
  GET  /crm/stats               — Dashboard summary statistics
  GET  /crm/leads/{id}/score    — Get AI score for a lead
  GET  /crm/leads/{id}/summary  — Get AI-generated lead summary
  GET  /crm/leads/{id}/call-summary — Get AI call summary
  GET  /crm/leads/{id}/next-action  — Get next best action recommendation
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.config import settings
from app.dashboard import AuthContext, _auth_context, _lead_row
from app.database import get_db
from app.models import Lead
from app.models_multi_tenant import Organization
from app.services.ai_scoring_service import (
    generate_call_summary,
    generate_lead_summary,
    get_next_best_action,
    score_lead,
)
from app.services.crm_service import get_crm_stats, search_leads
from app.services.org_context import OrganizationContext
from app.services.rate_limit import check_rate_limit

logger = logging.getLogger("strategy-call-agent.crm_router")

router = APIRouter(prefix="/crm", tags=["crm"])


def _get_lead_org_scoped(
    db: Session, lead_id: uuid.UUID, org_id: uuid.UUID | None
) -> Lead:
    """Fetch a lead by ID, scoped to the user's organization.

    Raises 404 if the lead doesn't exist or doesn't belong to the org.
    Platform admins (org_id=None) can access any lead.
    """
    stmt = db.query(Lead).filter(Lead.id == lead_id)
    if org_id is not None:
        stmt = stmt.filter(Lead.organization_id == org_id)
    lead = stmt.first()
    if lead is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Lead not found",
        )
    return lead


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/search")
def search_leads_endpoint(
    q: str | None = Query(None, description="Full-text search query"),
    status_filter: str | None = Query(
        None, alias="status", description="Single status filter"
    ),
    status_in: str | None = Query(
        None, description="Comma-separated list of statuses"
    ),
    assigned_to: str | None = Query(
        None, description="UUID of assigned team member"
    ),
    call_outcome: str | None = Query(None, description="Call outcome filter"),
    created_after: str | None = Query(None, description="ISO datetime"),
    created_before: str | None = Query(None, description="ISO datetime"),
    appt_after: str | None = Query(None, description="ISO datetime"),
    appt_before: str | None = Query(None, description="ISO datetime"),
    has_calendar_event: bool | None = Query(
        None, description="Filter by presence of calendar event"
    ),
    sort_by: str = Query("created_at", description="Sort column"),
    sort_dir: str = Query("desc", description="Sort direction: asc or desc"),
    limit: int = Query(50, ge=1, le=1000, description="Page size"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Full-text search with advanced filtering across CRM leads.

    Returns paginated results with total count, scoped to the
    authenticated user's organization.
    """
    if ctx.org_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization context required",
        )

    # Parse filters
    filters: dict = {}

    if status_filter:
        filters["status"] = status_filter

    if status_in:
        filters["status_in"] = [s.strip() for s in status_in.split(",") if s.strip()]

    if assigned_to:
        try:
            filters["assigned_to"] = uuid.UUID(assigned_to)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid assigned_to UUID",
            )

    if call_outcome:
        filters["call_outcome"] = call_outcome

    # Parse datetime filters
    for param_name, filter_key in [
        ("created_after", "created_after"),
        ("created_before", "created_before"),
        ("appt_after", "appt_after"),
        ("appt_before", "appt_before"),
    ]:
        raw = locals()[param_name]
        if raw:
            try:
                filters[filter_key] = datetime.fromisoformat(raw)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid ISO datetime for {param_name}: {raw}",
                )

    if has_calendar_event is not None:
        filters["has_calendar_event"] = has_calendar_event

    result = search_leads(
        db=db,
        org_id=ctx.org_id,
        search_query=q,
        filters=filters,
        sort_by=sort_by,
        sort_dir=sort_dir,
        limit=limit,
        offset=offset,
    )

    # Enrich leads with _lead_row formatting for consistent API output
    tz = ZoneInfo(settings.business_timezone)
    enriched_leads = []
    for lead_data in result["leads"]:
        lead_obj = db.query(Lead).filter(Lead.id == uuid.UUID(lead_data["id"])).first()
        if lead_obj:
            enriched_leads.append(_lead_row(lead_obj, tz))
        else:
            enriched_leads.append(lead_data)

    return {
        "total": result["total"],
        "limit": result["limit"],
        "offset": result["offset"],
        "leads": enriched_leads,
    }


@router.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Dashboard summary statistics for the authenticated organization.

    Returns aggregate counts: total leads, leads by status, upcoming
    calls, overdue calls, conversion rate, etc.
    """
    if ctx.org_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization context required",
        )

    return get_crm_stats(db, ctx.org_id)


@router.get("/leads/{lead_id}/score")
def get_lead_score(
    lead_id: uuid.UUID,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Get AI-powered quality score (1–100) for a lead.

    Returns the numeric score, scoring factors breakdown, and a
    human-readable recommendation.

    Rate-limited to 30 calls/min per org.
    """
    if ctx.org_id:
        check_rate_limit(
            key=f"ai_score:{ctx.org_id}", max_attempts=30,
            window_seconds=60, label="AI scoring",
        )
    lead = _get_lead_org_scoped(db, lead_id, ctx.org_id)
    return score_lead(db, lead)


@router.get("/leads/{lead_id}/summary")
def get_lead_summary(
    lead_id: uuid.UUID,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Get AI-generated 2–3 sentence summary of a lead.

    Uses the lead's data to produce a concise overview for quick
    CRM review.

    Rate-limited to 30 calls/min per org.
    """
    if ctx.org_id:
        check_rate_limit(
            key=f"ai_score:{ctx.org_id}", max_attempts=30,
            window_seconds=60, label="AI summary",
        )
    lead = _get_lead_org_scoped(db, lead_id, ctx.org_id)
    org_ctx = OrganizationContext.from_id(lead.organization_id) if lead.organization_id else None
    return generate_lead_summary(db, lead, org_context=org_ctx)


@router.get("/leads/{lead_id}/call-summary")
def get_lead_call_summary(
    lead_id: uuid.UUID,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Get AI-generated structured call summary for a lead.

    Requires that call notes exist on the lead (call must have been
    recorded). Returns 400 if no call notes are available.

    Rate-limited to 30 calls/min per org.
    """
    if ctx.org_id:
        check_rate_limit(
            key=f"ai_score:{ctx.org_id}", max_attempts=30,
            window_seconds=60, label="AI call summary",
        )
    lead = _get_lead_org_scoped(db, lead_id, ctx.org_id)

    if not lead.call_notes or not lead.call_notes.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No call notes available. Record call notes before generating a call summary.",
        )

    org_ctx = OrganizationContext.from_id(lead.organization_id) if lead.organization_id else None
    return generate_call_summary(db, lead, org_context=org_ctx)


@router.get("/leads/{lead_id}/next-action")
def get_lead_next_action(
    lead_id: uuid.UUID,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Get rule-based next best action recommendation for a lead.

    Returns a recommendation dict with action type, description,
    and priority.

    Phase 28 P1-B: Rate-limited to 30 calls/min per org.
    """
    if ctx.org_id:
        check_rate_limit(
            key=f"ai_score:{ctx.org_id}", max_attempts=30,
            window_seconds=60, label="AI next-action",
        )
    lead = _get_lead_org_scoped(db, lead_id, ctx.org_id)
    return get_next_best_action(db, lead)
