"""CRM search, filtering, and dashboard stats service (Phase 23).

Provides server-side lead search with full-text queries, advanced
filtering, sorting, pagination, and dashboard summary statistics.

All queries use SQLAlchemy 2.0 ``select()`` style and are scoped to
a single organization for multi-tenant data isolation.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models import CallOutcome, Lead, LeadStatus

logger = logging.getLogger("strategy-call-agent.crm")


# ---------------------------------------------------------------------------
# Search & Filtering
# ---------------------------------------------------------------------------


def _build_search_conditions(query: str) -> list:
    """Build LIKE conditions for full-text search across key lead fields.

    Searches name, email, company_address, phone_number, direct_number,
    and courses using case-insensitive LIKE with wildcards.

    Args:
        query: The search string (will be wrapped in ``%query%``).

    Returns:
        A list of SQLAlchemy ``or_``-compatible condition clauses.
    """
    pattern = f"%{query}%"
    return [
        Lead.name.ilike(pattern),
        Lead.email.ilike(pattern),
        Lead.company_address.ilike(pattern),
        Lead.phone_number.ilike(pattern),
        Lead.direct_number.ilike(pattern),
        Lead.courses.ilike(pattern),
    ]


def _apply_filters(
    stmt: Any,
    filters: dict[str, Any],
) -> Any:
    """Apply filter conditions to a SQLAlchemy select statement.

    Supported filter keys:
        - ``status``: Single ``LeadStatus`` value.
        - ``status_in``: List of ``LeadStatus`` values.
        - ``assigned_to``: UUID of the assigned team member.
        - ``call_outcome``: Single ``CallOutcome`` value.
        - ``created_after``: ``datetime`` — ``created_at >=``.
        - ``created_before``: ``datetime`` — ``created_at <=``.
        - ``appt_after``: ``datetime`` — ``appt_datetime_utc >=``.
        - ``appt_before``: ``datetime`` — ``appt_datetime_utc <=``.
        - ``has_calendar_event``: ``bool`` — calendar_event_id IS [NOT] NULL.

    Args:
        stmt: A SQLAlchemy ``select()`` statement.
        filters: Dictionary of filter parameters.

    Returns:
        The statement with all applicable WHERE clauses applied.
    """
    if filters.get("status"):
        stmt = stmt.where(Lead.status == filters["status"])

    if filters.get("status_in"):
        statuses = filters["status_in"]
        stmt = stmt.where(Lead.status.in_(statuses))

    if filters.get("assigned_to"):
        stmt = stmt.where(Lead.assigned_to == filters["assigned_to"])

    if filters.get("call_outcome"):
        stmt = stmt.where(Lead.call_outcome == filters["call_outcome"])

    if filters.get("created_after"):
        stmt = stmt.where(Lead.created_at >= filters["created_after"])

    if filters.get("created_before"):
        stmt = stmt.where(Lead.created_at <= filters["created_before"])

    if filters.get("appt_after"):
        stmt = stmt.where(Lead.appt_datetime_utc >= filters["appt_after"])

    if filters.get("appt_before"):
        stmt = stmt.where(Lead.appt_datetime_utc <= filters["appt_before"])

    if "has_calendar_event" in filters:
        if filters["has_calendar_event"]:
            stmt = stmt.where(Lead.calendar_event_id.isnot(None))
        else:
            stmt = stmt.where(Lead.calendar_event_id.is_(None))

    return stmt


# Allowed sort columns — prevents arbitrary column injection.
_SORTABLE_COLUMNS: dict[str, Any] = {
    "created_at": Lead.created_at,
    "updated_at": Lead.updated_at,
    "appt_datetime_utc": Lead.appt_datetime_utc,
    "name": Lead.name,
    "email": Lead.email,
    "status": Lead.status,
    "call_outcome": Lead.call_outcome,
    "reschedule_count": Lead.reschedule_count,
    "call_duration_minutes": Lead.call_duration_minutes,
}


def search_leads(
    db: Session,
    org_id: uuid.UUID,
    search_query: str | None = None,
    filters: dict[str, Any] | None = None,
    sort_by: str = "created_at",
    sort_dir: str = "desc",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Search and filter leads within an organization.

    Performs server-side full-text search across name, email, company,
    phone, and courses fields.  Supports advanced date/status/assignment
    filters, configurable sorting, and offset-based pagination.

    Args:
        db: Active database session.
        org_id: Organization UUID for tenant scoping.
        search_query: Optional free-text search string.
        filters: Optional dict of filter parameters (see ``_apply_filters``).
        sort_by: Column name to sort by (default ``"created_at"``).
        sort_dir: ``"asc"`` or ``"desc"`` (default ``"desc"``).
        limit: Page size, clamped to 1-1000 (default 50).
        offset: Number of rows to skip (default 0).

    Returns:
        Dict with keys ``total``, ``limit``, ``offset``, and ``leads``
        (list of dicts matching the ``LeadOut`` schema shape).
    """
    filters = filters or {}

    # Clamp pagination parameters.
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)

    # --- Base query: always scoped to the organization. ---
    base = select(Lead).where(Lead.organization_id == org_id)

    # --- Full-text search ---
    if search_query and search_query.strip():
        conditions = _build_search_conditions(search_query.strip())
        base = base.where(or_(*conditions))

    # --- Apply filters ---
    base = _apply_filters(base, filters)

    # --- Total count (before sorting/pagination) ---
    count_stmt = select(func.count()).select_from(base.subquery())
    total: int = db.execute(count_stmt).scalar_one()

    # --- Sorting ---
    sort_column = _SORTABLE_COLUMNS.get(sort_by, Lead.created_at)
    if sort_dir.lower() == "asc":
        base = base.order_by(sort_column.asc())
    else:
        base = base.order_by(sort_column.desc())

    # --- Pagination ---
    base = base.limit(limit).offset(offset)

    # --- Execute ---
    rows = db.execute(base).scalars().all()

    leads = [
        {
            "id": str(lead.id),
            "organization_id": str(lead.organization_id) if lead.organization_id else None,
            "interested": lead.interested,
            "name": lead.name,
            "company_address": lead.company_address,
            "phone_number": lead.phone_number,
            "direct_number": lead.direct_number,
            "courses": lead.courses,
            "email": lead.email,
            "scheduled_date": lead.scheduled_date,
            "caller_name": lead.caller_name,
            "appt_datetime_raw": lead.appt_datetime_raw,
            "appt_datetime_utc": lead.appt_datetime_utc.isoformat() if lead.appt_datetime_utc else None,
            "customer_timezone": lead.customer_timezone,
            "status": lead.status.value if lead.status else None,
            "calendar_event_id": lead.calendar_event_id,
            "reminder_sent_at": lead.reminder_sent_at.isoformat() if lead.reminder_sent_at else None,
            "call_outcome": lead.call_outcome.value if lead.call_outcome else None,
            "call_notes": lead.call_notes,
            "call_duration_minutes": lead.call_duration_minutes,
            "cancelled_at": lead.cancelled_at.isoformat() if lead.cancelled_at else None,
            "reschedule_count": lead.reschedule_count,
            "assigned_to": str(lead.assigned_to) if lead.assigned_to else None,
            "created_at": lead.created_at.isoformat() if lead.created_at else None,
            "updated_at": lead.updated_at.isoformat() if lead.updated_at else None,
        }
        for lead in rows
    ]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "leads": leads,
    }


# ---------------------------------------------------------------------------
# Dashboard Statistics
# ---------------------------------------------------------------------------


def get_crm_stats(db: Session, org_id: uuid.UUID) -> dict[str, Any]:
    """Compute dashboard summary statistics for an organization.

    Returns aggregate counts and breakdowns useful for a CRM dashboard:
        - ``total_leads``: All leads in the organization.
        - ``leads_this_month``: Leads created since the 1st of the
          current month (UTC).
        - ``leads_by_status``: Dict mapping status value → count.
        - ``leads_by_assigned_to``: Dict mapping user UUID string → count
          (includes ``"unassigned"`` for NULL assignments).
        - ``upcoming_calls``: Leads with an appointment in the next 7 days
          whose status is not terminal (completed, declined, not_interested,
          error).
        - ``overdue_calls``: Leads whose appointment is in the past but
          the call was not completed.
        - ``conversion_rate``: Percentage of leads with ``COMPLETED`` status
          (rounded to 1 decimal place).

    Args:
        db: Active database session.
        org_id: Organization UUID for tenant scoping.

    Returns:
        Dict of dashboard statistics.
    """
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    next_week = now + timedelta(days=7)

    terminal_statuses = {
        LeadStatus.COMPLETED,
        LeadStatus.DECLINED,
        LeadStatus.NOT_INTERESTED,
        LeadStatus.ERROR,
    }

    # --- Total leads ---
    total_stmt = (
        select(func.count())
        .select_from(Lead)
        .where(Lead.organization_id == org_id)
    )
    total_leads: int = db.execute(total_stmt).scalar_one()

    # --- Leads this month ---
    month_stmt = (
        select(func.count())
        .select_from(Lead)
        .where(
            Lead.organization_id == org_id,
            Lead.created_at >= month_start,
        )
    )
    leads_this_month: int = db.execute(month_stmt).scalar_one()

    # --- Leads by status ---
    status_stmt = (
        select(Lead.status, func.count())
        .where(Lead.organization_id == org_id)
        .group_by(Lead.status)
    )
    status_rows = db.execute(status_stmt).all()
    leads_by_status: dict[str, int] = {
        (row[0].value if row[0] else "unknown"): row[1] for row in status_rows
    }

    # --- Leads by assigned_to ---
    assigned_stmt = (
        select(Lead.assigned_to, func.count())
        .where(Lead.organization_id == org_id)
        .group_by(Lead.assigned_to)
    )
    assigned_rows = db.execute(assigned_stmt).all()
    leads_by_assigned_to: dict[str, int] = {
        (str(row[0]) if row[0] else "unassigned"): row[1] for row in assigned_rows
    }

    # --- Upcoming calls (next 7 days, non-terminal) ---
    upcoming_stmt = (
        select(func.count())
        .select_from(Lead)
        .where(
            Lead.organization_id == org_id,
            Lead.appt_datetime_utc >= now,
            Lead.appt_datetime_utc <= next_week,
            Lead.status.notin_(terminal_statuses),
        )
    )
    upcoming_calls: int = db.execute(upcoming_stmt).scalar_one()

    # --- Overdue calls (past appt, not completed) ---
    completed_values = {CallOutcome.CONNECTED, CallOutcome.COMPLETED}
    overdue_stmt = (
        select(func.count())
        .select_from(Lead)
        .where(
            Lead.organization_id == org_id,
            Lead.appt_datetime_utc < now,
            Lead.appt_datetime_utc.isnot(None),
            Lead.status.notin_(terminal_statuses),
        )
    )
    # Also exclude leads that had a completed/connected call outcome.
    overdue_stmt = overdue_stmt.where(
        or_(
            Lead.call_outcome.is_(None),
            Lead.call_outcome.notin_(completed_values),
        )
    )
    overdue_calls: int = db.execute(overdue_stmt).scalar_one()

    # --- Conversion rate ---
    completed_stmt = (
        select(func.count())
        .select_from(Lead)
        .where(
            Lead.organization_id == org_id,
            Lead.status == LeadStatus.COMPLETED,
        )
    )
    completed_count: int = db.execute(completed_stmt).scalar_one()
    conversion_rate: float = (
        round((completed_count / total_leads) * 100, 1) if total_leads > 0 else 0.0
    )

    return {
        "total_leads": total_leads,
        "leads_this_month": leads_this_month,
        "leads_by_status": leads_by_status,
        "leads_by_assigned_to": leads_by_assigned_to,
        "upcoming_calls": upcoming_calls,
        "overdue_calls": overdue_calls,
        "conversion_rate": conversion_rate,
    }
