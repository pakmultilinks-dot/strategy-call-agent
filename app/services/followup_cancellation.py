"""Auto-cancellation cascade and lead-status guard for follow-ups (Phase 7 Parts 3 & 4).

When a lead enters a terminal state (COMPLETED, DECLINED, NOT_INTERESTED, ERROR),
all pending and in-progress follow-ups for that lead are automatically cancelled.
This prevents the scheduler from contacting leads that are no longer eligible
for outreach.

Additionally, before any new follow-up is created or an email is sent, the lead's
current status is verified.  If the lead is terminal the operation is rejected,
preventing unnecessary database writes and accidental outreach.

Design:
  - cancel_pending_followups_for_lead() is the single entry point for the cascade.
  - is_lead_terminal_for_followup() is the shared guard for creation and execution.
  - Idempotent: calling multiple times produces the same final state.
  - Preserves COMPLETED and already-CANCELLED follow-ups.
  - Tenant-safe: every query filters by organization_id.
  - Integrates with existing audit event patterns (EventLog + SSE).
  - Does NOT commit — callers control the transaction boundary.

Integration:
  - dashboard.py: update_lead_status(), cancel_call(), create_follow_up()
  - rsvp_poller.py: _process_lead() (RSVP decline)
  - main.py: _mark_completed_meetings() (scheduler)
  - followup_router.py: create_followup()
  - auto_followup_service.py: create_post_call_followups()
  - followup_email_sender.py: _process_one_followup() (re-check after claim)
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.events import publish_event
from app.models import (
    EventLog,
    FollowUp,
    FollowUpStatus,
    Lead,
    LeadStatus,
)

logger = logging.getLogger("strategy-call-agent.followup-cancellation")


# ---------------------------------------------------------------------------
# Terminal Status Set
# ---------------------------------------------------------------------------

TERMINAL_LEAD_STATUSES: set[LeadStatus] = {
    LeadStatus.COMPLETED,
    LeadStatus.DECLINED,
    LeadStatus.NOT_INTERESTED,
    LeadStatus.ERROR,
}


def is_terminal_lead_status(status: LeadStatus | str) -> bool:
    """Check whether a lead status is terminal.

    Terminal leads should not receive follow-up emails or outreach.
    """
    if isinstance(status, str):
        try:
            status = LeadStatus(status)
        except ValueError:
            return False
    return status in TERMINAL_LEAD_STATUSES


# ---------------------------------------------------------------------------
# Lead Status Guard (Phase 7 Part 4)
# ---------------------------------------------------------------------------


class FollowUpCreationBlocked(Exception):
    """Raised when a follow-up cannot be created because the lead is terminal.

    Attributes:
        lead_id: UUID of the terminal lead.
        lead_status: The terminal status value.
    """

    def __init__(self, lead_id: uuid.UUID, lead_status: LeadStatus):
        self.lead_id = lead_id
        self.lead_status = lead_status
        super().__init__(
            f"Cannot create follow-up: lead {lead_id} is in terminal status "
            f"'{lead_status.value}'"
        )


def is_lead_terminal_for_followup(
    db: Session,
    lead_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> bool:
    """Re-fetch the lead and check if it is in a terminal status.

    This is the shared guard used by all follow-up creation paths and the
    execution engine.  It re-fetches the lead from the database to get the
    *current persisted status*, avoiding stale in-memory state.

    Behaviour:
      - Returns ``True`` if the lead exists and is terminal.
      - Returns ``False`` if the lead exists and is non-terminal.
      - Returns ``False`` if the lead is not found (caller should handle
        the not-found case separately).
      - Filters by organization_id for tenant isolation.

    Usage::

        # HTTP creation endpoints:
        if is_lead_terminal_for_followup(db, lead_id, org_id):
            raise HTTPException(status_code=409, detail="Lead is in terminal status")

        # Auto follow-up service:
        if is_lead_terminal_for_followup(db, lead.id, org_id):
            return []

        # Execution engine (after claim, before send):
        if is_lead_terminal_for_followup(db, lead_id, org_id):
            # revert status, skip send
            ...
    """
    lead = db.query(Lead).filter(
        Lead.id == lead_id,
        Lead.organization_id == organization_id,
    ).first()

    if lead is None:
        return False

    return is_terminal_lead_status(lead.status)


# ---------------------------------------------------------------------------
# Cancellation Cascade
# ---------------------------------------------------------------------------


def cancel_pending_followups_for_lead(
    db: Session,
    lead_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> int:
    """Cancel all pending and in-progress follow-ups for a lead.

    This is the centralized auto-cancellation cascade entry point.
    Called when a lead enters a terminal state to prevent the scheduler
    from contacting a lead that is no longer eligible for outreach.

    Behaviour:
      - Only cancels follow-ups in PENDING or IN_PROGRESS status.
      - COMPLETED follow-ups are preserved (already sent/executed).
      - Already-CANCELLED follow-ups are untouched (idempotent).
      - All queries are scoped by organization_id (tenant isolation).
      - Does NOT commit — caller controls the transaction boundary.
      - Publishes an SSE event and logs an audit event on success.

    Args:
        db: Active database session (caller manages commit/rollback).
        lead_id: UUID of the lead that became terminal.
        organization_id: UUID of the owning organization (tenant scope).

    Returns:
        Number of follow-ups that were newly cancelled (0 if none were eligible).
    """
    # Query only follow-ups that are still eligible for cancellation.
    # COMPLETED follow-ups have already been sent — preserve them.
    # Already-CANCELLED follow-ups are left alone (idempotent).
    followups = (
        db.query(FollowUp)
        .filter(
            FollowUp.lead_id == lead_id,
            FollowUp.organization_id == organization_id,
            FollowUp.status.in_([
                FollowUpStatus.PENDING,
                FollowUpStatus.IN_PROGRESS,
            ]),
        )
        .all()
    )

    if not followups:
        return 0

    now_utc = datetime.now(timezone.utc)
    cancelled_ids: list[str] = []

    for fu in followups:
        fu.status = FollowUpStatus.CANCELLED
        fu.cancelled_at = now_utc
        fu.updated_at = now_utc
        cancelled_ids.append(str(fu.id))

    db.flush()  # Ensure UPDATEs are written before audit event

    logger.info(
        "Auto-cancellation cascade: cancelled %d follow-ups for lead %s org=%s",
        len(cancelled_ids),
        lead_id,
        organization_id,
    )

    # Audit event — logged by the cancellation cascade for observability.
    # Uses the lead_id of the terminal lead and includes cancelled IDs.
    try:
        db.add(
            EventLog(
                lead_id=lead_id,
                event_type="followups_auto_cancelled",
                payload=json.dumps({
                    "cancelled_count": len(cancelled_ids),
                    "cancelled_ids": cancelled_ids,
                }),
                organization_id=organization_id,
            )
        )
    except Exception:
        logger.exception(
            "Failed to log auto-cancellation audit event for lead %s", lead_id
        )

    # Real-time SSE notification for dashboard visibility
    try:
        publish_event(
            "followups.cancelled",
            {
                "lead_id": str(lead_id),
                "cancelled_count": len(cancelled_ids),
                "cancelled_ids": cancelled_ids,
            },
            organization_id=organization_id,
        )
    except Exception:
        logger.debug(
            "Failed to publish auto-cancellation SSE event for lead %s",
            lead_id,
        )

    return len(cancelled_ids)
