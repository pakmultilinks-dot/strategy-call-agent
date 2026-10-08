"""Automatic follow-up creation after call outcomes (Phase 23).

When a call outcome is recorded, this service automatically creates
appropriate follow-up tasks based on the outcome type.  Follow-ups
are scoped to the lead's organization and assigned to the lead's
assigned team member (or left unassigned).

Design:
  - create_post_call_followups() is the main entry point, typically
    called from the call-outcome update endpoint or a background task.
  - get_followup_templates() returns the template(s) for a given
    outcome, useful for preview or testing.
  - All FollowUp records are created with status=PENDING.
  - publish_event() is called after creation for real-time SSE updates.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.events import publish_event
from app.models import CallOutcome, FollowUp, FollowUpPriority, FollowUpStatus, Lead

logger = logging.getLogger("strategy-call-agent.auto_followup")


# ---------------------------------------------------------------------------
# Follow-Up Templates
# ---------------------------------------------------------------------------

_FOLLOWUP_TEMPLATES: dict[str, list[dict]] = {
    "connected": [
        {
            "title": "Send proposal/follow-up email",
            "description": "Follow up with the prospect after a successful call. "
                           "Send a tailored proposal or recap email.",
            "priority": FollowUpPriority.HIGH,
            "due_days": 2,
        },
    ],
    "completed": [
        {
            "title": "Send proposal/follow-up email",
            "description": "Follow up with the prospect after a completed call. "
                           "Send a tailored proposal or recap email.",
            "priority": FollowUpPriority.HIGH,
            "due_days": 2,
        },
    ],
    "voicemail": [
        {
            "title": "Retry call — voicemail left",
            "description": "Prospect did not answer; voicemail was left. "
                           "Retry the call within 1 business day.",
            "priority": FollowUpPriority.MEDIUM,
            "due_days": 1,
        },
    ],
    "no_answer": [
        {
            "title": "Retry call — no answer",
            "description": "Prospect did not pick up. Retry the call within "
                           "1 business day.",
            "priority": FollowUpPriority.MEDIUM,
            "due_days": 1,
        },
    ],
    "busy": [
        {
            "title": "Retry call — line busy",
            "description": "Prospect's line was busy. Retry the call in "
                           "3 business days.",
            "priority": FollowUpPriority.LOW,
            "due_days": 3,
        },
    ],
    "rescheduled": [
        {
            "title": "Confirm rescheduled call",
            "description": "The call was rescheduled. Confirm the new time "
                           "with the prospect within 1 business day.",
            "priority": FollowUpPriority.HIGH,
            "due_days": 1,
        },
    ],
    "wrong_number": [
        {
            "title": "Verify phone number",
            "description": "Reached a wrong number. Verify and update the "
                           "prospect's phone number within 7 days.",
            "priority": FollowUpPriority.LOW,
            "due_days": 7,
        },
    ],
    "no_show": [
        {
            "title": "Reschedule attempt",
            "description": "Prospect did not show up for the scheduled call. "
                           "Attempt to reschedule within 1 business day.",
            "priority": FollowUpPriority.MEDIUM,
            "due_days": 1,
        },
    ],
    # Outcomes that produce NO follow-up:
    # "not_interested" → no follow-up
    # "cancelled"      → no follow-up
}


def get_followup_templates(call_outcome: str | CallOutcome) -> list[dict]:
    """Return the follow-up template(s) for a given call outcome.

    Args:
        call_outcome: The call outcome value (string or CallOutcome enum).

    Returns:
        A list of template dicts, each with keys:
            - ``title`` (str)
            - ``description`` (str)
            - ``priority`` (FollowUpPriority)
            - ``due_days`` (int)

        Returns an empty list for outcomes that produce no follow-ups
        (``not_interested``, ``cancelled``).
    """
    if isinstance(call_outcome, CallOutcome):
        key = call_outcome.value
    else:
        key = str(call_outcome).strip().lower()

    return list(_FOLLOWUP_TEMPLATES.get(key, []))


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------


def create_post_call_followups(
    db: Session,
    lead: Lead,
    call_outcome: CallOutcome | str,
    organization_id: uuid.UUID,
    created_by: uuid.UUID | None = None,
) -> list[uuid.UUID]:
    """Create automatic follow-up tasks after a call outcome is recorded.

    Inspects the call outcome and creates the appropriate number of
    FollowUp records (zero, one, or more) with pre-configured titles,
    priorities, and due dates.

    Each follow-up is:
      - Scoped to the lead's organization (``organization_id``).
      - Assigned to the lead's ``assigned_to`` user (if set).
      - Created with ``status=PENDING``.
      - Linked to the lead via ``lead_id``.

    After creation, a ``followup_created`` event is published for
    real-time SSE updates.

    Args:
        db: Active database session.
        lead: The Lead ORM instance the call was made on.
        call_outcome: The recorded call outcome.
        organization_id: The lead's organization UUID.

    Returns:
        A list of UUIDs for the newly created FollowUp records.
        Empty list if the outcome produces no follow-ups.
    """
    # Phase 7 Part 4 — Guard: skip follow-up creation for terminal leads
    from app.services.followup_cancellation import is_terminal_lead_status
    if is_terminal_lead_status(lead.status):
        logger.info(
            "Skipping auto follow-up: lead %s is in terminal status '%s'",
            lead.id,
            lead.status.value,
        )
        return []

    templates = get_followup_templates(call_outcome)
    if not templates:
        logger.info(
            "No auto follow-up for outcome=%s lead=%s org=%s",
            call_outcome,
            lead.id,
            organization_id,
        )
        return []

    # Resolve the creating user: explicit > lead.assigned_to > any org user
    from app.models_multi_tenant import User

    effective_creator = created_by or lead.assigned_to
    if effective_creator is None:
        org_user = db.query(User).filter(
            User.organization_id == organization_id
        ).first()
        if org_user:
            effective_creator = org_user.id
        else:
            logger.warning(
                "No user found in org %s for follow-up created_by", organization_id
            )
            return []

    now = datetime.now(timezone.utc)
    created_ids: list[uuid.UUID] = []

    for template in templates:
        due_date = now + timedelta(days=template["due_days"])

        followup = FollowUp(
            organization_id=organization_id,
            lead_id=lead.id,
            created_by=effective_creator,
            assigned_to=lead.assigned_to,
            title=template["title"],
            notes=template["description"],
            priority=template["priority"],
            status=FollowUpStatus.PENDING,
            due_at=due_date,
        )
        db.add(followup)
        db.flush()  # Populate followup.id

        created_ids.append(followup.id)

        logger.info(
            "Auto follow-up created: id=%s title=%s priority=%s due=%s "
            "lead=%s outcome=%s org=%s",
            followup.id,
            template["title"],
            template["priority"].value,
            due_date.isoformat(),
            lead.id,
            call_outcome if isinstance(call_outcome, str) else call_outcome.value,
            organization_id,
        )

    db.commit()

    # Publish SSE events for each created follow-up
    for fid in created_ids:
        try:
            publish_event(
                "followup_created",
                {
                    "followup_id": str(fid),
                    "lead_id": str(lead.id),
                    "lead_name": lead.name,
                },
                organization_id,
            )
        except Exception as exc:
            logger.warning(
                "Failed to publish followup_created event for %s: %s",
                fid,
                str(exc)[:200],
            )

    logger.info(
        "Created %d auto follow-up(s) for lead=%s outcome=%s org=%s",
        len(created_ids),
        lead.id,
        call_outcome if isinstance(call_outcome, str) else call_outcome.value,
        organization_id,
    )

    return created_ids
