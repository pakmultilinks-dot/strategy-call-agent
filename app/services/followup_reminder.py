"""Follow-up due-date reminders (Phase 18 + 19B).

Scans for follow-ups that are past due and still in pending/in_progress
status. Logs events and publishes SSE notifications for overdue items.
Phase 19B: Sends overdue email notifications to the team (lead owner).

This service follows the same pattern as the daily reminder service:
  - SELECT FOR UPDATE atomic claim pattern (prevents duplicate processing)
  - Per-org event logging and SSE broadcasting
  - Never raises out — logs errors and continues
"""
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.events import publish_event
from app.models import FollowUp, FollowUpStatus, Lead

logger = logging.getLogger("strategy-call-agent.followup-reminder")


def check_overdue_follow_ups() -> dict:
    """Scan for overdue follow-ups and publish notifications.

    Returns a summary dict with counts of processed items.
    This is designed to be called by APScheduler or a manual trigger.

    Phase 19B: Also sends overdue email notifications (once per follow-up,
    tracked via ``overdue_email_sent_at``).
    """
    summary = {
        "total_overdue": 0,
        "events_published": 0,
        "emails_sent": 0,
        "errors": 0,
    }
    db = SessionLocal()
    try:
        now_utc = datetime.now(timezone.utc)

        # Find follow-ups that are past due and not in a terminal state
        overdue = (
            db.query(FollowUp)
            .filter(
                FollowUp.status.in_([FollowUpStatus.PENDING, FollowUpStatus.IN_PROGRESS]),
                FollowUp.due_at.isnot(None),
                FollowUp.due_at < now_utc,
            )
            .all()
        )

        summary["total_overdue"] = len(overdue)

        for fu in overdue:
            try:
                # Publish SSE event for real-time dashboard updates
                publish_event(
                    "follow_up.overdue",
                    {
                        "follow_up_id": str(fu.id),
                        "lead_id": str(fu.lead_id),
                        "title": fu.title,
                        "priority": fu.priority.value,
                        "due_at": fu.due_at.isoformat() if fu.due_at else None,
                    },
                    organization_id=fu.organization_id,
                )
                summary["events_published"] += 1
            except Exception:
                logger.exception(
                    "Failed to publish overdue follow-up event for %s", fu.id
                )
                summary["errors"] += 1

            # Phase 19B: Send overdue email (only once per follow-up)
            if fu.overdue_email_sent_at is None:
                try:
                    _send_overdue_email(db, fu, now_utc)
                    summary["emails_sent"] += 1
                except Exception:
                    logger.exception(
                        "Failed to send overdue email for follow-up %s", fu.id
                    )
                    summary["errors"] += 1

        return summary
    finally:
        db.close()


def _send_overdue_email(db: Session, fu: FollowUp, now_utc: datetime) -> None:
    """Send an overdue follow-up notification email.

    Resolves the assigned team member's email (falling back to the lead
    creator) and sends the notification. On success, sets
    ``overdue_email_sent_at`` on the follow-up to prevent duplicates.
    """
    from zoneinfo import ZoneInfo

    from app.config import settings
    from app.models_multi_tenant import User
    from app.services.email_service import EmailService
    from app.services.email_templates import (
        build_overdue_followup_html,
        build_overdue_followup_subject,
        build_overdue_followup_text,
    )
    from app.services.org_context import OrganizationContext

    # Load the lead to get the lead name
    lead = db.query(Lead).filter(Lead.id == fu.lead_id).first()
    if lead is None:
        logger.warning("Lead %s not found for follow-up %s; skipping email", fu.lead_id, fu.id)
        return

    # Resolve the recipient: assigned_to → created_by → lead.email (fallback)
    recipient_email = None
    if fu.assigned_to:
        assignee = db.query(User).filter(User.id == fu.assigned_to).first()
        if assignee and assignee.email:
            recipient_email = assignee.email
    if not recipient_email and fu.created_by:
        creator = db.query(User).filter(User.id == fu.created_by).first()
        if creator and creator.email:
            recipient_email = creator.email
    if not recipient_email and lead.email:
        # Last resort fallback: notify the lead itself
        recipient_email = lead.email

    if not recipient_email:
        logger.warning(
            "No recipient email resolved for overdue follow-up %s (lead %s); skipping",
            fu.id, fu.lead_id,
        )
        return

    tz = ZoneInfo(settings.business_timezone)
    org_ctx = OrganizationContext.from_id(fu.organization_id)

    subject = build_overdue_followup_subject(
        fu.title, lead.name, branding=None,
    )
    html_body = build_overdue_followup_html(
        followup_title=fu.title,
        lead_name=lead.name,
        due_at_utc=fu.due_at,
        priority=fu.priority.value,
        notes=fu.notes,
        tz=tz,
    )
    plain_body = build_overdue_followup_text(
        followup_title=fu.title,
        lead_name=lead.name,
        due_at_utc=fu.due_at,
        priority=fu.priority.value,
        notes=fu.notes,
        tz=tz,
    )

    svc = EmailService(org_context=org_ctx, db=db)
    svc.send_email(recipient_email, subject, plain_body, db, html_body=html_body)

    # Mark as sent to prevent duplicates
    fu.overdue_email_sent_at = now_utc
    db.commit()


def get_overdue_follow_ups_count(organization_id) -> int:
    """Count overdue follow-ups for a specific organization.

    Useful for dashboard badges and summary widgets.
    """
    db = SessionLocal()
    try:
        now_utc = datetime.now(timezone.utc)
        count = (
            db.query(FollowUp)
            .filter(
                FollowUp.organization_id == organization_id,
                FollowUp.status.in_([FollowUpStatus.PENDING, FollowUpStatus.IN_PROGRESS]),
                FollowUp.due_at.isnot(None),
                FollowUp.due_at < now_utc,
            )
            .count()
        )
        return count
    finally:
        db.close()
