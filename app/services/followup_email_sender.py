"""Follow-up email execution engine (Phase 7 Part 1).

Sends scheduled follow-up emails to leads when follow-ups become due.
This is the MISSING piece that makes the follow-up system actionable -
previously follow-ups were only task records that never resulted in
actual outbound email communication.

Design:
  - Processes PENDING follow-ups whose due_at has passed.
  - Uses SELECT FOR UPDATE SKIP LOCKED on PostgreSQL (atomic claim);
    falls back to plain SELECT on SQLite (test environments).
  - Transitions PENDING → IN_PROGRESS → COMPLETED atomically.
  - Classifies errors as permanent vs temporary to prevent retry storms.
  - Records audit events and FailedJob rows for observability.
  - Never sends the same follow-up twice (idempotency via status guard).
  - Respects tenant isolation: every query filters by organization_id.
  - Bounded retry: MAX_EMAIL_RETRY_COUNT prevents unlimited attempts.

Scheduler integration:
  - This module exposes `execute_due_follow_ups()` as the job entry point.
  - Registered as a 5-minute IntervalTrigger job (id: followup_email_execution)
    in `app/main.py` lifespan.

Idempotency:
  - The only way a follow-up is selected is: status == PENDING AND due_at <= now.
  - Before sending, status is atomically set to IN_PROGRESS.
  - After sending, status is set to COMPLETED.
  - Any scheduler re-execution will skip follow-ups in IN_PROGRESS/COMPLETED/CANCELLED.
  - On failure, status reverts to PENDING (retry on next run) with incremented
    email_retry_count, preventing permanent loops.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.events import publish_event
from app.models import (
    EventLog,
    FollowUp,
    FollowUpStatus,
    Lead,
)
from app.services.email_service import EmailService
from app.services.org_context import OrganizationContext
from app.services.retry import is_transient, record_failed_job

logger = logging.getLogger("strategy-call-agent.followup-email-sender")

# ── Configuration ────────────────────────────────────────────────────────────

MAX_BATCH_SIZE = 50  # bounded batch processing per scheduler run
MAX_EMAIL_RETRY_COUNT = 3  # prevent infinite retry loops


def _ensure_aware(dt: datetime | None) -> datetime | None:
    """Ensure a datetime is timezone-aware (UTC).

    SQLite returns naive datetimes from DateTime(timezone=True) columns.
    This helper attaches UTC tzinfo if missing so comparisons with
    datetime.now(timezone.utc) don't raise TypeError.
    """
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ── Main Entry Point ─────────────────────────────────────────────────────────


def execute_due_follow_ups(organization_id: uuid.UUID | None = None) -> dict:
    """Process due follow-ups and send emails to leads.

    Args:
        organization_id: when set, only process follow-ups for that org
            (tenant isolation for manual triggers).  When None, process
            all orgs (platform scheduler).

    Returns a summary dict with counts of processed items.
    Designed to be called by APScheduler or a manual trigger.

    Execution flow:
      1. Query PENDING follow-ups with due_at <= now (bounded batch).
      2. For each follow-up, claim it atomically (PENDING → IN_PROGRESS).
      3. Send email to lead via the organization's Gmail credentials.
      4. On success: COMPLETED + audit event + SSE event.
      5. On failure: revert to PENDING + increment retry count.
      6. After MAX_EMAIL_RETRY_COUNT failures: permanent failure + FailedJob.
    """
    summary = {
        "total_due": 0,
        "emails_sent": 0,
        "skipped": 0,
        "permanent_failures": 0,
        "temporary_failures": 0,
        "errors": 0,
    }
    db = SessionLocal()
    try:
        due_followups = _query_due_followups(db, MAX_BATCH_SIZE, organization_id)
        summary["total_due"] = len(due_followups)

        for fu in due_followups:
            try:
                result = _process_one_followup(db, fu)
                summary[result] += 1
            except Exception:
                logger.exception(
                    "Unexpected error processing follow-up %s", fu.id
                )
                summary["errors"] += 1

        return summary
    finally:
        db.close()


# ── Query ────────────────────────────────────────────────────────────────────


def _query_due_followups(
    db: Session, limit: int, organization_id: uuid.UUID | None = None
) -> list[FollowUp]:
    """Fetch PENDING follow-ups whose due_at has passed.

    When organization_id is given, only that org's follow-ups are
    returned (tenant isolation).  When None, all orgs are included
    (platform scheduler).

    Uses SELECT FOR UPDATE SKIP LOCKED on PostgreSQL to safely claim
    rows without contention across concurrent scheduler instances.
    Falls back to plain SELECT on SQLite (test environments) where
    row-level locking is not supported.

    Returns at most ``limit`` rows to bound processing time.
    """
    now_utc = datetime.now(timezone.utc)
    # Use naive UTC for SQL comparison - SQLite stores datetimes without tz,
    # and comparing aware/naive at the SQL level causes issues.
    now_naive = now_utc.replace(tzinfo=None)
    base_filter = [
        FollowUp.status == FollowUpStatus.PENDING,
        FollowUp.due_at.isnot(None),
        FollowUp.due_at <= now_naive,
    ]
    if organization_id is not None:
        base_filter.append(FollowUp.organization_id == organization_id)

    try:
        # PostgreSQL: atomic claim with skip_locked
        rows = (
            db.query(FollowUp)
            .filter(*base_filter)
            .order_by(FollowUp.due_at.asc())
            .with_for_update(skip_locked=True)
            .limit(limit)
            .all()
        )
        return rows
    except Exception:
        # SQLite or other DB without FOR UPDATE support - safe fallback
        # for test environments. Sequential scheduler runs won't overlap
        # in practice for tests.
        logger.debug("FOR UPDATE not supported, falling back to plain SELECT")
        return (
            db.query(FollowUp)
            .filter(*base_filter)
            .order_by(FollowUp.due_at.asc())
            .limit(limit)
            .all()
        )


# ── Per-Follow-Up Processing ─────────────────────────────────────────────────


def _process_one_followup(db: Session, fu: FollowUp) -> str:
    """Process a single follow-up: validate, claim, send, record.

    Returns one of: "emails_sent", "skipped", "permanent_failures",
    "temporary_failures".
    """
    # Pre-claim validation (skip before wasting an UPDATE)
    skip_reason = _should_skip(fu)
    if skip_reason is not None:
        logger.info(
            "Skipping follow-up %s: %s", fu.id, skip_reason
        )
        return "skipped"

    # Lead email validation
    lead = db.query(Lead).filter(Lead.id == fu.lead_id).first()
    if lead is None:
        _record_failure(db, fu, "Lead not found", is_permanent=True)
        return "permanent_failures"
    if not lead.email or not lead.email.strip():
        _record_failure(db, fu, "Lead has no email address", is_permanent=True)
        return "permanent_failures"

    # Terminal lead check - don't send to completed/declined/etc. leads
    from app.services.followup_cancellation import is_terminal_lead_status
    if is_terminal_lead_status(lead.status):
        # BUG FIX: Cancel the follow-up instead of reverting to PENDING.
        # The old _record_failure() path set status=PENDING without
        # incrementing email_retry_count, causing an infinite retry loop
        # where every scheduler run reprocesses the same follow-up.
        fu.status = FollowUpStatus.CANCELLED
        fu.cancelled_at = datetime.now(timezone.utc)
        fu.last_error = f"Lead in terminal status: {lead.status.value}"
        fu.updated_at = datetime.now(timezone.utc)
        try:
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("Failed to commit terminal-lead cancellation for follow-up %s", fu.id)
            return "errors"

        # Record FailedJob for observability
        try:
            record_failed_job(
                db,
                job_type="followup_email_send",
                payload=json.dumps({
                    "follow_up_id": str(fu.id),
                    "lead_id": str(fu.lead_id),
                    "title": fu.title,
                }),
                error=f"Lead in terminal status: {lead.status.value}",
                organization_id=fu.organization_id,
            )
        except Exception:
            logger.exception("Failed to record FailedJob for follow-up %s", fu.id)

        # SSE event
        publish_event(
            "follow_up.failed",
            {
                "follow_up_id": str(fu.id),
                "lead_id": str(fu.lead_id),
                "title": fu.title,
                "error": f"Lead in terminal status: {lead.status.value}",
                "permanent": True,
            },
            organization_id=fu.organization_id,
        )
        return "permanent_failures"

    # ── Claim: PENDING → IN_PROGRESS ────────────────────────────────────
    if not _claim_followup(db, fu):
        logger.info(
            "Follow-up %s already claimed or no longer pending; skipping", fu.id
        )
        return "skipped"

    # Phase 7 Part 4 - Re-check lead status AFTER claim but BEFORE send.
    # The lead may have become terminal in the window between the pre-claim
    # check and the claim itself.  If terminal, CANCEL the follow-up and
    # skip the send.  We cancel (not revert to PENDING) to prevent an
    # infinite retry loop where the scheduler reprocesses the same follow-up
    # every run.
    from app.services.followup_cancellation import is_terminal_lead_status
    lead = db.query(Lead).filter(Lead.id == fu.lead_id).first()
    if lead is not None and is_terminal_lead_status(lead.status):
        fu.status = FollowUpStatus.CANCELLED
        fu.cancelled_at = datetime.now(timezone.utc)
        fu.updated_at = datetime.now(timezone.utc)
        try:
            db.commit()
        except Exception:
            db.rollback()
            logger.exception(
                "Failed to commit terminal-lead cancellation (post-claim) for follow-up %s",
                fu.id,
            )
            return "errors"
        logger.info(
            "Follow-up %s: lead %s became terminal after claim; cancelled",
            fu.id,
            fu.lead_id,
        )
        return "skipped"

    # ── Send email ──────────────────────────────────────────────────────
    try:
        gmail_message_id = _send_followup_email(db, fu, lead)
        _record_success(db, fu, gmail_message_id)
        return "emails_sent"
    except Exception as exc:
        error_str = str(exc)
        is_permanent = _is_permanent_error(exc)
        fu.email_retry_count = (fu.email_retry_count or 0) + 1

        if fu.email_retry_count >= MAX_EMAIL_RETRY_COUNT:
            is_permanent = True

        _record_failure(db, fu, error_str, is_permanent=is_permanent)

        if is_permanent:
            return "permanent_failures"
        return "temporary_failures"


# ── Skip Logic ───────────────────────────────────────────────────────────────


def _should_skip(fu: FollowUp) -> str | None:
    """Return a reason string if the follow-up should be skipped, else None."""
    if fu.status != FollowUpStatus.PENDING:
        return f"status is {fu.status.value} (not pending)"
    if fu.due_at is None:
        return "due_at is None"
    due = _ensure_aware(fu.due_at)
    if due > datetime.now(timezone.utc):
        return "due_at is in the future"
    # Already exceeded retry budget
    if (fu.email_retry_count or 0) >= MAX_EMAIL_RETRY_COUNT:
        return f"retry count {fu.email_retry_count} >= {MAX_EMAIL_RETRY_COUNT}"
    return None


# ── Atomic Claim ─────────────────────────────────────────────────────────────


def _claim_followup(db: Session, fu: FollowUp) -> bool:
    """Atomically transition PENDING → IN_PROGRESS.

    Uses UPDATE ... WHERE status = 'pending' to prevent double-claiming.
    Returns True if this call claimed the row, False if already claimed.

    On PostgreSQL this benefits from the FOR UPDATE SKIP LOCKED above.
    On SQLite this is still safe because:
      - The WHERE clause ensures only pending rows are updated.
      - Tests run sequentially (no concurrent schedulers).
    """
    now_utc = datetime.now(timezone.utc)
    result = db.execute(
        update(FollowUp)
        .where(FollowUp.id == fu.id, FollowUp.status == FollowUpStatus.PENDING)
        .values(
            status=FollowUpStatus.IN_PROGRESS,
            updated_at=now_utc,
        )
    )
    db.flush()

    if result.rowcount == 0:
        return False

    # Refresh the in-memory object to reflect the claimed state
    fu.status = FollowUpStatus.IN_PROGRESS
    fu.updated_at = now_utc
    return True


# ── Email Sending ────────────────────────────────────────────────────────────


def _send_followup_email(
    db: Session, fu: FollowUp, lead: Lead
) -> str:
    """Send the follow-up email to the lead.

    Resolves org-specific credentials via OrganizationContext, builds
    email content using branded outreach templates (Phase 7 Part 2),
    and sends via the existing EmailService.

    Template resolution:
      1. If the lead has a known call_outcome, use the branded outreach
         template from email_templates.py (outcome-aware, per-org branding).
      2. Otherwise, fall back to the generic follow-up template.

    Returns the Gmail message ID on success.
    Raises on failure - caller handles recording and retry logic.
    """
    org_ctx = OrganizationContext.from_id(fu.organization_id)
    email_svc = EmailService(org_context=org_ctx, db=db)

    # Try branded outreach template first (Phase 7 Part 2)
    outreach = _try_outreach_template(lead, fu)

    if outreach is not None:
        subject = outreach["subject"]
        html_body = outreach["html"]
        plain_body = outreach["text"]
    else:
        subject = _build_subject(lead.name, fu.title)
        html_body = _build_html_body(lead.name, fu.title, fu.notes)
        plain_body = _build_plain_body(lead.name, fu.title, fu.notes)

    return email_svc.send_email(
        to=lead.email,
        subject=subject,
        plain_body=plain_body,
        db=db,
        html_body=html_body,
    )


def _try_outreach_template(
    lead: Lead, fu: FollowUp
) -> dict[str, str] | None:
    """Attempt to render a branded outreach template for the follow-up.

    Returns a dict with keys "subject", "html", "text" if the lead has
    a known call_outcome that maps to an outreach template.  Returns
    None if the outcome is unknown or rendering fails.
    """
    call_outcome = getattr(lead, "call_outcome", None)
    if call_outcome is None:
        return None

    # Normalize enum to string value
    if hasattr(call_outcome, "value"):
        outcome_str = call_outcome.value
    else:
        outcome_str = str(call_outcome).strip().lower()

    # Skip outcomes that produce no customer-facing email
    if outcome_str in ("not_interested", "cancelled"):
        return None

    try:
        from app.services.email_templates import build_outreach_email
        return build_outreach_email(lead, outcome_str)
    except Exception:
        logger.debug(
            "Outreach template failed for outcome=%s, falling back to generic",
            outcome_str,
        )
        return None


def _build_subject(lead_name: str, followup_title: str) -> str:
    """Build email subject for a follow-up."""
    return f"Following Up - {followup_title}"


def _build_html_body(
    lead_name: str, followup_title: str, notes: str | None
) -> str:
    """Build HTML email body for a follow-up.

    Uses inline CSS for Gmail compatibility (same pattern as existing
    confirmation and reminder templates).
    """
    _esc(lead_name) if lead_name else "there"
    _esc(followup_title) if followup_title else "Follow-up"
    notes_html = ""
    if notes:
        safe_notes = _esc(notes)
        notes_html = (
            f'<p style="color:#5f6368;line-height:1.6;margin:16px 0 0 0;'
            f'white-space:pre-wrap;">{safe_notes}</p>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f8f9fa;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f8f9fa;padding:24px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#ffffff;border-radius:8px;overflow:hidden;">

  <!-- HEADING -->
  <tr><td style="padding:32px 32px 0;">
    <div style="font-size:22px;font-weight:700;color:#202124;margin-bottom:4px;">{_esc(followup_title) if followup_title else "Follow-Up"}</div>
  </td></tr>

  <!-- BODY -->
  <tr><td style="padding:20px 32px 0;">
    <div style="font-size:15px;color:#202124;line-height:1.6;">
      Hi {_esc(lead_name) if lead_name else "there"},<br><br>
      {_esc(followup_title) if followup_title else "This is a follow-up from our team."}
    </div>
    {notes_html}
  </td></tr>

  <!-- FOOTER -->
  <tr><td style="padding:32px 32px 24px;">
    <div style="font-size:13px;color:#5f6368;border-top:1px solid #dadce0;padding-top:16px;">
      This is an automated follow-up from Strategy Call Agent.
    </div>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""


def _build_plain_body(
    lead_name: str, followup_title: str, notes: str | None
) -> str:
    """Build plain-text email body for a follow-up."""
    parts = [
        f"Hi {lead_name or 'there'},",
        "",
        f"{followup_title or 'This is a follow-up from our team.'}",
    ]
    if notes:
        parts.extend(["", notes])
    parts.extend([
        "",
        "---",
        "This is an automated follow-up from Strategy Call Agent.",
    ])
    return "\n".join(parts)


def _esc(value: str) -> str:
    """HTML-escape a string for safe interpolation into email templates."""
    import html as _html
    return _html.escape(str(value), quote=True)


# ── Recording Outcomes ───────────────────────────────────────────────────────


def _record_success(
    db: Session, fu: FollowUp, gmail_message_id: str
) -> None:
    """Record successful email send: status → COMPLETED, audit, SSE."""
    now_utc = datetime.now(timezone.utc)
    fu.status = FollowUpStatus.COMPLETED
    fu.completed_at = now_utc
    fu.email_sent_at = now_utc
    fu.last_error = None
    fu.updated_at = now_utc

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to commit success for follow-up %s", fu.id)
        return

    # Audit event
    _log_event(
        db,
        lead_id=fu.lead_id,
        event_type="followup_email_sent",
        payload={
            "follow_up_id": str(fu.id),
            "title": fu.title,
            "priority": fu.priority.value if fu.priority else None,
            "gmail_message_id": gmail_message_id,
        },
        organization_id=fu.organization_id,
    )

    # Real-time SSE notification
    publish_event(
        "follow_up.completed",
        {
            "follow_up_id": str(fu.id),
            "lead_id": str(fu.lead_id),
            "title": fu.title,
            "email_sent_at": now_utc.isoformat(),
        },
        organization_id=fu.organization_id,
    )


def _record_failure(
    db: Session,
    fu: FollowUp,
    error_message: str,
    is_permanent: bool,
) -> None:
    """Record a failed email send attempt.

    On failure:
      - Reverts status from IN_PROGRESS back to PENDING (retry on next run).
      - Increments email_retry_count.
      - Stores last_error.
      - On permanent failure: records a FailedJob for observability.
    """
    now_utc = datetime.now(timezone.utc)

    # Revert to PENDING so the next scheduler run can retry
    fu.status = FollowUpStatus.PENDING
    fu.last_error = error_message[:2000]
    fu.updated_at = now_utc

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to commit failure for follow-up %s", fu.id)
        return

    if is_permanent:
        # Record a FailedJob for observability (pattern from reminder_service)
        try:
            record_failed_job(
                db,
                job_type="followup_email_send",
                payload=json.dumps({
                    "follow_up_id": str(fu.id),
                    "lead_id": str(fu.lead_id),
                    "title": fu.title,
                }),
                error=error_message[:4000],
                organization_id=fu.organization_id,
            )
        except Exception:
            logger.exception("Failed to record FailedJob for follow-up %s", fu.id)

        # Publish SSE event for dashboard visibility
        publish_event(
            "follow_up.failed",
            {
                "follow_up_id": str(fu.id),
                "lead_id": str(fu.lead_id),
                "title": fu.title,
                "error": error_message[:500],
                "permanent": True,
            },
            organization_id=fu.organization_id,
        )


# ── Error Classification ─────────────────────────────────────────────────────


def _is_permanent_error(exc: BaseException) -> bool:
    """Classify an exception as permanent (no point retrying) or temporary.

    Permanent: auth failures, invalid recipients, quota exceeded, validation.
    Temporary: rate limits, server errors, network timeouts.
    """
    # If the retry module classifies it as transient, it's temporary
    if is_transient(exc):
        return False

    # Email-specific permanent errors
    msg = str(exc).lower()
    permanent_markers = (
        "invalid", "not found", "does not exist", "invalid_grant",
        "unauthorized", "permission_denied", "quota",
        "recipient", "mailbox", "550", "553",
        "cannot send email",
    )
    return any(marker in msg for marker in permanent_markers)


# ── Lead Lifecycle ───────────────────────────────────────────────────────────


def _is_terminal_lead(lead: Lead) -> bool:
    """Check if a lead is in a terminal lifecycle state.

    Terminal leads should not receive follow-up emails.
    Delegates to the canonical is_terminal_lead_status() helper.
    """
    from app.services.followup_cancellation import is_terminal_lead_status
    return is_terminal_lead_status(lead.status)


# ── Audit Logging ────────────────────────────────────────────────────────────


def _log_event(
    db: Session,
    lead_id,
    event_type: str,
    payload: dict | None = None,
    organization_id=None,
) -> None:
    """Log an audit event for a follow-up action.

    Follows the same pattern as reminder_service._log_event.
    """
    db.add(
        EventLog(
            lead_id=lead_id,
            event_type=event_type,
            payload=json.dumps(payload) if payload is not None else None,
            organization_id=organization_id,
        )
    )
    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to log audit event: %s", event_type)


# ── Utility ──────────────────────────────────────────────────────────────────


def get_pending_followups_count(organization_id) -> int:
    """Count PENDING follow-ups due for an organization.

    Useful for dashboard badges and monitoring.
    """
    db = SessionLocal()
    try:
        now_utc = datetime.now(timezone.utc)
        return (
            db.query(FollowUp)
            .filter(
                FollowUp.organization_id == organization_id,
                FollowUp.status == FollowUpStatus.PENDING,
                FollowUp.due_at.isnot(None),
                FollowUp.due_at <= now_utc,
            )
            .count()
        )
    finally:
        db.close()
