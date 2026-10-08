"""FastAPI application entrypoint.

Phase 0 exposes only a liveness probe. Routers and startup wiring are
added in later phases.
"""
import json
import logging
import re
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import dateparser
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import app.models_multi_tenant
from app.config import settings
from app.database import SessionLocal, engine, get_db
from app.events import publish_event
from app.logging_config import RequestLoggingMiddleware, configure_structured_logging
from app.middleware import (
    OrgRateLimitMiddleware,
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from app.models import Base, EventLog, Lead, LeadStatus, ScheduleConfig

# Phase 6B.3 - Auth routers
from app.routers.auth_router import router as auth_router
from app.routers.organization_router import router as org_router
from app.schemas import FormSubmission
from app.tenant import lookup_organization_by_slug

logger = logging.getLogger("strategy-call-agent")

# Module-level scheduler reference so the settings API can reschedule jobs.
_scheduler: BackgroundScheduler | None = None


def _scheduled_rsvp_poll() -> None:
    """APScheduler job wrapper - never let an exception crash the scheduler."""
    from app.services.rsvp_poller import poll_rsvp_updates

    logger.info("scheduled job start: rsvp_poll")
    try:
        summary = poll_rsvp_updates()
        logger.info("scheduled job done: rsvp_poll %s", summary)
    except Exception:
        logger.exception("scheduled job raised: rsvp_poll")


def _scheduled_daily_reminder() -> None:
    """APScheduler job wrapper - never let an exception crash the scheduler."""
    from app.services.reminder_service import send_daily_reminders

    logger.info("scheduled job start: daily_reminder")
    try:
        summary = send_daily_reminders()
        logger.info("scheduled job done: daily_reminder %s", summary)
    except Exception:
        logger.exception("scheduled job raised: daily_reminder")


def _check_overdue_follow_ups() -> None:
    """APScheduler job wrapper - never let an exception crash the scheduler.

    Phase 18: Checks for overdue follow-ups and publishes SSE notifications.
    """
    from app.services.followup_reminder import check_overdue_follow_ups

    logger.info("scheduled job start: followup_overdue_check")
    try:
        summary = check_overdue_follow_ups()
        logger.info("scheduled job done: followup_overdue_check %s", summary)
    except Exception:
        logger.exception("scheduled job raised: followup_overdue_check")


def _scheduled_followup_email_execution() -> None:
    """APScheduler job wrapper - never let an exception crash the scheduler.

    Phase 7 Part 1: Sends due follow-up emails to leads.  This is the
    MISSING piece that completes the follow-up lifecycle - previously
    follow-ups were task records that never triggered outbound email.

    The actual logic lives in app.services.followup_email_sender.
    This wrapper exists solely so APScheduler never crashes on exceptions.
    """
    from app.services.followup_email_sender import execute_due_follow_ups

    logger.info("scheduled job start: followup_email_execution")
    try:
        summary = execute_due_follow_ups()
        logger.info("scheduled job done: followup_email_execution %s", summary)
    except Exception:
        logger.exception("scheduled job raised: followup_email_execution")





def _cleanup_token_blocklist() -> None:
    """APScheduler job wrapper - clean up expired token blocklist entries.

    Phase 28 (P1-D): Removes revoked token entries that have passed their
    expiry. Runs every 12 hours. Prevents unbounded table growth.
    """
    from app.auth import cleanup_expired_blocklist

    logger.info("scheduled job start: token_blocklist_cleanup")
    db = SessionLocal()
    try:
        count = cleanup_expired_blocklist(db)
        logger.info("token_blocklist_cleanup: removed %d expired entries", count)
    except Exception:
        logger.exception("scheduled job raised: token_blocklist_cleanup")
        db.rollback()
    finally:
        db.close()


def _check_token_health() -> None:
    """APScheduler job wrapper - check OAuth token lifecycle health.

    Phase 5: Runs every 6 hours to proactively detect expiring Zoom and
    Google OAuth tokens before they cause API failures.  Logs warnings
    for tokens expiring within 24 hours and errors for tokens expiring
    within 1 hour or already expired.

    No tokens are refreshed or modified - this is read-only monitoring.
    """
    from app.services.token_health import check_token_health

    logger.info("scheduled job start: token_health_check")
    db = SessionLocal()
    try:
        summary = check_token_health(db)  # None = check all orgs (scheduler)
        logger.info(
            "token_health_check: checked=%d healthy=%d warning=%d critical=%d overall=%s",
            summary["checked"],
            summary["healthy"],
            summary["warning"],
            summary["critical"],
            summary["overall"],
        )
    except Exception:
        logger.exception("scheduled job raised: token_health_check")
        db.rollback()
    finally:
        db.close()


def _scheduled_recover_stuck_leads() -> None:
    """APScheduler job wrapper - periodic recovery of leads stuck in PENDING.

    Runs every 10 minutes to catch leads that got stuck during a mid-pipeline
    crash. Previously this only ran once at startup.
    """
    logger.info("scheduled job start: stuck_lead_recovery")
    try:
        _recover_stuck_leads()
        logger.info("scheduled job done: stuck_lead_recovery")
    except Exception:
        logger.exception("scheduled job raised: stuck_lead_recovery")


def _get_schedule_config(db: Session) -> ScheduleConfig:
    """Return the single ScheduleConfig row, creating it with defaults if
    none exists (first startup)."""
    cfg = db.query(ScheduleConfig).first()
    if cfg is None:
        cfg = ScheduleConfig(reminder_time="08:00", rsvp_poll_interval_minutes=10)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _reschedule_jobs(cfg: ScheduleConfig) -> None:
    """Reschedule the live APScheduler jobs to the given config values.

    System-level ``rsvp_poll`` and ``daily_reminder`` jobs may have been
    removed when per-org jobs were registered at startup.  Silently skip
    any missing jobs so platform-admin settings updates never crash.
    """
    if _scheduler is None:
        return
    from apscheduler.jobstores.base import JobLookupError
    tz = ZoneInfo(settings.business_timezone)
    hour, minute = map(int, cfg.reminder_time.split(":"))
    try:
        _scheduler.reschedule_job(
            "rsvp_poll",
            trigger=IntervalTrigger(minutes=cfg.rsvp_poll_interval_minutes, timezone=tz),
        )
        _scheduler.reschedule_job(
            "daily_reminder",
            trigger=CronTrigger(hour=hour, minute=minute, timezone=tz),
        )
    except JobLookupError:
        # System-level jobs were replaced by per-org jobs at startup.
        # Per-org rescheduling is handled by reschedule_org_scheduler_jobs().
        logger.debug(
            "system-level scheduler jobs not found (per-org jobs active); "
            "rsvp_poll_interval_minutes=%s, reminder_time=%s",
            cfg.rsvp_poll_interval_minutes,
            cfg.reminder_time,
        )
        return
    logger.info(
        "rescheduled jobs: rsvp_poll every %s min, daily_reminder at %s",
        cfg.rsvp_poll_interval_minutes,
        cfg.reminder_time,
    )


# ── Per-Organization Scheduler Jobs (REMOVED for performance) ─────────────
# Previously: 2 jobs per org × 913 orgs = 1826 in-memory scheduler jobs
# that saturated the single gunicorn worker.  The system-level batch jobs
# (rsvp_poll + daily_reminder) now handle all orgs in a single pass.


def reschedule_org_scheduler_jobs(org_id: uuid.UUID) -> None:
    """No-op stub - per-org scheduler jobs have been removed for performance.

    Previously this created 2 APScheduler jobs per organization (daily_reminder
    + rsvp_poll), resulting in 1826+ in-memory jobs for 913 orgs that
    saturated the single worker process.  The system-level batch jobs now
    handle all organizations in a single pass.

    This function is kept as a no-op to avoid breaking callers
    (auth_router, organization_router, tests).
    """
    logger.debug(
        "reschedule_org_scheduler_jobs: no-op (batch jobs handle org %s)",
        org_id,
    )


def _recover_stuck_leads() -> None:
    """Find leads stuck in PENDING from a previous server run and re-queue
    them for pipeline completion.

    Two categories:
    1. With calendar_event_id: Calendar event exists but AI/email never
       completed. Pipeline skips Step 1 (Calendar) and runs Steps 2-3.
    2. Without calendar_event_id: Server crashed before the pipeline
       started or before Calendar event creation. Pipeline runs all steps.
       If the appointment time is in the past, mark ERROR instead.
    """
    db = SessionLocal()
    try:
        stuck_leads = (
            db.query(Lead)
            .filter(Lead.status == LeadStatus.PENDING)
            .limit(100)
            .all()
        )
        if not stuck_leads:
            return

        recovered = 0
        skipped = 0
        # H3 fix: locks left behind by a killed worker (gunicorn
        # --max-requests, OOM, deploy) would otherwise stick forever -
        # _run_pipeline_inner skips any lead with processing_started_at
        # set, so recovery re-queued them every cycle but they never ran.
        # Treat locks older than the TTL as stale and clear them here.
        lock_ttl = timedelta(minutes=30)
        now_utc = datetime.now(timezone.utc)
        for lead in stuck_leads:
            # Skip leads with no org - cannot log events without org_id.
            if lead.organization_id is None:
                logger.warning(
                    "stuck lead %s has no organization_id; skipping recovery", lead.id,
                )
                continue

            if lead.processing_started_at is not None:
                locked_at = lead.processing_started_at
                if locked_at.tzinfo is None:
                    locked_at = locked_at.replace(tzinfo=timezone.utc)
                if now_utc - locked_at > lock_ttl:
                    logger.warning(
                        "clearing stale pipeline lock for lead %s (locked at %s)",
                        lead.id, lead.processing_started_at,
                    )
                    lead.processing_started_at = None
                    db.commit()

            # If the appointment is in the past, mark ERROR rather than
            # trying to create a Calendar event for a past time.
            # (SQLite returns naive datetimes - attach UTC before comparing.)
            _appt_utc = lead.appt_datetime_utc
            if _appt_utc is not None and _appt_utc.tzinfo is None:
                _appt_utc = _appt_utc.replace(tzinfo=timezone.utc)
            if _appt_utc is None or _appt_utc < datetime.now(timezone.utc):
                logger.info(
                    "stuck lead %s has no/invalid appt_datetime_utc (%s); marking ERROR",
                    lead.id,
                    lead.appt_datetime_utc,
                )
                lead.status = LeadStatus.ERROR
                _log_event(
                    db,
                    lead.id,
                    "pipeline_recovery",
                    {
                        "reason": "past_or_none_appt",
                        "appt_datetime_utc": str(lead.appt_datetime_utc),
                    },
                    organization_id=lead.organization_id,
                )
                skipped += 1
                continue

            has_event = bool(lead.calendar_event_id)
            reason = "pending_with_calendar_event_id" if has_event else "pending_without_calendar_event_id"
            _log_event(
                db,
                lead.id,
                "pipeline_recovery",
                {
                    "reason": reason,
                    "calendar_event_id": lead.calendar_event_id,
                },
                organization_id=lead.organization_id,
            )
            run_pipeline(lead.id)
            recovered += 1
            logger.info("re-queued stuck lead %s (%s) for pipeline recovery", lead.id, reason)

        logger.info("stuck lead recovery: %d re-queued, %d skipped", recovered, skipped)
    except Exception:
        logger.exception("failed to recover stuck leads")
    finally:
        db.close()


# ── Phase 8: FailedJob recovery ─────────────────────────────────────────────

def _recover_failed_jobs() -> None:
    """Retry unresolved FailedJob rows across all recoverable job types.

    Phase 29 (P1-11): Expanded from pipeline-only to handle all job types.

    Recoverable job types:
      - pipeline: re-run pipeline for lead_id
      - ai_generate: re-run pipeline for lead_id (lead needs full pipeline)
      - calendar_create: re-run pipeline for lead_id (re-creates calendar)
      - followup_email_send: reset follow-up to PENDING for re-send

    Unrecoverable job types (marked resolved with explanation):
      - calendar_update_reschedule, calendar_delete: no lead context
      - email_send: only has to/subject, no lead context
      - daily_reminder, rsvp_poll: batch jobs, not individually retryable

    After 3 retries the job stays unresolved - manual intervention required.
    """
    from app.models import FailedJob

    # Job types that cannot be individually retried
    UNRECOVERABLE_TYPES = {
        "calendar_update_reschedule",
        "calendar_delete",
        "email_send",
        "daily_reminder",
        "rsvp_poll",
    }

    db = SessionLocal()
    try:
        jobs = (
            db.query(FailedJob)
            .filter(FailedJob.resolved == False)
            .order_by(FailedJob.created_at.asc())
            .limit(20)
            .all()
        )
        if not jobs:
            return

        recovered = 0
        resolved_unrecoverable = 0
        for job in jobs:
            try:
                # Immediately mark unrecoverable batch/context-less job types
                if job.job_type in UNRECOVERABLE_TYPES:
                    job.resolved = True
                    db.commit()
                    resolved_unrecoverable += 1
                    logger.info(
                        "failed job %s (%s) is unrecoverable; marking resolved",
                        job.id, job.job_type,
                    )
                    continue

                try:
                    payload = json.loads(job.payload) if job.payload else {}
                except (json.JSONDecodeError, TypeError):
                    # Unparseable payload - mark resolved, can never retry.
                    job.resolved = True
                    db.commit()
                    logger.warning("failed job %s has unparseable payload; marking resolved", job.id)
                    continue

                if job.retry_count >= 3:
                    logger.warning(
                        "failed job %s exceeded max retries (3) for %s",
                        job.id, job.job_type,
                    )
                    job.resolved = True
                    db.commit()
                    continue

                # ── Pipeline / AI generate / Calendar create ────────────
                # All three use lead_id and re-run the pipeline.
                if job.job_type in ("pipeline", "ai_generate", "calendar_create"):
                    lead_id_str = payload.get("lead_id")
                    if not lead_id_str:
                        job.resolved = True
                        db.commit()
                        continue

                    lead_id = uuid.UUID(lead_id_str)
                    lead = db.get(Lead, lead_id)
                    if lead is None:
                        job.resolved = True
                        db.commit()
                        continue

                    # Pipeline jobs require PENDING status; others are best-effort
                    if job.job_type == "pipeline" and lead.status != LeadStatus.PENDING:
                        job.resolved = True
                        db.commit()
                        continue

                    job.retry_count += 1
                    db.commit()
                    run_pipeline(lead_id)
                    recovered += 1
                    logger.info(
                        "retried failed job %s (attempt %d, type=%s) for lead %s",
                        job.id, job.retry_count, job.job_type, lead_id,
                    )

                # ── Follow-up email send ───────────────────────────────
                elif job.job_type == "followup_email_send":
                    follow_up_id_str = payload.get("follow_up_id")
                    if not follow_up_id_str:
                        job.resolved = True
                        db.commit()
                        continue

                    follow_up_id = uuid.UUID(follow_up_id_str)
                    from app.models import FollowUp, FollowUpStatus
                    fu = db.get(FollowUp, follow_up_id)
                    if fu is None:
                        job.resolved = True
                        db.commit()
                        continue

                    # Only retry if the follow-up is in a retryable state
                    if fu.status not in (FollowUpStatus.PENDING, FollowUpStatus.IN_PROGRESS):
                        job.resolved = True
                        db.commit()
                        continue

                    # Reset to PENDING so the scheduler picks it up again
                    fu.status = FollowUpStatus.PENDING
                    fu.updated_at = datetime.now(timezone.utc)
                    job.retry_count += 1
                    db.commit()
                    recovered += 1
                    logger.info(
                        "retried failed job %s (attempt %d, followup_email_send) for follow-up %s",
                        job.id, job.retry_count, follow_up_id,
                    )

                else:
                    # Unknown job type - mark resolved
                    job.resolved = True
                    db.commit()
                    logger.warning(
                        "failed job %s has unknown type '%s'; marking resolved",
                        job.id, job.job_type,
                    )

            except Exception:
                logger.exception("failed to recover failed job %s", job.id)
                db.rollback()

        if recovered or resolved_unrecoverable:
            logger.info(
                "failed job recovery: %d retried, %d unrecoverable marked resolved",
                recovered, resolved_unrecoverable,
            )
    except Exception:
        logger.exception("failed job recovery encountered an error")
    finally:
        db.close()


def _mark_completed_meetings() -> None:
    """Mark leads as COMPLETED when their appointment time has passed
    and they haven't been declined.

    A meeting is considered completed 2 hours after its scheduled end time.
    This allows a buffer for meetings that run over.
    """

    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        two_hours_ago = now - timedelta(hours=2)

        # Find leads whose meeting time + 2h buffer has passed
        # and who are still in a non-terminal state.
        candidates = (
            db.query(Lead)
            .filter(
                Lead.appt_datetime_utc.isnot(None),
                Lead.appt_datetime_utc < two_hours_ago,
                Lead.status.in_([
                    LeadStatus.SCHEDULED,
                    LeadStatus.ACCEPTED,
                    LeadStatus.TENTATIVE,
                    LeadStatus.REMINDED,
                ]),
            )
            .limit(100)
            .all()
        )

        if not candidates:
            return

        completed = 0
        for lead in candidates:
            previous_status = lead.status.value
            lead.status = LeadStatus.COMPLETED
            # Phase 7 Part 3: Auto-cancellation cascade - lead is entering COMPLETED
            # (terminal).  Cancel pending follow-ups to prevent the scheduler from
            # contacting a lead that is no longer eligible for outreach.
            if lead.organization_id is not None:
                try:
                    from app.services.followup_cancellation import (
                        cancel_pending_followups_for_lead,
                    )
                    cancel_pending_followups_for_lead(db, lead.id, lead.organization_id)
                except Exception:
                    logger.exception(
                        "auto-cancellation cascade failed for lead %s", lead.id
                    )
            _log_event(
                db, lead.id, "meeting_completed",
                {
                    "appt_datetime_utc": lead.appt_datetime_utc.isoformat(),
                    "previous_status": previous_status,
                },
                organization_id=lead.organization_id,
            )
            completed += 1

        if completed:
            db.commit()
            logger.info("meeting completion: %d leads marked COMPLETED", completed)
    except Exception:
        logger.exception("meeting completion check failed")
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables, seed the schedule config, start the scheduler, and
    recover any leads stuck in PENDING with an existing calendar_event_id
    (partial pipeline from a previous server run)."""
    global _scheduler

    # Phase 20 P1-E: Configure structured JSON logging for production.
    configure_structured_logging(
        level="INFO" if settings.app_env == "production" else "DEBUG"
    )

    # Phase 20 P0-A: Refuse to start in production mode if token.json exists.
    # token.json contains dev-only Google OAuth credentials that must never
    # be used in production.  The encrypted credential vault is required.
    if settings.app_env == "production":
        token_path = Path(settings.google_token_file)
        if token_path.exists():
            logger.critical(
                "STARTUP BLOCKED: token.json exists at %s in production mode. "
                "Remove it and use the encrypted credential vault instead."
                " This file contains live OAuth credentials."
                " Set APP_ENV=dev for local development.",
                token_path.resolve(),
            )
            raise RuntimeError(
                f"Refusing to start in production mode: {token_path} exists."
                " Remove it or set APP_ENV=dev for local development."
            )

    # Phase 27 (P0-5): Validate production configuration on startup.
    if settings.app_env == "production":
        warnings = settings.validate_production_config()
        if warnings:
            logger.warning(
                "Production config warnings on startup:\n%s",
                "\n".join(f"  {w}" for w in warnings),
            )

    # Only run create_all in dev mode; production uses Alembic migrations.
    if settings.app_env != "production":
        Base.metadata.create_all(bind=engine)
    else:
        logger.info("Skipping create_all in production; relying on Alembic migrations.")

    # Seed the schedule config with defaults on first startup.
    db = SessionLocal()
    try:
        cfg = _get_schedule_config(db)
    finally:
        db.close()

    # Phase 27 (P0-7): Persistent job store - uses SQLAlchemy so that
    # scheduled jobs survive server restarts. In dev/test mode, falls back
    # to the in-memory job store to avoid requiring a running database for
    # the job store (the main app database is used directly).
    # Each job body is wrapped so an exception never kills the scheduler.
    # The scheduler runs ONLY on the designated worker - in a multi-worker
    # deployment, set SCHEDULER_ENABLED=false on non-leader workers.
    tz = ZoneInfo(settings.business_timezone)
    if not settings.scheduler_is_enabled:
        logger.info("scheduler disabled (SCHEDULER_ENABLED=false); skipping job registration")
        yield
        return

    # Build job store: SQLAlchemyJobStore in production, MemoryJobStore in dev/test
    jobstores: dict = {}
    if settings.app_env == "production":
        try:
            from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
            jobstores["default"] = SQLAlchemyJobStore(
                url=settings.database_url,
                tablename="apscheduler_jobs",
            )
            logger.info(
                "scheduler using SQLAlchemyJobStore (persistent); "
                "jobs will survive server restarts"
            )
        except Exception:
            logger.exception(
                "Failed to initialize SQLAlchemyJobStore; "
                "falling back to MemoryJobStore"
            )
            jobstores = {}
    else:
        logger.info("scheduler using MemoryJobStore (dev/test mode)")

    _scheduler = BackgroundScheduler(
        timezone=tz,
        jobstores=jobstores,
    )
    _scheduler.add_job(
        _scheduled_rsvp_poll,
        IntervalTrigger(minutes=cfg.rsvp_poll_interval_minutes, timezone=tz),
        id="rsvp_poll",
        replace_existing=True,
    )
    hour, minute = map(int, cfg.reminder_time.split(":"))
    _scheduler.add_job(
        _scheduled_daily_reminder,
        CronTrigger(hour=hour, minute=minute, timezone=tz),
        id="daily_reminder",
        replace_existing=True,
    )
    # Phase 8: FailedJob recovery - runs every 5 minutes
    _scheduler.add_job(
        _recover_failed_jobs,
        IntervalTrigger(minutes=5, timezone=tz),
        id="failed_job_recovery",
        replace_existing=True,
    )
    # Phase 8: Meeting completion lifecycle - runs every 15 minutes
    _scheduler.add_job(
        _mark_completed_meetings,
        IntervalTrigger(minutes=15, timezone=tz),
        id="meeting_completion",
        replace_existing=True,
    )
    # Phase 18: Overdue follow-up check - runs every 30 minutes
    _scheduler.add_job(
        _check_overdue_follow_ups,
        IntervalTrigger(minutes=30, timezone=tz),
        id="followup_overdue_check",
        replace_existing=True,
    )
    # Phase 7 Part 1: Follow-up email execution - runs every 5 minutes
    _scheduler.add_job(
        _scheduled_followup_email_execution,
        IntervalTrigger(minutes=5, timezone=tz),
        id="followup_email_execution",
        replace_existing=True,
    )

    # Phase 28 (P1-D): Token blocklist cleanup - runs every 12 hours
    _scheduler.add_job(
        _cleanup_token_blocklist,
        IntervalTrigger(hours=12, timezone=tz),
        id="token_blocklist_cleanup",
        replace_existing=True,
    )
    # Phase 5: Token lifecycle health - runs every 6 hours
    _scheduler.add_job(
        _check_token_health,
        IntervalTrigger(hours=6, timezone=tz),
        id="token_health_check",
        replace_existing=True,
    )
    # Recover leads stuck in PENDING - runs every 10 minutes
    _scheduler.add_job(
        _scheduled_recover_stuck_leads,
        IntervalTrigger(minutes=10, timezone=tz),
        id="stuck_lead_recovery",
        replace_existing=True,
    )
    for job in _scheduler.get_jobs():
        logger.info("scheduled job registered: %s", job.id)
    _scheduler.start()
    for job in _scheduler.get_jobs():
        logger.info("scheduled job started: %s next_run=%s", job.id, getattr(job, "next_run_time", None))

    # PERF FIX: Removed per-org scheduler job registration (913 orgs × 2 jobs
    # = 1826 jobs) that was saturating the single worker process.  The system-
    # level rsvp_poll and daily_reminder jobs already process ALL orgs in a
    # single pass.  This eliminates ~1826 in-memory APScheduler jobs and their
    # associated DB sessions, fixing the severe app slowness.

    # Recover leads stuck in PENDING with a calendar_event_id from a
    # previous server run that crashed mid-pipeline.
    _recover_stuck_leads()

    try:
        yield
    finally:
        if _scheduler is not None:
            _scheduler.shutdown(wait=False)
            _scheduler = None


app = FastAPI(title="strategy-call-agent", version="0.0.0", lifespan=lifespan)

# ── Middleware (applied in reverse order - last added = first executed) ──────
# SECURITY (H8): trust X-Forwarded-For from the reverse proxy (Caddy) so
# per-IP rate limits and audit logs see the real client IP, not the proxy.
# (Starlette 1.x removed ProxyHeadersMiddleware; this is a minimal
# equivalent restricted to private/proxy networks - never "*".)
class _TrustedProxyHeadersMiddleware:
    def __init__(self, app, trusted_hosts: list[str]):
        from ipaddress import ip_network
        self.app = app
        self._trusted = [ip_network(h, strict=False) for h in trusted_hosts]

    def _is_trusted(self, host: str) -> bool:
        from ipaddress import ip_address
        try:
            ip = ip_address(host)
        except ValueError:
            return False
        return any(ip in net for net in self._trusted)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            client = scope.get("client")
            if client:
                peer_ip = client[0]
                if self._is_trusted(peer_ip):
                    headers = dict(scope.get("headers", []))
                    xff = headers.get(b"x-forwarded-for")
                    if xff:
                        # Leftmost is the original client.
                        real_ip = xff.decode("latin1").split(",")[0].strip()
                        if real_ip:
                            scope["client"] = (real_ip, client[1])
        await self.app(scope, receive, send)


app.add_middleware(
    _TrustedProxyHeadersMiddleware,
    trusted_hosts=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    RequestSizeLimitMiddleware,
)
app.add_middleware(
    OrgRateLimitMiddleware,
    requests_per_minute=120,
)
app.add_middleware(
    RateLimitMiddleware,
    requests_per_minute=settings.rate_limit_per_minute,
)

# CORS: allow the dashboard origin in dev; restrict in production.
# In production, the dashboard is served by the same origin (same FastAPI app),
# so CORS is not needed. In dev, allow localhost for local dashboard access.
_cors_origins: list[str] = []
if settings.app_env == "dev":
    _cors_origins = ["http://localhost:8000", "http://127.0.0.1:8000"]

if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT"],
        allow_headers=["*"],
    )

# Request logging: outermost middleware (executes first, completes last)
# so the logged duration includes all other middleware and the route handler.
app.add_middleware(RequestLoggingMiddleware)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Custom 422 handler for validation errors on the webhook.

    Returns a clear, structured response listing each invalid field and
    a human-readable error message. Safe logging records only field names
    and error types - never the full payload or any secrets.
    """
    errors = []
    for err in exc.errors():
        loc = err.get("loc", ())
        # loc is typically ("body", "<field_alias>") - extract the field name.
        field = loc[-1] if len(loc) > 1 else str(loc[0]) if loc else "unknown"
        msg = err.get("msg", "invalid value")
        errors.append({"field": field, "message": msg})

    # Safe logging: field names + error types only, never full payload values.
    field_names = [e["field"] for e in errors]
    logger.warning(
        "webhook validation rejected: fields=%s remote=%s",
        field_names,
        request.client.host if request.client else "unknown",
    )

    return JSONResponse(
        status_code=422,
        content={
            "status": "validation_error",
            "message": "Form submission has invalid fields. Please check and resubmit.",
            "errors": errors,
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler for unhandled exceptions.

    Phase 7: Ensures no stack traces, SQL errors, or internal details
    leak through HTTP responses. Returns a structured error with a
    safe message. The full exception is logged server-side only.
    """
    # Do NOT catch HTTPException - FastAPI handles those natively.
    if isinstance(exc, HTTPException):
        raise exc

    logger.exception(
        "Unhandled exception: %s %s - %s",
        request.method,
        request.url.path,
        exc,
    )

    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "An unexpected error occurred. Please try again later.",
        },
    )


# Read-only admin dashboard (Phase 4) - separate router keeps main.py lean.
from app.dashboard import AuthContext, _auth_context
from app.dashboard import router as dashboard_router

app.include_router(dashboard_router)
app.include_router(auth_router)
app.include_router(org_router)

# Phase 6E: Webhook configuration management endpoints.
from app.routers.webhook_config_router import router as webhook_config_router

app.include_router(webhook_config_router)



# Phase 23: CRM search, lead scoring, and dashboard stats.
from app.routers.crm_router import router as crm_router

app.include_router(crm_router)

# Phase 23: Follow-up management.
from app.routers.followup_router import router as followup_router

app.include_router(followup_router)

# Phase 4: Public RSVP routes (Accept/Decline).
from app.routers.rsvp_router import router as rsvp_router

app.include_router(rsvp_router)


@app.get("/health")
def health() -> dict:
    """Liveness probe - returns 200 with a JSON body when the app is up.

    Does NOT expose secrets, credentials, or internal configuration.
    """
    return {"status": "ok"}


@app.get("/health/ready")
def readiness() -> dict:
    """Readiness probe - verifies PostgreSQL connectivity.

    Returns 200 if the database is reachable, 503 otherwise.
    Does NOT perform expensive external API calls (Google, AI).
    Does NOT expose secrets or credentials.
    """
    try:
        from sqlalchemy import text

        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
        finally:
            db.close()
        return {"status": "ready", "database": "ok"}
    except Exception:
        logger.exception("readiness check failed")
        return JSONResponse(
            status_code=503,
            content={"status": "not ready", "database": "unavailable"},
        )


def _log_event(db, lead_id, event_type: str, payload: dict | None = None,
               organization_id: uuid.UUID | None = None) -> None:
    """Append an EventLog audit row (committed immediately so partial
    pipeline progress is always visible, even if a later step fails).

    Phase 6B.4: Accepts explicit organization_id to avoid relying on the
    global tenant context which may not be set in background tasks.

    Phase 1 (Hardening): organization_id is now REQUIRED.  Callers must
    always pass an explicit org_id - the default-org fallback has been
    removed.
    """
    if organization_id is None:
        raise RuntimeError(
            "_log_event() requires an explicit organization_id. "
            f"event_type={event_type!r} lead_id={lead_id}"
        )
    db.add(
        EventLog(
            lead_id=lead_id,
            event_type=event_type,
            payload=json.dumps(payload) if payload is not None else None,
            organization_id=organization_id,
        )
    )
    db.commit()


def _log_webhook_auth_failure(
    request: Request,
    org_slug: str | None,
    reason: str,
) -> None:
    """Log a webhook authentication failure to EventLog.

    Phase 6E: Webhook auth failures are now recorded for audit trail.
    Uses NULL lead_id since no lead is involved (migration 005 made
    events_log.lead_id nullable).  Attempts to resolve the org_id
    from the slug for audit trail completeness.
    The actual token is NEVER logged.
    """
    try:
        # Resolve org_id from slug when available (best-effort).
        org_id = None
        if org_slug:
            try:
                from app.tenant import lookup_organization_by_slug
                org = lookup_organization_by_slug(org_slug)
                if org is not None:
                    org_id = org.id
            except Exception:
                pass  # best-effort - don't fail if lookup fails

        db = SessionLocal()
        try:
            evt = EventLog(
                lead_id=None,
                event_type="webhook_auth_failed",
                payload=json.dumps({
                    "reason": reason,
                    "remote_ip": request.client.host if request.client else "unknown",
                    "org_slug": org_slug or "legacy",
                }),
                organization_id=org_id,
            )
            db.add(evt)
            db.flush()  # flush to catch constraint errors before commit
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
    except Exception as exc:
        # Never let audit logging failure block the main flow.
        logger.warning("Failed to log webhook auth failure: %s", exc, exc_info=True)


def _parse_appt_utc(raw: str | None, business_tz: str | None = None):
    """Best-effort parse of free-text appt time into an aware UTC datetime.

    Returns ``None`` when it can't parse - the raw string is always kept and
    the pipeline treats ``None`` as a (logged) error rather than calling
    Calendar.

    Timezone resolution order:
    1. Explicit timezone in the input (e.g. "EST", "(CDT)", "Eastern Time")
       → that timezone is used.
    2. No explicit timezone in the input → *business_tz* is used.
    3. Neither explicit nor business_tz → falls back to
       ``settings.business_timezone``.
    4. Final fallback → UTC.

    **Critical**: dateparser may auto-infer a timezone from the system
    locale (e.g. UTC in Docker containers).  When the input contains NO
    explicit timezone, this auto-inferred timezone is ALWAYS discarded in
    favour of the caller-supplied business timezone.  This ensures
    deterministic behaviour across environments.

    Handles the wide variety of free-text formats users enter in Google
    Forms, including ordinal suffixes (1st, 2nd, 3rd, 27th), parenthesised
    timezones ``(EST)``, full timezone names (``Eastern Standard Time``),
    ``at`` separators, relative dates (``tomorrow at 9 AM``), and extra
    whitespace/punctuation.
    """
    if not raw:
        return None

    # ------------------------------------------------------------------
    # 1.  Extract & remove any explicit timezone so dateparser never
    #     silently reinterprets it.  We'll re-apply it later.
    # ------------------------------------------------------------------
    cleaned, tz_abbrev = _extract_tz(raw)

    # ------------------------------------------------------------------
    # 2.  Strip form-label prefixes that users copy-paste from the
    #     Google Form question label, e.g.
    #     "Phone appt Date and Time: Monday 14th September 2026 at 10 AM PST"
    #     → "Monday 14th September 2026 at 10 AM PST"
    # ------------------------------------------------------------------
    cleaned = re.sub(
        r"Phone\s+Appt\s+Date\s+and\s+Time\s*:\s*",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )

    # ------------------------------------------------------------------
    # 3.  Normalize malformed time spacing:
    #     "9: 00 AM" → "9:00 AM"   (space between colon and minutes)
    #     "9 :00 AM" → "9:00 AM"   (space before colon)
    #     "12: 30 PM" → "12:30 PM"
    #     "9 : 00 AM" → "9:00 AM"  (spaces on both sides)
    #     Preserves valid formats: "9:00 AM", "09:00 AM", "9 AM"
    # ------------------------------------------------------------------
    cleaned = re.sub(r"(\d)\s*:\s*(\d)", r"\1:\2", cleaned)

    # ------------------------------------------------------------------
    # 4.  Strip ordinal suffixes:  "27th" → "27", "1st" → "1", etc.
    # ------------------------------------------------------------------
    cleaned = re.sub(r"(\d+)(?:st|nd|rd|th)\b", r"\1", cleaned)

    # ------------------------------------------------------------------
    # 5.  Normalise "at" between date and time:
    #     "Aug 27, 2026 at 9:00 AM" → "Aug 27, 2026 9:00 AM"
    # ------------------------------------------------------------------
    cleaned = re.sub(r"(\d)\s+at\s+(\d)", r"\1 \2", cleaned)

    # ------------------------------------------------------------------
    # 6.  Collapse redundant whitespace / leading-trailing junk.
    # ------------------------------------------------------------------
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" ,.;:!")

    # ------------------------------------------------------------------
    # 7.  Parse with dateparser.
    #     If a timezone was detected, pass it as a hint so dateparser
    #     applies the correct offset even when the tz string is gone.
    # ------------------------------------------------------------------
    dp_settings = {
        "RETURN_AS_TIMEZONE_AWARE": True,
        "PREFER_DATES_FROM": "future",
    }
    if tz_abbrev:
        dp_settings["TIMEZONE"] = tz_abbrev

    dt = dateparser.parse(cleaned, settings=dp_settings)
    if dt is None:
        dt = dateparser.parse(raw, settings=dp_settings)
    if dt is None:
        return None

    # ------------------------------------------------------------------
    # 8.  Apply the correct source timezone.
    #
    #     When the user provided an explicit timezone in the input,
    #     honour it - dateparser received the TIMEZONE hint and applied
    #     the correct offset.  When no explicit timezone was provided,
    #     ALWAYS use the caller-supplied business_tz (never the system
    #     locale) to ensure deterministic behaviour across environments.
    # ------------------------------------------------------------------
    # Determine the fallback business timezone: caller-supplied > global setting.
    _fallback_tz_name = (
        business_tz
        or getattr(settings, "business_timezone", None)
        or "UTC"
    )

    if tz_abbrev:
        # Explicit timezone in the input - dateparser already applied the
        # TIMEZONE hint.  If it returned an aware datetime, trust it.
        # Only apply explicitly when dateparser returned naive (rare edge
        # case where the hint was ignored).
        if dt.tzinfo is None:
            iana = _TZ_ABBREV_TO_IANA.get(tz_abbrev, tz_abbrev)
            try:
                dt = dt.replace(tzinfo=ZoneInfo(iana))
            except Exception:
                dt = dt.replace(tzinfo=timezone.utc)
    else:
        # No explicit timezone in the input - use business timezone,
        # discarding any auto-inferred timezone from dateparser.
        # This is the critical Docker fix: when the container's system
        # timezone is UTC, dateparser auto-infers UTC which is wrong
        # for a US business.  We MUST use the org's configured timezone.
        try:
            dt = dt.replace(tzinfo=ZoneInfo(_fallback_tz_name))
        except Exception:
            dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def _resolve_customer_tz(raw: str | None, business_tz: str | None = None) -> str:
    """Resolve the IANA timezone name from a raw datetime string.

    Uses the same timezone extraction logic as ``_parse_appt_utc`` but
    returns only the resolved IANA timezone name (e.g. ``"America/New_York"``).

    Falls back to *business_tz* → ``settings.business_timezone`` → ``"UTC"``
    when no explicit timezone is present in *raw*.
    """
    _fallback = (
        business_tz
        or getattr(settings, "business_timezone", None)
        or "UTC"
    )

    if not raw:
        return _fallback

    _cleaned, tz_abbrev = _extract_tz(raw)
    if tz_abbrev:
        return _TZ_ABBREV_TO_IANA.get(tz_abbrev, tz_abbrev)

    return _fallback


# Mapping of timezone strings (longest first) → IANA / abbreviation key
# that can be fed back to dateparser or used with ZoneInfo.
_TZ_STRINGS_TO_KEY: dict[str, str] = {
    "Eastern Standard Time": "EST",
    "Central Standard Time": "CST",
    "Mountain Standard Time": "MST",
    "Pacific Standard Time": "PST",
    "Eastern Daylight Time": "EDT",
    "Central Daylight Time": "CDT",
    "Mountain Daylight Time": "MDT",
    "Pacific Daylight Time": "PDT",
    "Eastern Time": "EST",
    "Central Time": "CST",
    "Mountain Time": "MST",
    "Pacific Time": "PST",
    "UTC": "UTC",
    "GMT": "GMT",
    "EST": "EST",
    "CST": "CST",
    "MST": "MST",
    "PST": "PST",
    "EDT": "EDT",
    "CDT": "CDT",
    "MDT": "MDT",
    "PDT": "PDT",
}

# Mapping from timezone abbreviations to valid IANA/Olson timezone names.
# Abbreviations like "CST" are ambiguous (Central vs China) and are NOT
# valid ZoneInfo keys on all platforms.  We map to the most likely US
# interpretation since this application only deals with US appointments.
_TZ_ABBREV_TO_IANA: dict[str, str] = {
    "EST": "America/New_York",
    "EDT": "America/New_York",
    "CST": "America/Chicago",
    "CDT": "America/Chicago",
    "MST": "America/Denver",
    "MDT": "America/Denver",
    "PST": "America/Los_Angeles",
    "PDT": "America/Los_Angeles",
    "UTC": "UTC",
    "GMT": "GMT",
}

# Regex that matches a timezone string at the end of the input, with
# optional surrounding punctuation or parentheses.
_TZ_REGEX = re.compile(
    r"[\s,]*"
    r"(?:"
    r"\((?:EST|CST|MST|PST|EDT|CDT|MDT|PDT|UTC|GMT"
    r"|Eastern\s+Time|Central\s+Time|Mountain\s+Time|Pacific\s+Time"
    r"|Eastern\s+Standard\s+Time|Central\s+Standard\s+Time"
    r"|Mountain\s+Standard\s+Time|Pacific\s+Standard\s+Time"
    r"|Eastern\s+Daylight\s+Time|Central\s+Daylight\s+Time"
    r"|Mountain\s+Daylight\s+Time|Pacific\s+Daylight\s+Time)"
    r"|"
    r"(?:Eastern\s+Time|Central\s+Time|Mountain\s+Time|Pacific\s+Time"
    r"|Eastern\s+Standard\s+Time|Central\s+Standard\s+Time"
    r"|Mountain\s+Standard\s+Time|Pacific\s+Standard\s+Time"
    r"|Eastern\s+Daylight\s+Time|Central\s+Daylight\s+Time"
    r"|Mountain\s+Daylight\s+Time|Pacific\s+Daylight\s+Time"
    r"|EST|CST|MST|PST|EDT|CDT|MDT|PDT|UTC|GMT)"
    r")\s*",
    re.IGNORECASE,
)

# Phase 34: Regex for timezone abbreviations appearing MID-STRING
# (e.g. "10:00 AM EST on September 15, 2026").  Matches a timezone
# that is preceded by time-of-day digits and followed by a word
# boundary, preventing false matches against unrelated text.
# Supports both abbreviations (EST, PST …) and full names
# (Eastern Time, Pacific Standard Time …).
_TZ_MID_STRING_REGEX = re.compile(
    r"(\d)\s+"
    r"(?:EST|CST|MST|PST|EDT|CDT|MDT|PDT|UTC|GMT"
    r"|Eastern\s+Time|Central\s+Time|Mountain\s+Time|Pacific\s+Time"
    r"|Eastern\s+Standard\s+Time|Central\s+Standard\s+Time"
    r"|Mountain\s+Standard\s+Time|Pacific\s+Standard\s+Time"
    r"|Eastern\s+Daylight\s+Time|Central\s+Daylight\s+Time"
    r"|Mountain\s+Daylight\s+Time|Pacific\s+Daylight\s+Time)"
    r"\b",
    re.IGNORECASE,
)


def _extract_tz(text: str) -> tuple[str, str]:
    """Strip timezone information from *text* and return ``(cleaned, tz_key)``.

    *tz_key* is an abbreviation such as ``"EST"`` or ``"UTC"`` that can be
    passed to ``dateparser`` via the ``TIMEZONE`` setting, or used with
    ``ZoneInfo``.  It is ``""`` when no timezone was found.

    Phase 34: Also matches timezone abbreviations appearing mid-string
    (e.g. ``"10:00 AM EST on September 15, 2026"``) via a secondary
    regex that requires the timezone to be preceded by time-of-day digits.
    """
    # First try the original end-of-string pattern.
    m = _TZ_REGEX.search(text)
    if m:
        # Extract the raw matched string, strip parentheses and whitespace.
        raw_tz = m.group(0).strip()
        inside = raw_tz.strip("() ")
        key = _TZ_STRINGS_TO_KEY.get(inside, "")
        if not key:
            key = inside.upper()
        cleaned = text[:m.start()] + text[m.end():]
        return cleaned, key

    # Phase 34: Try mid-string timezone (e.g. "10:00 AM EST on Sep 15").
    m2 = _TZ_MID_STRING_REGEX.search(text)
    if m2:
        # group(0) includes the preceding digit from the time; extract
        # only the timezone portion which starts after that digit.
        full_match = m2.group(0)
        # The timezone starts after the first character (the digit).
        tz_part = full_match[1:].strip()
        # Handle parenthesised timezone: "(EST)" → "EST"
        inside = tz_part.strip("() ")
        key = _TZ_STRINGS_TO_KEY.get(inside, "")
        if not key:
            key = inside.upper()
        if key:
            # Remove the timezone from the text.  Also strip a trailing
            # " on " or ", " that typically follows mid-string timezones.
            start = m2.start() + 1  # skip the captured digit
            end = m2.end()
            cleaned = text[:start] + text[end:]
            # Clean up trailing connectors left behind.
            cleaned = re.sub(r"\s+on\b\s*", " ", cleaned, count=1)
            cleaned = re.sub(r"^\s*,\s*", "", cleaned)
            cleaned = re.sub(r"\s+", " ", cleaned).strip()
            return cleaned, key

    return text, ""


# ---------------------------------------------------------------------------
# Phase 9 - Error Message Sanitization
#
# When integration health checks fail, the raw exception may contain
# credentials, tokens, or internal paths. This function sanitizes the
# error message to prevent credential leakage through API responses.
# ---------------------------------------------------------------------------

_SENSITIVE_PATTERNS = re.compile(
    r"(api[_-]?key|secret|token|password|credential|authorization|refresh_token"
    r"|access_token|bearer|client_secret|private[_-]?key)",
    re.IGNORECASE,
)


def _sanitize_error_message(raw: str | None) -> str | None:
    """Sanitize an error message for safe external display.

    Removes or masks anything that looks like a credential, token, or
    secret. Truncates to 200 chars. Returns None if the input is empty.
    """
    if not raw:
        return None
    # Truncate early
    msg = raw[:200]
    # If the message contains sensitive patterns, replace with generic message
    if _SENSITIVE_PATTERNS.search(msg):
        return "Service authentication error. Please check integration configuration."
    return msg


def _classify_error(exc: Exception) -> str:
    """Classify an exception into a user-friendly error category.

    Returns one of: 'auth', 'network', 'config', 'rate_limit', 'permission', 'unknown'.
    Used by the integration-health endpoint to provide structured error info.
    """
    msg = str(exc).lower()
    # Auth / token errors
    if any(kw in msg for kw in ("token", "unauthorized", "401", "403", "invalid_grant",
                                 "refresh token", "access token", "credentials are not valid")):
        return "auth"
    # Network errors
    if any(kw in msg for kw in ("connect", "network", "timeout", "dns", "resolved",
                                 "connection refused", "eof", "socket")):
        return "network"
    # Config errors (missing credentials, not configured)
    if any(kw in msg for kw in ("not configured", "no organization", "missing",
                                 "credentials incomplete", "not set")):
        return "config"
    # Rate limiting
    if any(kw in msg for kw in ("rate limit", "429", "too many requests")):
        return "rate_limit"
    # Permission / scope errors
    if any(kw in msg for kw in ("permission", "scope", "insufficient",
                                 "access denied", "forbidden")):
        return "permission"
    return "unknown"


def run_pipeline(lead_id: uuid.UUID) -> None:
    """Phase 1 pipeline: Calendar event -> AI email -> Gmail send.

    Runs as a BackgroundTask with its own DB session. Handles partial
    failure: never creates a second Calendar event on retry, logs every
    step, and marks the lead "error" (not stuck "pending") on failure.
    """
    try:
        _run_pipeline_inner(lead_id)
    except Exception:
        logger.exception("catastrophic pipeline failure for lead %s", lead_id)


def _run_pipeline_inner(lead_id: uuid.UUID) -> None:
    db = SessionLocal()
    try:
        lead = db.get(Lead, lead_id)
        if lead is None:
            return

        # Race guard: a duplicate webhook may arrive while a previous
        # background task is already processing this lead.
        if lead.status != LeadStatus.PENDING:
            logger.info("lead %s not pending (status=%s); skipping pipeline", lead_id, lead.status)
            return

        # Phase 8: Atomic claim - H2 fix.  The old check-then-set
        # (read processing_started_at, then UPDATE) had a race window:
        # two concurrent workers could both read NULL and both run the
        # pipeline, creating duplicate calendar events / emails.
        # A single conditional UPDATE is atomic on Postgres and SQLite:
        # exactly one worker wins the claim.
        now = datetime.now(timezone.utc)
        claimed = (
            db.query(Lead)
            .filter(
                Lead.id == lead_id,
                Lead.status == LeadStatus.PENDING,
                Lead.processing_started_at.is_(None),
            )
            .update(
                {"processing_started_at": now},
                synchronize_session=False,
            )
        )
        db.commit()
        if claimed == 0:
            logger.info(
                "lead %s already claimed by another worker; skipping", lead_id
            )
            return
        # Re-fetch so the ORM object reflects the claimed state.
        db.expire_all()
        lead = db.get(Lead, lead_id)
        if lead is None:
            return

        # Defensive: never call the Calendar API without a start time.
        if lead.appt_datetime_utc is None:
            _log_event(db, lead.id, "error", {"reason": "appt_datetime_utc is None"},
                       organization_id=lead.organization_id)
            lead.status = LeadStatus.ERROR
            db.commit()
            return

        # Lazy imports so /health and table creation work without Google/AI creds.
        from app.services.ai_service import AIService
        from app.services.calendar_service import CalendarService
        from app.services.email_service import EmailService
        from app.services.meeting_provider import DEFAULT_MEETING_DURATION_MINUTES
        from app.services.org_context import OrganizationContext

        # ── Org-id audit trail ──────────────────────────────────────
        # Log which organization this lead belongs to so misconfigurations
        # (e.g. wrong slug in Google Form webhook URL) are immediately
        # visible in logs instead of silently failing deep in services.
        if not lead.organization_id:
            logger.error(
                "pipeline ABORT: lead %s has no organization_id - "
                "this should never happen for org-scoped webhooks. "
                "Likely cause: legacy /webhooks/form-submission endpoint "
                "used without multi-tenant context.",
                lead_id,
            )
            lead.status = LeadStatus.ERROR
            db.commit()
            return

        logger.info(
            "pipeline start: lead=%s org_id=%s",
            lead_id,
            lead.organization_id,
        )

        # Build org context from the lead's organization for credential resolution.
        org_ctx = OrganizationContext.from_id(lead.organization_id)

        # ── Early credential validation ─────────────────────────────
        # Check whether this org has ANY integrations configured.  If not,
        # the pipeline will fail deep in service constructors with a
        # confusing error.  Fail fast with a clear diagnostic instead.
        try:
            from app.models_multi_tenant import IntegrationStatus, OrgIntegration
            has_calendar = db.query(OrgIntegration).filter(
                OrgIntegration.organization_id == lead.organization_id,
                OrgIntegration.integration_type == "google_oauth",
                OrgIntegration.status == IntegrationStatus.CONNECTED,
            ).first() is not None
            if not has_calendar:
                logger.warning(
                    "pipeline WARN: org %s has no CONNECTED Google OAuth "
                    "integration - pipeline will likely fail at calendar "
                    "event creation.  Verify the webhook URL uses the "
                    "correct org slug for an org that has Google OAuth "
                    "configured.",
                    lead.organization_id,
                )
        except Exception:
            pass  # non-fatal - let the pipeline proceed and fail naturally

        try:
            # Step 1: Meeting creation via provider abstraction.
            # Zoom or Google Meet - resolved from org integrations.
            meet_link = None
            provider_used = "google_meet"

            from app.services.meeting_provider import (
                ZoomMeetingProvider,
                resolve_meeting_provider,
            )

            if org_ctx is not None:
                provider = resolve_meeting_provider(
                    org_context=org_ctx, db=db
                )
                if isinstance(provider, ZoomMeetingProvider):
                    provider_used = "zoom"

            if provider_used == "zoom":
                # ── Zoom path ──────────────────────────────────────
                if not lead.zoom_meeting_id:
                    details = provider.create_meeting(
                        summary=lead.company_address or "Strategy Call",
                        description=f"Strategy call for {lead.name or lead.company_address or 'lead'}",
                        start_utc=lead.appt_datetime_utc,
                        duration_minutes=DEFAULT_MEETING_DURATION_MINUTES,
                        attendees=[lead.email] if lead.email else [],
                        idempotency_key=str(lead.id),
                        timezone=settings.business_timezone,
                    )
                    lead.zoom_meeting_id = details.meeting_id
                    lead.zoom_join_url = details.meeting_link
                    meet_link = details.meeting_link
                    db.commit()
                    _log_event(
                        db, lead.id, "zoom_meeting_created",
                        {"meeting_id": details.meeting_id, "meet_link": details.meeting_link},
                        organization_id=lead.organization_id,
                    )
                else:
                    # Re-fetch join URL for existing Zoom meeting.
                    meet_link = lead.zoom_join_url
                    if not meet_link:
                        try:
                            meet_link = provider.get_meeting_link(lead.zoom_meeting_id)
                        except Exception:
                            logger.warning(
                                "could not re-fetch Zoom join URL for lead %s", lead_id
                            )

                # Create a Google Calendar event as the scheduling/RSVP
                # record.  The event uses the Zoom join URL as its location
                # but does NOT create a Google Meet conference.
                if not lead.calendar_event_id:
                    try:
                        cal_svc = CalendarService(
                            org_context=org_ctx, db=db
                        )
                        event_id, _ = cal_svc.create_event(
                            lead, db,
                            external_meeting_link=meet_link,
                        )
                        lead.calendar_event_id = event_id
                        db.commit()
                        _log_event(
                            db, lead.id, "calendar_created",
                            {
                                "event_id": event_id,
                                "provider": "zoom",
                                "meet_link": meet_link,
                            },
                            organization_id=lead.organization_id,
                        )
                    except Exception as exc:
                        # Zoom meeting is already created and stored.
                        # Log but continue - RSVP/reminder features will be
                        # degraded but the lead is still callable.
                        logger.warning(
                            "calendar event creation failed for Zoom lead %s "
                            "(org_id=%s, operation=calendar_create, "
                            "exception_type=%s, exception_message=%s); "
                            "RSVP/reminder features will be degraded",
                            lead_id,
                            lead.organization_id,
                            type(exc).__name__,
                            str(exc),
                            exc_info=True,
                        )
            else:
                # ── Google Meet path (unchanged) ───────────────────
                if not lead.calendar_event_id:
                    event_id, meet_link = CalendarService(org_context=org_ctx, db=db).create_event(lead, db)
                    lead.calendar_event_id = event_id
                    db.commit()
                    _log_event(db, lead.id, "calendar_created", {"event_id": event_id, "meet_link": meet_link},
                               organization_id=lead.organization_id)
                else:
                    # Re-fetch Meet link from the existing Calendar event.
                    try:
                        meet_link = CalendarService(org_context=org_ctx, db=db).get_meet_link(lead.calendar_event_id)
                    except Exception:
                        logger.warning("could not re-fetch Meet link for lead %s", lead_id)

            # Step 2: AI-personalized greeting paragraph.
            ai_paragraph = None
            model_used = "static_fallback"
            try:
                ai_paragraph, model_used = AIService(org_context=org_ctx, db=db).generate_confirmation_email(lead, meet_link, db)
            except Exception:
                ai_paragraph = "Your strategy call has been successfully scheduled."
                model_used = "static_fallback"
            _log_event(db, lead.id, "email_generated", {"model_used": model_used},
                       organization_id=lead.organization_id)

            # Step 3: Build HTML + plain-text from deterministic templates,
            # then send via Gmail.
            # IDEMPOTENCY GUARD: If an email_sent event already exists for
            # this lead, skip sending to prevent duplicate emails after a
            # mid-pipeline crash.
            already_sent = (
                db.query(EventLog)
                .filter(
                    EventLog.lead_id == lead.id,
                    EventLog.event_type == "email_sent",
                )
                .first()
                is not None
            )
            if already_sent:
                logger.info(
                    "lead %s already has email_sent event; skipping duplicate send",
                    lead_id,
                )
            else:
                from zoneinfo import ZoneInfo as _ZI

                from app.services.email_templates import (
                    build_confirmation_html,
                    build_confirmation_text,
                )
                from app.services.integration_config_resolver import (
                    IntegrationConfigResolver,
                )

                tz = _ZI(settings.business_timezone)
                # Phase 6D: Resolve per-org branding for email templates
                branding = None
                if org_ctx is not None:
                    try:
                        branding = IntegrationConfigResolver.resolve_branding(db, org_ctx.organization_id)
                    except Exception:
                        branding = None

                # Phase 4: Generate RSVP tokens and build URLs for the email.
                # Tokens require lead status to be SCHEDULED; set temporarily
                # so generate_rsvp_tokens() can validate the lead.
                rsvp_accept_url = None
                rsvp_decline_url = None
                try:
                    from app.services.rsvp_token_service import generate_rsvp_tokens
                    # Temporarily set status to SCHEDULED for token generation
                    lead.status = LeadStatus.SCHEDULED
                    accept_token, decline_token = generate_rsvp_tokens(db, lead)
                    base_url = settings.rsvp_base_url.rstrip("/")
                    rsvp_accept_url = f"{base_url}/rsvp/{accept_token}"
                    rsvp_decline_url = f"{base_url}/rsvp/{decline_token}"
                    _log_event(
                        db, lead.id, "rsvp_tokens_generated",
                        {"accept_url": rsvp_accept_url, "decline_url": rsvp_decline_url},
                        organization_id=lead.organization_id,
                    )
                except Exception as exc:
                    # Non-fatal: email still sends without RSVP buttons
                    logger.warning(
                        "RSVP token generation failed for lead %s (non-fatal): %s",
                        lead_id, exc,
                    )
                    # Revert status if token generation failed mid-flow
                    if lead.status == LeadStatus.SCHEDULED:
                        lead.status = LeadStatus.PENDING

                html_body = build_confirmation_html(
                    lead, meet_link, ai_paragraph, tz,
                    branding=branding, meeting_provider=provider_used,
                    rsvp_accept_url=rsvp_accept_url,
                    rsvp_decline_url=rsvp_decline_url,
                )
                text_body = build_confirmation_text(
                    lead, meet_link, ai_paragraph, tz,
                    branding=branding, meeting_provider=provider_used,
                    rsvp_accept_url=rsvp_accept_url,
                    rsvp_decline_url=rsvp_decline_url,
                )
                # Phase 10B: Guard against leads with no email address.
                # The webhook schema requires email, but defensive check prevents
                # a confusing TypeError deep in EmailService.send_email().
                if not lead.email:
                    _log_event(db, lead.id, "error", {"reason": "lead has no email address"},
                               organization_id=lead.organization_id)
                    lead.status = LeadStatus.ERROR
                    lead.processing_started_at = None
                    db.commit()
                    return
                message_id = EmailService(org_context=org_ctx, db=db).send_confirmation_email(lead, text_body, html_body, db)
                _log_event(db, lead.id, "email_sent", {"message_id": message_id, "to": lead.email},
                           organization_id=lead.organization_id)

            lead.status = LeadStatus.SCHEDULED
            lead.processing_started_at = None  # Phase 8: clear lock
            db.commit()
            logger.info(
                "pipeline completed: lead=%s org_id=%s status=scheduled",
                lead_id, lead.organization_id,
            )
            publish_event("pipeline.completed", {"lead_id": str(lead_id), "status": "scheduled"}, organization_id=lead.organization_id)
        except Exception as exc:
            db.rollback()
            logger.exception("pipeline failed for lead %s", lead_id)
            try:
                # Re-fetch lead to get organization_id for FailedJob and EventLog.
                lead = db.get(Lead, lead_id)
                if lead is None or lead.organization_id is None:
                    logger.error(
                        "cannot record pipeline failure for lead %s: "
                        "lead not found or has no organization_id", lead_id,
                    )
                    return

                # Record a FailedJob for any failure not already recorded inside
                # a service (e.g. auth errors raised in service constructors).
                from app.services.retry import record_failed_job

                record_failed_job(
                    db,
                    job_type="pipeline",
                    payload=json.dumps({"lead_id": str(lead_id)}),
                    error=str(exc),
                    organization_id=lead.organization_id,
                )
                lead.status = LeadStatus.ERROR
                lead.processing_started_at = None  # Phase 8: clear lock
                db.commit()
                _log_event(db, lead_id, "error", {"error": str(exc)[:2000]},
                           organization_id=lead.organization_id)
            except Exception:
                logger.exception("failed to record pipeline error for lead %s", lead_id)
                db.rollback()
            publish_event("pipeline.failed", {"lead_id": str(lead_id), "error": str(exc)[:200]}, organization_id=lead.organization_id if lead is not None else None)
    finally:
        db.close()


def _verify_bearer_auth(request: Request, secret: str, org_slug: str | None = None) -> None:
    """Verify Bearer token from the Authorization header.

    Uses constant-time comparison (secrets.compare_digest) to prevent
    timing attacks.  Raises 401 on failure - never logs the token itself.

    Phase 6E: When org_slug is provided, auth failures are logged to
    EventLog for audit trail.  The event_type is "webhook_auth_failed"
    and includes the remote IP and org slug (but NOT the token).
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        logger.warning(
            "webhook rejected: missing Authorization header remote=%s org=%s",
            request.client.host if request.client else "unknown",
            org_slug or "legacy",
        )
        _log_webhook_auth_failure(request, org_slug, "missing_header")
        raise HTTPException(
            status_code=401,
            detail="missing or invalid Authorization header",
        )
    provided_token = auth_header[7:]  # strip "Bearer "
    # M12 fix: reject empty secrets/tokens BEFORE compare_digest -
    # compare_digest("", "") is True, which would be an auth bypass if
    # this function were ever called with an empty secret.
    if not secret or not provided_token:
        _log_webhook_auth_failure(request, org_slug, "empty_token")
        raise HTTPException(status_code=401, detail="invalid webhook secret")
    if not secrets.compare_digest(provided_token, secret):
        logger.warning(
            "webhook rejected: invalid Bearer token remote=%s org=%s",
            request.client.host if request.client else "unknown",
            org_slug or "legacy",
        )
        _log_webhook_auth_failure(request, org_slug, "invalid_token")
        raise HTTPException(status_code=401, detail="invalid webhook secret")


def _handle_form_submission(
    submission: FormSubmission,
    background_tasks: BackgroundTasks,
    organization_id: uuid.UUID,
    request_id: str | None = None,
) -> dict:
    """Shared lead-ingestion logic for both the org-scoped and legacy routes.

    Creates the Lead, handles Interested=No gating, records form_submitted
    event, and kicks off the background pipeline for active leads.

    Phase 6E: Accepts optional request_id for idempotency tracking.
    Apps Script sends a unique request_id to prevent duplicate processing
    on retries.  When a duplicate dedupe_key is detected, the request_id
    is included in the duplicate response so the caller can confirm it
    was the same submission.

"""
    db = SessionLocal()
    try:
        from app.models_multi_tenant import Organization
        org_check = db.query(Organization).filter(
            Organization.id == organization_id
        ).first()

        # Determine initial status based on Interested field.
        if submission.interested and submission.interested.lower() == "no":
            initial_status = LeadStatus.NOT_INTERESTED
        else:
            initial_status = LeadStatus.PENDING

        # Resolve organization timezone for date parsing.
        _org_tz = (
            org_check.timezone
            if org_check and getattr(org_check, "timezone", None)
            else settings.business_timezone
        )

        # Resolve appointment datetime from any available field.
        # The Google Form may deliver the datetime in different fields
        # depending on the form layout; try them in priority order.
        appt_dt: datetime | None = None
        customer_tz: str = ""
        for candidate in submission.get_appt_datetime_candidates():
            appt_dt = _parse_appt_utc(candidate, business_tz=_org_tz)
            if appt_dt is not None:
                customer_tz = _resolve_customer_tz(candidate, business_tz=_org_tz)
                break

        # Phase 27b: Reject clearly-past appointments at ingestion.
        # Past dates would be caught later by _recover_stuck_leads but
        # creating them as PENDING first creates unnecessary churn.
        if (
            appt_dt is not None
            and initial_status == LeadStatus.PENDING
            and appt_dt < datetime.now(timezone.utc)
        ):
            logger.info(
                "lead rejected: past appointment %s (raw=%r) for org %s",
                appt_dt, submission.appt_datetime_raw, organization_id,
            )
            # Still record the lead for observability but as ERROR.
            initial_status = LeadStatus.ERROR

        lead = Lead(
            interested=submission.interested,
            name=submission.name,
            company_address=submission.company_address,
            phone_number=submission.phone_number,
            direct_number=submission.direct_number,
            courses=submission.courses,
            email=str(submission.email),
            scheduled_date=submission.scheduled_date,
            caller_name=submission.caller_name,
            appt_datetime_raw=submission.appt_datetime_raw,
            appt_datetime_utc=appt_dt,
            customer_timezone=customer_tz or None,
            dedupe_key=submission.compute_dedupe_key(
                organization_id=str(organization_id), appt_utc=appt_dt
            ),
            status=initial_status,
            organization_id=organization_id,
        )
        db.add(lead)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            # Duplicate submission (same email + same appt time) - dedupe.
            # Phase 6E: Include request_id in response for idempotency tracking.
            dedupe_key = submission.compute_dedupe_key(
                organization_id=str(organization_id), appt_utc=appt_dt
            )
            logger.info(
                "webhook dedup: duplicate submission rejected "
                "(email=%s, dedupe_key=%s, org=%s, request_id=%s)",
                submission.email, dedupe_key, organization_id, request_id,
            )
            result = {"status": "duplicate"}
            if request_id:
                result["request_id"] = request_id
            return result
        db.refresh(lead)
        _log_event(
            db, lead.id, "form_submitted",
            {
                "dedupe_key": lead.dedupe_key,
                "request_id": request_id,
            },
            organization_id=organization_id,
        )
        lead_id = lead.id
        interested = submission.interested
    finally:
        db.close()

    logger.info(
        "webhook accepted: lead created id=%s name=%s email=%s "
        "status=%s org=%s request_id=%s",
        lead_id, submission.name, submission.email,
        initial_status, organization_id, request_id,
    )

    # Gate: Interested=No never enters the pipeline.
    if interested and interested.lower() == "no":
        log_db = SessionLocal()
        try:
            _log_event(
                log_db,
                lead_id,
                "form_ignored",
                {"reason": "interested=no", "request_id": request_id},
                organization_id=organization_id,
            )
        finally:
            log_db.close()
        logger.info(
            "webhook gate: lead %s ignored (interested=no) org=%s",
            lead_id, organization_id,
        )
        publish_event(
            "lead.ignored",
            {"lead_id": str(lead_id), "name": submission.name},
            organization_id=organization_id,
        )
        result = {"status": "ignored", "lead_id": str(lead_id)}
        if request_id:
            result["request_id"] = request_id
        return result

    background_tasks.add_task(run_pipeline, lead_id)
    logger.info(
        "webhook pipeline dispatched: lead=%s org=%s request_id=%s",
        lead_id, organization_id, request_id,
    )
    publish_event(
        "lead.created",
        {"lead_id": str(lead_id), "name": submission.name},
        organization_id=organization_id,
    )
    result = {"status": "accepted", "lead_id": str(lead_id)}
    if request_id:
        result["request_id"] = request_id
    return result


# ── Org-scoped webhook (Phase 6B.5) ─────────────────────────────────────────
# NEW route - registered BEFORE the legacy route so FastAPI matches it first.
# Apps Script sends to: POST /webhooks/{org_slug}/form-submission


@app.post("/webhooks/{org_slug}/form-submission", status_code=202)
async def org_form_submission(
    org_slug: str,
    background_tasks: BackgroundTasks,
    request: Request,
) -> dict:
    """Ingest a Google Form submission for a specific organization.

    Route: POST /webhooks/{org_slug}/form-submission

    Resolves the organization from the URL slug, verifies it is active,
    authenticates using the org's webhook_secret (falling back to the
    global WEBHOOK_SECRET), and ingests the form submission.

    Phase 29: Uses the organization's field mapping to translate form
    question labels to canonical Lead fields before validation.
    Falls back to default mapping when no custom mapping is configured.

    Returns immediately (202) - the Calendar/AI/Gmail work runs in a
    background task so the Apps Script caller isn't kept waiting.

    If Interested? == "No", the lead is recorded for observability but
    NEVER enters the active pipeline.

    SECURITY:
    - Slug must resolve to an ACTIVE organization (404 otherwise)
    - Bearer token is validated against org secret, then global secret
    - Constant-time comparison prevents timing attacks
    - Credentials are NEVER logged
    """
    from app.schemas import FormSubmission
    from app.services.field_mapping_resolver import load_field_mapping

    # Step 1: Resolve organization from slug.
    org = lookup_organization_by_slug(org_slug)
    if org is None:
        # SECURITY: Do not reveal whether the slug exists but is disabled.
        # Return a generic 404 to avoid information leakage.
        logger.warning(
            "webhook org lookup failed: slug=%s remote=%s",
            org_slug,
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=404,
            detail="organization not found",
        )

    # Step 2: Verify Bearer token (org secret → global secret fallback).
    # When the org has a webhook_secret configured, use it exclusively
    # (do NOT fall back to the global secret for org-scoped routes).
    org_secret = getattr(org, "webhook_secret", None)
    if org_secret:
        # Org has its own secret - use it exclusively.
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.warning(
                "webhook rejected: missing Authorization header remote=%s org=%s",
                request.client.host if request.client else "unknown",
                org_slug,
            )
            _log_webhook_auth_failure(request, org_slug, "missing_header")
            raise HTTPException(
                status_code=401,
                detail="missing or invalid Authorization header",
            )
        provided_token = auth_header[7:]
        if not secrets.compare_digest(provided_token, org_secret):
            logger.warning(
                "webhook rejected: invalid Bearer token remote=%s org=%s",
                request.client.host if request.client else "unknown",
                org_slug,
            )
            _log_webhook_auth_failure(request, org_slug, "invalid_token")
            raise HTTPException(status_code=401, detail="invalid webhook secret")
    elif settings.webhook_secret:
        # No org secret - fall back to global webhook secret.
        _verify_bearer_auth(request, settings.webhook_secret)
    # else: no secret configured anywhere - allow (dev mode)

    # Step 3: Read raw JSON body and apply org field mapping.
    body_bytes = await request.body()
    try:
        payload = json.loads(body_bytes)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid JSON body")

    # Load org's field mapping and translate the payload.
    db = SessionLocal()
    try:
        field_mapping = load_field_mapping(db, org.id)
    finally:
        db.close()

    try:
        submission = FormSubmission.from_webhook_payload(payload, field_mapping)
    except Exception as exc:
        logger.warning(
            "webhook validation failed for org %s: %s",
            org.id, str(exc)[:200],
        )
        raise HTTPException(
            status_code=422,
            detail=f"Form submission validation failed: {exc}",
        )

    # Step 4: Ingest the form submission with org context.
    # Phase 6E: Extract request_id from header for idempotency tracking.
    request_id = request.headers.get("X-Request-ID") or None
    return _handle_form_submission(submission, background_tasks, org.id, request_id=request_id)


# ── Legacy webhook - REMOVED (Phase 1 Hardening) ────────────────────────────
# The legacy /webhooks/form-submission endpoint without an org_slug is no
# longer supported.  Apps Script must use POST /webhooks/{org_slug}/form-submission.


@app.post("/webhooks/form-submission", status_code=410)
def form_submission(
    submission: FormSubmission,
    background_tasks: BackgroundTasks,
    request: Request,
) -> dict:
    """LEGACY endpoint - REMOVED in Phase 1 (Multi-Tenant Hardening).

    This endpoint previously resolved all requests to a default organization,
    which is a tenant-isolation violation.  Apps Script installations must
    use the org-scoped endpoint instead:

        POST /webhooks/{org_slug}/form-submission

    Returns 410 Gone with migration instructions.
    """
    raise HTTPException(
        status_code=410,
        detail={
            "error": "gone",
            "message": (
                "This endpoint is no longer supported. Update your Apps Script "
                "to POST to /webhooks/{org_slug}/form-submission instead. "
                "See docs/STATE.md for migration instructions."
            ),
        },
    )


# --- Schedule settings + manual triggers (Phase 5) ---
# Protected by the dashboard's HTTPBasic auth (single auth mechanism).
# The old /internal/* endpoints (INTERNAL_API_SECRET) are removed.

_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _validate_settings(payload: dict) -> None:
    """Validate schedule settings; raise 422 with a clear message on bad input."""
    if "reminder_time" in payload:
        rt = payload["reminder_time"]
        if not isinstance(rt, str) or not _HHMM.match(rt):
            raise HTTPException(
                status_code=422,
                detail="reminder_time must be valid HH:MM (24hr), e.g. '08:00'",
            )
    if "rsvp_poll_interval_minutes" in payload:
        iv = payload["rsvp_poll_interval_minutes"]
        if not isinstance(iv, int) or iv < 1:
            raise HTTPException(
                status_code=422,
                detail="rsvp_poll_interval_minutes must be a positive integer (>= 1)",
            )


@app.get("/dashboard/api/settings")
def get_settings(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Return the current schedule configuration.

    Phase 6B.6: Customer users see their org's OrgScheduleConfig.
    Platform admins see the global ScheduleConfig.
    """
    if auth_ctx.org_id is not None:
        # Customer user - read from OrgScheduleConfig
        from app.models_multi_tenant import OrgScheduleConfig
        cfg = (
            db.query(OrgScheduleConfig)
            .filter(OrgScheduleConfig.organization_id == auth_ctx.org_id)
            .first()
        )
        if cfg is None:
            # Create default config for this org
            cfg = OrgScheduleConfig(
                organization_id=auth_ctx.org_id,
                timezone="America/Chicago",
                reminder_hour=8,
                reminder_minute=0,
                rsvp_poll_interval_minutes=10,
            )
            db.add(cfg)
            db.commit()
            db.refresh(cfg)
        return {
            "reminder_time": f"{cfg.reminder_hour:02d}:{cfg.reminder_minute:02d}",
            "rsvp_poll_interval_minutes": cfg.rsvp_poll_interval_minutes,
            "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None,
        }
    else:
        # Platform admin - global ScheduleConfig
        cfg = _get_schedule_config(db)
        return {
            "reminder_time": cfg.reminder_time,
            "rsvp_poll_interval_minutes": cfg.rsvp_poll_interval_minutes,
            "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None,
        }


@app.put("/dashboard/api/settings")
def put_settings(
    payload: dict,
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Update the schedule and immediately reschedule the live APScheduler jobs.

    Phase 6B.6: Owner/admin required.  Customer users update their org's
    OrgScheduleConfig.  Platform admins update the global ScheduleConfig.
    """
    from app.dashboard import _require_owner_or_admin
    _require_owner_or_admin(auth_ctx)

    _validate_settings(payload)

    if auth_ctx.org_id is not None:
        # Customer user - write to OrgScheduleConfig
        from app.models_multi_tenant import OrgScheduleConfig
        cfg = (
            db.query(OrgScheduleConfig)
            .filter(OrgScheduleConfig.organization_id == auth_ctx.org_id)
            .first()
        )
        if cfg is None:
            cfg = OrgScheduleConfig(
                organization_id=auth_ctx.org_id,
                timezone="America/Chicago",
                reminder_hour=8,
                reminder_minute=0,
                rsvp_poll_interval_minutes=10,
            )
            db.add(cfg)
            db.flush()

        if "reminder_time" in payload:
            parts = payload["reminder_time"].split(":")
            cfg.reminder_hour = int(parts[0])
            cfg.reminder_minute = int(parts[1])
        if "rsvp_poll_interval_minutes" in payload:
            cfg.rsvp_poll_interval_minutes = payload["rsvp_poll_interval_minutes"]
        db.commit()
        db.refresh(cfg)
        reminder_time = f"{cfg.reminder_hour:02d}:{cfg.reminder_minute:02d}"
        publish_event(
            "settings.changed",
            {"reminder_time": reminder_time, "rsvp_poll_interval_minutes": cfg.rsvp_poll_interval_minutes},
            organization_id=auth_ctx.org_id,
        )
        return {
            "reminder_time": reminder_time,
            "rsvp_poll_interval_minutes": cfg.rsvp_poll_interval_minutes,
            "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None,
        }
    else:
        # Platform admin - global ScheduleConfig
        cfg = _get_schedule_config(db)
        if "reminder_time" in payload:
            cfg.reminder_time = payload["reminder_time"]
        if "rsvp_poll_interval_minutes" in payload:
            cfg.rsvp_poll_interval_minutes = payload["rsvp_poll_interval_minutes"]
        db.commit()
        db.refresh(cfg)
        _reschedule_jobs(cfg)
        publish_event(
            "settings.changed",
            {"reminder_time": cfg.reminder_time, "rsvp_poll_interval_minutes": cfg.rsvp_poll_interval_minutes},
            organization_id=auth_ctx.org_id,
        )
        return {
            "reminder_time": cfg.reminder_time,
            "rsvp_poll_interval_minutes": cfg.rsvp_poll_interval_minutes,
            "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None,
        }


@app.post("/dashboard/api/trigger/reminders")
def trigger_reminders(
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Run send_daily_reminders() immediately and return its summary.

    Phase 6B.6: Owner/admin required.  Customer users trigger reminders
    only for their organization's leads.

    Note: reminder_sent_at semantics still apply - a lead already reminded
    today will not be re-sent, so a 0-sent summary is expected if everyone
    eligible was already reminded.
    """
    from app.dashboard import _require_owner_or_admin
    _require_owner_or_admin(auth_ctx)

    from app.services.reminder_service import send_daily_reminders

    org_filter = auth_ctx.org_id  # None for platform admin (all orgs)
    result = send_daily_reminders(organization_id=org_filter)
    publish_event("trigger.completed", {"job": "reminders", "result": result}, organization_id=org_filter)
    return result


@app.post("/dashboard/api/trigger/poll-rsvps")
def trigger_poll_rsvps(
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Run poll_rsvp_updates() immediately and return its summary.

    Phase 6B.6: Owner/admin required.  Customer users poll RSVPs
    only for their organization's leads.
    """
    from app.dashboard import _require_owner_or_admin
    _require_owner_or_admin(auth_ctx)

    from app.services.rsvp_poller import poll_rsvp_updates

    org_filter = auth_ctx.org_id  # None for platform admin (all orgs)
    result = poll_rsvp_updates(organization_id=org_filter)
    publish_event("trigger.completed", {"job": "poll-rsvps", "result": result}, organization_id=org_filter)
    return result


@app.post("/dashboard/api/trigger/followup-emails")
def trigger_followup_emails(
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Run execute_due_follow_ups() immediately and return its summary.

    Phase 7 Part 1: Owner/admin required.  Sends any follow-up emails
    whose due_at timestamp has passed.  Returns the same summary dict
    produced by execute_due_follow_ups() (total_due, emails_sent, etc.).

    Note: This is idempotent - follow-ups already in IN_PROGRESS or
    COMPLETED are skipped on re-execution.
    """
    from app.dashboard import _require_owner_or_admin
    _require_owner_or_admin(auth_ctx)

    from app.services.followup_email_sender import execute_due_follow_ups

    # SECURITY (C3): the manual trigger is org-scoped - an org's
    # owner/admin may only fire follow-ups for their OWN org.
    result = execute_due_follow_ups(organization_id=auth_ctx.org_id)
    publish_event("trigger.completed", {"job": "followup-emails", "result": result}, organization_id=auth_ctx.org_id)
    return result


# ---------------------------------------------------------------------------
# Phase 7 - Setup Status & Pipeline Health
#
# New endpoints for the customer platform that expose:
#   1. Setup-status checklist (onboarding progress)
#   2. Pipeline health overview (lead processing stats)
# ---------------------------------------------------------------------------


@app.get("/dashboard/api/setup-status")
def setup_status(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Return the onboarding/setup completion checklist for this org.

    Checks whether key configuration steps are done:
      - Google OAuth connected
      - Webhook secret rotated from default
      - Schedule config customized
      - Org branding configured

    Used by the frontend to show the setup checklist widget on the overview
    page and the onboarding wizard for new organizations.
    """
    if auth_ctx.org_id is None:
        return {"setup_complete": True, "steps": {}, "platform_admin": True}

    from app.models_multi_tenant import Organization, OrgIntegration, OrgScheduleConfig

    org = db.query(Organization).filter(Organization.id == auth_ctx.org_id).first()
    if org is None:
        return {"setup_complete": False, "steps": {}, "error": "Organization not found"}

    # Check Google OAuth
    # BUG FIX: integration_type must be "google_oauth" to match the records
    # created by GoogleOAuthFlow._store_credentials().  The previous value
    # "oauth" never matched, so the onboarding wizard always showed Google
    # as not connected even after a successful OAuth callback.
    #
    # FIX A (Phase 34): Do NOT trust the DB status column alone.  Decrypt
    # the stored credentials and verify that a non-empty refresh_token is
    # present.  A row can be marked "connected" with an empty refresh_token
    # after a partial OAuth callback or data corruption.  We keep the vault
    # check lightweight (no live provider calls on every page render).
    google_integration = (
        db.query(OrgIntegration)
        .filter(
            OrgIntegration.organization_id == auth_ctx.org_id,
            OrgIntegration.provider == "google",
            OrgIntegration.integration_type == "google_oauth",
        )
        .first()
    )
    google_connected = False
    if (
        google_integration is not None
        and google_integration.status.value == "connected"
        and google_integration.credentials_encrypted is not None
    ):
        # Validate the refresh_token is non-empty
        try:
            from app.services.credential_vault import CredentialVault
            google_creds = CredentialVault.get_credentials(
                db, auth_ctx.org_id, "google", "google_oauth"
            )
            google_connected = bool(google_creds.get("refresh_token"))
        except Exception:
            google_connected = False

    # Check webhook secret (rotated from default)
    webhook_configured = org.webhook_secret is not None and org.webhook_secret != ""

    # Check schedule config customized (not all defaults)
    schedule_cfg = (
        db.query(OrgScheduleConfig)
        .filter(OrgScheduleConfig.organization_id == auth_ctx.org_id)
        .first()
    )
    schedule_configured = schedule_cfg is not None

    # Check branding
    branding_configured = org.sender_name is not None or org.brand_color is not None

    steps = {
        "google_connected": {
            "label": "Connect Google Account",
            "description": "Link your Google account for Calendar and Gmail",
            "done": google_connected,
            "route": "integrations",
        },
        "webhook_configured": {
            "label": "Configure Webhook",
            "description": "Set up your form submission webhook",
            "done": webhook_configured,
            "route": "webhook",
        },
        "schedule_configured": {
            "label": "Schedule Settings",
            "description": "Set your timezone and reminder preferences",
            "done": schedule_configured,
            "route": "settings",
        },
        "branding_configured": {
            "label": "Brand Your Emails",
            "description": "Add your sender name and brand color",
            "done": branding_configured,
            "route": "org-settings",
        },
    }

    total = len(steps)
    completed = sum(1 for s in steps.values() if s["done"])

    return {
        "setup_complete": completed == total,
        "completed_steps": completed,
        "total_steps": total,
        "steps": steps,
    }


@app.get("/dashboard/api/pipeline/status")
def pipeline_status(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Return pipeline health and lead processing statistics.

    Provides counts of leads in each status, total processed, success rate,
    and recent error count. Useful for the dashboard overview and
    diagnostics.
    """
    from sqlalchemy import func as sqlfunc

    base_q = db.query(Lead)
    if auth_ctx.org_id is not None:
        base_q = base_q.filter(Lead.organization_id == auth_ctx.org_id)

    # Count by status
    status_counts = dict(
        base_q.with_entities(Lead.status, sqlfunc.count(Lead.id))
        .group_by(Lead.status)
        .all()
    )

    total = sum(status_counts.values())
    completed = status_counts.get(LeadStatus.SCHEDULED, 0) + status_counts.get(LeadStatus.ACCEPTED, 0)
    pending = status_counts.get(LeadStatus.PENDING, 0)
    errors = status_counts.get(LeadStatus.ERROR, 0)
    declined = status_counts.get(LeadStatus.DECLINED, 0) + status_counts.get(LeadStatus.NOT_INTERESTED, 0)
    active = status_counts.get(LeadStatus.TENTATIVE, 0) + status_counts.get(LeadStatus.REMINDED, 0)

    success_rate = round((completed / total * 100) if total > 0 else 0, 1)

    # Recent errors (last 24h)
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_errors = (
        db.query(EventLog)
        .filter(
            EventLog.event_type == "error",
            EventLog.created_at >= cutoff,
        )
    )
    if auth_ctx.org_id is not None:
        recent_errors = recent_errors.filter(EventLog.organization_id == auth_ctx.org_id)
    recent_error_count = recent_errors.count()

    # Failed jobs count
    from app.models import FailedJob
    failed_jobs_q = db.query(FailedJob)
    if auth_ctx.org_id is not None:
        failed_jobs_q = failed_jobs_q.filter(FailedJob.organization_id == auth_ctx.org_id)
    failed_jobs_count = failed_jobs_q.count()

    return {
        "total_leads": total,
        "by_status": {s.value: status_counts.get(s, 0) for s in LeadStatus},
        "completed": completed,
        "pending": pending,
        "errors": errors,
        "declined": declined,
        "active": active,
        "success_rate": success_rate,
        "recent_errors_24h": recent_error_count,
        "failed_jobs_total": failed_jobs_count,
    }


# ── Phase 8: Integration Health Check ────────────────────────────────────────

@app.get("/dashboard/api/integration-health")
def integration_health(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Verify connectivity to external integrations (Google Calendar, Gmail, Zoom, AI).

    Returns a per-service health status without exposing credentials.
    Each service is tested with a real provider API call.
    """
    # Only owner/admin may trigger real external API calls.
    if auth_ctx.role not in ("owner", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only owner or admin may check integration health",
        )

    result: dict = {}

    # Google Calendar
    google_ok = False
    google_error = None
    google_error_type = None
    try:
        from app.services.org_context import OrganizationContext
        org_ctx = None
        if auth_ctx.org_id is not None:
            org_ctx = OrganizationContext.from_id(auth_ctx.org_id)
        from app.services.calendar_service import CalendarService
        cal_svc = CalendarService(org_context=org_ctx, db=db)
        # Lightweight read: get calendar info (minimal scope)
        cal_svc._service.calendars().get(calendarId=cal_svc._calendar_id).execute()
        google_ok = True
    except Exception as exc:
        # Phase 9: Sanitize error message to avoid leaking credentials
        google_error = _sanitize_error_message(str(exc))
        google_error_type = _classify_error(exc)

    result["google_calendar"] = {
        "status": "connected" if google_ok else "error",
        "error": google_error,
        "error_type": google_error_type if not google_ok else None,
    }

    # Gmail - scope-compatible health check.
    # FIX C (Phase 34): The previous health check used users.getProfile()
    # which requires gmail.readonly scope.  The app only requests
    # gmail.send scope.  Instead of artificially adding gmail.readonly,
    # we validate that the Gmail service can be constructed with valid
    # credentials and that the credentials can refresh.  This proves
    # the OAuth tokens are usable for sending mail without requiring
    # a broader Gmail scope.
    gmail_ok = False
    gmail_error = None
    gmail_error_type = None
    gmail_profile_email = None
    try:
        from app.services.org_context import OrganizationContext
        org_ctx = None
        if auth_ctx.org_id is not None:
            org_ctx = OrganizationContext.from_id(auth_ctx.org_id)
        from app.services.email_service import EmailService
        email_svc = EmailService(org_context=org_ctx, db=db)
        # FIX C: Verify credentials are functional by explicitly refreshing
        # the token if expired.  This catches invalid/revoked refresh tokens
        # without calling getProfile (which requires gmail.readonly scope).
        creds_obj = getattr(email_svc, '_credentials', None) or getattr(email_svc._service, '_credentials', None)
        if creds_obj and not creds_obj.valid and creds_obj.expired:
            from google.auth.transport.requests import Request as _GRequest
            creds_obj.refresh(_GRequest())
        # Extract email from stored metadata rather than an API call.
        if auth_ctx.org_id is not None:
            from app.services.credential_vault import CredentialVault
            _gmail_meta = CredentialVault.get_safe_metadata(
                db, auth_ctx.org_id, "google", "email"
            ) or {}
            gmail_profile_email = _gmail_meta.get("sender_email")
        gmail_ok = True
    except Exception as exc:
        # Phase 9: Sanitize error message to avoid leaking credentials
        gmail_error = _sanitize_error_message(str(exc))
        gmail_error_type = _classify_error(exc)

    result["gmail"] = {
        "status": "connected" if gmail_ok else "error",
        "error": gmail_error,
        "error_type": gmail_error_type if not gmail_ok else None,
        "email": gmail_profile_email,
    }

    # Zoom - real API call: get account info (proves OAuth tokens are valid)
    zoom_ok = False
    zoom_error = None
    zoom_error_type = None
    zoom_account_email = None
    try:
        from app.services.credential_vault import CredentialVault as _CV
        if auth_ctx.org_id is not None:
            has_zoom = _CV.has_credentials(
                db, auth_ctx.org_id, "zoom", "zoom_oauth"
            )
            if not has_zoom:
                zoom_error = "Zoom not configured"
                zoom_error_type = "config"
            else:
                from app.services.zoom_oauth_flow import ZoomOAuthFlow
                access_token = ZoomOAuthFlow.refresh_token_if_needed(db, auth_ctx.org_id)
                from app.services.zoom_api_client import ZoomAPIClient
                account_info = ZoomAPIClient.get_account_info(access_token)
                zoom_account_email = account_info.get("email")
                zoom_ok = True
        else:
            zoom_error = "No organization context"
            zoom_error_type = "config"
    except Exception as exc:
        zoom_error = _sanitize_error_message(str(exc))
        zoom_error_type = _classify_error(exc)
        # Mark the Zoom integration as ERROR when token refresh fails,
        # so the dashboard reflects the true state.
        if zoom_error_type == "auth" and auth_ctx.org_id is not None:
            try:
                from app.services.credential_vault import CredentialVault as _CVErr
                _CVErr.mark_error(
                    db=db,
                    org_id=auth_ctx.org_id,
                    provider="zoom",
                    integration_type="zoom_oauth",
                    error_message=str(exc),
                )
            except Exception:
                logger.debug("failed to mark Zoom error in integration_health")

    result["zoom"] = {
        "status": "connected" if zoom_ok else "error",
        "error": zoom_error,
        "error_type": zoom_error_type if not zoom_ok else None,
        "email": zoom_account_email,
    }

    # AI provider
    ai_ok = False
    ai_error = None
    ai_error_type = None
    ai_provider_label = None
    ai_model_name = None
    try:
        from app.services.ai_service import AIService
        from app.services.org_context import OrganizationContext
        org_ctx = None
        if auth_ctx.org_id is not None:
            org_ctx = OrganizationContext.from_id(auth_ctx.org_id)
        else:
            # Platform admin (basic auth) - find any org with a
            # fully-configured vault AI entry so we test the real
            # configured provider instead of the platform default
            # which may be a placeholder (e.g. tokenrouter 503).
            import json as _json

            from app.models_multi_tenant import OrgIntegration
            _candidates = (
                db.query(OrgIntegration)
                .filter(
                    OrgIntegration.provider == "openai",
                    OrgIntegration.integration_type == "ai_provider",
                    OrgIntegration.credentials_encrypted.isnot(None),
                    OrgIntegration.metadata_json.isnot(None),
                )
                .all()
            )
            for _ai_row in _candidates:
                meta = _ai_row.metadata_json or {}
                if isinstance(meta, str):
                    try:
                        meta = _json.loads(meta)
                    except Exception:
                        meta = {}
                if meta.get("provider_id"):
                    org_ctx = OrganizationContext.from_id(_ai_row.organization_id)
                    break
        ai_svc = AIService(org_context=org_ctx, db=db)
        # Resolve the provider label from the resolved config
        from app.services.ai_provider_registry import get_provider
        _ai_provider_def = get_provider(ai_svc._primary_provider_id)
        ai_provider_label = _ai_provider_def.display_name if _ai_provider_def else ai_svc._primary_provider_id
        ai_model_name = ai_svc._primary_model

        # Phase 25: Build a lightweight OpenAI client from the resolved
        # credentials instead of accessing a non-existent _primary_client.
        from httpx import Timeout as _Timeout
        from openai import OpenAI as _OpenAI
        _health_client = _OpenAI(
            base_url=ai_svc._primary_url,
            api_key=ai_svc._primary_key,
            max_retries=0,
            timeout=_Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
        )
        resp = _health_client.chat.completions.create(
            model=ai_svc._primary_model,
            messages=[{"role": "user", "content": "Say OK"}],
            max_tokens=2,
        )
        ai_ok = resp.choices is not None
    except Exception as exc:
        # Phase 9: Sanitize error message to avoid leaking credentials
        ai_error = _sanitize_error_message(str(exc))
        ai_error_type = _classify_error(exc)

    result["ai_provider"] = {
        "status": "connected" if ai_ok else "error",
        "provider": ai_provider_label,
        "model": ai_model_name,
        "error": ai_error,
        "error_type": ai_error_type if not ai_ok else None,
    }

    # Overall status
    result["overall"] = "healthy" if all(
        v["status"] == "connected" for v in result.values() if isinstance(v, dict)
    ) else "degraded"

    return result


# ── Phase 8: Manual trigger endpoints for scheduled jobs ─────────────────────

@app.post("/dashboard/api/jobs/failed-job-recovery")
def trigger_failed_job_recovery(
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Manually trigger FailedJob recovery. Owner/Admin only."""
    if auth_ctx.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Owner or admin required")
    _recover_failed_jobs()
    return {"status": "completed", "message": "FailedJob recovery completed"}


@app.post("/dashboard/api/jobs/meeting-completion")
def trigger_meeting_completion(
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Manually trigger meeting completion check. Owner/Admin only."""
    if auth_ctx.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Owner or admin required")
    _mark_completed_meetings()
    return {"status": "completed", "message": "Meeting completion check completed"}


@app.post("/dashboard/api/jobs/token-health-check")
def trigger_token_health_check(
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Manually trigger token lifecycle health check. Owner/Admin only.

    Phase 5: Returns the health summary for all org tokens without
    exposing credentials or refreshing any tokens.
    """
    if auth_ctx.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Owner or admin required")
    from app.services.token_health import check_token_health
    db = SessionLocal()
    try:
        # Phase 5: Scope to caller's org unless platform admin
        org_id = None if auth_ctx.is_platform_admin else auth_ctx.org_id
        summary = check_token_health(db, org_id=org_id)
        return {"status": "completed", "summary": summary}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Phase 9 - Production Operations Dashboard
#
# Unified ops status endpoint that combines pipeline health, integration
# connectivity (DB-based, lightweight), failure classification, scheduler
# status, and meeting lifecycle health into a single call.
# ---------------------------------------------------------------------------


@app.get("/dashboard/api/ops-status")
def ops_status(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Unified operational status for the customer dashboard.

    Returns a single view combining:
      - Pipeline health (lead counts by status)
      - Integration connectivity (DB-stored status, no live API calls)
      - Failure classification (retryable vs permanently failed)
      - Scheduler job status
      - Meeting lifecycle health (overdue leads)
      - Recent operational event summary

    All data is org-scoped for customer users. Platform admins see all.
    NO credentials, tokens, or secrets are included.
    """
    from datetime import timedelta

    from sqlalchemy import func as sqlfunc

    now_utc = datetime.now(timezone.utc)

    # ── 1. Pipeline health ─────────────────────────────────────────────────
    lead_q = db.query(Lead)
    if auth_ctx.org_id is not None:
        lead_q = lead_q.filter(Lead.organization_id == auth_ctx.org_id)

    status_counts = dict(
        lead_q.with_entities(Lead.status, sqlfunc.count(Lead.id))
        .group_by(Lead.status)
        .all()
    )
    total = sum(status_counts.values())

    # ── 2. Integration connectivity (DB-based, lightweight) ────────────────
    integrations_summary = {"google": "unknown", "ai": "unknown"}
    try:
        from app.models_multi_tenant import OrgIntegration
        integ_q = db.query(OrgIntegration)
        if auth_ctx.org_id is not None:
            integ_q = integ_q.filter(OrgIntegration.organization_id == auth_ctx.org_id)
        integrations = integ_q.all()
        for integ in integrations:
            provider = integ.provider
            status_val = integ.status.value if hasattr(integ.status, 'value') else str(integ.status)
            if provider == "google":
                integrations_summary["google"] = status_val
            elif provider in ("openai", "ai"):
                integrations_summary["ai"] = status_val
    except Exception:
        pass  # org_integrations table may not exist yet

    # ── 3. Failure classification ──────────────────────────────────────────
    from app.models import FailedJob
    MAX_RETRIES = 3

    failed_q = db.query(FailedJob).filter(FailedJob.resolved == False)
    if auth_ctx.org_id is not None:
        failed_q = failed_q.filter(FailedJob.organization_id == auth_ctx.org_id)
    all_failed = failed_q.all()

    retryable = 0
    permanently_failed = 0
    for fj in all_failed:
        if fj.retry_count < MAX_RETRIES:
            retryable += 1
        else:
            permanently_failed += 1

    # Recently recovered (resolved in last 24h)
    cutoff_24h = now_utc - timedelta(hours=24)
    recovered_q = db.query(FailedJob).filter(
        FailedJob.resolved == True,
        FailedJob.created_at >= cutoff_24h,
    )
    if auth_ctx.org_id is not None:
        recovered_q = recovered_q.filter(FailedJob.organization_id == auth_ctx.org_id)
    recovered_24h = recovered_q.count()

    # ── 4. Scheduler status ────────────────────────────────────────────────
    scheduler_running = _scheduler is not None and _scheduler.running
    scheduler_jobs = []
    if scheduler_running and _scheduler is not None:
        for job in _scheduler.get_jobs():
            scheduler_jobs.append({
                "id": job.id,
                "next_run": getattr(job, "next_run_time", None),
            })

    # ── 5. Meeting lifecycle health ────────────────────────────────────────
    overdue_leads = []
    two_hours_ago = now_utc - timedelta(hours=2)
    overdue_q = db.query(Lead).filter(
        Lead.appt_datetime_utc.isnot(None),
        Lead.appt_datetime_utc < two_hours_ago,
        Lead.status.in_([
            LeadStatus.SCHEDULED,
            LeadStatus.ACCEPTED,
            LeadStatus.TENTATIVE,
            LeadStatus.REMINDED,
        ]),
    )
    if auth_ctx.org_id is not None:
        overdue_q = overdue_q.filter(Lead.organization_id == auth_ctx.org_id)
    overdue_rows = overdue_q.limit(50).all()
    for lead in overdue_rows:
        overdue_leads.append({
            "id": str(lead.id),
            "name": lead.name,
            "status": lead.status.value,
            "appt_datetime_utc": lead.appt_datetime_utc.isoformat() if lead.appt_datetime_utc else None,
        })

    # Currently processing (locked) leads
    locked_q = lead_q.filter(Lead.processing_started_at.isnot(None))
    locked_count = locked_q.count()

    # ── 6. Recent event summary (last 24h) ────────────────────────────────
    event_q = db.query(
        EventLog.event_type, sqlfunc.count(EventLog.id)
    ).filter(EventLog.created_at >= cutoff_24h)
    if auth_ctx.org_id is not None:
        event_q = event_q.filter(EventLog.organization_id == auth_ctx.org_id)
    event_counts = dict(event_q.group_by(EventLog.event_type).all())

    recent_errors_24h = event_counts.get("error", 0)

    # ── Overall health determination ───────────────────────────────────────
    has_errors = permanently_failed > 0 or recent_errors_24h > 0 or len(overdue_leads) > 0
    has_warnings = retryable > 0 or locked_count > 0
    if has_errors:
        overall = "degraded"
    elif has_warnings:
        overall = "warning"
    else:
        overall = "healthy"

    return {
        "overall": overall,
        "pipeline": {
            "total_leads": total,
            "by_status": {s.value: status_counts.get(s, 0) for s in LeadStatus},
            "locked_leads": locked_count,
        },
        "integrations": integrations_summary,
        "failures": {
            "total_unresolved": len(all_failed),
            "retryable": retryable,
            "permanently_failed": permanently_failed,
            "recovered_24h": recovered_24h,
        },
        "scheduler": {
            "running": scheduler_running,
            "jobs": scheduler_jobs,
        },
        "meetings": {
            "overdue_count": len(overdue_leads),
            "overdue_leads": overdue_leads,
        },
        "events_24h": event_counts,
        "recent_errors_24h": recent_errors_24h,
    }


# ---------------------------------------------------------------------------
# Phase 9 - Enhanced Failed Jobs Classification
# ---------------------------------------------------------------------------


@app.get("/dashboard/api/failed-jobs/classified")
def classified_failed_jobs(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Failed jobs with explicit classification by recoverability.

    Returns jobs grouped by classification:
      - processing: leads currently being retried (locked)
      - retryable: failed but retry_count < max_retries
      - permanently_failed: failed and retry_count >= max_retries
      - recently_recovered: resolved in the last 24h

    NO credentials, tokens, or secrets are included.
    """
    from datetime import timedelta

    from app.models import FailedJob

    MAX_RETRIES = 3
    now_utc = datetime.now(timezone.utc)

    # All unresolved failed jobs
    q = db.query(FailedJob).filter(FailedJob.resolved == False)
    if auth_ctx.org_id is not None:
        q = q.filter(FailedJob.organization_id == auth_ctx.org_id)
    jobs = q.order_by(FailedJob.created_at.desc()).all()

    retryable = []
    permanently_failed = []
    for j in jobs:
        row = {
            "id": str(j.id),
            "job_type": j.job_type,
            "payload": _safe_json_parse(j.payload),
            "error": j.error[:500] if j.error else None,
            "retry_count": j.retry_count,
            "created_at": j.created_at.isoformat() if j.created_at else None,
        }
        if j.retry_count < MAX_RETRIES:
            row["recoverable"] = True
            row["classification"] = "retryable"
            retryable.append(row)
        else:
            row["recoverable"] = False
            row["classification"] = "permanently_failed"
            permanently_failed.append(row)

    # Recently recovered
    cutoff_24h = now_utc - timedelta(hours=24)
    rec_q = db.query(FailedJob).filter(
        FailedJob.resolved == True,
        FailedJob.created_at >= cutoff_24h,
    )
    if auth_ctx.org_id is not None:
        rec_q = rec_q.filter(FailedJob.organization_id == auth_ctx.org_id)
    recently_recovered = []
    for j in rec_q.order_by(FailedJob.created_at.desc()).limit(50).all():
        recently_recovered.append({
            "id": str(j.id),
            "job_type": j.job_type,
            "payload": _safe_json_parse(j.payload),
            "error": j.error[:500] if j.error else None,
            "retry_count": j.retry_count,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "classification": "recovered",
        })

    # Currently processing (locked leads)
    locked_q = db.query(Lead)
    if auth_ctx.org_id is not None:
        locked_q = locked_q.filter(Lead.organization_id == auth_ctx.org_id)
    locked_leads = locked_q.filter(Lead.processing_started_at.isnot(None)).all()
    processing = [
        {
            "id": str(l.id),
            "name": l.name,
            "status": l.status.value,
            "processing_started_at": l.processing_started_at.isoformat() if l.processing_started_at else None,
        }
        for l in locked_leads
    ]

    return {
        "summary": {
            "retryable": len(retryable),
            "permanently_failed": len(permanently_failed),
            "processing": len(processing),
            "recently_recovered": len(recently_recovered),
        },
        "retryable": retryable,
        "permanently_failed": permanently_failed,
        "processing": processing,
        "recently_recovered": recently_recovered,
    }


def _safe_json_parse(raw: str | None) -> dict | None:
    """Safely parse a JSON string, returning None on any failure."""
    if not raw:
        return None
    try:
        data = json.loads(raw)
        return data
    except (json.JSONDecodeError, TypeError, ValueError):
        return {"_raw": "[malformed]"}


# ── Phase 8: Hardened pipeline status with COMPLETED count ──────────────────

@app.get("/dashboard/api/pipeline/status/v2")
def pipeline_status_v2(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Enhanced pipeline status with Phase 8 data (COMPLETED, locked leads, etc)."""
    from sqlalchemy import func as sqlfunc

    base_q = db.query(Lead)
    if auth_ctx.org_id is not None:
        base_q = base_q.filter(Lead.organization_id == auth_ctx.org_id)

    status_counts = dict(
        base_q.with_entities(Lead.status, sqlfunc.count(Lead.id))
        .group_by(Lead.status)
        .all()
    )

    total = sum(status_counts.values())
    completed = status_counts.get(LeadStatus.COMPLETED, 0)
    scheduled = status_counts.get(LeadStatus.SCHEDULED, 0)
    accepted = status_counts.get(LeadStatus.ACCEPTED, 0)
    pending = status_counts.get(LeadStatus.PENDING, 0)
    errors = status_counts.get(LeadStatus.ERROR, 0)
    declined = status_counts.get(LeadStatus.DECLINED, 0)
    not_interested = status_counts.get(LeadStatus.NOT_INTERESTED, 0)
    tentative = status_counts.get(LeadStatus.TENTATIVE, 0)
    reminded = status_counts.get(LeadStatus.REMINDED, 0)

    terminal = completed + declined + not_interested + errors
    success_rate = round(((completed + accepted) / total * 100) if total > 0 else 0, 1)

    # Count currently locked leads (being processed)
    locked_count = (
        base_q.filter(Lead.processing_started_at.isnot(None)).count()
    )

    # Unresolved failed jobs
    from app.models import FailedJob
    failed_jobs_q = db.query(FailedJob).filter(FailedJob.resolved == False)
    if auth_ctx.org_id is not None:
        failed_jobs_q = failed_jobs_q.filter(FailedJob.organization_id == auth_ctx.org_id)
    unresolved_failed_jobs = failed_jobs_q.count()

    return {
        "total_leads": total,
        "by_status": {s.value: status_counts.get(s, 0) for s in LeadStatus},
        "pending": pending,
        "active": scheduled + accepted + tentative + reminded,
        "completed": completed,
        "terminal": terminal,
        "errors": errors,
        "success_rate": success_rate,
        "locked_leads": locked_count,
        "unresolved_failed_jobs": unresolved_failed_jobs,
    }


# ---------------------------------------------------------------------------
# Phase 6B.7 - Integration Credentials Management
#
# Customer-facing API for managing external service integrations
# (Google OAuth, AI provider, Calendar, Gmail).
#
# SECURITY:
#   - NEVER returns decrypted credentials through any response
#   - Owner/Admin required for write operations (save, update, disconnect)
#   - Member role can read integration status only
#   - All operations are scoped to the authenticated user's organization
#   - Platform admins see all integrations but still never see secrets
# ---------------------------------------------------------------------------


@app.get("/dashboard/api/integrations")
def list_integrations(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """List all integrations for the authenticated organization.

    Returns safe metadata (status, labels, timestamps) - never credentials.

    Phase 6B.7: All authenticated users (owner, admin, member) can list.
    Platform admins see all integrations across all organizations.
    """
    from app.services.integration_service import IntegrationService

    if auth_ctx.org_id is not None:
        items = IntegrationService.list_integrations(db, auth_ctx.org_id)
        return {"integrations": items, "organization_id": str(auth_ctx.org_id)}
    else:
        # Platform admin - list integrations for all organizations
        from app.models_multi_tenant import Organization
        orgs = db.query(Organization).all()
        all_items = []
        for org in orgs:
            items = IntegrationService.list_integrations(db, org.id)
            for item in items:
                item["organization_id"] = str(org.id)
                item["organization_name"] = org.name
            all_items.extend(items)
        return {"integrations": all_items}


@app.get("/dashboard/api/integrations/{provider}")
def get_integration_status(
    provider: str,
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Get the status of a specific provider's integrations.

    Returns metadata and status for each integration type under this provider.
    Never returns credentials or encrypted data.

    Phase 6B.7: All authenticated users can read status.
    """
    from app.services.integration_service import IntegrationService

    if auth_ctx.org_id is None:
        # Platform admin - need to search across all orgs
        from sqlalchemy import select

        from app.models_multi_tenant import OrgIntegration

        stmt = select(OrgIntegration).where(
            OrgIntegration.provider == provider,
        )
        integrations = db.execute(stmt).scalars().all()
        items = []
        for integration in integrations:
            items.append({
                "id": str(integration.id),
                "organization_id": str(integration.organization_id),
                "integration_type": integration.integration_type,
                "status": integration.status.value,
                "has_credentials": integration.credentials_encrypted is not None,
                "connected_at": (
                    integration.connected_at.isoformat()
                    if integration.connected_at
                    else None
                ),
                "last_error": integration.last_error,
                "metadata": integration.metadata_json or {},
                "created_at": (
                    integration.created_at.isoformat()
                    if integration.created_at
                    else None
                ),
                "updated_at": (
                    integration.updated_at.isoformat()
                    if integration.updated_at
                    else None
                ),
            })
        return {"provider": provider, "integrations": items}
    else:
        return IntegrationService.get_integration_status(db, auth_ctx.org_id, provider)


@app.post("/dashboard/api/integrations/{provider}/{integration_type}")
def save_integration(
    provider: str,
    integration_type: str,
    payload: dict,
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Save credentials for an integration.

    Phase 6B.7: Owner/Admin required. Creates or updates the credentials.
    Credentials are encrypted at rest and NEVER returned in the response.
    An audit log entry is recorded for each save.

    Request body:
        {
            "credentials": {"key": "value", ...},    // Required
            "metadata": {"display_name": "..."}      // Optional
        }
    """
    from app.dashboard import _require_owner_or_admin
    from app.services.integration_service import (
        InsufficientPermissionsError,
        IntegrationService,
        IntegrationServiceError,
        IntegrationValidationError,
    )

    _require_owner_or_admin(auth_ctx)

    credentials = payload.get("credentials")
    if not credentials or not isinstance(credentials, dict):
        raise HTTPException(
            status_code=422,
            detail="Missing or invalid 'credentials' in request body",
        )

    metadata = payload.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        raise HTTPException(
            status_code=422,
            detail="'metadata' must be a dictionary if provided",
        )

    try:
        return IntegrationService.save_integration(
            db=db,
            org_id=auth_ctx.org_id,
            provider=provider,
            integration_type=integration_type,
            credentials=credentials,
            metadata=metadata,
            role=auth_ctx.role,
        )
    except InsufficientPermissionsError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except IntegrationValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except IntegrationServiceError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.put("/dashboard/api/integrations/{provider}/{integration_type}")
def update_integration(
    provider: str,
    integration_type: str,
    payload: dict,
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Update an existing integration's credentials or metadata.

    Phase 6B.7: Owner/Admin required.

    Request body (at least one required):
        {
            "credentials": {"key": "value", ...},    // Optional - update credentials
            "metadata": {"display_name": "..."}      // Optional - update metadata
        }
    """
    from app.dashboard import _require_owner_or_admin
    from app.services.integration_service import (
        InsufficientPermissionsError,
        IntegrationService,
        IntegrationServiceError,
        IntegrationValidationError,
    )

    _require_owner_or_admin(auth_ctx)

    credentials = payload.get("credentials")
    metadata = payload.get("metadata")

    if credentials is None and metadata is None:
        raise HTTPException(
            status_code=422,
            detail="At least one of 'credentials' or 'metadata' must be provided",
        )

    try:
        return IntegrationService.update_integration(
            db=db,
            org_id=auth_ctx.org_id,
            provider=provider,
            integration_type=integration_type,
            credentials=credentials,
            metadata=metadata,
            role=auth_ctx.role,
        )
    except InsufficientPermissionsError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except IntegrationValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except IntegrationServiceError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.delete("/dashboard/api/integrations/{provider}/{integration_type}")
def disconnect_integration(
    provider: str,
    integration_type: str,
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Disconnect an integration: clear credentials and set DISCONNECTED.

    Phase 6B.7: Owner/Admin required. Records an audit log entry.
    """
    from app.dashboard import _require_owner_or_admin
    from app.services.integration_service import (
        InsufficientPermissionsError,
        IntegrationNotFoundError,
        IntegrationService,
        IntegrationServiceError,
    )

    _require_owner_or_admin(auth_ctx)

    try:
        return IntegrationService.disconnect_integration(
            db=db,
            org_id=auth_ctx.org_id,
            provider=provider,
            integration_type=integration_type,
            role=auth_ctx.role,
        )
    except InsufficientPermissionsError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except IntegrationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except IntegrationServiceError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/dashboard/api/meeting-provider")
def get_meeting_provider(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Return which meeting provider is active for this organization.

    If Zoom OAuth credentials exist, ``zoom`` is active; otherwise
    ``google_meet`` is the default.

    Returns:
      provider: str - "zoom" or "google_meet"
      zoom_connected: bool
      google_connected: bool

    SECURITY: Read-only, all authenticated users can query.
    """
    from app.services.credential_vault import CredentialVault

    org_id = auth_ctx.org_id
    if org_id is None:
        raise HTTPException(status_code=400, detail="Organization context required.")

    zoom_connected = CredentialVault.has_credentials(
        db, org_id, "zoom", "zoom_oauth",
    )
    google_connected = CredentialVault.has_credentials(
        db, org_id, "google", "google_oauth",
    )

    active_provider = "zoom" if zoom_connected else "google_meet"

    return {
        "provider": active_provider,
        "zoom_connected": zoom_connected,
        "google_connected": google_connected,
    }


@app.get("/dashboard/api/ai/status")
def get_ai_status(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Return AI provider configuration status for this organization.

    Returns configured status, provider_id, masked API key, model, base_url.
    Never returns plaintext credentials.

    SECURITY: Read-only, all authenticated users can query.
    """
    from app.services.credential_vault import CredentialVault
    from app.services.crypto import mask_secret

    org_id = auth_ctx.org_id
    if org_id is None:
        return {
            "configured": False,
            "provider_id": None,
            "provider_label": None,
            "masked_key": None,
            "model": None,
            "base_url": None,
            "adapter_ready": None,
        }

    try:
        creds = CredentialVault.get_credentials(db, org_id, "openai", "ai_provider")
        meta = CredentialVault.get_safe_metadata(db, org_id, "openai", "ai_provider") or {}
        api_key = creds.get("api_key", "")
        if api_key:
            provider_id = meta.get("provider_id", "openai")
            from app.services.ai_provider_registry import get_provider
            provider_def = get_provider(provider_id)
            return {
                "configured": True,
                "provider_id": provider_id,
                "provider_label": provider_def.display_name if provider_def else provider_id,
                "masked_key": mask_secret(api_key),
                "model": meta.get("model", ""),
                "base_url": creds.get("base_url", ""),
                "adapter_ready": provider_def.adapter_ready if provider_def else False,
            }
    except Exception:
        pass

    return {
        "configured": False,
        "provider_id": None,
        "provider_label": None,
        "masked_key": None,
        "model": None,
        "base_url": None,
        "adapter_ready": None,
    }


@app.get("/dashboard/api/ai/providers")
def list_ai_providers(
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """List all available AI providers for the dashboard UI.

    Returns provider definitions with display names, default URLs, etc.
    No credentials are exposed.

    SECURITY: Read-only, all authenticated users can query.
    """
    from app.services.ai_provider_registry import get_all_providers

    providers = []
    for p in get_all_providers():
        providers.append({
            "id": p.id,
            "display_name": p.display_name,
            "protocol": p.protocol,
            "default_base_url": p.default_base_url,
            "api_key_label": p.api_key_label,
            "supports_custom_base_url": p.supports_custom_base_url,
            "supports_model_discovery": p.supports_model_discovery,
            "default_model": p.default_model,
            "adapter_ready": p.adapter_ready,
            "help_text": p.help_text,
        })
    return {"providers": providers}


@app.post("/dashboard/api/ai/test-connection")
def test_ai_connection(
    payload: dict | None = None,
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Test the currently configured AI provider connection.

    Accepts an optional request body with form values to test:
        { "provider_id": "...", "base_url": "...", "api_key": "...", "model": "..." }
    When provided, these override the vault values for the test.
    This allows users to test BEFORE saving.

    Performs the smallest safe connectivity test:
    - For OpenAI-compatible providers: lightweight models list request
    - Fallback: minimal chat completion with max_tokens=1

    NEVER sends real emails, creates events, or exposes credentials.

    SECURITY: Owner/Admin required for testing.
    """
    from app.dashboard import _require_owner_or_admin
    from app.services.ai_provider_registry import get_provider, is_openai_compatible
    from app.services.credential_vault import CredentialVault

    _require_owner_or_admin(auth_ctx)
    org_id = auth_ctx.org_id

    if org_id is None:
        return {"status": "error", "error": "Organization context required"}

    # Read body overrides (frontend sends form values for pre-save testing)
    body = payload or {}
    body_api_key = (body.get("api_key") or "").strip()
    body_base_url = (body.get("base_url") or "").strip()
    body_model = (body.get("model") or "").strip()
    body_provider_id = (body.get("provider_id") or "").strip()

    # Load vault values as fallback
    vault_api_key = ""
    vault_base_url = ""
    vault_model = ""
    vault_provider_id = "openai"
    try:
        creds = CredentialVault.get_credentials(db, org_id, "openai", "ai_provider")
        meta = CredentialVault.get_safe_metadata(db, org_id, "openai", "ai_provider") or {}
        vault_api_key = creds.get("api_key", "")
        vault_base_url = creds.get("base_url", "")
        vault_model = meta.get("model", "")
        vault_provider_id = meta.get("provider_id", "openai")
    except Exception:
        pass

    # Prefer form values, fall back to vault
    api_key = body_api_key or vault_api_key
    base_url = body_base_url or vault_base_url
    model = body_model or vault_model
    provider_id = body_provider_id or vault_provider_id

    if not api_key:
        return {"status": "error", "error": "No API key configured. Enter an API key and save before testing."}

    if not base_url:
        return {"status": "error", "error": "No base URL configured. Enter a base URL and save before testing."}

    if not base_url:
        return {"status": "error", "error": "No base URL configured"}

    provider_def = get_provider(provider_id)
    if provider_def and not provider_def.adapter_ready:
        return {
            "status": "configured",
            "provider": provider_def.display_name,
            "model": model or "(not set)",
            "message": "Provider configured but this provider requires an adapter that is not yet enabled.",
        }

    if not is_openai_compatible(provider_id):
        return {
            "status": "configured",
            "provider": provider_def.display_name if provider_def else provider_id,
            "model": model or "(not set)",
            "message": "Provider configured; native adapter not yet enabled for connectivity test.",
        }

    # OpenAI-compatible: try a lightweight models list, then fallback to chat completion
    import httpx

    headers = {"Authorization": f"Bearer {api_key}"}
    # SECURITY (H4): base_url is administrator-supplied - validate it
    # before the server fetches it (SSRF protection).
    from app.services.ssrf_guard import SSRFBlockedError, validate_outbound_url
    try:
        normalized_url = validate_outbound_url(base_url, field_name="Base URL")
    except SSRFBlockedError as exc:
        return {
            "status": "error",
            "provider": provider_def.display_name if provider_def else provider_id,
            "model": model or "(not set)",
            "error": str(exc),
        }

    # Attempt 1: GET /models
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{normalized_url}/models", headers=headers)
            if resp.status_code == 200:
                return {
                    "status": "connected",
                    "provider": provider_def.display_name if provider_def else provider_id,
                    "model": model or "(not set)",
                    "message": "Connection successful.",
                }
            elif resp.status_code in (401, 403):
                return {
                    "status": "error",
                    "provider": provider_def.display_name if provider_def else provider_id,
                    "model": model or "(not set)",
                    "error": f"AI provider rejected the request ({resp.status_code} {'Forbidden' if resp.status_code == 403 else 'Unauthorized'}). Check the API key, account permissions, provider endpoint, or model.",
                }
            elif resp.status_code == 404:
                # /models not supported - try chat completion instead
                pass
            else:
                return {
                    "status": "error",
                    "provider": provider_def.display_name if provider_def else provider_id,
                    "model": model or "(not set)",
                    "error": f"Unexpected response ({resp.status_code}) from provider.",
                }
    except httpx.ConnectError:
        return {
            "status": "error",
            "provider": provider_def.display_name if provider_def else provider_id,
            "model": model or "(not set)",
            "error": "Network error: could not connect to provider endpoint.",
        }
    except httpx.TimeoutException:
        return {
            "status": "error",
            "provider": provider_def.display_name if provider_def else provider_id,
            "model": model or "(not set)",
            "error": "Connection timed out.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "provider": provider_def.display_name if provider_def else provider_id,
            "model": model or "(not set)",
            "error": f"Network error: {str(exc)[:100]}",
        }

    # Attempt 2: lightweight chat completion
    if not model:
        return {
            "status": "error",
            "provider": provider_def.display_name if provider_def else provider_id,
            "model": "(not set)",
            "error": "Model not configured. Set a model to test the connection.",
        }

    from app.services.ai_provider_registry import normalize_chat_completions_url

    chat_url = normalize_chat_completions_url(normalized_url)
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.post(
                chat_url,
                headers={**headers, "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "Say OK"}],
                    "max_tokens": 2,
                },
            )
            if resp.status_code == 200:
                return {
                    "status": "connected",
                    "provider": provider_def.display_name if provider_def else provider_id,
                    "model": model,
                    "message": "Connection successful.",
                }
            elif resp.status_code in (401, 403):
                return {
                    "status": "error",
                    "provider": provider_def.display_name if provider_def else provider_id,
                    "model": model,
                    "error": f"AI provider rejected the request ({resp.status_code} {'Forbidden' if resp.status_code == 403 else 'Unauthorized'}). Check the API key, account permissions, provider endpoint, or model.",
                }
            elif resp.status_code == 404:
                return {
                    "status": "error",
                    "provider": provider_def.display_name if provider_def else provider_id,
                    "model": model,
                    "error": "Model not found. Check the model name and provider.",
                }
            elif resp.status_code == 429:
                return {
                    "status": "error",
                    "provider": provider_def.display_name if provider_def else provider_id,
                    "model": model,
                    "error": "Rate limited. Try again later.",
                }
            else:
                return {
                    "status": "error",
                    "provider": provider_def.display_name if provider_def else provider_id,
                    "model": model,
                    "error": f"Unexpected response ({resp.status_code}) from provider.",
                }
    except httpx.ConnectError:
        return {
            "status": "error",
            "provider": provider_def.display_name if provider_def else provider_id,
            "model": model,
            "error": "Network error: could not connect to provider endpoint.",
        }
    except httpx.TimeoutException:
        return {
            "status": "error",
            "provider": provider_def.display_name if provider_def else provider_id,
            "model": model,
            "error": "Connection timed out.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "provider": provider_def.display_name if provider_def else provider_id,
            "model": model,
            "error": f"Network error: {str(exc)[:100]}",
        }


@app.post("/dashboard/api/ai/load-models")
def load_ai_models(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Load available models from the configured AI provider.

    For OpenAI-compatible providers: GET /models endpoint.
    Returns model IDs that the user can select or reference.

    SECURITY: Owner/Admin required. Never exposes credentials.
    """
    from app.dashboard import _require_owner_or_admin
    from app.services.ai_provider_registry import get_provider, is_openai_compatible
    from app.services.credential_vault import CredentialVault

    _require_owner_or_admin(auth_ctx)
    org_id = auth_ctx.org_id

    if org_id is None:
        return {"models": [], "error": "Organization context required"}

    try:
        creds = CredentialVault.get_credentials(db, org_id, "openai", "ai_provider")
        meta = CredentialVault.get_safe_metadata(db, org_id, "openai", "ai_provider") or {}
    except Exception:
        return {"models": [], "error": "No AI provider configured"}

    api_key = creds.get("api_key", "")
    base_url = creds.get("base_url", "")
    provider_id = meta.get("provider_id", "openai")

    if not api_key or not base_url:
        return {"models": [], "error": "API key and base URL required"}

    provider_def = get_provider(provider_id)
    if not provider_def or not provider_def.supports_model_discovery:
        return {
            "models": [],
            "error": f"Model discovery not supported for {provider_def.display_name if provider_def else provider_id}",
        }

    if not is_openai_compatible(provider_id):
        return {"models": [], "error": "Model discovery only available for OpenAI-compatible providers"}

    import httpx

    # SECURITY (H4): vault-saved base_url is administrator-supplied -
    # validate before the server fetches it (SSRF protection).
    from app.services.ssrf_guard import SSRFBlockedError, validate_outbound_url
    try:
        normalized_url = validate_outbound_url(base_url, field_name="Base URL")
    except SSRFBlockedError as exc:
        return {"models": [], "error": str(exc)}

    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(f"{normalized_url}/models", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                models = []
                for m in data.get("data", []):
                    mid = m.get("id", "")
                    if mid:
                        models.append(mid)
                models.sort()
                return {"models": models}
            elif resp.status_code in (401, 403):
                return {
                    "models": [],
                    "error": f"Provider rejected the request ({resp.status_code}). Check your API key.",
                }
            else:
                return {
                    "models": [],
                    "error": f"Unexpected response ({resp.status_code}) from provider.",
                }
    except Exception as exc:
        return {
            "models": [],
            "error": f"Failed to load models: {str(exc)[:100]}",
        }


# ---------------------------------------------------------------------------
# Phase 6C - Google OAuth2 Web Application Flow
#
# Endpoints for initiating, completing, and managing the Google OAuth2
# authorization code flow. This replaces the legacy token.json approach
# with a proper Web Application OAuth2 flow.
#
# SECURITY:
#   - State tokens are cryptographically random (secrets.token_urlsafe)
#   - State tokens are single-use with configurable TTL (default 10 min)
#   - CSRF protection via OAuth2 state parameter
#   - Owner/Admin required for connection and disconnection
#   - Access tokens are NEVER stored - only refresh tokens
#   - All credential storage is encrypted via CredentialVault
# ---------------------------------------------------------------------------


@app.get("/auth/google/start")
def google_oauth_start(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Initiate the Google OAuth2 authorization code flow.

    Generates a CSRF state token, persists it in the database, and
    returns the authorization URL as JSON for the frontend to open.

    SECURITY:
      - Owner/Admin role required
      - State token is bound to the authenticated user and organization
      - State expires after configurable TTL (default 10 minutes)

    Returns:
      JSON with authorization_url for the frontend to open.
      HTTP 400 if Google client is not configured.
      HTTP 403 if user is not owner/admin.
    """
    from app.dashboard import _require_owner_or_admin
    from app.services.google_oauth_flow import (
        GoogleOAuthError,
        GoogleOAuthFlow,
        resolve_client_credentials,
    )

    _require_owner_or_admin(auth_ctx)

    try:
        state_row = GoogleOAuthFlow.create_authorization_url(
            db=db,
            org_id=auth_ctx.org_id,
            user_id=auth_ctx.user_id,
        )
    except GoogleOAuthError as exc:
        if exc.error_code == "client_not_configured":
            raise HTTPException(
                status_code=400,
                detail=(
                    "Google sign-in is not set up on this server yet. "
                    "The platform administrator must complete the one-time "
                    "Google Cloud Console setup (GOOGLE_CLIENT_ID / "
                    "GOOGLE_CLIENT_SECRET)."
                ),
            )
        raise HTTPException(status_code=500, detail=str(exc))

    # Platform-owned client_id for the auth URL (create_authorization_url
    # already validated that usable credentials exist; this re-resolution
    # is deterministic.  The fallback covers mocked flows in tests.)
    try:
        platform_client_id, _ = resolve_client_credentials(db, auth_ctx.org_id)
    except GoogleOAuthError:
        platform_client_id = (settings.google_client_id or "").strip() or None

    authorization_url = GoogleOAuthFlow.build_authorization_url(
        state_token=state_row.state_token,
        redirect_uri=state_row.redirect_uri,
        scopes=state_row.scopes,
        client_id=platform_client_id,
    )

    logger.info(
        "[OAUTH_FLOW] Initiating Google OAuth",
        extra={
            "org_id": str(auth_ctx.org_id),
            "user_id": str(auth_ctx.user_id),
        },
    )

    return {"authorization_url": authorization_url}


@app.get("/auth/google/callback")
def google_oauth_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Handle the Google OAuth2 callback after user consent.

    This endpoint is called by Google (browser redirect) after the user
    authorizes (or denies) the application.  Because it is a *browser
    navigation* (not an AJAX call), it MUST return an HTML page - not
    JSON - so the user sees a meaningful message and is redirected back
    to the dashboard.

    SECURITY:
      - State validation prevents CSRF attacks
      - State tokens are single-use (replay protection)
      - State tokens expire (prevents stale authorization attempts)
      - Access tokens are NEVER stored - only refresh tokens
      - Error messages are sanitized to prevent token leakage

    Query parameters:
      code: Authorization code (present on success)
      state: CSRF state token (present on success)
      error: Error code (present on denial, e.g., "access_denied")

    Returns:
      HTMLResponse - a self-contained page that shows the result and
      redirects to the dashboard integrations tab after a short delay.
    """
    from html import escape as _esc

    from app.services.google_oauth_flow import (
        GoogleOAuthFlow,
        OAuthDenialError,
        OAuthStateError,
        OAuthTokenExchangeError,
    )

    # Derive the dashboard base URL from the request origin so the
    # redirect works behind any reverse proxy / ngrok tunnel.
    dashboard_url = "/dashboard"

    # Build the redirect URL once to avoid f-string escaping issues
    # with JavaScript curly braces.
    _redirect_url = dashboard_url + "?tab=integrations"

    def _oauth_result_page(
        *,
        success: bool = False,
        title: str = "",
        message: str = "",
        email: str = "",
        status_code: int = 200,
    ) -> HTMLResponse:
        """Return a minimal HTML page that communicates the result to the
        user and then redirects to the dashboard integrations page."""
        icon = "✓" if success else "✕"
        color = "#34a853" if success else "#ea4335"
        toast_type = "success" if success else "error"
        # Build extra info line
        extra = ""
        if email:
            extra = "<p style='margin:8px 0 0;font-size:13px;color:#555'>Connected as <strong>" + _esc(email) + "</strong></p>"
        # Build the page without f-strings to avoid JS curly-brace conflicts
        page = (
            "<!DOCTYPE html><html><head>"
            "<meta charset='utf-8'>"
            "<title>Google OAuth</title>"
            "<style>"
            "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
            "display:flex;justify-content:center;align-items:center;min-height:100vh;"
            "margin:0;background:#f5f5f5}"
            ".card{background:#fff;border-radius:12px;padding:40px;max-width:420px;"
            "width:90%;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.1)}"
            ".icon{font-size:48px;margin-bottom:12px}"
            "h2{margin:0 0 8px;font-size:20px}"
            ".msg{color:#555;font-size:14px;line-height:1.5}"
            ".link{display:inline-block;margin-top:20px;color:#1a73e8;"
            "text-decoration:none;font-weight:500}"
            ".link:hover{text-decoration:underline}"
            "</style></head><body>"
            "<div class='card'>"
            "<div class='icon' style='color:" + color + "'>" + icon + "</div>"
            "<h2>" + _esc(title) + "</h2>"
            "<div class='msg'>" + _esc(message) + "</div>"
            + extra +
            "<a class='link' href='" + _esc(_redirect_url) + "'>"
            "\u2190 Back to Dashboard</a>"
            "</div>"
            "<script>"
            "localStorage.setItem('oauth_result','" + toast_type + ":" + _esc(title) + "');"
            "setTimeout(function(){window.location.href='" + _esc(_redirect_url) + "';},2500);"
            "</script></body></html>"
        )
        return HTMLResponse(content=page, status_code=status_code)

    # ── Handle user denial at Google consent screen ────────────────────
    if error:
        if error == "access_denied":
            return _oauth_result_page(
                success=False,
                title="Authorization Denied",
                message="You declined access. No changes were made. You can try connecting again.",
                status_code=200,  # 200 so the page renders nicely
            )
        return _oauth_result_page(
            success=False,
            title="Google Returned an Error",
            message=f"Google returned the error: {_esc(error)}. Please try again.",
            status_code=200,
        )

    # ── Validate required parameters ──────────────────────────────────
    if not code or not state:
        return _oauth_result_page(
            success=False,
            title="Missing Parameters",
            message="Authorization code or state parameter is missing. Please try connecting again.",
            status_code=200,
        )

    # ── Exchange code for tokens ──────────────────────────────────────
    try:
        result = GoogleOAuthFlow.exchange_code(
            db=db,
            code=code,
            state=state,
        )
    except OAuthStateError as exc:
        return _oauth_result_page(
            success=False,
            title="Connection Expired",
            message=str(exc),
            status_code=200,
        )
    except OAuthDenialError as exc:
        return _oauth_result_page(
            success=False,
            title="Authorization Denied",
            message=str(exc),
            status_code=200,
        )
    except OAuthTokenExchangeError as exc:
        return _oauth_result_page(
            success=False,
            title="Token Exchange Failed",
            message=str(exc),
            status_code=200,
        )

    return _oauth_result_page(
        success=True,
        title="Google Account Connected!",
        message="Calendar and Gmail integration are now active.",
        email=result.get("email", ""),
        status_code=200,
    )


@app.get("/auth/google/status")
def google_oauth_status(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Get the Google OAuth connection status for the authenticated org.

    Returns:
      - configured: bool - whether the platform Google OAuth client is set
      - connected: bool - whether Google OAuth is connected (tokens exchanged)
      - masked_client_id: str | None - partially masked platform Client ID
      - redirect_uri: str | None - platform redirect URI
      - email: str | None - connected account email
      - scopes: list - granted OAuth scopes
      - connected_at: str | None - ISO timestamp of connection

    SECURITY: Never returns credentials, tokens, or secrets.
    """
    from app.services.google_oauth_flow import GoogleOAuthFlow

    if auth_ctx.org_id is None:
        raise HTTPException(
            status_code=400,
            detail="Organization context required.",
        )

    # Start with the basic connection status from the flow
    result = GoogleOAuthFlow.get_connection_status(db, auth_ctx.org_id)

    # PLATFORM MODEL: "configured" means a usable OAuth client exists -
    # the platform client (.env, one-time setup by the app owner), or a
    # legacy org-owned client in the vault.  Orgs never paste credentials,
    # they just click Connect.
    from app.config import settings
    from app.services.credential_vault import CredentialVault

    platform_id = (settings.google_client_id or "").strip()
    platform_secret = (settings.google_client_secret or "").strip()

    legacy_id = ""
    try:
        vault_creds = CredentialVault.get_credentials(
            db, auth_ctx.org_id, "google", "google_oauth"
        ) or {}
        if (vault_creds.get("client_id") or "").strip() and (
            vault_creds.get("client_secret") or ""
        ).strip():
            legacy_id = (vault_creds.get("client_id") or "").strip()
    except Exception:
        pass

    # Legacy-first, mirroring resolve_client_credentials()
    effective_id = legacy_id or platform_id
    result["configured"] = bool(effective_id and (legacy_id or platform_secret))
    if effective_id and len(effective_id) > 8:
        result["masked_client_id"] = effective_id[:4] + "..." + effective_id[-4:]
    else:
        result["masked_client_id"] = effective_id or None
    result["redirect_uri"] = (settings.google_redirect_uri or "").strip() or None

    return result


@app.delete("/auth/google/disconnect")
def google_oauth_disconnect(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Disconnect Google OAuth for the authenticated organization.

    Clears stored credentials and sets integration status to DISCONNECTED.
    The organization will need to re-authorize to reconnect.

    SECURITY: Owner/Admin role required.
    """
    from app.dashboard import _require_owner_or_admin
    from app.services.google_oauth_flow import GoogleOAuthFlow

    _require_owner_or_admin(auth_ctx)

    if auth_ctx.org_id is None:
        raise HTTPException(
            status_code=400,
            detail="Organization context required.",
        )

    result = GoogleOAuthFlow.disconnect(db, auth_ctx.org_id)

    logger.info(
        "[OAUTH_FLOW] Google OAuth disconnected via API",
        extra={"org_id": str(auth_ctx.org_id)},
    )

    return result


# =========================================================================
# Zoom OAuth2 Web Application Flow Routes (Phase 6B.5 - Steps 4-6)
# =========================================================================
# Mirrors the Google OAuth routes exactly.  Owner/Admin required for
# connect and disconnect.  Access tokens stored in encrypted vault.
# =========================================================================


@app.get("/auth/zoom/start")
def zoom_oauth_start(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Initiate the Zoom OAuth2 authorization code flow.

    Generates a CSRF state token, persists it in the database, and
    returns the authorization URL for the frontend to navigate to.

    SECURITY:
      - Owner/Admin role required
      - State token is bound to the authenticated user and organization
      - State expires after configurable TTL (default 10 minutes)

    Returns:
      JSON with authorization_url for the frontend to open.
      HTTP 400 if Zoom client is not configured.
      HTTP 403 if user is not owner/admin.
    """
    from app.dashboard import _require_owner_or_admin
    from app.services.zoom_oauth_flow import (
        ZoomOAuthError,
        ZoomOAuthFlow,
        resolve_client_credentials,
    )

    _require_owner_or_admin(auth_ctx)

    try:
        state_row = ZoomOAuthFlow.create_authorization_url(
            db=db,
            org_id=auth_ctx.org_id,
            user_id=auth_ctx.user_id,
        )
    except ZoomOAuthError as exc:
        if exc.error_code == "zoom_client_not_configured":
            raise HTTPException(
                status_code=400,
                detail=(
                    "Zoom connect is not set up on this server yet. "
                    "The platform administrator must complete the one-time "
                    "Zoom Marketplace setup (ZOOM_CLIENT_ID / "
                    "ZOOM_CLIENT_SECRET / ZOOM_REDIRECT_URI)."
                ),
            )
        raise HTTPException(status_code=500, detail=str(exc))

    # Platform-owned client_id for the auth URL (create_authorization_url
    # already validated that usable credentials exist; this re-resolution
    # is deterministic.  The fallback covers mocked flows in tests;
    # build_authorization_url falls back to settings when client_id is None.
    try:
        platform_client_id, _, _ = resolve_client_credentials(db, auth_ctx.org_id)
    except ZoomOAuthError:
        platform_client_id = None

    authorization_url = ZoomOAuthFlow.build_authorization_url(
        state_token=state_row.state_token,
        redirect_uri=state_row.redirect_uri,
        client_id=platform_client_id,
    )

    logger.info(
        "[ZOOM_OAUTH] Initiating Zoom OAuth",
        extra={
            "org_id": str(auth_ctx.org_id),
            "user_id": str(auth_ctx.user_id),
        },
    )

    return {"authorization_url": authorization_url}


@app.get("/auth/zoom/callback")
def zoom_oauth_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Handle the Zoom OAuth2 callback after user consent.

    Returns an HTML page that auto-redirects to the dashboard integrations
    page.  Shows a brief success or error message before redirecting.

    SECURITY:
      - State validation prevents CSRF attacks
      - State tokens are single-use (replay protection)
      - State tokens expire (prevents stale authorization attempts)
      - Error messages are sanitized to prevent token leakage
      - No tokens or credentials are embedded in the HTML page
    """
    from fastapi.responses import HTMLResponse as _HTMLResponse

    from app.services.zoom_oauth_flow import (
        ZoomOAuthDenialError,
        ZoomOAuthFlow,
        ZoomOAuthStateError,
        ZoomOAuthTokenExchangeError,
    )

    _REDIRECT_JS = """
<script>
  (function(){
    var msg = %s;
    var ok  = %s;
    var el  = document.getElementById('oauth-message');
    el.textContent = msg;
    el.style.color = ok ? '#22c55e' : '#ef4444';
    setTimeout(function(){ window.location.href = '/dashboard/#integrations'; }, 2500);
  })();
</script>
"""
    _PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Zoom OAuth</title>
  <style>
    body{margin:0;display:flex;align-items:center;justify-content:center;
         min-height:100vh;font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0}
    .box{text-align:center;padding:40px;border-radius:12px;background:#1e293b;
         box-shadow:0 4px 24px rgba(0,0,0,.3)}
    #oauth-message{font-size:18px;margin:16px 0}
    .spinner{width:32px;height:32px;border:3px solid #334155;border-top-color:#3b82f6;
             border-radius:50%%;animation:spin .8s linear infinite;margin:0 auto 16px}
    @keyframes spin{to{transform:rotate(360deg)}}
  </style>
</head>
<body>
  <div class="box">
    <div class="spinner"></div>
    <div id="oauth-message">Connecting Zoom…</div>
  </div>
  %s
</body>
</html>"""

    # ── User denied consent ──────────────────────────────────────────
    if error:
        error_msg = (
            "Authorization was denied. You can try connecting again."
            if error == "access_denied"
            else f"Zoom returned an error: {error}"
        )
        # Sanitize - strip angle brackets to prevent injection
        safe_msg = error_msg.replace("<", "").replace(">", "")
        page = _PAGE_TEMPLATE % (
            _REDIRECT_JS % (json.dumps(safe_msg), "false"),
        )
        return _HTMLResponse(content=page, status_code=200)

    # ── Missing parameters ───────────────────────────────────────────
    if not code or not state:
        safe_msg = "Authorization failed - missing parameters."
        page = _PAGE_TEMPLATE % (
            _REDIRECT_JS % (json.dumps(safe_msg), "false"),
        )
        return _HTMLResponse(content=page, status_code=200)

    # ── Exchange code for tokens ─────────────────────────────────────
    try:
        result = ZoomOAuthFlow.exchange_code(
            db=db,
            code=code,
            state=state,
        )
    except (ZoomOAuthStateError, ZoomOAuthDenialError) as exc:
        safe_msg = str(exc).replace("<", "").replace(">", "")
        page = _PAGE_TEMPLATE % (
            _REDIRECT_JS % (json.dumps(safe_msg), "false"),
        )
        return _HTMLResponse(content=page, status_code=200)
    except ZoomOAuthTokenExchangeError as exc:
        safe_msg = "Failed to exchange authorization code. Please try again."
        logger.warning("[ZOOM_OAUTH] Token exchange failed: %s", exc)
        page = _PAGE_TEMPLATE % (
            _REDIRECT_JS % (json.dumps(safe_msg), "false"),
        )
        return _HTMLResponse(content=page, status_code=200)

    logger.info(
        "[ZOOM_OAUTH] Zoom OAuth callback succeeded",
        extra={
            "org_id": str(result.get("organization_id", "")),
            "email": result.get("email", ""),
        },
    )

    safe_msg = "Zoom connected successfully!"
    page = _PAGE_TEMPLATE % (
        _REDIRECT_JS % (json.dumps(safe_msg), "true"),
    )
    return _HTMLResponse(content=page, status_code=200)


@app.get("/auth/zoom/status")
def zoom_oauth_status(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Get the Zoom OAuth connection status for the authenticated org.

    Returns:
      - configured: bool - whether org has Zoom credentials configured
      - connected: bool - whether Zoom OAuth is connected (tokens exchanged)
      - masked_client_id: str | None - partially masked Client ID
      - redirect_uri: str | None - configured redirect URI
      - account_email: str | None - connected account email
      - account_id: str | None - Zoom account ID
      - connected_at: str | None - ISO timestamp of connection

    SECURITY: Never returns credentials, tokens, or secrets.
    """
    from app.services.credential_vault import CredentialVault

    if auth_ctx.org_id is None:
        raise HTTPException(
            status_code=400,
            detail="Organization context required.",
        )

    org_uuid = (
        uuid.UUID(str(auth_ctx.org_id))
        if not isinstance(auth_ctx.org_id, uuid.UUID)
        else auth_ctx.org_id
    )

    has_creds = CredentialVault.has_credentials(
        db, org_uuid, "zoom", "zoom_oauth"
    )

    # PLATFORM MODEL: "configured" means a usable OAuth client exists -
    # the platform Zoom app (.env, one-time setup by the app owner), or a
    # legacy org-owned app in the vault.  Orgs never paste credentials,
    # they just click Connect.
    from app.config import settings

    platform_id = (settings.zoom_client_id or "").strip()
    platform_secret = (settings.zoom_client_secret or "").strip()

    legacy_id = ""
    try:
        _vault_creds = CredentialVault.get_credentials(
            db, org_uuid, "zoom", "zoom_oauth"
        ) or {}
        if (
            (_vault_creds.get("client_id") or "").strip()
            and (_vault_creds.get("client_secret") or "").strip()
            and (_vault_creds.get("redirect_uri") or "").strip()
        ):
            legacy_id = (_vault_creds.get("client_id") or "").strip()
    except Exception:
        pass

    # Legacy-first, mirroring resolve_client_credentials()
    effective_id = legacy_id or platform_id
    platform_configured = bool(effective_id and (legacy_id or platform_secret))

    result: dict = {
        "provider": "zoom",
        "integration_type": "zoom_oauth",
        "configured": platform_configured,
        "connected": False,
        "masked_client_id": None,
        "redirect_uri": (settings.zoom_redirect_uri or "").strip() or None,
        "account_email": None,
        "account_id": None,
        "connected_at": None,
    }

    if effective_id and len(effective_id) > 8:
        result["masked_client_id"] = effective_id[:4] + "..." + effective_id[-4:]
    elif effective_id:
        result["masked_client_id"] = effective_id

    if has_creds:
        metadata = CredentialVault.get_safe_metadata(
            db, org_uuid, "zoom", "zoom_oauth"
        ) or {}
        # Connected ONLY when status is actually CONNECTED (OAuth completed),
        # not merely when config credentials exist (PENDING).
        from app.models_multi_tenant import IntegrationStatus, OrgIntegration
        integration_row = db.query(OrgIntegration).filter(
            OrgIntegration.organization_id == org_uuid,
            OrgIntegration.provider == "zoom",
            OrgIntegration.integration_type == "zoom_oauth",
        ).first()
        result["connected"] = (
            integration_row is not None
            and integration_row.status == IntegrationStatus.CONNECTED
        )
        # Expose last_error so the dashboard can show "reconnect needed"
        # when the stored refresh token has been revoked or expired.
        if integration_row is not None and integration_row.last_error:
            result["last_error"] = integration_row.last_error
            result["status"] = integration_row.status.value
        else:
            result["last_error"] = None
            result["status"] = (
                integration_row.status.value if integration_row else None
            )
        result["account_id"] = metadata.get("account_id")
        result["account_email"] = metadata.get("account_email")
        result["connected_at"] = metadata.get("connected_at")

    return result


@app.delete("/auth/zoom/disconnect")
def zoom_oauth_disconnect(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(_auth_context),
) -> dict:
    """Disconnect Zoom OAuth for the authenticated organization.

    Clears stored credentials and sets integration status to DISCONNECTED.
    The organization will need to re-authorize to reconnect.

    SECURITY: Owner/Admin role required.
    """
    from app.dashboard import _require_owner_or_admin
    from app.services.zoom_oauth_flow import ZoomOAuthFlow

    _require_owner_or_admin(auth_ctx)

    if auth_ctx.org_id is None:
        raise HTTPException(
            status_code=400,
            detail="Organization context required.",
        )

    result = ZoomOAuthFlow.disconnect(db, auth_ctx.org_id)

    logger.info(
        "[ZOOM_OAUTH] Zoom OAuth disconnected via API",
        extra={"org_id": str(auth_ctx.org_id)},
    )

    return result
