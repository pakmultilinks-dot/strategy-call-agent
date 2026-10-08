"""Shared retry + FailedJob persistence for external API calls.

Used by calendar, AI, and email services so transient failures are retried
with exponential backoff and permanent failures are recorded for later
retry instead of being silently swallowed.
"""
import logging

from sqlalchemy.orm import Session
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

# Transient = worth retrying (5xx, 429 rate limit, network). Permanent
# (4xx other than 429, auth, validation) is NOT retried.
_TRANSIENT_MARKERS = ("429", "500", "502", "503", "504")


def is_transient(exc: BaseException) -> bool:
    """True for rate-limit / server / network errors; False for 4xx/auth."""
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    if status is not None:
        try:
            return int(status) == 429 or int(status) >= 500
        except (TypeError, ValueError):
            pass
    msg = str(exc).lower()
    if any(m in msg for m in ("401", "403", "400", "404", "invalid_grant", "unauthorized")):
        return False
    # Model content-policy refusals are permanent - do not retry.
    if any(kw in msg for kw in ("refusal", "candidate refusal", "content_policy", "safety")):
        return False
    if any(m in msg for m in _TRANSIENT_MARKERS):
        return True
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    # OpenAI SDK exceptions don't inherit from Python builtins.
    # APITimeoutError → retry (server may be slow), APIConnectionError →
    # retry (network blip), APIStatusError with 429/5xx → retry.
    try:
        from openai import APIConnectionError, APIStatusError, APITimeoutError

        if isinstance(exc, APITimeoutError):
            return True
        if isinstance(exc, APIConnectionError):
            return True
        if isinstance(exc, APIStatusError):
            return exc.status_code == 429 or exc.status_code >= 500
    except ImportError:
        pass
    return False


# Retry on transient errors, exponential backoff, max 3 attempts, then raise.
external_call_retry = retry(
    retry=retry_if_exception(is_transient),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    stop=stop_after_attempt(3),
    reraise=True,
)


def record_failed_job(
    db: Session, job_type: str, payload: str | None, error: str,
    organization_id=None,
) -> None:
    """Write a FailedJob row so a failed external call can be retried later.

    Uses its own session lifecycle-safe commit; never raises into the caller.

    Phase 6B.4: Accepts explicit organization_id to avoid relying on the
    global tenant context which may not be set in background tasks.

    Phase 1 (Hardening): organization_id is now REQUIRED.  The default-org
    fallback has been removed.
    """
    from app.models import FailedJob  # local import to avoid cycles

    if organization_id is None:
        # M13 fix: never raise into the caller (this runs inside except
        # handlers - raising here would mask the original error).  A
        # platform-scoped failure has no org to attribute to, so log it
        # and return instead of crashing.
        logger = logging.getLogger(__name__)
        logger.error(
            "record_failed_job() called without organization_id; "
            "cannot persist FailedJob row. job_type=%r error=%s",
            job_type, error[:500],
        )
        return

    try:
        db.add(
            FailedJob(
                job_type=job_type,
                payload=payload,
                error=error[:4000],
                organization_id=organization_id,
            )
        )
        db.commit()
    except Exception:
        db.rollback()
