"""Reusable in-memory sliding-window rate limiter.

Used by multiple routers to protect expensive or security-sensitive
endpoints.  Single-worker safe (dict-based).  On restart, counters
reset — documented as acceptable trade-off for this deployment.

Usage:
    from app.services.rate_limit import check_rate_limit

    # In an endpoint:
    check_rate_limit(
        key=f"ai:{org_id}",
        max_attempts=30,
        window_seconds=60,
        label="AI endpoint",
    )
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict

from fastapi import HTTPException, status

logger = logging.getLogger("strategy-call-agent.rate_limit")

# Class-level hit store — shared across instances so tests can call
# _clear_all_hits() between runs.
_hits: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(
    *,
    key: str,
    max_attempts: int,
    window_seconds: int,
    label: str = "endpoint",
) -> None:
    """Check if *key* has exceeded the sliding-window limit.

    Raises HTTPException 429 if the limit is breached.
    Callers do NOT need to record hits — this function does it
    automatically when the check passes.

    Parameters
    ----------
    key : str
        Unique identifier for the rate-limit bucket (e.g. ``f"ai:{org_id}"``
        or ``f"forgot:{email}"``).
    max_attempts : int
        Maximum number of allowed hits within the window.
    window_seconds : int
        Sliding window duration in seconds.
    label : str
        Human-readable label for log messages.
    """
    now = time.monotonic()
    window_start = now - window_seconds

    # Prune old timestamps
    _hits[key] = [t for t in _hits[key] if t > window_start]

    if len(_hits[key]) >= max_attempts:
        logger.warning(
            "rate limit exceeded: key=%s attempts=%d/%d window=%ds label=%s",
            key,
            len(_hits[key]),
            max_attempts,
            window_seconds,
            label,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for {label}. Please try again later.",
        )

    _hits[key].append(now)


def reset_rate_limit(key: str) -> None:
    """Clear the counter for a specific key (useful after successful actions)."""
    _hits.pop(key, None)


def _clear_all_hits() -> None:
    """Clear all rate-limit state.  FOR TESTS ONLY."""
    _hits.clear()
