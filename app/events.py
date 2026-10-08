"""In-memory event bus for real-time dashboard updates (Phase 6).

Provides a thread-safe publish/subscribe mechanism so background pipeline
tasks, RSVP polls, and reminder sends can push events to connected SSE
clients in real time.

Design:
- publish_event(event_type, data, organization_id) - thread-safe, callable
  from sync background tasks (pipeline runs in BackgroundTasks which may
  execute in a thread).  Accepts an optional organization_id so the event
  can be scoped to a single tenant.
- subscribe(organization_id) - returns an asyncio.Queue for an SSE client;
  the queue receives JSON-encoded event strings.  When organization_id is
  provided, only events for that organization are delivered.
- MAX_QUEUE_SIZE prevents a slow client from growing unbounded memory.

SSE endpoint is in dashboard.py; this module is the bus only.
"""
import asyncio
import json
import logging
import threading
import time
import uuid
from collections.abc import AsyncGenerator

logger = logging.getLogger("strategy-call-agent.events")

# --- In-memory subscriber list (asyncio.Queue per connected client) ---
# Each entry is a tuple: (queue, organization_id | None)
# When organization_id is None, the subscriber receives ALL events (platform admin).
_subscribers: list[tuple[asyncio.Queue, uuid.UUID | None]] = []
_lock = threading.Lock()

MAX_QUEUE_SIZE = 64  # per-client; drop oldest on overflow
KEEPALIVE_SECONDS = 30  # SSE comment keepalive


def subscribe(organization_id: uuid.UUID | None = None) -> asyncio.Queue:
    """Register a new SSE client and return its queue.

    Args:
        organization_id: When provided, only events for this organization
            will be delivered to the queue.  None means the subscriber
            receives ALL events (used by platform admins).
    """
    q: asyncio.Queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
    with _lock:
        _subscribers.append((q, organization_id))
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    """Remove an SSE client queue on disconnect."""
    with _lock:
        _subscribers[:] = [
            (queue, org_id) for queue, org_id in _subscribers if queue is not q
        ]


def publish_event(
    event_type: str,
    data: dict | None = None,
    organization_id: uuid.UUID | None = None,
) -> None:
    """Publish an event to connected SSE clients.

    Thread-safe: can be called from sync background tasks (pipeline,
    RSVP poll, reminder send) as well as async handlers.

    When organization_id is provided, the event is only delivered to
    subscribers that are watching that specific organization (or platform
    admins with organization_id=None).  When organization_id is None,
    the event is delivered to ALL subscribers (platform admin broadcast).

    If a client's queue is full (slow consumer), the oldest undelivered
    event is dropped to prevent memory growth.
    """
    event_payload = {"type": event_type, "data": data or {}, "ts": time.time()}
    if organization_id is not None:
        event_payload["org_id"] = str(organization_id)
    message = json.dumps(event_payload)
    with _lock:
        dead: list[asyncio.Queue] = []
        for q, sub_org_id in _subscribers:
            # Tenant-scoped filter (M4 fix): an event with organization_id=None
            # is a platform broadcast - deliver ONLY to platform-admin
            # subscribers (sub_org_id=None).  Previously it was delivered to
            # every subscriber, leaking other orgs' lead_ids + error text
            # onto org-scoped dashboards.
            if organization_id is None:
                if sub_org_id is not None:
                    continue
            elif sub_org_id is not None and sub_org_id != organization_id:
                continue
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                # Drop oldest to make room (bounded memory).
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    q.put_nowait(message)
                except asyncio.QueueFull:
                    dead.append(q)
        for q in dead:
            try:
                _subscribers[:] = [
                    (queue, org_id) for queue, org_id in _subscribers if queue is not q
                ]
            except ValueError:
                pass
    if _subscribers:
        logger.debug("published event %s to %d clients", event_type, len(_subscribers))


async def event_stream(queue: asyncio.Queue) -> AsyncGenerator[str, None]:
    """Async generator that yields SSE-formatted messages from the queue.

    Sends a keepalive comment every KEEPALIVE_SECONDS if no real events
    arrive, preventing proxy/load-balancer timeouts.

    Automatically unsubscribes the queue on disconnect (GeneratorExit or
    CancelledError) to prevent unbounded memory growth from leaked
    subscriber queues.
    """
    try:
        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=KEEPALIVE_SECONDS)
                yield f"data: {message}\n\n"
            except asyncio.TimeoutError:
                # Keepalive comment (lines starting with ':' are ignored by
                # the browser's EventSource but reset proxy read timeouts).
                yield ": keepalive\n\n"
    except (asyncio.CancelledError, GeneratorExit):
        pass
    finally:
        unsubscribe(queue)
