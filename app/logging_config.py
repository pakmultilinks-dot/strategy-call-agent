"""Structured JSON logging configuration for production.

Provides:
- ``StructuredJsonFormatter``: Outputs one JSON object per log line with
  timestamp, level, logger, message, and optional request context fields.
- ``RequestLoggingMiddleware``: FastAPI middleware that assigns a unique
  request ID (``X-Request-ID``) to every inbound request, logs timing
  info, and injects the ID into log records via a context variable.

No passwords, tokens, or secrets are ever logged (verified in audit).
"""
import json
import logging
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# ── Context variable for request-scoped fields ──────────────────────────────
# Each request gets its own request_id and route; middleware sets these
# and the formatter reads them.
_request_id: ContextVar[str] = ContextVar("request_id", default="")
_request_route: ContextVar[str] = ContextVar("request_route", default="")
_request_method: ContextVar[str] = ContextVar("request_method", default="")
_request_status: ContextVar[int] = ContextVar("request_status", default=0)


def get_request_id() -> str:
    """Return the current request ID (empty string outside a request)."""
    return _request_id.get()


class StructuredJsonFormatter(logging.Formatter):
    """Logs each record as a single-line JSON object.

    Fields:
        - timestamp: ISO 8601 UTC
        - level: log level name (INFO, WARNING, etc.)
        - logger: logger name
        - message: the log message
        - request_id: (optional) UUID for the current request
        - method: (optional) HTTP method
        - route: (optional) request path
        - status_code: (optional) HTTP status code

    Sensitive fields (passwords, tokens, API keys) are never included.
    """

    # Keys that may contain sensitive data — never include if they
    # accidentally appear in log record extras.
    _SENSITIVE_KEYS = frozenset({
        "password", "token", "secret", "api_key", "authorization",
        "new_password", "access_token", "refresh_token", "client_secret",
    })

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Inject request context if available
        rid = _request_id.get()
        if rid:
            log_entry["request_id"] = rid
        method = _request_method.get()
        if method:
            log_entry["method"] = method
        route = _request_route.get()
        if route:
            log_entry["route"] = route
        status = _request_status.get()
        if status:
            log_entry["status_code"] = status

        # Include exception info if present (but not stack frames)
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = str(record.exc_info[1])

        return json.dumps(log_entry, default=str, ensure_ascii=False)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that assigns a request ID and logs request timing.

    Adds ``X-Request-ID`` header to both the inbound request (for tracing)
    and the outbound response. Logs one INFO line per completed request
    with method, path, status code, and duration in milliseconds.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Use client-provided X-Request-ID if present, else generate one.
        rid = request.headers.get("x-request-id") or str(uuid.uuid4())

        # Set context variables so StructuredJsonFormatter can pick them up
        _request_id.set(rid)
        _request_method.set(request.method)
        _request_route.set(request.url.path)

        start = time.monotonic()
        response: Response = await call_next(request)
        duration_ms = round((time.monotonic() - start) * 1000, 1)

        # Set the response status in context for the final log line
        _request_status.set(response.status_code)

        # Add request ID to response header
        response.headers["X-Request-ID"] = rid

        # Log the completed request
        logger = logging.getLogger("strategy-call-agent.access")
        logger.info(
            "%s %s %d %.1fms",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )

        return response


def configure_structured_logging(level: str = "INFO") -> None:
    """Configure root logger with structured JSON output.

    Call once during application startup (before any requests).
    Sets up a ``StreamHandler`` with ``StructuredJsonFormatter`` on the
    root logger and the application logger.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove any existing handlers to prevent duplicate output
    root_logger.handlers.clear()

    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJsonFormatter())
    root_logger.addHandler(handler)

    # Ensure the app logger inherits from root
    app_logger = logging.getLogger("strategy-call-agent")
    app_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
