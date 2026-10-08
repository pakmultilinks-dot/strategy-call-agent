"""Production middleware: rate limiting, security headers, request size limits.

All middleware is lightweight and appropriate for a single-tenant deployment.
No distributed rate limiter (Redis) is needed - an in-memory sliding window
sufficiently protects a single-worker production instance.
"""
import logging
import re
import time
from collections import defaultdict
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import settings

logger = logging.getLogger("strategy-call-agent.middleware")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter applied ONLY to the public webhook.

    Dashboard endpoints are NOT rate-limited (internal use only).
    The limiter is in-memory and single-worker safe - appropriate for
    the Docker Compose single-worker deployment.
    """

    # Class-level hit tracking: shared across instances so tests can
    # clear _global_hits between test runs to prevent cross-test state.
    _global_hits: dict[str, list[float]] = defaultdict(list)

    def __init__(self, app, requests_per_minute: int = 30):
        super().__init__(app)
        self.rpm = requests_per_minute
        self._hits = RateLimitMiddleware._global_hits
        self._cleanup_interval = 60.0  # prune stale entries every 60s
        self._last_cleanup = time.monotonic()

    # Phase 5: Regex for org-scoped webhook - matches exactly one slug segment
    _ORG_WEBHOOK_RE = re.compile(r"^/webhooks/[^/]+/form-submission$")

    async def dispatch(self, request: Request, call_next: Callable):
        # Rate-limit public webhook endpoints (legacy + org-scoped)
        # Phase 5: extended to cover /webhooks/{org_slug}/form-submission
        path = request.url.path
        is_webhook = (
            path == "/webhooks/form-submission"
            or bool(self._ORG_WEBHOOK_RE.match(path))
        )
        if not is_webhook or request.method != "POST":
            return await call_next(request)

        if self.rpm <= 0:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        window_start = now - 60.0

        # Periodic cleanup to prevent memory growth
        if now - self._last_cleanup > self._cleanup_interval:
            self._last_cleanup = now
            stale_keys = [
                ip for ip, timestamps in self._hits.items()
                if not timestamps or timestamps[-1] < window_start
            ]
            for ip in stale_keys:
                del self._hits[ip]

        # Prune entries outside the window for this IP
        timestamps = self._hits[client_ip]
        self._hits[client_ip] = [t for t in timestamps if t > window_start]

        if len(self._hits[client_ip]) >= self.rpm:
            logger.warning(
                "rate limit exceeded: ip=%s path=%s",
                client_ip, request.url.path,
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "rate limit exceeded, try again later"},
            )

        self._hits[client_ip].append(now)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to all responses.

    Lightweight protections appropriate for a single-tenant API:
    - Content-Security-Policy: restricts resource loading origins
    - Referrer-Policy: controls referrer information leakage
    - Permissions-Policy: disables unnecessary browser features
    - X-Content-Type-Options: nosniff (prevent MIME sniffing)
    - X-Frame-Options: DENY (prevent clickjacking on dashboard)
    - Cache-Control: no-store (prevent sensitive data caching)
    - Strict-Transport-Security: HTTPS enforcement (prod only)

    CSP Policy (Phase 28 P1-C):
    The dashboard uses ~2300 lines of inline JavaScript and 70+ inline
    onclick event handlers.  A nonce-based or hash-based CSP would require
    migrating every inline handler to addEventListener - a disproportionate
    refactor for the current phase.  The policy below applies
    ``'unsafe-inline'`` for script-src (the minimum required for the inline
    dashboard) while restricting all other resource types to same-origin.
    This blocks external script injection, object/embed loading, base-tag
    hijacking, and form submission to third parties.

    Future hardening path:
    1. Refactor inline onclick handlers to addEventListener (Step A)
    2. Generate SHA-256 hashes for the remaining inline <script> block
    3. Replace 'unsafe-inline' with hash-based allowlisting (Step B)
    """

    # CSP directives - built once at class level for zero per-request cost.
    # Phase 28 P1-C: event-source-src is NOT a valid CSP directive;
    # EventSource (SSE) connections are governed by connect-src.
    # Font CSS is loaded from api.fontshare.com but font FILES are
    # served from cdn.fontshare.com - both must be allowed.
    _CSP_DIRECTIVES = (
        "default-src 'self';"
        "script-src 'self' 'unsafe-inline';"
        "style-src 'self' 'unsafe-inline' https://api.fontshare.com;"
        "font-src 'self' https://cdn.fontshare.com;"
        "img-src 'self' data:;"
        "connect-src 'self';"
        "frame-ancestors 'none';"
        "base-uri 'self';"
        "form-action 'self';"
    )

    async def dispatch(self, request: Request, call_next: Callable):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # Phase 28 P1-C: Content-Security-Policy
        response.headers["Content-Security-Policy"] = self._CSP_DIRECTIVES
        # Phase 28 P1-C: Referrer-Policy - no referrer on cross-origin,
        # full referrer on same-origin.  Prevents leaking URL paths to
        # third-party fonts while preserving analytics for internal links.
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Phase 28 P1-C: Permissions-Policy - disable unnecessary browser
        # features.  Camera, microphone, geolocation, and payment are not
        # needed by the strategy-call-agent dashboard.
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(),"
            "payment=(), usb=(), magnetometer=(),"
            "gyroscope=(), accelerometer=()"
        )
        # Phase 25 + 28: HSTS header - only in production where a TLS-
        # terminating reverse proxy is guaranteed.  In dev/test the server
        # typically runs plain HTTP, and HSTS would cause browser warnings
        # or broken connections on localhost.
        if settings.app_env == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        # Allow short caching for health & semi-static config endpoints.
        # Dashboard data endpoints remain no-store to always show fresh data.
        path = request.url.path
        if path in ("/health", "/health/ready"):
            response.headers["Cache-Control"] = "public, max-age=5"
        elif path in ("/dashboard/api/ai/status", "/dashboard/api/ai/providers",
                       "/auth/google/status", "/auth/zoom/status",
                       "/dashboard/api/setup-status"):
            response.headers["Cache-Control"] = "private, max-age=10"
        elif path != "/health":
            response.headers["Cache-Control"] = "no-store"
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects requests exceeding a reasonable body size.

    Google Form payloads are small JSON (< 5KB). This prevents abuse
    without impacting legitimate traffic.
    """

    MAX_BODY_BYTES = 64 * 1024  # 64 KB

    async def dispatch(self, request: Request, call_next: Callable):
        content_length = request.headers.get("content-length")
        # M6 fix: a malformed Content-Length must be a 400, not an
        # unhandled 500 from int().
        if content_length:
            try:
                declared = int(content_length)
            except (ValueError, TypeError):
                return JSONResponse(
                    status_code=400,
                    content={"detail": "invalid Content-Length header"},
                )
            if declared > self.MAX_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "request body too large"},
                )

        # M5 fix: without a Content-Length (chunked transfer encoding)
        # the header check above is skipped entirely.  Count bytes as
        # the body streams in and reject oversized bodies with 413.
        received = 0
        original_receive = request._receive

        async def _counting_receive():
            nonlocal received
            message = await original_receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
            return message

        request._receive = _counting_receive  # type: ignore[method-assign]
        try:
            response = await call_next(request)
        finally:
            request._receive = original_receive  # type: ignore[method-assign]

        if received > self.MAX_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content={"detail": "request body too large"},
            )
        return response


class OrgRateLimitMiddleware(BaseHTTPMiddleware):
    """Per-organization sliding-window rate limiter for authenticated API endpoints.

    Extracts org_id from the JWT Authorization header (without full validation)
    and applies per-org request throttling.  This prevents a single org from
    degrading service for others through excessive API usage.

    Default: 120 requests per minute per organization.
    In-memory, single-worker safe - appropriate for Docker Compose deployment.
    """

    _global_hits: dict[str, list[float]] = defaultdict(list)

    def __init__(self, app, requests_per_minute: int = 120):
        super().__init__(app)
        self.rpm = requests_per_minute
        self._hits = OrgRateLimitMiddleware._global_hits
        self._cleanup_interval = 60.0
        self._last_cleanup = time.monotonic()

    async def dispatch(self, request: Request, call_next: Callable):
        # Skip rate-limiting for public and webhook paths
        path = request.url.path
        if (
            path.startswith("/webhooks/")
            or path == "/health"
            or path.startswith("/docs")
            or path.startswith("/openapi")
            or path.startswith("/redoc")
            or path == "/auth/register"
            or path == "/auth/login"
            or path == "/auth/forgot-password"
            or path == "/auth/reset-password"
        ):
            return await call_next(request)

        # Extract org_id from JWT without full validation (rate limiting only)
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return await call_next(request)

        token = auth_header[7:]
        org_id = self._extract_org_id(token)
        if org_id is None:
            return await call_next(request)

        # M7 fix: the org_id comes from a signature-UNVERIFIED token, so it
        # must not be the sole bucket key - anyone could mint a token with
        # a victim's org_id and burn their quota.  Key by client IP too, so
        # forged claims only burn the attacker's own IP bucket.
        client_ip = request.client.host if request.client else "unknown"
        bucket_key = f"{client_ip}:{org_id}"

        now = time.monotonic()
        window_start = now - 60.0

        # Periodic cleanup to prevent memory growth
        if now - self._last_cleanup > self._cleanup_interval:
            self._last_cleanup = now
            stale_keys = [
                k for k, timestamps in self._hits.items()
                if not timestamps or timestamps[-1] < window_start
            ]
            for k in stale_keys:
                del self._hits[k]

        timestamps = self._hits[bucket_key]
        self._hits[bucket_key] = [t for t in timestamps if t > window_start]

        if len(self._hits[bucket_key]) >= self.rpm:
            logger.warning(
                "per-org rate limit exceeded: org_id=%s ip=%s path=%s",
                org_id, client_ip, path,
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "organization rate limit exceeded, try again later"},
                headers={"Retry-After": "60"},
            )

        self._hits[bucket_key].append(now)
        return await call_next(request)

    @staticmethod
    def _extract_org_id(token: str) -> str | None:
        """Extract org_id from a JWT without full validation.

        Uses unverified decode for rate-limiting purposes only.
        Actual JWT validation is performed by the _auth dependency downstream.
        """
        try:
            from jose import jwt as _jwt
            payload = _jwt.get_unverified_claims(token)
            return payload.get("org_id")
        except Exception:
            return None
