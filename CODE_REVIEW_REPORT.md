# Code Review Report: strategy-call-agent

**Repo:** `~/workspace/strategy-call-agent-review` (FastAPI multi-tenant SaaS - AI call-scheduling agent, Google Calendar/Gmail + Zoom)
**Reviewer:** senior code reviewer (subagent)
**Date:** 2026-10-08
**Method:** full manual read of security-critical paths (auth, JWT, tenant isolation, OAuth, webhooks, pipeline, migrations, Docker/prod config) + targeted greps + live verification of risky claims (APScheduler jobstore behavior, Postgres SQL semantics) + test-suite execution.
**Note:** the parent agent concurrently rebuilt the Google/Zoom OAuth UX (platform-owned one-click connect) in this working tree while the review was in progress. Every finding cited in `app/main.py` / `app/dashboard.py` / OAuth services was re-verified against the modified tree afterward (via `git diff` + re-grep); all findings below are present in the current working tree.

**Scope covered:** auth/JWT/tenant isolation, secrets handling, SQLi/SSRF/XSS, OAuth state & redirects, CORS/rate limiting, pipeline races & idempotency, transactions, timezone handling, migrations 001–021, background jobs, webhooks, entrypoint/Docker/Caddy, CI, tests.

**Verdict up front:** the auth model (JWT + blocklist, org-scoped queries, constant-time webhook secrets) is fundamentally sound, and most dashboard/router queries are correctly org-scoped. But there are **4 critical** issues that each independently break production or security: a hardcoded admin password shipped in the Docker image, a migration chain that cannot bootstrap a fresh production database, a cross-tenant email trigger, and a model/column type mismatch that 500s two dashboard endpoints on Postgres. Plus 10 high-severity reliability/security issues (secret in entrypoint logs, pipeline double-processing races, SSRF, privilege escalation, TLS bypass, broken CI).

---

## CRITICAL

### C1 - Hardcoded admin password shipped in the Docker image
**File:** `scripts/ensure_default_org_user.py:27`, `:50`, `:57`, `:76`
**What's wrong:** `ADMIN_PASSWORD = "ChangeMe123!"` is hardcoded for `admin@integratedittrainings.com`, and line 76 `print(f"  Password: {ADMIN_PASSWORD}")` prints it to stdout. The Dockerfile does `COPY scripts/ scripts/`, so this password is baked into every production image and visible to anyone who can pull/inspect it.
**Why it matters:** anyone with the image (or repo access) gets a known owner credential for the default org - full tenant admin. This is a backdoor, not a default.
**Fix:** delete the hardcoded password; require it via env var (`ADMIN_PASSWORD` prompt) or interactive input; never print it; exclude the script from the production image (`.dockerignore`).

### C2 - Fresh production databases can never start (migration chain has no baseline)
**Files:** `alembic/versions/001_multi_tenant_foundation.py` (whole file), `entrypoint.sh`, `Dockerfile`, `DEPLOYMENT.md:143`
**What's wrong:** 001 is the first migration (`down_revision = None`) but it only *adds* `organization_id` to `leads`, `events_log`, `failed_jobs` - it never *creates* those tables (nor `schedule_config`). On a fresh DB, `_column_exists()` returns False and `op.add_column("leads", …)` raises `OperationalError: relation "leads" does not exist`. `entrypoint.sh` runs `alembic upgrade head` under `set -euo pipefail`, so the container exits → crash loop on every fresh prod deploy. Meanwhile `DEPLOYMENT.md:143` claims "The application creates all tables automatically on startup via SQLAlchemy `Base.metadata.create_all()`" - but `lifespan` in `app/main.py` explicitly **skips** `create_all` when `APP_ENV=production`. Docs and code contradict each other; neither path works for a fresh prod DB.
**Fix:** add a baseline migration (000) that creates `leads`, `events_log`, `failed_jobs`, `schedule_config` (matching the models), or make 001 create the tables when missing. Correct DEPLOYMENT.md.

### C3 - Cross-tenant email trigger: any org owner can fire follow-up emails for ALL orgs
**Files:** `app/main.py:2231` (`trigger_followup_emails`), `app/services/followup_email_sender.py:76` (`execute_due_follow_ups`)
**What's wrong:** `POST /dashboard/api/trigger/followup-emails` requires only owner/admin of the *caller's* org, but calls `execute_due_follow_ups()` which takes **no** `organization_id` parameter - `_query_due_followups(db, MAX_BATCH_SIZE)` (line 100, 121) selects due follow-ups across every tenant and sends them. Compare the sibling triggers `trigger_reminders` / `trigger_poll_rsvps`, which correctly pass `organization_id=auth_ctx.org_id`. The module docstring even claims "Respects tenant isolation: every query filters by organization_id" - false for the entry point.
**Why it matters:** a customer org's owner can (accidentally or maliciously) send emails to every other customer's leads from their Gmail identities. Tenant-isolation breach + spam/phishing blast radius.
**Fix:** add `organization_id` parameter to `execute_due_follow_ups()` / `_query_due_followups()` and pass `auth_ctx.org_id` (None only for platform admin).

### C4 - `FailedJob.resolved` is a `String` column used as a boolean: 500s on Postgres
**Files:** `app/models.py:299`, `app/dashboard.py:1163`, `app/dashboard.py:1190`, `app/main.py:364`
**What's wrong:** `resolved: Mapped[bool] = mapped_column(String, nullable=False, default=False, server_default="false")` - the Python type says bool, the DB type is VARCHAR. `dashboard.py:1163` (`GET /dashboard/api/failed-jobs`) and `:1190` (`GET /dashboard/api/summary`) use `.is_(False)`, which renders `WHERE resolved IS false`. On Postgres, `IS FALSE` requires a boolean operand → `ERROR: argument of IS FALSE must be type boolean, not type character varying` → **HTTP 500 on both endpoints in production**. (SQLite accepts it silently, which is why the test suite never catches it.) The `== False` usages (e.g. `main.py:364`) only work by accident via string coercion (`'False'`), and `server_default="false"` (lowercase) vs Python-side `'False'` means rows inserted via raw SQL never match the filter.
**Fix:** change the column to `Boolean`, add a migration that alters the type and normalizes `'false'/'true'/'False'/'True'` values; use `.is_(False)` consistently afterward.

---

## HIGH

### H1 - `entrypoint.sh` prints the database password to container logs
**File:** `entrypoint.sh:9` - `echo "[entrypoint] Database URL: ${DATABASE_URL:-(not set)}"`
**What's wrong:** `DATABASE_URL` contains `postgres:<password>@…`; it is echoed verbatim on every container start. Docker logs are routinely shipped to aggregators and visible to anyone with log access.
**Fix:** redact before printing, e.g. strip the password with sed: `echo "${DATABASE_URL}" | sed -E 's#(://[^:]+:)[^@]+@#\1***@#'`.

### H2 - Pipeline double-processing race (duplicate calendar events + duplicate emails)
**File:** `app/main.py:1362–1372` (`_run_pipeline_inner`)
**What's wrong:** the "optimistic lock" is check-then-set with no row lock:
```python
if lead.processing_started_at is not None: return
lead.processing_started_at = datetime.now(timezone.utc)
db.commit()
```
Two concurrent executions (duplicate webhook deliveries, or `_recover_stuck_leads` + a background task - sync `BackgroundTasks` run in a threadpool, so this interleaves) can both read `None`, both commit, both run the pipeline. The email idempotency guard (`email_sent` event check, ~line 1590) is the same check-then-act pattern with no lock. Result: duplicate Google Calendar events, duplicate Zoom meetings, duplicate confirmation emails to prospects.
**Fix:** `SELECT … FOR UPDATE` on the lead row (or `pg_advisory_xact_lock(lead_id)`), or a partial unique index preventing two in-flight claims; make the email-sent guard atomic.

### H3 - Stale pipeline locks are never cleared: leads stuck in PENDING forever
**Files:** `app/main.py` (`_run_pipeline_inner` guard at `:1368`, `_recover_stuck_leads`)
**What's wrong:** if the worker dies mid-pipeline (gunicorn `--max-requests 1000` recycles workers; OOM kills; deploys), `processing_started_at` stays set - the in-`except` cleanup never runs. `_recover_stuck_leads` re-queues PENDING leads but `_run_pipeline_inner` then hits `if lead.processing_started_at is not None: … skipping` and returns. Nothing ever clears a stale lock, so the lead is stuck in PENDING permanently (recovery logs "already being processed" every 10 min forever).
**Fix:** treat locks older than N minutes as stale in `_recover_stuck_leads` (clear `processing_started_at` before re-queue), and/or store a heartbeat.

### H4 - SSRF via AI provider test endpoints (user-supplied `base_url` fetched server-side)
**Files:** `app/main.py:3446` (`test_ai_connection`; body `base_url` read at `:3479`, fetched at `:3539` and `:3601`), `app/main.py:3668` (`load_ai_models`; vault `base_url` fetched at `:3718`)
**What's wrong:** `test_ai_connection` accepts `{"base_url": "<arbitrary>"}` in the request body and the server performs `httpx.Client().get/post(f"{normalized_url}/models")` against it - with `Authorization: Bearer <api_key>` attached. An org owner/admin (or a compromised admin account) can make the server probe internal network targets (e.g. `http://169.254.169.254/`, internal admin ports). `load_ai_models` has the same shape using the vault-saved `base_url`.
**Fix:** validate the URL before fetching: require `https`, resolve DNS and reject private/loopback/link-local ranges and the metadata IP, or restrict testing to already-saved vault values with an allowlist.

### H5 - Privilege escalation: admins can create owner accounts
**File:** `app/routers/organization_router.py:82` (`create_user`)
**What's wrong:** `create_user` requires `OWNER` or `ADMIN` and then does `role = UserRole(payload.role)` with **no** restriction - an admin can create a new user with `role: "owner"`. The sibling `update_user` correctly has "Only the owner can assign the owner role" (`:154`–`168`), but creation was missed.
**Fix:** mirror the update check - only `OWNER` may create `owner`-role users.

### H6 - Admin can disable/demote the owner; no last-owner protection on update
**File:** `app/routers/organization_router.py:154` (`update_user`)
**What's wrong:** `DELETE /users/{id}` has last-owner protection, but `PATCH` lets an admin set the owner's `status` to `disabled` (or an owner demote themselves), potentially leaving the org with no functioning owner and locking everyone out. No self-demotion guard either.
**Fix:** refuse to disable/demote the last active owner; refuse self-demotion via this endpoint (use change-password/delete flows).

### H7 - Production app port exposed: Caddy TLS can be bypassed
**Files:** `docker-compose.yml` (app `ports: ["8000:8000"]`), `docker-compose.prod.yml`
**What's wrong:** the prod override removes the host port mapping for `db` (`ports: []`) but **not** for `app` - in production the FastAPI app is still directly reachable on host port 8000, bypassing Caddy's TLS termination, HSTS, and access logging. Plain-HTTP API access in "production".
**Fix:** add `ports: []` for `app` in `docker-compose.prod.yml` (keep the mapping only in a dev override).

### H8 - No `ProxyHeadersMiddleware`: rate limits and audit IPs are wrong behind Caddy
**Files:** `app/main.py` (middleware stack - no `ProxyHeadersMiddleware`), `app/middleware.py`, `Caddyfile` (sets `X-Forwarded-For`)
**What's wrong:** Starlette's `request.client.host` is the direct TCP peer. Behind Caddy it is always the Caddy container IP, so: (a) the webhook per-IP rate limit (30/min) and the register per-IP limit (5/5min) become **single global buckets** - normal webhook bursts 429 themselves, and one actor can exhaust the bucket for everyone; (b) every audit/security log records the proxy IP, not the client.
**Fix:** add `ProxyHeadersMiddleware(app, trusted_hosts=[...])` with trusted hosts restricted to the Docker/proxy network (never `*` when the app port is directly reachable - see H7).

### H9 - CI pipeline is broken several independent ways
**Files:** `.github/workflows/ci.yml`, `requirements.txt`
**What's wrong:**
1. `requirements.txt` contains neither `pytest` nor `pytest-timeout`, but CI runs `python -m pytest tests/ --timeout=120` → "No module named pytest" / "unrecognized arguments: --timeout". (Verified: neither is installed by requirements.)
2. CI sets `JWT_SECRET`, but the app setting is `jwt_secret_key` → env var `JWT_SECRET_KEY`; in `APP_ENV=test`, `get_jwt_secret_key()` raises `RuntimeError` for any non-monkeypatched code path.
3. CI never sets `CREDENTIAL_ENCRYPTION_KEY` → `get_credential_encryption_key()` raises `RuntimeError` in test mode on non-monkeypatched paths.
4. CI never sets `DASHBOARD_USERNAME`/`DASHBOARD_PASSWORD` → `conftest.py`'s `_AUTH_HEADER` is `base64(":")` → every Basic-auth test 401s (reproduced locally: `test_csv_export.py::TestLeadCSVExport::test_export_returns_csv_content_type` fails 401).
**Fix:** add `pytest` + `pytest-timeout` (or a `requirements-test.txt`), rename to `JWT_SECRET_KEY`, add the two secrets plus dashboard creds to CI env.

### H10 - Migration 021 can crash `alembic upgrade head` on real data (no NULL cleanup)
**File:** `alembic/versions/021_events_log_org_not_null.py`
**What's wrong:** `op.alter_column("events_log", "organization_id", nullable=False)` with no backfill/cleanup step, unlike 001 which checks `null_count` first. NULL rows are reachable: `_log_webhook_auth_failure` (`app/main.py`) inserts `EventLog(organization_id=None)` whenever the org slug doesn't resolve (e.g. attacker probing random slugs with bad tokens) - before 021 the DB column is nullable, so those rows persist. On such a DB, 021 fails → `entrypoint.sh` (`set -e`) exits → crash loop on deploy.
**Fix:** in the migration, `UPDATE events_log SET organization_id = <default> WHERE organization_id IS NULL` (or delete them) before altering, mirroring 001's guard.

---

## MEDIUM

### M1 - Retried Zoom `create_meeting` POST can create duplicate meetings
**Files:** `app/services/retry.py` (`external_call_retry` = tenacity, 3 attempts on transient incl. timeouts), `app/services/zoom_api_client.py:135,202` (`@external_call_retry` on meeting POSTs), `app/services/meeting_provider.py:301` ("idempotency_key: Unique key (logged, **not sent to Zoom**)")
**What's wrong:** retrying a POST after a timeout is unsafe when the first attempt may have succeeded server-side. Zoom has no idempotency-key support and the provider admits the key is only logged. A single timeout → 2 Zoom meetings for one lead (plus the pipeline race in H2).
**Fix:** don't blanket-retry non-idempotent POSTs; on timeout, list/reconcile before re-creating, or gate creation behind the DB claim (H2).

### M2 - SSE credentials in the URL: JWT/Basic tokens land in access logs
**File:** `app/dashboard.py:1260` (`GET /dashboard/api/events?token=…`)
**What's wrong:** EventSource can't send headers, so auth goes in the query string. Caddy's `log` block (`Caddyfile`) writes the full request URI → long-lived JWTs (30 min) and permanent Basic credentials are persisted in plaintext access logs, plus browser history.
**Fix:** issue a short-lived, single-purpose SSE ticket via an authenticated POST, then `?ticket=`; or set an HttpOnly cookie.

### M3 - SSE validation skips revocation/status checks
**File:** `app/dashboard.py:1215` (`_validate_sse_token`)
**What's wrong:** unlike `get_current_user` / `_resolve_auth_context`, it only decodes the JWT - no blocklist check, no user-active check, no org-suspended check, no user-existence check. A logged-out (revoked) or disabled user's token still opens a live event stream.
**Fix:** replicate the revocation + status checks from `_resolve_auth_context`.

### M4 - `organization_id=None` events broadcast to org-scoped SSE subscribers
**Files:** `app/events.py` (`publish_event`), `app/main.py` (`publish_event("pipeline.failed", …, organization_id=lead.organization_id if lead is not None else None)`)
**What's wrong:** the fan-out filter skips only when *both* sides are non-None and differ - a `None`-org event is delivered to **every** subscriber including org-scoped ones, leaking other orgs' `lead_id` + error text onto their dashboards.
**Fix:** drop `None`-org events for org-scoped subscribers (deliver only to platform-admin subscribers).

### M5 - Request-size limit bypass via chunked transfer encoding
**File:** `app/middleware.py` (`RequestSizeLimitMiddleware`)
**What's wrong:** it only inspects the `content-length` header. Requests without it (chunked) skip the 64 KB cap entirely; `org_form_submission` then does `await request.body()` + `json.loads` on an unbounded body → memory exhaustion via the public webhook.
**Fix:** enforce the cap incrementally while reading the body (or set a server-level limit).

### M6 - Malformed `Content-Length` → unhandled 500
**File:** `app/middleware.py` (`int(content_length)`)
**What's wrong:** a non-numeric `Content-Length` header raises `ValueError`, which isn't caught → 500 instead of 400.
**Fix:** `try/except (ValueError, TypeError)` → 400.

### M7 - Per-org rate limiting keyed by *unverified* JWT claims
**File:** `app/middleware.py` (`OrgRateLimitMiddleware._extract_org_id` → `jwt.get_unverified_claims`)
**What's wrong:** the bucket key comes from a signature-unverified token. Anyone can mint a token with a victim's `org_id` and burn their 120/min quota with invalid requests (practical exploitability is limited - org IDs are random UUIDs not exposed publicly - but the layering is wrong: unauthenticated input must not drive per-tenant buckets).
**Fix:** rate-limit pre-auth by IP; apply the per-org bucket only after successful authentication.

### M8 - Manual-lead dedupe key isn't org-scoped → cross-org false 409s
**Files:** `app/schemas.py` (`ManualLeadRequest.compute_dedupe_key` → `f"manual|{email}|{appt}"`), `app/models.py` (global unique index `ix_leads_dedupe_key`), `app/dashboard.py` (`create_lead`)
**What's wrong:** the webhook path correctly prefixes the key with `organization_id`, but the dashboard manual-lead path doesn't. Two orgs creating a manual lead with the same email+time collide on the global unique index → second gets a spurious 409.
**Fix:** include `organization_id` in the manual key, same as the webhook path.

### M9 - Manual leads parse appointment times as UTC; webhook path uses org timezone
**File:** `app/dashboard.py` (`create_lead` - raw `dateparser.parse` + naive→UTC), vs `app/main.py` (`_parse_appt_utc` with org `business_tz`)
**What's wrong:** the same free-text input ("tomorrow 2pm") is interpreted in two different timezones depending on entry path → appointments land hours off for manual leads.
**Fix:** route manual leads through `_parse_appt_utc` with the org's timezone.

### M10 - Password-reset emails fail silently when the org's Gmail isn't connected
**File:** `app/routers/auth_router.py` (`forgot_password` - "best-effort" send, exception swallowed)
**What's wrong:** the reset email is sent via the *org's own* Gmail integration. If it's not connected, the endpoint still returns the generic success message and the user can never reset their password - no fallback, no signal.
**Fix:** fall back to a platform sender for auth-critical mail, or surface a actionable error to admins.

### M11 - Dedupe key uses the raw appt string, not the normalized instant
**File:** `app/schemas.py` (`compute_dedupe_key`)
**What's wrong:** `"Aug 27 2026 9am"` vs `"2026-08-27 09:00"` (same instant) produce different keys → duplicate leads → duplicate pipeline runs → duplicate prospect emails. The key is normalized only for case/whitespace.
**Fix:** key on the parsed UTC instant (fall back to the raw string when unparseable).

### M12 - `_verify_bearer_auth` accepts empty-secret/empty-token comparison
**File:** `app/main.py` (`_verify_bearer_auth`): `secrets.compare_digest("", "")` is `True`
**What's wrong:** if ever called with an empty secret, `Authorization: Bearer ` (empty token) authenticates. Currently unreachable (both call sites guard on non-empty secrets), but it's a latent auth bypass one refactor away.
**Fix:** `if not secret or not provided_token: raise 401` before comparing.

### M13 - `record_failed_job` raises when `organization_id=None`, masking the real error
**Files:** `app/services/retry.py:80`, `app/services/email_service.py:87` (`send_email` except-handler)
**What's wrong:** `record_failed_job` raises `RuntimeError` on `None` org. In `EmailService`'s platform-default path (`_org_id=None`), an email failure enters the except handler, which then raises `RuntimeError` instead of the original exception - the real error is lost and no `FailedJob` is recorded. (All current call sites pass an org context, so this is latent.)
**Fix:** make `record_failed_job` tolerate `None` (platform-scoped job) or assert org context at construction.

### M15 - Public RSVP route 500s on SQLite: naive/aware datetime comparison
**File:** `app/services/rsvp_token_service.py:188` (`validate_and_process_rsvp`)
**What's wrong:** `now = datetime.now(timezone.utc)` (line ~141) is compared with `rsvp_token.expires_at` at line 188 (`if rsvp_token.expires_at < now:`). On SQLite, `DateTime(timezone=True)` columns come back **naive**, so this raises `TypeError: can't compare offset-naive and offset-aware datetimes` → HTTP 500 on the public `GET /rsvp/{token}` route. The OAuth state validators (`_validate_state` in both OAuth flows) and `followup_email_sender._ensure_aware` all handle naive datetimes explicitly - this service was missed. 29 of the repo's own RSVP tests fail on SQLite for exactly this reason (verified on the pristine baseline). Production Postgres (TIMESTAMPTZ) is unaffected, so this bites dev/test environments.
**Fix:** normalize with the same `_ensure_aware` pattern (attach UTC when `tzinfo is None`) before comparing.

### M16 - `decrypt_secret` raises raw `TypeError` on non-string ciphertext
**File:** `app/services/crypto.py:179` (`decrypt_secret`)
**What's wrong:** `ciphertext.startswith(_VERSION_PREFIX)` assumes `str`. If the DB row holds bytes (corruption, manual edit, driver quirk - the column is `Text`), this raises `TypeError`, which is *not* wrapped in `DecryptionError` (it's outside the try block). `CredentialVault.get_credentials` only catches `DecryptionError`/`CryptoError`, so callers expecting `CredentialCorruptError` get an unexpected `TypeError` instead (one repo test fails on this). 
**Fix:** validate/coerce input at the top: `if isinstance(ciphertext, bytes): try decode except → DecryptionError`; `if not isinstance(ciphertext, str): raise DecryptionError`.

### M14 - Login rate limit has no per-IP dimension
**File:** `app/routers/auth_router.py` (`_check_login_rate_limit` - per-email only, 10 failures/5 min)
**What's wrong:** 10 attempts/5 min per email is generous for targeted guessing, and there's no per-IP brake for distributed credential stuffing across many emails (the register per-IP limiter exists but is broken behind the proxy - see H8).
**Fix:** add a per-IP bucket alongside the per-email bucket (after fixing H8).

---

## LOW / HYGIENE

- **L1** - `config.py` (`get_jwt_secret_key`) writes `.dev_jwt_secret` into the app source tree; it's not in `.dockerignore`, so a dev-built image can bake a long-lived JWT signing key into the image. Write to a temp dir or ignore it.
- **L2** - Doc drift: `RSVPToken` (`app/models.py`) and `PasswordResetToken` (`app/models_multi_tenant.py`) docstrings claim bcrypt storage; the code correctly uses SHA-256 (appropriate for high-entropy single-use tokens - no action needed on the code).
- **L3** - `TOKEN_EXCHANGE_MAX_RETRIES = 2` (`app/services/google_oauth_flow.py`) is defined but never used.
- **L4** - `register` slug generation has a TOCTOU: two concurrent same-name registrations → second gets 409 "email already exists" (safe but misleading) (`app/routers/auth_router.py`, `app/auth.py:generate_organization_slug`).
- **L5** - `openapi.json` is committed at the repo root and will drift from the code; generate it in CI instead.
- **L6** - `register` enforces *global* email uniqueness in app code while the DB constraint is per-org (`uq_users_org_email`); `login` uses `.first()`, so a duplicate (inserted out-of-band) makes login pick an arbitrary account (`app/routers/auth_router.py`).
- **L7** - `GET /dashboard/api/integration-health` performs a real paid AI chat completion on every click with no rate limit (`app/main.py`).
- **L8** - The legacy `POST /webhooks/form-submission` (410 Gone) still parses/validates the `FormSubmission` body before returning 410, so malformed bodies get 422 instead of 410 and wasted validation work (`app/main.py`).
- **L9** - OAuth callbacks return HTTP 200 for error pages (by design, so the HTML renders) - fine, but log scrapers keying on 4xx/5xx won't see OAuth failures (`app/main.py`).
- **L10** - `scripts/authorize_google.py` writes `token.json` via `os.makedirs(...exist_ok=True)` with default umask - OAuth credentials file is group/world-readable on shared hosts. Set `0o600`.

## What was checked and found OK (no action)
- JWT design: HS256, short expiry, `jti` blocklist + bulk-revoke sentinel, org-match defense-in-depth, role taken from DB not token (`app/auth.py`, `app/dashboard.py:_resolve_auth_context`).
- OAuth state: cryptographically random, single-use (marked used before exchange), 10-min TTL, naive/aware expiry handled, `prompt=select_account consent` already present (`app/services/google_oauth_flow.py`, `zoom_oauth_flow.py`).
- Webhook auth: org-secret → global-secret fallback, `secrets.compare_digest`, generic 404 for unknown/disabled slugs (no org-enumeration), auth failures audit-logged without the token (`app/main.py`, `app/tenant.py`).
- Tenant isolation: all sampled `Lead`/`FollowUp`/`EventLog`/`FailedJob` queries in `dashboard.py`, `crm_router.py`, `followup_router.py`, `organization_router.py`, `webhook_config_router.py` filter by the authenticated org; `organization_id` never taken from client input.
- Credential vault: Fernet AES-128-CBC+HMAC, versioned ciphertext, decrypt-on-read only, never returned by list/status endpoints; masked display helpers (`app/services/credential_vault.py`, `crypto.py`).
- RSVP/password-reset tokens: 256-bit `secrets.token_urlsafe`, SHA-256 stored hash, single-use, expiry, org+lead scoping; RSVP HTML escapes lead-controlled values (`rsvp_token_service.py`, `rsvp_router.py`, `auth_router.py`).
- Security headers: CSP (with documented `unsafe-inline` rationale), HSTS in prod only, `nosniff`, `DENY` framing, no-store on data endpoints (`app/middleware.py`).
- CORS: dev-only, same-origin in prod (`app/main.py`).
- Migration chain 001→021 is linear with no broken `down_revision` links; 001 is idempotent for *upgrades* (table/column/index existence guards).
- `.dockerignore` excludes `.env`, `token.json`, `credentials.json`, `*.pem`, tests.
- APScheduler `SQLAlchemyJobStore` auto-creates `apscheduler_jobs` (verified live against APScheduler 3.11.3) - no startup crash there.

## Test-suite results
- Environment: Python 3.12 venv, `APP_ENV=test`, SQLite (no local Postgres available), `SCHEDULER_ENABLED=false`, test JWT + Fernet keys injected, `DASHBOARD_USERNAME`/`DASHBOARD_PASSWORD` set.
- Collection: **3133 tests collected, 0 collection errors.**
- Full run on the current working tree (minus `test_production_e2e.py`, which needs live infra): **2948 passed, 95 failed, 44 skipped** (16.4 min).
- Full run on the pristine baseline (`HEAD = aa2ef55`, via `git worktree`, fresh DB): **3013 passed, 30 failed, 44 skipped** (16.2 min).
- Failure breakdown (verified by differential runs):
  - **30 pre-existing failures on the pristine baseline**, all reproduced without any parent changes:
    - 29 × `tests/test_rsvp_workflow.py` - `TypeError: can't compare offset-naive and offset-aware datetimes` at `app/services/rsvp_token_service.py:188` (finding M15). SQLite-only; Postgres unaffected.
    - 1 × `tests/test_phase34_defect_fixes.py::TestCredentialVaultRefreshTokenValidation::test_credential_corruption_detected` - raw `TypeError` from `decrypt_secret` instead of `CredentialCorruptError` (finding M16).
    - (The `test_csv_export` 401 seen in the early `-x` run was purely the missing `DASHBOARD_USERNAME`/`DASHBOARD_PASSWORD` env; it passes once those are set, and is folded into H9's CI defects.)
  - **65 additional failures on the modified tree are caused by the parent's concurrent OAuth rebuild** (platform-owned one-click connect), not by pre-existing bugs: changed error messages (`"Zoom connect is not set up on this server yet."` vs tests matching `"not configured"`), changed `integration_config_resolver` behavior (`ConfigurationError` where tests expected vault fallback), and 2 modified test files. These tests pass on the pristine baseline.
  - Several migration tests (e.g. `test_phase_20_p1b_migration.py`) are Postgres-specific and cannot meaningfully pass on SQLite; CI runs them against the Postgres service container.
- Untested critical paths (no test coverage found): fresh-DB migration bootstrap (C2), `entrypoint.sh` behavior, `trigger_followup_emails` cross-tenant behavior (C3), Postgres-specific SQL paths (C4's `.is_(False)`), concurrent pipeline races (H2/H3), SSRF validation (H4), Caddy/proxy behavior (H7/H8).

## Files changed by the parent during review (re-verified)
`app/main.py`, `app/dashboard.py`, `app/services/google_oauth_flow.py`, `app/services/zoom_oauth_flow.py`, `app/services/integration_config_resolver.py`, `.env.example`, `tests/test_google_oauth_flow.py`, `tests/test_integration_fixes.py` (+ new `SYSTEM_DESIGN_REVIEW.md`, `docs/OAUTH_CONNECT_SETUP.md`). All findings above were re-checked against the modified tree; the OAuth rebuild did not introduce or remove any of the cited issues.

## Recommended fix order (production safety)
1. C1 (rotate/remove hardcoded password immediately; rebuild images), C2 (baseline migration), H1 (stop logging DB password)
2. C4 (Boolean migration), C3 (org-scope the trigger), H10 (021 NULL guard)
3. H2 + H3 (pipeline locking/lock TTL), H4 (SSRF validation), H5 + H6 (RBAC)
4. H7 + H8 (prod networking), H9 (CI), then the mediums in M-order.
