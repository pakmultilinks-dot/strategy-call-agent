# SYSTEM DESIGN REVIEW, strategy-call-agent

**Date:** 2026-10-08
**Scope:** Architecture-level review (components, data flow, tenancy, credential model, background processing, deployment). Line-level bugs are covered by a separate reviewer.
**Sources:** repository at `~/workspace/strategy-call-agent-review`, `docs/STATE.md`, git history, `Dockerfile`, `docker-compose.yml`, `docker-compose.prod.yml`, `Caddyfile`, `DEPLOYMENT.md`.

---

## 1. Current architecture (as implemented)

### 1.1 Component map (ASCII)

```
                       +--------------------------+
                       |  Google Apps Script      |
                       |  apps_script/webhook.gs  |
                       +------------+-------------+
                                    | HTTPS POST /webhooks/{org_slug}/form-submission
                                    | Bearer <org webhook_secret>, X-Request-ID
                                    v
+------------------------------------------------------------------+
|  FastAPI monolith (single container, gunicorn, 1 uvicorn worker) |
|  app/main.py (~4,460 lines: API + webhooks + pipeline + jobs)     |
|  app/dashboard.py (~6,700 lines: server-rendered SPA, 50+ API     |
|    endpoints, inline JS: integrations UI, OAuth flows, CRUD)      |
|                                                                  |
|  Request path:                                                   |
|    webhook -> 202 Accepted -> Starlette BackgroundTasks           |
|    -> run_pipeline(lead_id)  [IN-PROCESS, sequential]             |
|       1. dedupe check (leads.dedupe_key, org-scoped)              |
|       2. AI personalization (Kimi K2/K3 via OpenAI-compat router) |
|       3. meeting_provider.resolve (Zoom creds? -> Zoom API        |
|          : Google Meet via Calendar API)                          |
|       4. Calendar event create + Meet link (Google Calendar API)  |
|       5. Gmail API send confirmation email (RSVP links)          |
|       6. Lead status transitions -> EventLog entries              |
|       7. failures -> failed_jobs + retry/recovery                 |
|                                                                  |
|  Background (in-process APScheduler, 9 jobs):                    |
|    rsvp_poll (interval)          - polls Calendar RSVPs, all orgs|
|    daily_reminder (cron 08:00)   - per-org reminder emails        |
|    failed_job_recovery (5 min)   - retries failed_jobs           |
|    meeting_completion (15 min)   - marks past meetings completed |
|    followup_overdue_check (30 min)                               |
|    followup_email_execution (5 min)                              |
|    token_blocklist_cleanup (12 h)                                |
|    token_health_check (6 h)      - refresh/validate OAuth tokens  |
|    stuck_lead_recovery (10 min)                                  |
|    Job store: SQLAlchemyJobStore in prod, MemoryJobStore in dev.  |
|    SCHEDULER_ENABLED=false allows disabling on non-leader nodes. |
+--------------+----------------------+--------------------------+
               |                      |
               v                      v
+----------------------+   +-----------------------------+
| PostgreSQL 16        |   | External APIs (per org)       |
| SQLAlchemy 2.0       |   |  - Google Calendar API        |
| Alembic 001-021      |   |  - Gmail API                  |
| pool_size=5,         |   |  - Zoom Meeting API (OAuth)   |
| max_overflow=10      |   |  - AI token router (Kimi)     |
+----------------------+   +-----------------------------+

+----------------------+        +----------------------+
| Caddy (prod only)    |        | Backup cron sidecar  |
| TLS termination      |        | pg_dump daily 03:00  |
| reverse_proxy app:8000|       | local ./backups vol  |
+----------------------+        +----------------------+
```

### 1.2 Request lifecycle

1. **Ingest:** Apps Script on a Google Form submit POSTs JSON to `/webhooks/{org_slug}/form-submission`. The app resolves the org by slug, verifies the Bearer webhook secret (org secret, falling back to a global `WEBHOOK_SECRET`), applies the org's field mapping, validates, inserts a `Lead` (dedupe via unique `dedupe_key` per org), and returns **202 immediately**.
2. **Pipeline:** A Starlette `BackgroundTasks` task runs `run_pipeline(lead_id)` in the same process, after the response. It is synchronous, sequential, and shares the single gunicorn worker. Steps: dedupe guard, appointment parsing, AI email drafting, meeting creation (Zoom if org has Zoom creds, else Google Meet), Calendar event, Gmail send, status transitions, EventLog writes, failures land in `failed_jobs`.
3. **Steady state:** 9 APScheduler jobs poll for RSVP changes, send reminders, execute follow-up emails, recover stuck leads/failed jobs, and check OAuth token health. Everything runs in-process in the single worker container.

### 1.3 Tenant isolation model

- **Logical (app-level) isolation.** Every customer-owned table carries `organization_id`; all queries are expected to filter by the org resolved from the JWT claim (`app/tenant.py`, `org_context.py`). A test suite (~233 isolation tests) enforces this.
- **No database-level enforcement.** There is no Postgres Row-Level Security, no per-tenant schemas, no separate databases. Isolation is a code-discipline property, verified by tests, not by the database.
- **RBAC:** owner / admin / member roles; JWT HS256, 30-minute expiry, JTI blocklist in DB; HTTP Basic for the legacy dashboard endpoints.

### 1.4 Credential / vault design

- `org_integrations` table: one row per (org_id, provider, integration_type). Secrets live in `credentials_encrypted`, a Fernet (AES-128-CBC + HMAC-SHA256) encrypted JSON blob; non-secret config in `metadata_json`.
- **One master Fernet key** for all tenants, from `CREDENTIAL_ENCRYPTION_KEY` env var (auto-generated, non-persistent, in dev). No key rotation, no per-org keys, no KMS/HSM.
- **Org-owned OAuth model (current):** each organization must create its own Google Cloud OAuth client and its own Zoom Marketplace OAuth app, then paste Client ID, Client Secret, and Redirect URI into the dashboard (stored encrypted in the vault). Token exchange is server-side via `httpx`; only refresh tokens (Google) / access+refresh (Zoom) are stored; OAuth state tokens are single-use DB rows with 10-min TTL.
- Credential resolution precedence: org vault first, then `.env` platform defaults, then error (`integration_config_resolver.py`).

### 1.5 Database design (summary)

Core tables: `organizations`, `users`, `org_integrations`, `org_schedule_config`, `leads`, `events_log`, `failed_jobs`, `follow_ups`, `google_oauth_states`, `zoom_oauth_states`, `token_blocklist`, `password_reset_tokens`, `rsvp_tokens`, `org_form_field_mappings`, plus `apscheduler_jobs` in prod. 21 Alembic migrations, chain intact. UUID primary keys, `organization_id` FKs, dedupe unique key on leads.

### 1.6 Deployment (as implemented)

Single-node `docker-compose`: `db` (Postgres 16) + `app` (gunicorn, **1 worker**) + optional Caddy TLS + cron backup sidecar. Migrations run in `entrypoint.sh`. Non-root user, health checks, log rotation in the prod override. Designed for one server.

---

## 2. Design strengths and weaknesses

### Strengths

- **Honest multi-tenancy groundwork:** org-scoped data model, RBAC, and an unusually thorough tenant-isolation test suite for a project this size.
- **Credential hygiene basics are right:** secrets encrypted at rest, never returned by APIs, sanitized in logs, error messages scrubbed of tokens, single-use expiring OAuth states, refresh-tokens-only storage.
- **Pipeline resilience patterns:** idempotent dedupe keys, `failed_jobs` table with recovery job, stuck-lead recovery, crash-safe scheduler wrappers, persistent APScheduler job store in prod.
- **Deployment basics:** non-root container, health checks, startup config validation, automated backups, Caddy TLS.

### Weaknesses (architecture-level)

**W1. Background work runs inside the web process.** `run_pipeline` executes as a Starlette `BackgroundTasks` task in the single gunicorn worker. BackgroundTasks are sequential, in-memory, invisible to monitoring, and lost on restart/deploy. At 100 orgs / 10k calls a day (roughly one pipeline run every 8-9 seconds, each doing several external API calls plus an AI call), the single worker serializes webhook responses behind pipeline work, requests time out, and a deploy mid-pipeline drops work. This is the first thing that breaks at scale, and it breaks silently.

**W2. In-process scheduler with a leader flag instead of a real job system.** APScheduler with `SCHEDULER_ENABLED` is a workable single-node answer, but it is not a distributed scheduler: failover is manual, there is no visibility into job runs, no per-job retry/backoff policy, and the SQLAlchemyJobStore silently falls back to MemoryJobStore if it fails to initialize. The comment in the code itself records that per-org jobs once saturated the worker (913 orgs x 2 jobs = 1826 jobs); the fix was to collapse to global jobs, which confirms the scheduler does not scale by design.

**W3. Polling instead of push for external state.** RSVP status is learned by polling Google Calendar on an interval across all orgs. Google Calendar push notifications (watch channels) and Zoom webhooks exist precisely for this; polling multiplies API quota consumption linearly with org count and adds latency to declines (a declined slot stays "held" until the next poll).

**W4. App-level tenancy with no database backstop.** 192+ org-scoped query points are enforced by convention and tests. One missed filter, one raw SQL path, one analytics query, and tenants leak. Postgres Row-Level Security (or at minimum a DB role per service with a mandatory org filter) would make isolation a property of the data layer instead of a property of developer discipline.

**W5. Single master encryption key, no rotation, no KMS.** Every tenant's Google refresh tokens, Zoom tokens, and OAuth client secrets are encrypted under one Fernet key from an env var. Key compromise = all tenants compromised. Key rotation is effectively impossible without re-encrypting every row with downtime planning, and dev auto-generates a non-persistent key (fine for dev, but the same code path existing in prod-adjacent config is a footgun).

**W6. God files.** `app/main.py` (~4,460 lines: routing, pipeline, scheduler, OAuth callbacks, dashboard APIs) and `app/dashboard.py` (~6,700 lines: API + inline SPA JS) make the system hard to reason about, hard to split into services, and hard to onboard onto. Architecture cannot evolve while the codebase is two files.

**W7. Gmail as the sending infrastructure.** Confirmation and reminder emails go through each org's own Gmail API credentials. Gmail sending quotas are ~500/day (consumer) to ~2,000/day (Workspace) per account, and `gmail.send` is a **restricted** Google scope. At 10k calls/day across tenants, per-tenant Gmail accounts will hit quota walls constantly, and every deliverability problem (spam foldering, bounces) becomes the platform's support burden with no centralized control. Transactional email needs dedicated sending infrastructure (SES / SendGrid / Postmark) with per-org verified sender identities, with Gmail API reserved for reading RSVP/calendar state.

**W8. Gmail scopes are broader than the product needs.** The default scopes request `calendar` (full), `gmail.send`, `gmail.readonly`, and `userinfo.email`. `gmail.readonly` appears unused by the described features (RSVP comes from Calendar). Every restricted scope multiplies OAuth verification cost and user distrust at the consent screen. Least privilege is a design issue, not just a code issue.

**W9. Single-node deployment, single points of failure everywhere.** One gunicorn worker, one Postgres on the same host, backups to a local volume with no offsite copy and no restore testing, no read replicas, no rolling deploys, DB pool of 5 connections shared by web + pipeline + 9 scheduler jobs. A host failure is a full outage plus potential data loss since the last local backup.

**W10. Observability gap.** Structured JSON logs exist, but there are no metrics (request latency, pipeline duration, per-org API quota consumption, queue depth), no tracing across the multi-step pipeline, no alerting, no SLOs. When the pipeline silently slows at 100 orgs, nobody will know until customers complain.

**What breaks first at 100 orgs / 10k calls/day, in order:** (1) the single worker serializing BackgroundTasks pipelines behind webhook traffic; (2) Gmail per-account send quotas; (3) Google Calendar API quota under RSVP polling load; (4) the 5-connection DB pool shared by web + scheduler + pipeline; (5) deploy-time loss of in-flight background work.

---

## 3. The credential model question: org-owned vs platform-owned OAuth

### 3.1 What exists today (org-owned)

Each organization must: create a Google Cloud project, configure the OAuth consent screen, create an OAuth client, register redirect URIs, then paste Client ID + Client Secret + Redirect URI into the dashboard. Same story for Zoom: create a Zoom Marketplace OAuth app, paste Client ID + Secret + Redirect URI (+ Account ID).

### 3.2 Evaluation

| Dimension | Org-owned (current) | Platform-owned (one Google client + one Zoom app) |
|---|---|---|
| **User experience** | Terrible. Non-technical customers cannot create GCP projects or Zoom Marketplace apps. This is the single biggest adoption blocker. The user's requested flow (click Connect, pick Google account, consent, done) is impossible. | One click. Account chooser, consent screen, done. This is the industry-standard SaaS pattern (Calendly, Cal.com, etc.). |
| **Google verification** | Every org's GCP project shows an "unverified app" warning; testing-mode projects are capped at 100 users and refresh tokens expire in 7 days. Each org would need its own verification. Practically unusable. | Verify once. One consent screen, one brand, one verification review. |
| **Restricted Gmail scopes** | Each org independently faces Google's restricted-scope requirements (`gmail.send`, `gmail.readonly` require a CASA security assessment for verified apps). No small business will do this. | The platform does one CASA assessment and amortizes it across all tenants. (Also: drop `gmail.readonly`; keep scopes minimal to reduce assessment scope.) |
| **Zoom Marketplace** | Each org publishing its own Zoom OAuth app means each org goes through Zoom's app review, business verification, and scope justification. Infeasible for customers; effectively nobody will complete it. | Publish one Zoom Marketplace app once. Org admins install it on their Zoom account with two clicks. This is how every Zoom-integrated SaaS works. |
| **Quotas** | Spreads quota across orgs' projects (the one genuine advantage). | Concentrates quota on the platform project. Mitigated with per-org rate limiting, quota monitoring, and Google quota increase requests. Manageable, standard practice. |
| **Blast radius** | A compromised org client secret affects one org. | A compromised platform client secret or a Google project suspension affects all orgs. Mitigated: secret in a real secret manager (not the DB), project-level monitoring, and keeping BYO credentials as an enterprise option. |
| **Security posture** | N client secrets stored in the app DB, pasted through the dashboard UI by users (clipboard exposure, screenshots in support tickets). | One client secret, held server-side only, never in the DB, never pasted by users. Strictly better secret hygiene. |
| **Redirect URIs** | Every org registers its own redirect URI; localhost defaults leak into prod configs; mismatch errors are the #1 OAuth support ticket generator. | One redirect URI per environment, registered once. Tenant identity travels in the signed `state` parameter. Entire class of support tickets disappears. |

### 3.3 Recommendation

**Adopt the platform-owned model as the default, keep org-owned (BYO credentials) as an enterprise option.**

Concretely:
- The platform owns **one** Google Cloud OAuth client and **one** Zoom Marketplace OAuth app. The platform completes Google verification + CASA assessment once and publishes the Zoom app once.
- End-user flow is exactly what was requested: Integrations page shows **"Connect with Google"** (and **"Connect Zoom"**). Clicking opens the provider's authorization page (popup or redirect): the user picks any Google account, sees the platform's verified consent screen, clicks through, and lands back connected. No console, no developer portal, no pasting secrets.
- The platform's client secret lives in a secret manager / env, never in the database and never in the UI.
- Per-org OAuth **tokens** (refresh tokens, Zoom access/refresh tokens) are still stored per-org in the vault, encrypted. Multi-tenancy of *tokens* is retained; only the *client registration* is centralized.
- Keep the org-owned path behind a feature flag for enterprise customers who require their own GCP project (data-governance requirements). The existing `integration_config_resolver` precedence (vault -> platform default -> error) already supports this shape; it just needs the default to become "platform-owned client" instead of "nothing configured".

**Why not stay org-owned:** it is not a viable SaaS integration model. It fails on UX (customers cannot do it), on Google's verification regime (unverified-app warnings, 100-user testing cap, 7-day refresh token expiry), and on Zoom's marketplace review (per-customer app publication). The org-owned model is the reason the product cannot onboard a non-technical customer today.

---

## 4. Proposed improved system design

### 4.1 Target architecture (ASCII)

```
                         +------------------+
                         |  Google Form     |
                         |  Apps Script     |
                         +--------+---------+
                                  | POST /webhooks/{org_slug}/form-submission
                                  | (Bearer secret + HMAC payload signature)
                                  v
+------------------+   +--------------------+   +------------------+
|  api service     |   |  worker service    |   |  scheduler       |
|  (FastAPI,       |   |  (pipeline +       |   |  (1 replica,     |
|   N replicas,    |   |   email + followup |   |   leader-elected)|
|   stateless)     |   |   executors,       |   |  cron-like jobs  |
|                  |   |   N replicas,      |   |  enqueue work,   |
|  - webhooks      |   |   stateless)       |   |  never execute   |
|  - dashboard API |   |                    |   +------------------+
|  - OAuth start/  |   |  - run_pipeline    |           |
|    callback      |   |  - send_email      |           v
|  - CRUD/RBAC     |   |  - rsvp_sync       |   +------------------+
+--------+---------+   +---------+----------+   |  Redis           |
         |                       |              |  - job queue     |
         |  outbox write (1 txn) |  consume     |  - rate limits   |
         v                       v              |  - cache         |
+--------------------------------------------------+-------------+
|  PostgreSQL (managed: RDS/Cloud SQL)              |             |
|  - primary + read replica (dashboard reads)      |             |
|  - RLS policies: app connects as per-service     |             |
|    role, org_id enforced by policy               |             |
|  - outbox table (transactional job enqueue)      |             |
|  - PITR backups, offsite, tested restores        |             |
+--------------------------------------------------+             |
         ^                                                       |
         | KMS envelope encryption                               |
+--------+---------+                                            |
|  Secret manager  |  (platform OAuth client secrets,            |
|  + KMS           |   Fernet master key, webhook secrets)        |
+------------------+                                            |
                                                                |
+---------------------------------------------------------------+
|  External: Google Calendar push channels -> /webhooks/google  |
|  Zoom webhooks -> /webhooks/zoom  (replace polling)           |
|  Transactional email: SES/Sendgrid (per-org verified sender) |
|  Gmail API kept for calendar/RSVP reads only                 |
+---------------------------------------------------------------+
```

### 4.2 Key design decisions

**Async pipeline via transactional outbox, not BackgroundTasks.** The webhook handler writes the `Lead` row and an `outbox_events` row in one DB transaction and returns 202. Workers consume from the queue (Redis Streams / SQS / Cloud Tasks). This gives: durability across deploys, retries with exponential backoff, dead-letter queues, per-org concurrency limits, and horizontal scaling of workers independent of the API. BackgroundTasks is removed from the request path entirely.

**Scheduler enqueues, workers execute.** The scheduler replica's only job is to enqueue due work (reminder sweep, follow-up execution, token health). Long-running work never executes in the scheduler process. Leader election (or simply "run exactly one scheduler replica" in the orchestrator) replaces the `SCHEDULER_ENABLED` flag hack.

**Push over poll.** Register Google Calendar push notification channels per org calendar and Zoom webhooks for meeting events. Inbound provider webhooks update RSVP state within seconds and eliminate the polling quota burn. Keep a low-frequency poll as a reconciliation backstop, not the primary mechanism.

**Platform-owned OAuth (per section 3).** One Google OAuth client, one Zoom Marketplace app. Connect flow below.

**Database hardening.** Enable Postgres Row-Level Security on tenant tables as defense in depth (service roles set `app.current_org_id`; policies enforce it). Read replica for dashboard/reporting queries. Partition `events_log` by month. Add missing indexes on hot paths (`leads(org_id, status)`, `leads(dedupe_key)`, `events_log(org_id, created_at)`).

**Secrets: envelope encryption via KMS.** Data keys per org (or per integration row), encrypted by a KMS master key; only encrypted data keys in the DB. Rotation becomes a re-wrap operation, not a re-encrypt-everything outage. Platform OAuth client secrets move out of the DB into the secret manager.

**Email split.** Transactional email (confirmations, reminders, follow-ups) moves to a dedicated provider (SES/Sendmail) with per-org verified sender identities and centralized bounce/complaint handling. Gmail API remains for calendar operations and RSVP reads. This removes the per-account send-quota ceiling that would otherwise cap the business.

**Break up the god files as the enabler.** `main.py` splits into: `api/` (routers), `workers/` (pipeline, executors), `scheduler/` (job definitions). `dashboard.py` splits into API routers plus a real frontend (or at minimum, separated static assets). No new service extraction is credible while everything lives in two files.

**Observability.** Prometheus metrics (webhook latency, pipeline duration/success per stage, per-org provider quota usage, queue depth, worker lag), OpenTelemetry traces across pipeline stages, alerting on DLQ growth and token-health failures, Sentry for exceptions. The current JSON logging is kept and extended with trace IDs.

### 4.3 Recommended OAuth connect flow (platform-owned): sequence

```
User (org admin, logged into dashboard, JWT)
  |
  | 1. GET /auth/google/start  (dashboard "Connect with Google" button)
  v
API: create signed state {org_id, user_id, nonce, exp: 10 min}
     (HMAC-signed, stored in oauth_states table, single-use)
  |
  | 2. 302 redirect to accounts.google.com/o/oauth2/v2/auth
  |    ?client_id=<PLATFORM_CLIENT_ID>
  |    &redirect_uri=https://app.example.com/auth/google/callback   (ONE uri, registered once)
  |    &scope=calendar gmail.send userinfo.email
  |    &access_type=offline &prompt=consent &state=<signed>
  v
Google: account chooser -> verified platform consent screen -> user approves
  |
  | 3. 302 back to /auth/google/callback?code=...&state=...
  v
API: validate state signature + expiry + single-use (constant-time compare)
     exchange code with PLATFORM client_secret (from secret manager, never DB)
     fetch userinfo email
     encrypt {refresh_token} with org data key (KMS envelope) -> vault upsert
     metadata: {email, scopes, connected_at}
  |
  | 4. redirect to dashboard /integrations?connected=google (success toast)
  v
Dashboard shows: "Connected as <email>" + Disconnect button.
Token refresh: token_health worker refreshes via platform client before expiry;
on refresh failure -> integration status=ERROR + dashboard banner + email to org admins.

Zoom is identical, except: one Zoom Marketplace OAuth app (published by the
platform), scopes fixed in the marketplace app config, account_id captured
at callback, Zoom webhooks registered per installed account.
```

Note on the user's literal request ("popup shows my Google account no matter which one I click, then next as you know"): with the platform-owned client, the Google account chooser lists all of the user's signed-in accounts, and whichever they pick flows through the same verified consent screen. That behavior falls out of the standard OAuth flow for free; there is nothing per-account to configure.

### 4.4 Data model changes needed

1. `oauth_clients` (new): platform vs BYO client registrations; `provider`, `client_id`, `client_secret_ref` (secret-manager reference, not the secret), `redirect_uri`, `is_platform_default`, `verification_status`.
2. `org_integrations`: replace raw `client_secret` inside the encrypted blob with a `client_id` reference to `oauth_clients`; add `token_expires_at`, `token_scope`, `provider_account_id` (Zoom), `last_refresh_at`, `consecutive_refresh_failures`.
3. `oauth_states`: generalize `google_oauth_states` / `zoom_oauth_states` into one table with HMAC-signed state payloads.
4. `outbox_events` (new): `id`, `org_id`, `type`, `payload`, `status`, `attempts`, `next_retry_at`, `created_at`. Consumed by workers; the transactional outbox for the pipeline.
5. `provider_webhook_subscriptions` (new): calendar watch channels / Zoom webhook registrations per org, with renewal timestamps.
6. RLS policies on `leads`, `events_log`, `failed_jobs`, `follow_ups`, `org_integrations`, `users`.
7. Indexes: `leads(org_id, status)`, `leads(dedupe_key)`, `events_log(org_id, created_at)`, `outbox_events(status, next_retry_at)`.

### 4.5 Migration path from current design

- **Phase A (no downtime):** add `oauth_clients` + platform client rows; add `client_ref` columns; ship platform-owned connect flow alongside the existing org-owned flow (feature flag per org). New orgs get platform flow; existing orgs keep working untouched.
- **Phase B:** bulk-migrate willing orgs: "Reconnect with one click" banner re-runs OAuth against the platform client and replaces vault tokens; org-owned rows marked deprecated but kept as fallback.
- **Phase C:** introduce `outbox_events`; webhook writes both (dual-write), workers consume from outbox behind a flag; cut over once lag is zero; remove BackgroundTasks pipeline path.
- **Phase D:** envelope encryption: add `data_key_encrypted` column; backfill by decrypting with old master key and re-wrapping under KMS (online, per-row); then drop reliance on the single master key.
- **Phase E:** enable RLS in permissive-then-enforcing mode; split email to SES; switch RSVP to push webhooks; split the monolith files service by service.

### 4.6 What to build first (prioritized)

1. **P0, Platform-owned OAuth connect flow** (Google first, then Zoom). Unblocks all non-technical onboarding; removes the #1 adoption blocker. Includes: one GCP OAuth client, minimal scopes (drop `gmail.readonly`), verification + CASA scoping, signed-state callback, token vaulting per org.
2. **P0, Outbox + worker extraction for the lead pipeline.** Fixes the first scalability wall; makes deploys safe; enables retries/DLQ.
3. **P1, KMS envelope encryption + secret manager for platform secrets.** Before more tenants' tokens accumulate under one env-var key.
4. **P1, Transactional email via SES/SendGrid.** Before Gmail quotas become the growth ceiling.
5. **P2, Push webhooks (Calendar + Zoom) replacing polling.** Quota and latency win; keep poll as backstop.
6. **P2, RLS + read replica + hot-path indexes.** Defense in depth and dashboard performance.
7. **P3, Observability (metrics/tracing/alerting) and monolith file split.** Needed before the team or the feature set grows further.

---

## 5. Deployment design

### 5.1 Assessment of current deployment

| Area | Current state | Verdict |
|---|---|---|
| Topology | Single host, docker-compose: db + app + caddy + backup cron | Fine for dev / first 10 orgs; not a production topology |
| App serving | gunicorn, **1 worker**, uvicorn worker class | No concurrency headroom; one slow pipeline task stalls everything |
| DB | Postgres 16 on the same host, pool 5/10 | SPOF; pool shared by web + pipeline + 9 jobs |
| TLS | Caddy, auto Let's Encrypt | Good choice, keep |
| Migrations | `entrypoint.sh` runs `alembic upgrade head` at container start | Correct pattern, but with 1 replica only; needs a dedicated migrate job when replicas > 1 |
| Backups | Cron sidecar, `pg_dump` daily to local volume, 30-day retention | Local-only = not a backup strategy (host loss kills data + backups); no offsite copy; no restore drills; no PITR |
| Config/secrets | `.env` file on host | Workable; should move to a secret manager at the P1 stage |
| Scaling story | `SCHEDULER_ENABLED` flag for multi-worker | Manual leader election; no autoscaling; no rolling deploys |

### 5.2 Proposed production deployment

**Small-scale production (10-100 orgs), still simple:**

```
Host(s): 2+ app hosts (or one orchestrator)
- api: 2+ replicas behind Caddy (or ALB), rolling updates, readiness gates
- worker: 2+ replicas (pipeline/email executors)
- scheduler: 1 replica (orchestrator enforces singleton)
- redis: managed (ElastiCache/Memorystore) or single container with persistence
- postgres: managed (RDS/Cloud SQL), Multi-AZ, automated backups + PITR,
  read replica for dashboard queries
- migrations: dedicated one-shot job on deploy (not in app entrypoint)
- backups: managed snapshots + pg_dump to object storage (S3/GCS), offsite,
  monthly restore drill
- secrets: cloud secret manager; KMS for data keys
- logs: JSON to centralized logging; metrics to Prometheus/Grafana;
  alerts on DLQ depth, worker lag, token-health failures, 5xx rate
```

**At 100+ orgs / 10k calls/day:** move to Kubernetes (or Cloud Run + Cloud Tasks equivalents): HPA on queue depth and p95 latency, pod-disruption budgets, separate node pools for workers, regional Postgres with read replicas, Redis Cluster, and the push-webhook ingestion path. The application changes in section 4 (outbox, stateless services, RLS) are what make this move possible; the current in-process design cannot be lifted onto an orchestrator without first doing Phase C.

**Non-negotiable deployment fixes regardless of scale:**
1. Backups offsite + tested restores (current local-only backups are the largest data-loss risk).
2. Migrations as a deploy-time job, not in the app entrypoint (prevents concurrent-migration races at >1 replica).
3. More than one API replica with health-gated rolling deploys (eliminates deploy downtime and the single worker bottleneck).
4. Secret manager for all secrets (no `.env`-on-host as the long-term answer).

---

## Appendix: glossary of the current org-owned flow (for the migration team)

- `GoogleOAuthFlow.create_authorization_url` / `exchange_code` (`app/services/google_oauth_flow.py`), `ZoomOAuthFlow` (`app/services/zoom_oauth_flow.py`): full state-machine implementations; reusable almost verbatim under the platform-owned model, with the client resolution changed from "org vault (required)" to "platform client (default), org vault (BYO override)".
- `IntegrationConfigResolver` (`app/services/integration_config_resolver.py`): already implements vault -> platform-default -> error precedence; the platform-owned model makes the middle tier real instead of vestigial.
- Dashboard credential forms (`app/dashboard.py`, `saveGoogleCredentials` / Zoom equivalent): replaced by Connect/Disconnect buttons; keep the BYO form behind an "Advanced: use your own OAuth app" disclosure.
- `token_health.py` + `token_health_check` job: keep; it becomes the refresh orchestrator for platform-client tokens.

---

*End of system design review. No code was written; all recommendations are design-level and intended for the implementation team.*

---

## Addendum (2026-10-08): P0 item 1 implemented - platform-owned OAuth one-click connect

The platform-owned OAuth model recommended in section 3.3 has been implemented in this working copy (branch/diff vs upstream `rehmantechx/strategy-call-agent`):

- `app/services/google_oauth_flow.py` / `zoom_oauth_flow.py`: new public `resolve_client_credentials(db, org_id)` - platform `.env` client first, legacy org-vault client as fallback. Vault now stores only the end user's tokens (refresh/access tokens), never `client_id`/`client_secret`.
- `app/services/integration_config_resolver.py`: `resolve_google_oauth` / `resolve_zoom_config` are platform-first; missing platform client raises a clear admin-facing `ConfigurationError` instead of asking the org for console credentials.
- `app/main.py`: `/auth/google/start`, `/auth/zoom/start` simplified to the platform client; status endpoints report platform `configured` state.
- `app/dashboard.py`: the Client ID / Client Secret / Redirect URI forms for Google and Zoom are removed. One **Connect** button per provider; Google auth URL now forces `prompt=select_account consent` so the user always sees the Google account chooser.
- `.env.example` rewritten for the platform model; new `docs/OAUTH_CONNECT_SETUP.md` with the one-time Google Cloud Console + Zoom Marketplace steps for the app owner.

End-user flow is now exactly: click Connect → pick Google account (or authorize on zoom.us) → done. The app owner still performs the one-time console registration (unavoidable: Google/Zoom require app registration), and must complete Google verification + Zoom Marketplace publishing before non-test users can connect.
