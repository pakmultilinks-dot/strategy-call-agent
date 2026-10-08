# Strategy Call Agent - Production Deployment Guide

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Repository Setup](#3-repository-setup)
4. [Environment Configuration](#4-environment-configuration)
5. [Secrets Management](#5-secrets-management)
6. [Database Setup](#6-database-setup)
7. [Building the Docker Image](#7-building-the-docker-image)
8. [Running with Docker Compose](#8-running-with-docker-compose)
9. [Webhook Configuration (Apps Script)](#9-webhook-configuration-apps-script)
10. [Google OAuth2 Setup](#10-google-oauth2-setup)
11. [SSL / TLS Termination](#11-ssl--tls-termination)
12. [Monitoring & Health Checks](#12-monitoring--health-checks)
13. [Rate Limiting](#13-rate-limiting)
14. [Logging](#14-logging)
15. [Backups & Recovery](#15-backups--recovery)
16. [Scaling Considerations](#16-scaling-considerations)
17. [Troubleshooting](#17-troubleshooting)
18. [Security Checklist](#18-security-checklist)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                    Internet                         │
│                      │                              │
│               ┌──────▼──────┐                       │
│               │  Nginx/TLS  │  ← SSL termination    │
│               │  :443 → :8000│                      │
│               └──────┬──────┘                       │
│                      │                              │
│  ┌───────────────────▼───────────────────┐          │
│  │  strategy-call-agent-app (gunicorn)  │          │
│  │  1 worker × uvicorn                  │          │
│  │  :8000                               │          │
│  │                                      │          │
│  │  ┌──────────┐  ┌──────────────────┐  │          │
│  │  │Scheduler │  │ Rate Limiter     │  │          │
│  │  │09:00 CST │  │ 30 RPM/webhook   │  │          │
│  │  │RSVP 15m  │  │                  │  │          │
│  │  └──────────┘  └──────────────────┘  │          │
│  └──────────────┬───────────────────────┘          │
│                 │                                   │
│  ┌──────────────▼───────────────────────┐          │
│  │  PostgreSQL 16 (strategy_calls DB)   │          │
│  │  Containerized with persistent vol   │          │
│  └──────────────────────────────────────┘          │
│                                                     │
│  External:                                         │
│  • Google OAuth2 (Calendar + Gmail)                │
│  • AI Router (TokenRouter → OpenRouter fallback)   │
│  • Google Apps Script (form webhook trigger)       │
└─────────────────────────────────────────────────────┘
```

## 2. Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| Docker | ≥ 24.0 | Container runtime |
| Docker Compose | ≥ 2.20 | Multi-service orchestration |
| Python | 3.13 | Local development / tests |
| Google Cloud Project | - | OAuth2 credentials, Calendar & Gmail APIs |
| Google Apps Script | - | Webhook trigger from Google Form |
| Domain + TLS cert | - | Public HTTPS endpoint for webhook |

## 3. Repository Setup

```bash
git clone <repo-url> strategy-call-agent
cd strategy-call-agent

# Create and populate .env from the template
cp .env.example .env
# Edit .env with your values (see Section 4)
```

## 4. Environment Configuration

Copy `.env.example` → `.env` and fill in every value. **Critical variables:**

| Variable | Required | Example | Notes |
|---|---|---|---|
| `APP_ENV` | Yes | `production` | Controls CORS, scheduler defaults |
| `DATABASE_URL` | Yes | `postgresql+psycopg2://postgres:SECRET@db:5432/strategy_calls` | Use `db` as host inside Docker |
| `POSTGRES_PASSWORD` | Yes | `StrongPassword123!` | Must match `DATABASE_URL` credentials |
| `WEBHOOK_SECRET` | Yes | `<random-64-chars>` | Shared with Apps Script |
| `DASHBOARD_PASSWORD` | Yes | `<random-32-chars>` | HTTP Basic auth for `/dashboard` |
| `GOOGLE_CLIENT_ID` | Yes | `xxxx.apps.googleusercontent.com` | From Google Cloud Console |
| `GOOGLE_CLIENT_SECRET` | Yes | `GOCSPX-xxxx` | From Google Cloud Console |
| `GOOGLE_REFRESH_TOKEN` | Yes | `1//xxxx` | From `authorize_google.py` |
| `GMAIL_SENDER` | Yes | `you@gmail.com` | Must match OAuth2 account |
| `AI_API_KEY` | Yes | `sk-xxxx` | TokenRouter or OpenRouter key |
| `RATE_LIMIT_PER_MINUTE` | No | `30` | Default 30; 0 = unlimited |
| `SCHEDULER_ENABLED` | No | `true` | Set `false` if running separate scheduler |
| `BUSINESS_TIMEZONE` | No | `America/Chicago` | Default CST/CDT |

## 5. Secrets Management

### Production Secrets Rules

1. **Never commit** `.env`, `token.json`, `*.pem`, `*.key` to Git (`.gitignore` enforced)
2. **Generate strong secrets** with: `python -c "import secrets; print(secrets.token_urlsafe(48))"`
3. **Use Docker secrets** or a vault for production deployments:
   ```yaml
   # docker-compose.yml override example:
   secrets:
     db_password:
       file: ./secrets/db_password.txt
   ```

### Webhook Secret

The webhook secret is shared between the Apps Script and this server. Apps Script sends it as:
```
Authorization: Bearer <WEBHOOK_SECRET>
```
The server validates it using constant-time comparison (`secrets.compare_digest`).

**Regenerate procedure:**
1. Generate new secret: `python -c "import secrets; print(secrets.token_urlsafe(48))"`
2. Update `.env` → `WEBHOOK_SECRET=<new-value>`
3. Update Apps Script → Script Properties → `WEBHOOK_SECRET=<new-value>`
4. Restart the app container: `docker compose restart app`

## 6. Database Setup

The PostgreSQL database is fully containerized. On first run, the `pgdata` volume is created automatically.

```bash
# Start only the database (app depends on it being healthy)
docker compose up db -d

# Verify health
docker compose exec db pg_isready -U postgres -d strategy_calls
```

Database schema is managed by Alembic migrations, which run automatically
on container start via `entrypoint.sh` (`alembic upgrade head`). Migration
001 bootstraps all base tables on fresh databases, so no manual setup is
needed. (`Base.metadata.create_all()` is only used in non-production
lifespan as a fallback.)

### Connection Pool Settings

| Setting | Value | Purpose |
|---|---|---|
| `pool_size` | 5 | Persistent connections |
| `max_overflow` | 10 | Burst capacity |
| `pool_recycle` | 300s | Prevent stale connections |
| `connect_timeout` | 10s | Fail fast on unreachable DB |

### Backup

```bash
# Backup
docker compose exec db pg_dump -U postgres strategy_calls > backup_$(date +%Y%m%d).sql

# Restore
cat backup_20250101.sql | docker compose exec -T db psql -U postgres strategy_calls
```

## 7. Building the Docker Image

```bash
# Build
docker compose build

# Or manually:
docker build -t strategy-call-agent:latest .
```

The image:
- Base: `python:3.13-slim`
- Runs as non-root user `appuser`
- Includes `HEALTHCHECK` (curl → `/health`)
- Serves via `gunicorn` with 1 uvicorn worker

## 8. Running with Docker Compose

```bash
# Start everything (db + app)
docker compose up -d

# View logs
docker compose logs -f app

# Check status
docker compose ps

# Stop
docker compose down

# Stop and remove data volume (⚠️ destroys DB data)
docker compose down -v
```

### First-Time Startup

```bash
# 1. Ensure .env is configured
cat .env

# 2. Start
docker compose up -d

# 3. Verify health
curl http://localhost:8000/health
# → {"status": "ok"}

curl http://localhost:8000/health/ready
# → {"status": "ready", "database": "connected"}

# 4. Access dashboard
open http://localhost:8000/dashboard
# Login: admin / <your DASHBOARD_PASSWORD>
```

## 9. Webhook Configuration (Apps Script)

### Setup

1. Open the Apps Script project bound to your Google Form
2. Update Script Properties (File → Project Settings → Script Properties):
   | Property | Value |
   |---|---|
   | `WEBHOOK_URL` | `https://your-domain.com/webhooks/form-submission` |
   | `WEBHOOK_SECRET` | Same value as `.env` → `WEBHOOK_SECRET` |
3. Deploy the webhook function as a trigger:
   - In the Apps Script editor, run `sendToWebhook` once to authorize
   - Or set up an `onFormSubmit` trigger manually

### Verification

Submit a test form entry, then check:
```bash
# Should return 200
docker compose logs app | grep "webhook"
```

## 10. Google OAuth2 Setup

### Initial Authorization (One-Time)

```bash
# Run locally (not in Docker) - needs browser interaction
python scripts/authorize_google.py

# This produces token.json with refresh token
# Copy token.json to the server or mount it as a volume
```

### Docker Mount

Add to `docker-compose.yml`:
```yaml
app:
  volumes:
    - ./token.json:/app/token.json:ro
```

### Token Refresh

The application auto-refreshes OAuth2 tokens using the refresh token. No manual intervention needed.

## 11. SSL / TLS Termination

**The application does NOT terminate TLS.** Use a reverse proxy:

### Option A: Nginx

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /etc/ssl/certs/your-domain.pem;
    ssl_certificate_key /etc/ssl/private/your-domain.key;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Option B: Caddy (auto-TLS)

```
your-domain.com {
    reverse_proxy localhost:8000
}
```

## 12. Monitoring & Health Checks

### Endpoints

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/health` | GET | None | Liveness probe - returns `{"status": "ok"}` |
| `/health/ready` | GET | None | Readiness probe - checks DB connectivity |

### Docker Health Checks

Both the container and Compose service have built-in health checks:

```bash
# Docker-level health status
docker inspect --format='{{.State.Health.Status}}' strategy-call-agent-app
# → "healthy"
```

### Prometheus / Grafana (Optional)

Add to `docker-compose.yml`:
```yaml
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
```

## 13. Rate Limiting

| Setting | Default | Scope |
|---|---|---|
| `RATE_LIMIT_PER_MINUTE` | 30 | Per IP, POST `/webhooks/form-submission` only |

- Dashboard and health endpoints are **NOT** rate-limited
- Returns HTTP 429 with `Retry-After` header when exceeded
- Sliding window algorithm with 60s automatic cleanup

### Unprotected Endpoints (by design)

- `GET /health` and `GET /health/ready` - required for container health checks
- `GET /dashboard` - HTTP Basic auth protected, not rate-limited
- `GET /dashboard/api/*` - HTTP Basic auth protected

## 14. Logging

All application logs go to stdout/stderr (Docker best practice):

```bash
# Follow logs
docker compose logs -f app

# Last 100 lines
docker compose logs --tail 100 app
```

### Log Redaction

Secrets are **never logged**:
- Webhook payloads log only `payload_keys`, not values
- OAuth tokens never appear in logs
- Database URLs have passwords stripped in error messages

### Structured Logging (Recommended for Production)

Add to `.env`:
```bash
LOG_FORMAT=json
```

## 15. Backups & Recovery

### Automated Backup Script

```bash
#!/bin/bash
# backup.sh
BACKUP_DIR="/backups/strategy-call-agent"
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

docker compose exec -T db pg_dump -U postgres strategy_calls \
  | gzip > "$BACKUP_DIR/strategy_calls_$TIMESTAMP.sql.gz"

# Keep last 30 backups
ls -t "$BACKUP_DIR"/*.sql.gz | tail -n +31 | xargs rm -f
```

### Recovery

```bash
gunzip < backup_20250101_120000.sql.gz \
  | docker compose exec -T db psql -U postgres strategy_calls
```

## 16. Scaling Considerations

### Current Architecture (Single Worker)

- 1 gunicorn worker with 1 uvicorn async worker
- APScheduler runs in-process (single instance only)
- In-memory rate limiter (single instance only)

### Scaling to Multiple Workers

1. Set `SCHEDULER_ENABLED=false` on all but one worker
2. Replace in-memory rate limiter with Redis-backed:
   ```python
   # Replace RateLimitMiddleware with Redis implementation
   # Use redis-py: pip install redis
   ```
3. Use external PostgreSQL (RDS, Cloud SQL) instead of containerized DB
4. Consider a task queue (Celery) for background email sending

### Recommended Production Stack (Scaled)

```
                    ┌─────────┐
                    │  Nginx  │ ← SSL + load balancing
                    └────┬────┘
                    ┌────▼────┐
                    │ Worker 1│ ← Scheduler enabled
                    │ Worker 2│ ← Scheduler disabled
                    │ Worker N│ ← Scheduler disabled
                    └────┬────┘
              ┌──────────▼──────────┐
              │     PostgreSQL      │ ← Managed (RDS/Cloud SQL)
              └─────────────────────┘
              ┌─────────────────────┐
              │       Redis         │ ← Rate limiting + caching
              └─────────────────────┘
```

## 17. Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `503` on `/health/ready` | DB not reachable | Check `docker compose ps` - is `db` healthy? |
| `401` on webhook | Wrong `WEBHOOK_SECRET` | Verify `.env` matches Apps Script properties |
| `429` on webhook | Rate limit exceeded | Check `RATE_LIMIT_PER_MINUTE`; verify legitimate traffic |
| OAuth errors | Token expired / revoked | Re-run `python scripts/authorize_google.py` |
| Scheduler not running | `SCHEDULER_ENABLED=false` | Set `SCHEDULER_ENABLED=true` in `.env` |
| App won't start | Missing `.env` or `token.json` | Check `docker compose logs app` for details |
| DB connection timeout | Pool exhausted | Increase `pool_size` in `app/database.py` |

### Debug Mode

```bash
# Run app directly (not Docker) with debug logging
APP_ENV=dev python -m uvicorn app.main:app --reload --log-level debug
```

## 18. Security Checklist

### Pre-Deployment

- [ ] `.env` has strong, unique passwords for `POSTGRES_PASSWORD`, `DASHBOARD_PASSWORD`, `WEBHOOK_SECRET`
- [ ] `APP_ENV=production` (disables CORS, enables scheduler defaults)
- [ ] `.env` and `token.json` are in `.gitignore`
- [ ] No secrets in Git history: `git log --all --diff-filter=A -- '*.env' '*.pem' '*.key' 'token.json'`
- [ ] Google Apps Script uses Bearer token auth (not Basic auth)
- [ ] Apps Script reads `WEBHOOK_URL` and `WEBHOOK_SECRET` from Script Properties (not hardcoded)

### Runtime

- [ ] App runs as non-root user (`appuser`)
- [ ] PostgreSQL is NOT exposed to the public internet (only Docker internal network)
- [ ] Dashboard has strong HTTP Basic auth credentials
- [ ] TLS termination handled by reverse proxy (Nginx/Caddy)
- [ ] Rate limiting is active on webhook endpoint (30 RPM default)
- [ ] Security headers present: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`
- [ ] Request body size limited to 64KB (prevents memory abuse)
- [ ] Database connections use pooling (5 persistent + 10 overflow)
- [ ] Health checks configured for both container and Compose

### Ongoing

- [ ] Regular backups (daily recommended)
- [ ] Monitor `docker compose logs` for anomalies
- [ ] Rotate `WEBHOOK_SECRET` quarterly
- [ ] Review Google OAuth2 token refresh logs
- [ ] Check for dependency updates (`pip-audit`, `docker scout`)
