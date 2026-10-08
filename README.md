# strategy-call-agent

Automation that reads booked strategy calls from a Google Form/Sheet, creates
Google Calendar events with Meet links, sends AI-personalized confirmation
emails (Kimi K2/K3 via an OpenAI-compatible token router), tracks declines,
and sends daily reminders.

## Status

**Phase 20 — Production Hardening (complete).** 65 features, 1107+ passing
tests, full CI/CD, structured logging, password reset, CSV export, RBAC,
multi-tenancy, and Alembic migrations.

See [docs/STATE.md](docs/STATE.md) for the running build log — it is the
source of truth across sessions. Read it first when resuming work.

## Features

- **Lead ingestion** — Google Form/Sheet webhook → Lead creation with dedup
- **AI confirmation emails** — Kimi K2/K3 via OpenAI-compatible router
- **Google Calendar** — Auto-create events with Meet links, RSVP tracking
- **Daily reminders** — APScheduler-driven email reminders
- **Follow-up system** — Task tracking with status transitions and overdue alerts
- **Multi-tenancy** — Organization-scoped data isolation, RBAC (owner/admin/member)
- **Password reset** — Secure token-based self-service recovery
- **CSV export** — Download leads as CSV with optional status filtering
- **Structured logging** — JSON-formatted logs with request IDs for production observability
- **CI/CD** — GitHub Actions pipeline with PostgreSQL service container

## Setup

```bash
cp .env.example .env        # fill in real values; .env is git-ignored
docker compose up -d        # start local Postgres
pip install -r requirements.txt
alembic upgrade head        # run database migrations
uvicorn app.main:app --reload
curl http://localhost:8000/health   # -> {"status":"ok"}
```

## Running Tests

```bash
pytest tests/ -q            # full suite (~1107 tests)
pytest tests/ -q --timeout=120
```

## Stack

- **Backend**: Python 3.13 + FastAPI + Uvicorn
- **Database**: PostgreSQL 16 + SQLAlchemy 2.0 + Alembic migrations
- **AI**: Kimi K2/K3 via OpenAI-compatible token router (credentials from `.env` only)
- **Google**: Calendar API + Gmail API, OAuth2 (credentials from `.env` only)
- **Auth**: HTTP Basic (dashboard) + JWT (customer API), bcrypt password hashing
- **Scheduler**: APScheduler for background jobs (reminders, RSVP polling, recovery)
- **Testing**: pytest + FastAPI TestClient
