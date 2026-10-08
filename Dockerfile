FROM python:3.13-slim AS base

# Prevent Python from buffering stdout/stderr (critical for Docker logs)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install system deps for psycopg2-binary
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpq-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application code
COPY app/ app/
COPY scripts/ scripts/
COPY alembic.ini .
COPY alembic/ alembic/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Non-root user for security
RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Phase 25: --max-requests prevents memory leaks in long-running workers.
# --max-requests-jitter adds randomness so workers don't all restart at once.
# Phase 25: entrypoint.sh runs Alembic migrations before starting the server.
ENTRYPOINT ["/entrypoint.sh"]
CMD ["gunicorn", "app.main:app", \
     "-w", "1", \
     "-k", "uvicorn.workers.UvicornWorker", \
     "-b", "0.0.0.0:8000", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "50"]
