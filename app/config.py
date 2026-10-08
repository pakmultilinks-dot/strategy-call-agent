"""Application settings loaded from .env.

Secrets (AI router key, Google OAuth2 credentials) are read from the
environment / .env file only — never hardcoded, never committed.
"""
import logging

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Runtime configuration sourced from environment variables / .env."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Cache for auto-generated JWT secret key (dev mode only).
    # Ensures the same key is used for signing AND verification within a process.
    _jwt_key_cache: str | None = None

    # Database (defaults match docker-compose.yml local Postgres)
    database_url: str = "postgresql+psycopg2://postgres:postgres@localhost:5432/strategy_calls"
    # Present in .env for docker-compose's Postgres init; not read elsewhere
    # (database_url is the actual connection string). Declared so the extra
    # .env keys don't trip pydantic-settings' extra="forbid" validation.
    postgres_user: str = ""
    postgres_password: str = ""
    postgres_db: str = ""

    # AI provider — OpenAI-compatible token router for Kimi K2/K3
    ai_base_url: str = ""
    ai_api_key: str = ""
    ai_model: str = ""
    # Fallback AI provider — a DIFFERENT provider (own base URL + key + model),
    # used only if the primary exhausts its retries. All three must be set.
    ai_fallback_base_url: str = ""
    ai_fallback_api_key: str = ""
    ai_fallback_model: str = ""

    # Google OAuth2 / Calendar + Gmail
    google_client_id: str = ""
    google_client_secret: str = ""
    google_refresh_token: str = ""
    google_token_file: str = "token.json"  # written by scripts/authorize_google.py (dev only)
    google_redirect_uri: str = "http://localhost:8000/auth/google/callback"
    google_oauth_state_ttl_minutes: int = 10
    calendar_id: str = "primary"
    gmail_sender: str = ""

    # Zoom OAuth2 — platform default credentials + Web Application flow.
    # Organizations override via the integration API / CredentialVault.
    zoom_account_id: str = ""
    zoom_client_id: str = ""
    zoom_client_secret: str = ""
    zoom_redirect_uri: str = "http://localhost:8000/auth/zoom/callback"
    zoom_oauth_state_ttl_minutes: int = 10

    # Business timezone (IANA name) — used for the daily 08:00 reminder job and
    # for "today" boundaries / human-readable local times. America/Chicago gives
    # correct CST/CDT handling across DST. NOTE: the task referenced an existing
    # BUSINESS_TIMEZONE in timeparse.py, but no such file/setting existed, so it
    # is introduced here.
    business_timezone: str = "America/Chicago"

    # Read-only admin dashboard (HTTP Basic auth) — the single auth mechanism
    # for the dashboard and the manual trigger endpoints.
    dashboard_username: str = ""
    dashboard_password: str = ""

    # Environment: dev | test | production — controls default behavior
    app_env: str = "dev"


    # Webhook shared secret — when set, the /webhooks/form-submission endpoint
    # requires "Authorization: Bearer <secret>". Prevents arbitrary callers
    # from submitting fake leads. Leave empty to disable (dev mode).
    webhook_secret: str = ""

    # Public URL where the webhook is reachable (no trailing slash).
    # Used in deployment docs; not enforced at runtime.
    webhook_public_url: str = ""

    # Dashboard base URL for password reset links (no trailing slash).
    # Example: "https://dashboard.example.com" or "http://localhost:8000"
    dashboard_base_url: str = "http://localhost:8000"

    # RSVP base URL for Accept/Decline links in confirmation emails (no trailing slash).
    # Example: "https://app.example.com" or "http://localhost:8000"
    rsvp_base_url: str = "http://localhost:8000"

    # Rate limiting: max POST requests per minute per IP on the webhook endpoint.
    # 0 = unlimited (dev mode). 30 is production-appropriate.
    rate_limit_per_minute: int = 30

    # Scheduler: set to "false" to disable the in-process scheduler.
    # Use when running a separate scheduler container/process.
    scheduler_enabled: str = "true"

    # ─── Credential Encryption (Phase 6B.2) ────────────────────────────────
    # Fernet key used to encrypt/decrypt customer credentials stored in
    # org_integrations.credentials_encrypted.  In production this MUST be
    # a real Fernet key (44-char URL-safe base64).  Generate one with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    #
    # In test environments we accept an empty string; the test fixtures
    # generate and inject a valid key via monkeypatch / env override.
    # In dev mode, a fallback key is auto-generated if not set (insecure,
    # single-node only — do NOT deploy with auto-generated key).
    credential_encryption_key: str = ""

    # ─── JWT Authentication (Phase 6B.3) ──────────────────────────────────
    # Secret key for signing JWTs. In production MUST be set and strong.
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(64))"
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30

    @property
    def scheduler_is_enabled(self) -> bool:
        return self.scheduler_enabled.lower() == "true"

    def get_credential_encryption_key(self) -> str:
        """Return the validated credential encryption key.

        In production (app_env == "production"), raises InvalidKeyError if
        the key is missing or invalid.

        In dev/test, returns the configured key or falls back to a generated
        key (dev only — test fixtures always provide their own).
        """
        import logging

        from app.services.crypto import generate_key, validate_key

        logger = logging.getLogger(__name__)

        if self.app_env == "production":
            return validate_key(self.credential_encryption_key)

        # Dev/test — allow empty (test fixtures provide via monkeypatch)
        if not self.credential_encryption_key:
            if self.app_env == "test":
                raise RuntimeError(
                    "CREDENTIAL_ENCRYPTION_KEY must be set in test mode. "
                    "Use conftest.py fixtures or set the env var."
                )
            # Dev fallback — auto-generate (single-node only)
            key = generate_key()
            logger.warning(
                "Auto-generated CREDENTIAL_ENCRYPTION_KEY for dev mode. "
                "This key will NOT persist across restarts. "
                "Set CREDENTIAL_ENCRYPTION_KEY in .env for persistent credentials."
            )
            return key

        return validate_key(self.credential_encryption_key)

    def get_jwt_secret_key(self) -> str:
        """Return the validated JWT signing secret.

        In production: MUST be set and at least 32 characters.
        In test: raises RuntimeError if not set (forces fixtures to provide).
        In dev: auto-generates if not set (cached for process lifetime).
        """
        import logging

        logger = logging.getLogger(__name__)

        if self.app_env == "production":
            if not self.jwt_secret_key or len(self.jwt_secret_key) < 32:
                raise ValueError(
                    "JWT_SECRET_KEY must be set and at least 32 characters in production. "
                    "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
                )
            return self.jwt_secret_key

        if not self.jwt_secret_key:
            if self.app_env == "test":
                raise RuntimeError(
                    "JWT_SECRET_KEY must be set in test mode. "
                    "Use conftest.py fixtures or set the env var."
                )
            # Dev fallback — auto-generate once per process lifetime.
            # CRITICAL: Must return the SAME key for signing and verification.
            # Phase 28 P1-D: Persist to disk so tokens survive server restarts.
            # Without this, every restart invalidates all dashboard sessions.
            if self._jwt_key_cache is not None:
                return self._jwt_key_cache
            import os
            import secrets as _secrets
            _jwt_file = os.path.join(os.path.dirname(__file__), ".dev_jwt_secret")
            if os.path.exists(_jwt_file):
                try:
                    key = open(_jwt_file).read().strip()
                    if len(key) >= 32:
                        self._jwt_key_cache = key
                        return key
                except Exception:
                    pass
            key = _secrets.token_urlsafe(64)
            self._jwt_key_cache = key
            try:
                with open(_jwt_file, "w") as f:
                    f.write(key)
            except Exception:
                pass
            logger.warning(
                "Auto-generated JWT_SECRET_KEY for dev mode. "
                "Persisted to .dev_jwt_secret for restart survival. "
                "Set JWT_SECRET_KEY in .env for production."
            )
            return key

        return self.jwt_secret_key

    def validate_production_config(self) -> list[str]:
        """Validate all critical settings for production mode.

        Phase 27 (P0-5): Startup validation ensures that production
        deployments don't accidentally start with missing or default
        configuration.

        Returns:
            List of warning messages. Empty list means all checks pass.
            Raises RuntimeError on critical failures.
        """
        if self.app_env != "production":
            return []  # Skip validation in dev/test modes

        errors: list[str] = []
        warnings: list[str] = []

        # ── Critical: JWT secret key ─────────────────────────────────
        if not self.jwt_secret_key or len(self.jwt_secret_key) < 32:
            errors.append(
                "JWT_SECRET_KEY must be set and at least 32 characters. "
                "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
            )

        # ── Critical: Credential encryption key ──────────────────────
        if not self.credential_encryption_key:
            errors.append(
                "CREDENTIAL_ENCRYPTION_KEY must be set in production. "
                "Generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )

        # ── Critical: Dashboard credentials ──────────────────────────
        if not self.dashboard_username or not self.dashboard_password:
            errors.append(
                "DASHBOARD_USERNAME and DASHBOARD_PASSWORD must be set in production."
            )

        # ── Warning: Webhook secret ──────────────────────────────────
        if not self.webhook_secret:
            warnings.append(
                "WEBHOOK_SECRET is not set. Webhook endpoints are unprotected. "
                "Set it to prevent unauthorized lead submissions."
            )

        # ── Critical: Database URL not using default ─────────────────
        if "postgres:postgres@localhost" in self.database_url:
            errors.append(
                "DATABASE_URL still points to the default local Postgres. "
                "Update it for your production database."
            )

        # ── Warning: AI provider configured ──────────────────────────
        if not self.ai_base_url or not self.ai_api_key or not self.ai_model:
            warnings.append(
                "AI provider (AI_BASE_URL/AI_API_KEY/AI_MODEL) not fully configured. "
                "AI features will not work."
            )

        # ── Warning: Google OAuth configured ─────────────────────────
        if not self.google_client_id or not self.google_client_secret:
            warnings.append(
                "Google OAuth (GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET) not configured. "
                "Calendar and Gmail features will not work."
            )

        # ── Warning: Dashboard base URL ──────────────────────────────
        if self.dashboard_base_url == "http://localhost:8000":
            warnings.append(
                "DASHBOARD_BASE_URL is still the localhost default. "
                "Update it for production password reset links."
            )

        if errors:
            error_msg = "PRODUCTION CONFIG VALIDATION FAILED:\n" + "\n".join(
                f"  {e}" for e in errors
            )
            if warnings:
                error_msg += "\n\nWARNINGS:\n" + "\n".join(
                    f"  {w}" for w in warnings
                )
            raise RuntimeError(error_msg)

        if warnings:
            logger.warning(
                "Production config warnings:\n%s",
                "\n".join(f"  {w}" for w in warnings),
            )

        return warnings


settings = Settings()
