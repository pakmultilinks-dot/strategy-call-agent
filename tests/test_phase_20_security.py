"""Phase 20 — Production Hardening Security Tests.

Tests for P0-A (token.json production guard) and P0-B (org status enforcement).
"""
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.database import SessionLocal
from app.models_multi_tenant import (
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)


# ══════════════════════════════════════════════════════════════════════════════
# P0-A: Token.json Production Guard
# ══════════════════════════════════════════════════════════════════════════════


class TestTokenJsonProductionGuard:
    """Verify that the app refuses to start in production if token.json exists."""

    def test_production_mode_blocks_with_token_json(self, tmp_path):
        """Lifespan raises RuntimeError when token.json exists in production mode."""
        from app.main import lifespan

        token_file = tmp_path / "token.json"
        token_file.write_text('{"token": "test"}')

        with patch.object(settings, "app_env", "production"), \
             patch.object(settings, "google_token_file", str(token_file)):
            with pytest.raises(RuntimeError, match="Refusing to start in production"):
                # We need to async-iterate the lifespan context manager
                import asyncio

                async def _run():
                    async with lifespan(None):
                        pass  # pragma: no cover

                asyncio.get_event_loop().run_until_complete(_run())

    def test_dev_mode_allows_with_token_json(self, tmp_path):
        """Lifespan does NOT block when token.json exists in dev mode."""
        from app.main import lifespan

        token_file = tmp_path / "token.json"
        token_file.write_text('{"token": "test"}')

        with patch.object(settings, "app_env", "dev"), \
             patch.object(settings, "google_token_file", str(token_file)), \
             patch.object(settings, "scheduler_enabled", "false"):
            # Should not raise — dev mode allows token.json
            import asyncio

            async def _run():
                async with lifespan(None):
                    pass  # pragma: no cover

            # This should complete without RuntimeError about token.json
            # (it may fail for other reasons like no DB, but not for token.json)
            try:
                asyncio.get_event_loop().run_until_complete(_run())
            except RuntimeError as e:
                if "token.json" in str(e):
                    pytest.fail(f"Dev mode should not block on token.json: {e}")
                # Other RuntimeErrors are OK (e.g., DB not available in test)

    def test_production_mode_without_token_json_ok(self, tmp_path):
        """Lifespan does NOT block in production when token.json is absent."""
        from app.main import lifespan

        non_existent = tmp_path / "nonexistent_token.json"

        with patch.object(settings, "app_env", "production"), \
             patch.object(settings, "google_token_file", str(non_existent)), \
             patch.object(settings, "scheduler_enabled", "false"):
            import asyncio

            async def _run():
                async with lifespan(None):
                    pass  # pragma: no cover

            try:
                asyncio.get_event_loop().run_until_complete(_run())
            except RuntimeError as e:
                if "token.json" in str(e):
                    pytest.fail(f"Should not block when token.json is absent: {e}")
