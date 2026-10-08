"""Phase 20 — Production Hardening Tests.

Tests for P1-B (Startup DDL → Alembic migration).
"""
import importlib
import inspect
from pathlib import Path

import pytest


# ══════════════════════════════════════════════════════════════════════════════
# P1-B: Startup DDL moved to Alembic migration
# ══════════════════════════════════════════════════════════════════════════════


class TestStartupDDLMovedToAlembic:
    """Verify that startup DDL functions are removed from main.py and
    handled by Alembic migration 010_startup_ddl_values."""

    def test_main_py_no_longer_has_ensure_enum_values(self):
        """_ensure_enum_values() should not exist in main.py."""
        import app.main as main_mod

        assert not hasattr(main_mod, "_ensure_enum_values"), (
            "_ensure_enum_values should be removed from main.py; "
            "its logic is now in alembic/versions/010_startup_ddl_values.py"
        )

    def test_main_py_no_longer_has_ensure_phase8_columns(self):
        """_ensure_phase8_columns() should not exist in main.py."""
        import app.main as main_mod

        assert not hasattr(main_mod, "_ensure_phase8_columns"), (
            "_ensure_phase8_columns should be removed from main.py; "
            "its logic is now in alembic/versions/010_startup_ddl_values.py"
        )


class TestStartupDDLMigrationExists:
    """Verify that migration 010_startup_ddl_values.py exists and has correct structure."""

    def test_migration_file_exists(self):
        """Migration file 010_startup_ddl_values.py must exist."""
        migration_path = Path("alembic/versions/010_startup_ddl_values.py")
        assert migration_path.exists(), (
            f"Migration file not found: {migration_path}"
        )

    def test_migration_has_correct_revision_metadata(self):
        """Migration must have revision='010_startup_ddl_values' and
        down_revision='009_password_reset_tokens'."""
        # Import the migration module dynamically
        spec = importlib.util.spec_from_file_location(
            "migration_010",
            "alembic/versions/010_startup_ddl_values.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        assert mod.revision == "010_startup_ddl_values"
        assert mod.down_revision == "009_password_reset_tokens"

    def test_migration_has_upgrade_and_downgrade(self):
        """Migration must define both upgrade() and downgrade() functions."""
        spec = importlib.util.spec_from_file_location(
            "migration_010",
            "alembic/versions/010_startup_ddl_values.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        assert callable(getattr(mod, "upgrade", None)), (
            "Migration must define an upgrade() function"
        )
        assert callable(getattr(mod, "downgrade", None)), (
            "Migration must define a downgrade() function"
        )
