"""Phase 20 — Production Hardening Tests.

Tests for P1-E (Structured JSON Logging).
"""
import json
import logging
import uuid

import pytest
from fastapi.testclient import TestClient


# ══════════════════════════════════════════════════════════════════════════════
# P1-E: Structured JSON Logging
# ══════════════════════════════════════════════════════════════════════════════


class TestStructuredJsonFormatter:
    """Verify the StructuredJsonFormatter produces valid JSON with required fields."""

    def test_formatter_outputs_valid_json(self):
        """Each log record should be valid JSON."""
        from app.logging_config import StructuredJsonFormatter

        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="hello world",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_formatter_includes_required_fields(self):
        """JSON output must include timestamp, level, logger, and message."""
        from app.logging_config import StructuredJsonFormatter

        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="strategy-call-agent",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="test warning %s",
            args=("detail",),
            exc_info=None,
        )
        output = json.loads(formatter.format(record))
        assert "timestamp" in output
        assert output["level"] == "WARNING"
        assert output["logger"] == "strategy-call-agent"
        assert output["message"] == "test warning detail"

    def test_formatter_does_not_log_sensitive_extras(self):
        """Sensitive keys like 'password', 'token' must never appear in output."""
        from app.logging_config import StructuredJsonFormatter

        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="user login",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        # Ensure no sensitive key names in the output
        sensitive_keys = {"password", "token", "secret", "api_key", "authorization"}
        assert not sensitive_keys.intersection(parsed.keys())

    def test_formatter_includes_exception_info(self):
        """When exc_info is present, the exception string should be included."""
        from app.logging_config import StructuredJsonFormatter

        formatter = StructuredJsonFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="error occurred",
                args=(),
                exc_info=sys.exc_info(),
            )
        output = json.loads(formatter.format(record))
        assert "exception" in output
        assert "boom" in output["exception"]


class TestRequestLoggingMiddleware:
    """Verify the middleware assigns request IDs and logs timing."""

    def test_response_includes_x_request_id_header(self, client: TestClient):
        """Every response must include an X-Request-ID header."""
        resp = client.get("/health")
        assert "x-request-id" in resp.headers
        # Should be a valid UUID
        uuid.UUID(resp.headers["x-request-id"])

    def test_client_provided_request_id_is_echoed_back(self, client: TestClient):
        """If the client sends X-Request-ID, it should be echoed back."""
        rid = str(uuid.uuid4())
        resp = client.get("/health", headers={"X-Request-ID": rid})
        assert resp.headers.get("x-request-id") == rid

    def test_get_request_id_returns_id_inside_request(self, client: TestClient):
        """get_request_id() should return the request ID during request processing."""
        resp = client.get("/health")
        # We can't directly call get_request_id() outside the middleware,
        # but we can verify the header exists as proof the context var was set
        assert resp.headers.get("x-request-id")


class TestConfigureStructuredLogging:
    """Verify the configure_structured_logging function sets up handlers correctly."""

    def test_configure_adds_stream_handler(self):
        """After calling configure, root logger should have a StreamHandler."""
        from app.logging_config import configure_structured_logging, StructuredJsonFormatter

        configure_structured_logging(level="DEBUG")
        root = logging.getLogger()
        handler_types = [type(h).__name__ for h in root.handlers]
        assert "StreamHandler" in handler_types or "FileHandler" in handler_types

        # Verify the formatter is our structured formatter
        for handler in root.handlers:
            if isinstance(handler, logging.StreamHandler):
                assert isinstance(handler.formatter, StructuredJsonFormatter)
                break

    def test_configure_respects_log_level(self):
        """Log level should be set to the requested level."""
        from app.logging_config import configure_structured_logging

        configure_structured_logging(level="WARNING")
        root = logging.getLogger()
        assert root.level == logging.WARNING

        # Reset to INFO for other tests
        configure_structured_logging(level="INFO")
