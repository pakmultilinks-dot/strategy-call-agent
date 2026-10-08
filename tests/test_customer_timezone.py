"""Tests for the customer_timezone column infrastructure (Step 1).

Verifies that:
  1. _parse_appt_utc() still returns datetime | None (backward compatible)
  2. _resolve_customer_tz() extracts the correct IANA timezone name
  3. Explicit timezone abbreviations resolve to correct IANA zones
  4. DST-aware abbreviations (EDT, CDT, etc.) map correctly
  5. No-explicit-timezone falls back to business_tz (IANA)
  6. Integration: both functions agree on timezone
  7. IANA mapping consistency
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from app.main import _parse_appt_utc, _resolve_customer_tz, _extract_tz, _TZ_ABBREV_TO_IANA


# ---------------------------------------------------------------------------
# _parse_appt_utc backward compatibility — must still return datetime | None
# ---------------------------------------------------------------------------

class TestParseApptUtcBackwardCompat:
    """Ensure _parse_appt_utc still returns a plain datetime, not a tuple."""

    def test_returns_datetime_not_tuple(self):
        result = _parse_appt_utc("09/11/2026 9:00 AM EST")
        assert result is not None
        assert isinstance(result, datetime)
        assert not isinstance(result, tuple)

    def test_none_for_empty(self):
        assert _parse_appt_utc("") is None

    def test_none_for_none(self):
        assert _parse_appt_utc(None) is None


# ---------------------------------------------------------------------------
# _resolve_customer_tz: explicit timezone abbreviations → IANA
# ---------------------------------------------------------------------------

class TestResolveExplicitAbbreviations:
    """Explicit timezone abbreviations resolve to correct IANA zones."""

    def test_est_returns_america_new_york(self):
        assert _resolve_customer_tz("09/11/2026 9:00 AM EST") == "America/New_York"

    def test_cst_returns_america_chicago(self):
        assert _resolve_customer_tz("09/11/2026 9:00 AM CST") == "America/Chicago"

    def test_pst_returns_america_los_angeles(self):
        assert _resolve_customer_tz("09/11/2026 9:00 AM PST") == "America/Los_Angeles"

    def test_mst_returns_america_denver(self):
        assert _resolve_customer_tz("09/11/2026 9:00 AM MST") == "America/Denver"

    def test_utc_returns_utc(self):
        assert _resolve_customer_tz("09/11/2026 9:00 AM UTC") == "UTC"

    def test_gmt_returns_gmt(self):
        assert _resolve_customer_tz("09/11/2026 9:00 AM GMT") == "GMT"


# ---------------------------------------------------------------------------
# _resolve_customer_tz: DST-aware abbreviations → correct IANA zones
# ---------------------------------------------------------------------------

class TestResolveDstAbbreviations:
    """EDT/CDT/MDT/PDT map to the same IANA zone as their standard counterpart."""

    def test_edt_returns_america_new_york(self):
        assert _resolve_customer_tz("06/15/2026 2:00 PM EDT") == "America/New_York"

    def test_cdt_returns_america_chicago(self):
        assert _resolve_customer_tz("06/15/2026 2:00 PM CDT") == "America/Chicago"

    def test_pdt_returns_america_los_angeles(self):
        assert _resolve_customer_tz("06/15/2026 2:00 PM PDT") == "America/Los_Angeles"

    def test_mdt_returns_america_denver(self):
        assert _resolve_customer_tz("06/15/2026 2:00 PM MDT") == "America/Denver"


# ---------------------------------------------------------------------------
# _resolve_customer_tz: full timezone names → IANA
# ---------------------------------------------------------------------------

class TestResolveFullTimezoneNames:
    """Full names like 'Eastern Time', 'Central Standard Time' resolve to IANA."""

    def test_eastern_time(self):
        assert _resolve_customer_tz("09/11/2026 9:00 AM Eastern Time") == "America/New_York"

    def test_central_time(self):
        assert _resolve_customer_tz("09/11/2026 9:00 AM Central Time") == "America/Chicago"

    def test_pacific_time(self):
        assert _resolve_customer_tz("09/11/2026 9:00 AM Pacific Time") == "America/Los_Angeles"

    def test_eastern_standard_time(self):
        assert _resolve_customer_tz("09/11/2026 9:00 AM Eastern Standard Time") == "America/New_York"

    def test_central_standard_time(self):
        assert _resolve_customer_tz("09/11/2026 9:00 AM Central Standard Time") == "America/Chicago"

    def test_mountain_time(self):
        assert _resolve_customer_tz("09/11/2026 9:00 AM Mountain Time") == "America/Denver"

    def test_pacific_standard_time(self):
        assert _resolve_customer_tz("09/11/2026 9:00 AM Pacific Standard Time") == "America/Los_Angeles"


# ---------------------------------------------------------------------------
# _resolve_customer_tz: parenthesised timezone
# ---------------------------------------------------------------------------

class TestResolveParenthesisedTz:
    """Parenthesised timezones like (EST) are handled."""

    def test_parens_est(self):
        assert _resolve_customer_tz("09/11/2026 9:00 PM (EST)") == "America/New_York"

    def test_parens_cst(self):
        assert _resolve_customer_tz("09/11/2026 9:00 PM (CST)") == "America/Chicago"

    def test_parens_pdt(self):
        assert _resolve_customer_tz("09/11/2026 2:00 PM (PDT)") == "America/Los_Angeles"


# ---------------------------------------------------------------------------
# _resolve_customer_tz: no explicit timezone → falls back to business_tz
# ---------------------------------------------------------------------------

class TestResolveFallbackToBusinessTz:
    """When no tz in the input, the resolved IANA name should be the business_tz."""

    def test_no_tz_uses_business_tz_new_york(self):
        assert _resolve_customer_tz(
            "09/11/2026 9:00 AM", business_tz="America/New_York"
        ) == "America/New_York"

    def test_no_tz_uses_business_tz_chicago(self):
        assert _resolve_customer_tz(
            "09/11/2026 9:00 AM", business_tz="America/Chicago"
        ) == "America/Chicago"

    def test_no_tz_uses_business_tz_la(self):
        assert _resolve_customer_tz(
            "09/11/2026 9:00 AM", business_tz="America/Los_Angeles"
        ) == "America/Los_Angeles"


# ---------------------------------------------------------------------------
# _resolve_customer_tz: None/empty input → fallback
# ---------------------------------------------------------------------------

class TestResolveEmptyInput:
    """None and empty string inputs return the fallback timezone."""

    def test_none_input_returns_fallback(self):
        assert _resolve_customer_tz(None, business_tz="America/Denver") == "America/Denver"

    def test_empty_input_returns_fallback(self):
        assert _resolve_customer_tz("", business_tz="America/Los_Angeles") == "America/Los_Angeles"


# ---------------------------------------------------------------------------
# Integration: _parse_appt_utc + _resolve_customer_tz together
# ---------------------------------------------------------------------------

class TestIntegrationParseAndResolve:
    """Verify that _parse_appt_utc and _resolve_customer_tz agree on timezone."""

    @pytest.mark.parametrize("raw,business_tz,expected_iana", [
        ("09/11/2026 9:00 AM EST", None, "America/New_York"),
        ("09/11/2026 9:00 AM CST", None, "America/Chicago"),
        ("09/11/2026 9:00 AM PST", None, "America/Los_Angeles"),
        ("09/11/2026 9:00 AM MST", None, "America/Denver"),
        ("09/11/2026 9:00 AM EDT", None, "America/New_York"),
        ("09/11/2026 9:00 AM CDT", None, "America/Chicago"),
        # No explicit tz → falls back to business_tz
        ("09/11/2026 9:00 AM", "America/Chicago", "America/Chicago"),
        ("09/11/2026 9:00 AM", "America/New_York", "America/New_York"),
    ])
    def test_parse_succeeds_and_resolve_matches(self, raw, business_tz, expected_iana):
        """Both functions should agree: parse produces a datetime and resolve
        returns the expected IANA zone."""
        dt = _parse_appt_utc(raw, business_tz=business_tz)
        tz = _resolve_customer_tz(raw, business_tz=business_tz)
        assert dt is not None, f"Failed to parse: {raw}"
        assert dt.tzinfo is not None, f"No tzinfo on: {raw}"
        assert tz == expected_iana, f"Wrong IANA for {raw}"


# ---------------------------------------------------------------------------
# IANA mapping consistency check
# ---------------------------------------------------------------------------

class TestTzAbbrevToIanaMapping:
    """Ensure every US timezone abbreviation resolves to a valid IANA name."""

    @pytest.mark.parametrize("abbrev,expected_iana", [
        ("EST", "America/New_York"),
        ("EDT", "America/New_York"),
        ("CST", "America/Chicago"),
        ("CDT", "America/Chicago"),
        ("MST", "America/Denver"),
        ("MDT", "America/Denver"),
        ("PST", "America/Los_Angeles"),
        ("PDT", "America/Los_Angeles"),
        ("UTC", "UTC"),
        ("GMT", "GMT"),
    ])
    def test_mapping(self, abbrev, expected_iana):
        assert _TZ_ABBREV_TO_IANA[abbrev] == expected_iana

    def test_all_mapped_zones_are_valid_zoneinfo(self):
        """Every IANA zone name in the mapping should be constructable with ZoneInfo."""
        for abbrev, iana in _TZ_ABBREV_TO_IANA.items():
            try:
                ZoneInfo(iana)
            except Exception as exc:
                pytest.fail(f"ZoneInfo({iana!r}) failed for abbreviation {abbrev}: {exc}")
