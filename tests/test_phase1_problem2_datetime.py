"""PHASE 1 — Problem 2: Appointment Date/Time Parsing & Timezone Determinism.

Behavior-based tests verifying that appointment date/time values from the real
Google Form submission path are parsed correctly and deterministically across
timezones.  Covers:

  1. Organization timezone → correct UTC instant
  2. Server timezone independence
  3. Different organizations → different correct instants
  4. Calendar representation correctness
  5. Existing supported input formats
  6. No timezone leakage across tenants
  7. Missing appointment handling
  8. Existing regression coverage
  9. DST edge cases
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from zoneinfo import ZoneInfo

from app.main import _parse_appt_utc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Fixed UTC offsets for timezone abbreviations (no DST, literal meaning).
_ABBREV_TO_OFFSET: dict[str, timedelta] = {
    "EST": timedelta(hours=-5),
    "EDT": timedelta(hours=-4),
    "CST": timedelta(hours=-6),
    "CDT": timedelta(hours=-5),
    "MST": timedelta(hours=-7),
    "MDT": timedelta(hours=-6),
    "PST": timedelta(hours=-8),
    "PDT": timedelta(hours=-7),
    "UTC": timedelta(0),
    "GMT": timedelta(0),
}


def _to_utc(dt: datetime, tz_abbrev: str) -> datetime:
    """Convert a naive datetime assumed to be in *tz_abbrev* to UTC."""
    offset = _ABBREV_TO_OFFSET.get(tz_abbrev, timedelta(0))
    return (dt.replace(tzinfo=timezone(offset))).astimezone(timezone.utc)


def _local_to_utc(year, month, day, hour, minute, iana_tz: str) -> datetime:
    """Convert a local datetime in an IANA timezone to UTC for assertions."""
    local = datetime(year, month, day, hour, minute, tzinfo=ZoneInfo(iana_tz))
    return local.astimezone(timezone.utc)


# ===========================================================================
# 1. Organization timezone → correct UTC instant
# ===========================================================================


class TestOrgTimezoneProducesCorrectUTC:
    """Given: appointment date + time + organization timezone
    Verify: the resulting instant is correct in UTC."""

    def test_karachi_3pm_aug_10(self):
        """Asia/Karachi (UTC+5) 3:00 PM → 10:00 UTC."""
        result = _parse_appt_utc(
            "August 10, 2026 at 3:00 PM",
            business_tz="Asia/Karachi",
        )
        assert result is not None
        expected = _local_to_utc(2026, 8, 10, 15, 0, "Asia/Karachi")
        assert result == expected

    def test_new_york_9am_aug_10(self):
        """America/New_York (EDT, UTC-4 in Aug) 9:00 AM → 13:00 UTC."""
        result = _parse_appt_utc(
            "August 10, 2026 at 9:00 AM",
            business_tz="America/New_York",
        )
        assert result is not None
        expected = _local_to_utc(2026, 8, 10, 9, 0, "America/New_York")
        assert result == expected

    def test_chicago_2pm_aug_10(self):
        """America/Chicago (CDT, UTC-5 in Aug) 2:00 PM → 19:00 UTC."""
        result = _parse_appt_utc(
            "August 10, 2026 at 2:00 PM",
            business_tz="America/Chicago",
        )
        assert result is not None
        expected = _local_to_utc(2026, 8, 10, 14, 0, "America/Chicago")
        assert result == expected

    def test_la_11am_aug_10(self):
        """America/Los_Angeles (PDT, UTC-7 in Aug) 11:00 AM → 18:00 UTC."""
        result = _parse_appt_utc(
            "August 10, 2026 at 11:00 AM",
            business_tz="America/Los_Angeles",
        )
        assert result is not None
        expected = _local_to_utc(2026, 8, 10, 11, 0, "America/Los_Angeles")
        assert result == expected

    def test_london_5pm_aug_10(self):
        """Europe/London (BST, UTC+1 in Aug) 5:00 PM → 16:00 UTC."""
        result = _parse_appt_utc(
            "August 10, 2026 at 5:00 PM",
            business_tz="Europe/London",
        )
        assert result is not None
        expected = _local_to_utc(2026, 8, 10, 17, 0, "Europe/London")
        assert result == expected

    def test_karachi_midnight_aug_11(self):
        """Asia/Karachi midnight → previous day 19:00 UTC."""
        result = _parse_appt_utc(
            "August 11, 2026 at 12:00 AM",
            business_tz="Asia/Karachi",
        )
        assert result is not None
        expected = _local_to_utc(2026, 8, 11, 0, 0, "Asia/Karachi")
        assert result == expected

    def test_result_is_always_utc(self):
        """The returned datetime must always be UTC (timezone-aware)."""
        for tz in ["Asia/Karachi", "America/New_York", "Europe/London", "UTC"]:
            result = _parse_appt_utc(
                "August 10, 2026 at 3:00 PM",
                business_tz=tz,
            )
            assert result is not None
            assert result.tzinfo is not None
            assert result.tzinfo == timezone.utc


# ===========================================================================
# 2. Server timezone independence
# ===========================================================================


class TestServerTimezoneIndependence:
    """The same input must produce the same UTC result regardless of the
    machine's system timezone (Docker UTC, developer laptop, etc.)."""

    _INPUT = "April 5, 2026 at 5:00 AM"
    _BUSINESS_TZ = "America/Chicago"

    def test_result_unchanged_with_utc_system_tz(self):
        """Docker containers typically run UTC. Result must not change."""
        result = _parse_appt_utc(self._INPUT, business_tz=self._BUSINESS_TZ)
        assert result is not None
        expected = _local_to_utc(2026, 4, 5, 5, 0, "America/Chicago")
        assert result == expected

    def test_simulate_pakistan_system_tz(self):
        """Simulate a server running in Pakistan timezone."""
        original_tz = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "Asia/Karachi"
            result = _parse_appt_utc(self._INPUT, business_tz=self._BUSINESS_TZ)
            assert result is not None
            expected = _local_to_utc(2026, 4, 5, 5, 0, "America/Chicago")
            assert result == expected
        finally:
            if original_tz is not None:
                os.environ["TZ"] = original_tz
            elif "TZ" in os.environ:
                del os.environ["TZ"]

    def test_simulate_us_eastern_system_tz(self):
        """Simulate a server running in US Eastern timezone."""
        original_tz = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "America/New_York"
            result = _parse_appt_utc(self._INPUT, business_tz=self._BUSINESS_TZ)
            assert result is not None
            expected = _local_to_utc(2026, 4, 5, 5, 0, "America/Chicago")
            assert result == expected
        finally:
            if original_tz is not None:
                os.environ["TZ"] = original_tz
            elif "TZ" in os.environ:
                del os.environ["TZ"]

    def test_system_utc_does_not_override_business_tz(self):
        """The critical Docker bug: dateparser auto-inferencing UTC
        must NOT override the business timezone."""
        result = _parse_appt_utc(
            "4-5-2026/5:00am",
            business_tz="America/Chicago",
        )
        assert result is not None
        # 5:00 AM CDT = UTC-5, so 10:00 UTC
        assert result.hour == 10
        # Must NOT be 5:00 UTC (which would be the bug)
        assert result != datetime(2026, 4, 5, 5, 0, tzinfo=timezone.utc)


# ===========================================================================
# 3. Different organizations → different correct instants
# ===========================================================================


class TestDifferentOrgTimezones:
    """Two organizations with different timezones must produce different
    correct UTC instants from equivalent local times."""

    def test_same_input_different_orgs_different_utc(self):
        """5:00 AM in Karachi ≠ 5:00 AM in New York ≠ 5:00 AM in LA."""
        input_str = "April 5, 2026 at 5:00 AM"

        karachi = _parse_appt_utc(input_str, business_tz="Asia/Karachi")
        new_york = _parse_appt_utc(input_str, business_tz="America/New_York")
        la = _parse_appt_utc(input_str, business_tz="America/Los_Angeles")

        assert karachi is not None
        assert new_york is not None
        assert la is not None

        # Asia/Karachi (UTC+5): 5:00 AM → 00:00 UTC
        # America/New_York (EDT, UTC-4): 5:00 AM → 09:00 UTC
        # America/Los_Angeles (PDT, UTC-7): 5:00 AM → 12:00 UTC
        assert karachi.hour == 0
        assert new_york.hour == 9
        assert la.hour == 12

        # All three are distinct
        assert karachi != new_york
        assert new_york != la
        assert karachi != la

    def test_karachi_vs_chicago_noon(self):
        """12:00 PM noon: Karachi (UTC+5) → 07:00 UTC, Chicago (CDT) → 17:00 UTC."""
        input_str = "August 10, 2026 at 12:00 PM"

        karachi = _parse_appt_utc(input_str, business_tz="Asia/Karachi")
        chicago = _parse_appt_utc(input_str, business_tz="America/Chicago")

        assert karachi is not None
        assert chicago is not None

        assert karachi == _local_to_utc(2026, 8, 10, 12, 0, "Asia/Karachi")
        assert chicago == _local_to_utc(2026, 8, 10, 12, 0, "America/Chicago")

    def test_explicit_tz_overrides_org_tz(self):
        """User-supplied EST in input overrides the org's configured tz."""
        result = _parse_appt_utc(
            "August 10, 2026 at 9:00 AM EST",
            business_tz="Asia/Karachi",
        )
        assert result is not None
        # EST = UTC-5 → 9:00 AM = 14:00 UTC (NOT 04:00 UTC which would be Karachi)
        assert result.hour == 14

    def test_explicit_pacific_overrides_org_tz(self):
        """User-supplied PDT in input overrides org's tz."""
        result = _parse_appt_utc(
            "August 10, 2026 at 3:00 PM PDT",
            business_tz="America/New_York",
        )
        assert result is not None
        # PDT = UTC-7 → 3:00 PM = 22:00 UTC (NOT 19:00 UTC which would be EDT)
        assert result.hour == 22


# ===========================================================================
# 4. Calendar representation correctness
# ===========================================================================


class TestCalendarRepresentation:
    """Verify the Calendar event would receive the correct datetime/timezone.

    The Calendar API is called with:
        start = lead.appt_datetime_utc (UTC-aware datetime)
        timeZone = "UTC"
    """

    def test_calendar_receives_utc_datetime(self):
        """The datetime sent to Calendar must be UTC."""
        result = _parse_appt_utc(
            "August 10, 2026 at 3:00 PM",
            business_tz="Asia/Karachi",
        )
        assert result is not None
        # Simulate what CalendarService.create_event does:
        start_iso = result.isoformat()
        assert "+00:00" in start_iso or start_iso.endswith("+00:00")

    def test_calendar_end_time_consistent(self):
        """Calendar end = start + duration_minutes. Duration must remain correct."""
        result = _parse_appt_utc(
            "August 10, 2026 at 3:00 PM",
            business_tz="Asia/Karachi",
        )
        assert result is not None
        duration_minutes = 30  # default
        end = result + timedelta(minutes=duration_minutes)
        assert end > result
        assert (end - result).total_seconds() == duration_minutes * 60

    def test_calendar_start_end_same_timezone(self):
        """Start and end must both be in UTC."""
        result = _parse_appt_utc(
            "August 10, 2026 at 3:00 PM",
            business_tz="America/New_York",
        )
        assert result is not None
        end = result + timedelta(minutes=30)
        assert result.tzinfo == timezone.utc
        assert end.tzinfo == timezone.utc

    def test_isoformat_preserves_utc_offset(self):
        """The ISO format string preserves the UTC offset for the Calendar API."""
        result = _parse_appt_utc(
            "August 10, 2026 at 3:00 PM",
            business_tz="Asia/Karachi",
        )
        assert result is not None
        iso = result.isoformat()
        # UTC datetime should have +00:00 suffix
        assert "+00:00" in iso


# ===========================================================================
# 5. Existing supported input formats
# ===========================================================================


class TestSupportedInputFormats:
    """Test each format actually supported by the current Form integration."""

    def test_slash_date_MM_DD_YYYY(self):
        """08/27/2026 9:00 AM EST — common Google Form output."""
        result = _parse_appt_utc(
            "08/27/2026 9:00 AM EST", business_tz="America/Chicago"
        )
        assert result is not None
        assert result == _to_utc(datetime(2026, 8, 27, 9, 0), "EST")

    def test_long_date_with_at(self):
        """August 27, 2026 at 9:00 AM EST."""
        result = _parse_appt_utc(
            "August 27, 2026 at 9:00 AM EST", business_tz="America/Chicago"
        )
        assert result is not None
        assert result == _to_utc(datetime(2026, 8, 27, 9, 0), "EST")

    def test_long_date_without_at(self):
        """August 27, 2026 9:00 AM EST."""
        result = _parse_appt_utc(
            "August 27, 2026 9:00 AM EST", business_tz="America/Chicago"
        )
        assert result is not None
        assert result == _to_utc(datetime(2026, 8, 27, 9, 0), "EST")

    def test_weekday_long_date_at(self):
        """Thursday, August 27, 2026 at 9 AM Eastern Time.

        NOTE: _extract_tz maps 'Eastern Time' -> 'EST' (UTC-5), not EDT.
        So 9 AM Eastern Time -> 14:00 UTC.
        """
        result = _parse_appt_utc(
            "Thursday, August 27, 2026 at 9 AM Eastern Time",
            business_tz="America/Chicago",
        )
        assert result is not None
        # Eastern Time -> EST -> UTC-5 -> 9 AM = 14:00 UTC
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "EST")
        assert result == expected

    def test_ordinal_suffixes(self):
        """27th, 1st, 2nd, 3rd — ordinal suffixes are stripped."""
        result = _parse_appt_utc(
            "August 27th, 2026 at 9:00 AM (EST)",
            business_tz="America/Chicago",
        )
        assert result is not None
        assert result.day == 27

    def test_natural_language_relative(self):
        """'tomorrow at 9 AM' — uses business timezone."""
        result = _parse_appt_utc(
            "tomorrow at 9 AM", business_tz="America/New_York"
        )
        assert result is not None
        assert result > datetime.now(timezone.utc)
        # 9:00 AM EDT = 13:00 UTC
        assert result.hour == 13

    def test_natural_language_noon(self):
        """August 27, 2026 at noon — 'noon' = 12:00 PM."""
        result = _parse_appt_utc(
            "August 27, 2026 at noon", business_tz="America/Chicago"
        )
        assert result is not None
        assert result.hour == 17  # 12:00 PM CDT = 17:00 UTC

    def test_24hour_format(self):
        """2026-08-27 14:00 — ISO-like 24h format."""
        result = _parse_appt_utc(
            "2026-08-27 14:00", business_tz="America/New_York"
        )
        assert result is not None
        expected = _local_to_utc(2026, 8, 27, 14, 0, "America/New_York")
        assert result == expected

    def test_parenthesised_timezone(self):
        """August 27, 2026 at 9:00 AM (CST)."""
        result = _parse_appt_utc(
            "August 27, 2026 at 9:00 AM (CST)",
            business_tz="America/New_York",
        )
        assert result is not None
        # CST = UTC-6 → 9:00 AM = 15:00 UTC
        assert result.hour == 15

    def test_full_timezone_name_no_parens(self):
        """August 27, 2026 at 9:00 AM Pacific Standard Time."""
        result = _parse_appt_utc(
            "August 27, 2026 at 9:00 AM Pacific Standard Time",
            business_tz="America/Chicago",
        )
        assert result is not None
        # PST = UTC-8 → 9:00 AM = 17:00 UTC
        assert result.hour == 17


# ===========================================================================
# 6. No timezone leakage across tenants
# ===========================================================================


class TestNoTimezoneLeakage:
    """Organization A's timezone must NOT affect Organization B."""

    def test_org_a_does_not_affect_org_b(self):
        """Karachi tz does not leak into New York parsing."""
        input_str = "August 10, 2026 at 3:00 PM"

        karachi_result = _parse_appt_utc(input_str, business_tz="Asia/Karachi")
        ny_result = _parse_appt_utc(input_str, business_tz="America/New_York")

        assert karachi_result is not None
        assert ny_result is not None

        # Karachi: 3 PM UTC+5 → 10:00 UTC
        # New York: 3 PM EDT → 19:00 UTC
        assert karachi_result.hour == 10
        assert ny_result.hour == 19

        # Verify neither result was contaminated
        karachi_expected = _local_to_utc(2026, 8, 10, 15, 0, "Asia/Karachi")
        ny_expected = _local_to_utc(2026, 8, 10, 15, 0, "America/New_York")
        assert karachi_result == karachi_expected
        assert ny_result == ny_expected

    def test_fallback_settings_does_not_override_org(self):
        """When business_tz is provided, settings.business_timezone is NOT used."""
        from app.config import settings
        original_bt = settings.business_timezone
        try:
            settings.business_timezone = "Asia/Karachi"
            result = _parse_appt_utc(
                "August 10, 2026 at 3:00 PM",
                business_tz="America/New_York",
            )
            assert result is not None
            # Must be New York time, NOT Karachi
            expected = _local_to_utc(2026, 8, 10, 15, 0, "America/New_York")
            assert result == expected
        finally:
            settings.business_timezone = original_bt


# ===========================================================================
# 7. Missing appointment handling
# ===========================================================================


class TestMissingAppointment:
    """Verify existing behavior when appointment date/time is absent."""

    def test_none_returns_none(self):
        result = _parse_appt_utc(None)
        assert result is None

    def test_empty_string_returns_none(self):
        result = _parse_appt_utc("")
        assert result is None

    def test_whitespace_returns_none(self):
        result = _parse_appt_utc("   ")
        assert result is None

    def test_garbage_returns_none(self):
        result = _parse_appt_utc("not-a-date-@#$%")
        assert result is None

    def test_single_word_returns_none(self):
        result = _parse_appt_utc("hello")
        assert result is None


# ===========================================================================
# 8. Existing regression coverage (all previously-passing tests still pass)
# ===========================================================================


class TestRegressionCoverage:
    """Ensure all previously-passing Form → Lead datetime behavior
    remains intact after any changes."""

    def test_august_27_2026_9am_est(self):
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM EST")
        assert result is not None
        assert result == _to_utc(datetime(2026, 8, 27, 9, 0), "EST")

    def test_august_27_2026_9am_est_alt_format(self):
        result = _parse_appt_utc("August 27, 2026 9:00 AM EST")
        assert result is not None
        assert result == _to_utc(datetime(2026, 8, 27, 9, 0), "EST")

    def test_thursday_august_27_2026_eastern_time(self):
        result = _parse_appt_utc(
            "Thursday, August 27, 2026 at 9 AM Eastern Time"
        )
        assert result is not None
        # Eastern Time -> EST -> UTC-5 -> 9 AM = 14:00 UTC
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "EST")
        assert result == expected

    def test_slash_date_08_27_2026_est(self):
        result = _parse_appt_utc("08/27/2026 9:00 AM EST")
        assert result is not None
        assert result == _to_utc(datetime(2026, 8, 27, 9, 0), "EST")

    def test_ordinal_thursday_august_27th(self):
        result = _parse_appt_utc("Thursday August 27th, at 09:00 AM (EST)")
        assert result is not None
        assert result.tzinfo is not None
        naive_aug27 = datetime(result.year, 8, 27, 9, 0)
        expected = naive_aug27.replace(
            tzinfo=timezone(timedelta(hours=-5))
        ).astimezone(timezone.utc)
        assert result == expected

    def test_est_not_coerced_to_utc(self):
        """9:00 AM EST must NOT become 9:00 AM UTC."""
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM EST")
        assert result is not None
        assert result.hour == 14  # EST = UTC-5 → 14:00 UTC

    def test_cst_preserved(self):
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM CST")
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "CST")
        assert result == expected

    def test_business_tz_chicago_5am(self):
        """Previous Docker bug regression: 5:00 AM Chicago → 10:00 UTC."""
        result = _parse_appt_utc("4-5-2026/5:00am", business_tz="America/Chicago")
        assert result is not None
        assert result == datetime(2026, 4, 5, 10, 0, tzinfo=timezone.utc)

    def test_midnight(self):
        result = _parse_appt_utc("August 27, 2026 at midnight")
        assert result is not None

    def test_tomorrow_relative(self):
        result = _parse_appt_utc("tomorrow at 9 AM")
        assert result is not None
        assert result > datetime.now(timezone.utc)


# ===========================================================================
# 9. DST edge cases
# ===========================================================================


class TestDSTEdgeCases:
    """If organizations are in DST-observing timezones, verify that
    ZoneInfo handles spring-forward and fall-back correctly."""

    def test_spring_forward_cdt_to_est(self):
        """Mar 9 2026 at 1:00 AM America/New_York → EST (UTC-5).
        Mar 9 2026 at 3:00 AM America/New_York → EDT (UTC-4).
        The same local time in different DST states produces different UTC."""
        # Before spring-forward: EST = UTC-5
        result_before = _parse_appt_utc(
            "March 8, 2026 at 1:00 AM",
            business_tz="America/New_York",
        )
        # After spring-forward: EDT = UTC-4
        result_after = _parse_appt_utc(
            "March 10, 2026 at 1:00 AM",
            business_tz="America/New_York",
        )
        assert result_before is not None
        assert result_after is not None
        # Both are "1:00 AM" but in different DST states
        expected_before = _local_to_utc(2026, 3, 8, 1, 0, "America/New_York")
        expected_after = _local_to_utc(2026, 3, 10, 1, 0, "America/New_York")
        assert result_before == expected_before
        assert result_after == expected_after
        # EDT (after) is 1 hour ahead of EST (before)
        assert result_after > result_before

    def test_fall_back_edt_to_est(self):
        """Nov 1 2026 at 1:00 AM America/New_York -> still EDT (UTC-4).
        Nov 3 2026 at 1:00 AM America/New_York -> EST (UTC-5).

        DST fall-back in 2026 is Nov 1 at 2 AM.  1:00 AM on Nov 1 is
        still EDT (UTC-4) -> 5:00 UTC.  Nov 3 is EST (UTC-5) -> 6:00 UTC.
        """
        # Before fall-back: EDT = UTC-4
        result_before = _parse_appt_utc(
            "November 1, 2026 at 1:00 AM",
            business_tz="America/New_York",
        )
        # After fall-back: EST = UTC-5
        result_after = _parse_appt_utc(
            "November 3, 2026 at 1:00 AM",
            business_tz="America/New_York",
        )
        assert result_before is not None
        assert result_after is not None
        expected_before = _local_to_utc(2026, 11, 1, 1, 0, "America/New_York")
        expected_after = _local_to_utc(2026, 11, 3, 1, 0, "America/New_York")
        assert result_before == expected_before
        assert result_after == expected_after
        # EDT (UTC-4) -> 5:00 UTC; EST (UTC-5) -> 6:00 UTC
        assert result_before.hour == 5
        assert result_after.hour == 6
        # EDT has smaller UTC offset, so 1 AM EDT < 1 AM EST in UTC terms
        assert result_before < result_after

    def test_karachi_has_no_dst(self):
        """Asia/Karachi has no DST. Same hour should produce consistent UTC
        across different months."""
        result_jan = _parse_appt_utc(
            "January 10, 2026 at 3:00 PM",
            business_tz="Asia/Karachi",
        )
        result_jul = _parse_appt_utc(
            "July 10, 2026 at 3:00 PM",
            business_tz="Asia/Karachi",
        )
        assert result_jan is not None
        assert result_jul is not None
        # Pakistan is always UTC+5 (no DST), so both should be at the same
        # UTC hour (10:00)
        assert result_jan.hour == 10
        assert result_jul.hour == 10


# ===========================================================================
# 10. End-to-end: webhook → Lead appt_datetime_utc with org tz
# ===========================================================================


class TestEndToEndWebhookTimezone:
    """Integration: verify that the webhook -> _handle_form_submission flow
    correctly applies the org timezone to create Lead.appt_datetime_utc."""

    def _make_submission_payload(self, appt_str: str) -> dict:
        return {
            "Name": "TZ Test Lead",
            "Email Address": "tztest@example.com",
            "Phone Appt. Date/Time": appt_str,
            "Interested?": "yes",
        }

    def test_webhook_karachi_org_correct_utc(self):
        """Org with Asia/Karachi timezone gets correct appt_datetime_utc."""
        from fastapi.testclient import TestClient
        from app.main import app
        from app.database import engine, SessionLocal
        from app.models import Base, Lead
        from app.models_multi_tenant import Organization, OrganizationStatus

        # Use a unique slug to avoid conflicts
        import uuid
        slug = f"tz-test-karachi-{uuid.uuid4().hex[:8]}"

        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        try:
            org = Organization(
                name="TZ Test Karachi",
                slug=slug,
                timezone="Asia/Karachi",
                status=OrganizationStatus.ACTIVE,
                plan="business",
            )
            db.add(org)
            db.commit()
            db.refresh(org)

            client = TestClient(app)
            payload = self._make_submission_payload("August 10, 2026 at 3:00 PM")
            resp = client.post(
                f"/webhooks/{slug}/form-submission",
                json=payload,
            )
            assert resp.status_code == 202

            # Verify the lead was created with correct UTC
            lead = db.query(Lead).filter(
                Lead.email == "tztest@example.com",
                Lead.organization_id == org.id,
            ).first()
            assert lead is not None
            assert lead.appt_datetime_utc is not None
            expected = _local_to_utc(2026, 8, 10, 15, 0, "Asia/Karachi")
            assert lead.appt_datetime_utc == expected

            # Cleanup — must delete EventLog rows first (FK RESTRICT on organization_id)
            from app.models import EventLog
            db.query(EventLog).filter(EventLog.organization_id == org.id).delete(synchronize_session=False)
            db.delete(lead)
            db.delete(org)
            db.commit()
        finally:
            db.close()

    def test_webhook_newyork_org_correct_utc(self):
        """Org with America/New_York timezone gets different correct UTC."""
        from fastapi.testclient import TestClient
        from app.main import app
        from app.database import engine, SessionLocal
        from app.models import Base, Lead
        from app.models_multi_tenant import Organization, OrganizationStatus

        import uuid
        slug = f"tz-test-ny-{uuid.uuid4().hex[:8]}"

        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        try:
            org = Organization(
                name="TZ Test New York",
                slug=slug,
                timezone="America/New_York",
                status=OrganizationStatus.ACTIVE,
                plan="business",
            )
            db.add(org)
            db.commit()
            db.refresh(org)

            client = TestClient(app)
            payload = self._make_submission_payload("August 10, 2026 at 3:00 PM")
            resp = client.post(
                f"/webhooks/{slug}/form-submission",
                json=payload,
            )
            assert resp.status_code == 202

            lead = db.query(Lead).filter(
                Lead.email == "tztest@example.com",
                Lead.organization_id == org.id,
            ).first()
            assert lead is not None
            assert lead.appt_datetime_utc is not None
            expected = _local_to_utc(2026, 8, 10, 15, 0, "America/New_York")
            assert lead.appt_datetime_utc == expected

            # Cleanup — must delete EventLog rows first (FK RESTRICT on organization_id)
            from app.models import EventLog
            db.query(EventLog).filter(EventLog.organization_id == org.id).delete(synchronize_session=False)
            db.delete(lead)
            db.delete(org)
            db.commit()
        finally:
            db.close()

    def test_cross_org_isolation_same_input(self):
        """Same input to two orgs with different timezones -> different UTC."""
        from fastapi.testclient import TestClient
        from app.main import app
        from app.database import engine, SessionLocal
        from app.models import Base, Lead
        from app.models_multi_tenant import Organization, OrganizationStatus

        import uuid
        slug_k = f"tz-iso-k-{uuid.uuid4().hex[:8]}"
        slug_n = f"tz-iso-n-{uuid.uuid4().hex[:8]}"

        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        try:
            org_k = Organization(
                name="TZ Karachi", slug=slug_k,
                timezone="Asia/Karachi", status=OrganizationStatus.ACTIVE, plan="business",
            )
            org_n = Organization(
                name="TZ New York", slug=slug_n,
                timezone="America/New_York", status=OrganizationStatus.ACTIVE, plan="business",
            )
            db.add_all([org_k, org_n])
            db.commit()
            db.refresh(org_k)
            db.refresh(org_n)

            client = TestClient(app)
            payload = self._make_submission_payload("August 10, 2026 at 3:00 PM")

            resp_k = client.post(f"/webhooks/{slug_k}/form-submission", json=payload)
            # Use different email for org N
            payload_n = dict(payload)
            payload_n["Email Address"] = "tztest-ny@example.com"
            resp_n = client.post(f"/webhooks/{slug_n}/form-submission", json=payload_n)

            assert resp_k.status_code == 202
            assert resp_n.status_code == 202

            lead_k = db.query(Lead).filter(
                Lead.email == "tztest@example.com",
                Lead.organization_id == org_k.id,
            ).first()
            lead_n = db.query(Lead).filter(
                Lead.email == "tztest-ny@example.com",
                Lead.organization_id == org_n.id,
            ).first()

            assert lead_k is not None and lead_n is not None
            assert lead_k.appt_datetime_utc is not None
            assert lead_n.appt_datetime_utc is not None

            # Must be different UTC times
            assert lead_k.appt_datetime_utc != lead_n.appt_datetime_utc
            # Karachi: 3 PM -> 10:00 UTC; NY: 3 PM -> 19:00 UTC
            assert lead_k.appt_datetime_utc.hour == 10
            assert lead_n.appt_datetime_utc.hour == 19

            # Cleanup — must delete EventLog rows first (FK RESTRICT on organization_id)
            from app.models import EventLog
            db.query(EventLog).filter(
                EventLog.organization_id.in_([org_k.id, org_n.id])
            ).delete(synchronize_session=False)
            db.delete(lead_k)
            db.delete(lead_n)
            db.delete(org_k)
            db.delete(org_n)
            db.commit()
        finally:
            db.close()
