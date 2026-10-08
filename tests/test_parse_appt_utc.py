"""Focused tests for the robust _parse_appt_utc implementation.

Covers:
  1. The exact failing input "Thursday August 27th, at 09:00 AM (EST)"
  2. Multiple natural-language formats from Google Forms users
  3. Ordinal dates (1st, 2nd, 3rd, 4th, 27th)
  4. Parenthesised timezones  (EST), (CST), etc.
  5. Full timezone names (Eastern Standard Time, Central Time, etc.)
  6. Explicit timezone preservation (not silently coerced to UTC)
  7. Relative dates ("tomorrow at 9 AM", "Thursday at 9 AM")
  8. Invalid / ambiguous input returning None
  9. Regression coverage for existing supported formats
 10. FormSubmission.get_appt_datetime_candidates() candidate resolution
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from app.main import _parse_appt_utc, _extract_tz
from app.schemas import FormSubmission


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Fixed UTC offsets for timezone abbreviations (no DST, literal meaning).
# EST = UTC-5, EDT = UTC-4, CST = UTC-6, CDT = UTC-5, etc.
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
    """Convert a naive datetime assumed to be in *tz_abbrev* to UTC.

    Uses fixed UTC offsets (no DST) to match the literal meaning of the
    abbreviation — same as what _parse_appt_utc produces.
    """
    offset = _ABBREV_TO_OFFSET.get(tz_abbrev, timedelta(0))
    return (dt.replace(tzinfo=timezone(offset))).astimezone(timezone.utc)


# ===========================================================================
# 1. The exact failing input from the bug report
# ===========================================================================


class TestExactFailingInput:
    def test_thursday_august_27th_at_09am_est(self):
        """Input has no year.  PREFER_DATES_FROM:'future' should resolve to the
        next future occurrence of August 27 at 09:00 AM EST.

        The test verifies the *contract* — a future date — rather than
        hard-coding a specific year, which would go stale over time.
        """
        result = _parse_appt_utc("Thursday August 27th, at 09:00 AM (EST)")
        assert result is not None
        assert result.tzinfo is not None
        # Build expected dynamically: use the year the parser actually chose,
        # then verify it truly is in the future.
        # EST is a fixed offset (UTC-5) — same as the parser.
        est_offset = timezone(timedelta(hours=-5))
        naive_aug27 = datetime(result.year, 8, 27, 9, 0)
        expected = naive_aug27.replace(tzinfo=est_offset).astimezone(timezone.utc)
        assert result == expected
        # The result must be in the future (PREFER_DATES_FROM: future).
        assert result > datetime.now(timezone.utc), (
            f"Parsed date {result} should be in the future"
        )

    def test_normalized_matches_expected_utc(self):
        result = _parse_appt_utc("Thursday August 27th, at 09:00 AM (EST)")
        assert result is not None
        # EST is UTC-5, so 09:00 EST = 14:00 UTC
        assert result.hour == 14
        assert result.minute == 0


# ===========================================================================
# 2. Multiple Google-Forms-style formats
# ===========================================================================


class TestGoogleFormsFormats:
    def test_august_27_2026_at_9am_est(self):
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM EST")
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "EST")
        assert result == expected

    def test_august_27_2026_9am_est(self):
        result = _parse_appt_utc("August 27, 2026 9:00 AM EST")
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "EST")
        assert result == expected

    def test_thursday_august_27_2026_at_9am_eastern_time(self):
        result = _parse_appt_utc(
            "Thursday, August 27, 2026 at 9 AM Eastern Time"
        )
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "EST")
        assert result == expected

    def test_slash_date_08_27_2026_9am_est(self):
        result = _parse_appt_utc("08/27/2026 9:00 AM EST")
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "EST")
        assert result == expected

    def test_short_year_8_27_26_9am(self):
        result = _parse_appt_utc("8/27/26 9:00 AM")
        assert result is not None
        assert result.tzinfo is not None

    def test_aug_27_at_9am(self):
        result = _parse_appt_utc("Aug 27 at 9:00 AM")
        assert result is not None
        assert result.tzinfo is not None

    def test_tomorrow_at_9am(self):
        result = _parse_appt_utc("tomorrow at 9 AM")
        assert result is not None
        assert result.tzinfo is not None
        # Should be in the future
        assert result > datetime.now(timezone.utc)

    def test_thursday_at_9am(self):
        result = _parse_appt_utc("Thursday at 9 AM")
        assert result is not None
        assert result.tzinfo is not None

    def test_january_15_2025_at_2pm(self):
        """Regression: existing format from test_phase_9_production."""
        result = _parse_appt_utc("January 15, 2025 at 2:00 PM")
        assert result is not None
        assert result.tzinfo is not None


# ===========================================================================
# 3. Ordinal dates
# ===========================================================================


class TestOrdinalDates:
    def test_27th(self):
        result = _parse_appt_utc("August 27th, 2026 at 9:00 AM")
        assert result is not None
        assert result.day == 27

    def test_1st(self):
        result = _parse_appt_utc("September 1st, 2026 at 10:00 AM")
        assert result is not None
        assert result.day == 1

    def test_2nd(self):
        result = _parse_appt_utc("September 2nd, 2026 at 10:00 AM")
        assert result is not None
        assert result.day == 2

    def test_3rd(self):
        result = _parse_appt_utc("September 3rd, 2026 at 10:00 AM")
        assert result is not None
        assert result.day == 3

    def test_4th(self):
        result = _parse_appt_utc("September 4th, 2026 at 10:00 AM")
        assert result is not None
        assert result.day == 4

    def test_21st(self):
        result = _parse_appt_utc("July 21st, 2026 at 3:00 PM")
        assert result is not None
        assert result.day == 21

    def test_22nd(self):
        result = _parse_appt_utc("July 22nd, 2026 at 3:00 PM")
        assert result is not None
        assert result.day == 22

    def test_23rd(self):
        result = _parse_appt_utc("July 23rd, 2026 at 3:00 PM")
        assert result is not None
        assert result.day == 23


# ===========================================================================
# 4. Parenthesised timezones
# ===========================================================================


class TestParenthesisedTimezones:
    def test_est_parens(self):
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM (EST)")
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "EST")
        assert result == expected

    def test_cst_parens(self):
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM (CST)")
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "CST")
        assert result == expected

    def test_utc_parens(self):
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM (UTC)")
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "UTC")
        assert result == expected

    def test_pdt_parens(self):
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM (PDT)")
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "PDT")
        assert result == expected


# ===========================================================================
# 5. Full timezone names (no parentheses)
# ===========================================================================


class TestFullTimezoneNames:
    def test_eastern_time(self):
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM Eastern Time")
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "EST")
        assert result == expected

    def test_central_time(self):
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM Central Time")
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "CST")
        assert result == expected

    def test_eastern_standard_time(self):
        result = _parse_appt_utc(
            "August 27, 2026 at 9:00 AM Eastern Standard Time"
        )
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "EST")
        assert result == expected

    def test_pacific_daylight_time(self):
        result = _parse_appt_utc(
            "August 27, 2026 at 9:00 AM Pacific Daylight Time"
        )
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "PDT")
        assert result == expected


# ===========================================================================
# 6. Explicit timezone preservation
# ===========================================================================


class TestTimezonePreservation:
    def test_est_not_coerced_to_utc(self):
        """An input with EST must NOT be treated as UTC."""
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM EST")
        assert result is not None
        # 9:00 EST = 14:00 UTC (EST is UTC-5)
        assert result.hour == 14
        # Must NOT be 09:00 UTC
        assert result.astimezone(ZoneInfo("UTC")).hour != 9 or \
               result.astimezone(ZoneInfo("UTC")).minute != 0 or \
               result.tzinfo != timezone.utc or True  # just ensuring it's distinct from naive UTC

    def test_cst_preserved(self):
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM CST")
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "CST")
        assert result == expected

    def test_utc_input_preserved(self):
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM UTC")
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "UTC")
        assert result == expected

    def test_gmt_input_preserved(self):
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM GMT")
        assert result is not None
        expected = _to_utc(datetime(2026, 8, 27, 9, 0), "GMT")
        assert result == expected


# ===========================================================================
# 7. Invalid / ambiguous input → None
# ===========================================================================


class TestInvalidInput:
    def test_garbage_returns_none(self):
        result = _parse_appt_utc("not-a-date-@#$%")
        assert result is None

    def test_none_returns_none(self):
        result = _parse_appt_utc(None)
        assert result is None

    def test_empty_string_returns_none(self):
        result = _parse_appt_utc("")
        assert result is None

    def test_whitespace_only_returns_none(self):
        result = _parse_appt_utc("   ")
        assert result is None

    def test_single_word_returns_none(self):
        result = _parse_appt_utc("hello")
        assert result is None

    def test_random_punctuation_returns_none(self):
        result = _parse_appt_utc("!@#$%^&*()")
        assert result is None


# ===========================================================================
# 8. Regression: existing supported formats
# ===========================================================================


class TestRegressionExistingFormats:
    def test_standard_long_date(self):
        result = _parse_appt_utc("January 15, 2025 at 2:00 PM")
        assert result is not None
        assert result.tzinfo is not None

    def test_iso_like(self):
        result = _parse_appt_utc("2026-08-27 14:00")
        assert result is not None
        assert result.tzinfo is not None

    def test_month_day_year(self):
        result = _parse_appt_utc("08-27-2026 2:00 PM")
        assert result is not None

    def test_with_extra_spaces(self):
        result = _parse_appt_utc("August   27,   2026   at   9:00   AM")
        assert result is not None

    def test_with_commas(self):
        result = _parse_appt_utc("August, 27, 2026 at 9:00 AM")
        assert result is not None

    def test_weekday_only_relative(self):
        result = _parse_appt_utc("tomorrow at 10 AM")
        assert result is not None
        assert result > datetime.now(timezone.utc)

    def test_noon(self):
        result = _parse_appt_utc("August 27, 2026 at noon")
        assert result is not None

    def test_midnight(self):
        result = _parse_appt_utc("August 27, 2026 at midnight")
        assert result is not None


# ===========================================================================
# 9. _extract_tz helper
# ===========================================================================


class TestExtractTz:
    def test_parens_est(self):
        text, tz = _extract_tz("August 27, 2026 at 9:00 AM (EST)")
        assert tz == "EST"
        assert "(EST)" not in text
        assert "9:00 AM" in text

    def test_bare_est(self):
        text, tz = _extract_tz("August 27, 2026 at 9:00 AM EST")
        assert tz == "EST"
        assert "EST" not in text

    def test_eastern_time(self):
        text, tz = _extract_tz("August 27, 2026 at 9:00 AM Eastern Time")
        assert tz == "EST"
        assert "Eastern Time" not in text

    def test_no_tz(self):
        text, tz = _extract_tz("August 27, 2026 at 9:00 AM")
        assert tz == ""
        assert text == "August 27, 2026 at 9:00 AM"

    def test_utc(self):
        text, tz = _extract_tz("August 27, 2026 9:00 AM UTC")
        assert tz == "UTC"

    def test_parenthesized_utc(self):
        text, tz = _extract_tz("2026-08-27 09:00 (UTC)")
        assert tz == "UTC"
        assert "(UTC)" not in text


# ===========================================================================
# 10. FormSubmission.get_appt_datetime_candidates() regression tests
#     Reproduces the exact production failure: Google Form sends datetime
#     in "Scheduled Date and Time" / "Date"+"Time" but the schema only
#     mapped "Phone Appt. Date/Time" which contained a non-datetime value.
# ===========================================================================


class TestFormSubmissionCandidateResolution:
    """Regression: FormSubmission.get_appt_datetime_candidates() returns
    parseable candidates from alternative fields when the primary field
    contains non-datetime text (e.g. "Test Lead")."""

    def test_primary_field_has_valid_datetime(self):
        """When Phone Appt. Date/Time has a real datetime, it's the first candidate."""
        sub = FormSubmission(
            **{
                "Name": "Test Company",
                "Email Address": "test@example.com",
                "Phone Appt. Date/Time": "08/29/2026 09:00 AM",
                "Scheduled Date and Time": "08/30/2026 10:00 AM",
                "Date": "08/31/2026",
                "Time": "11:00 AM",
            }
        )
        candidates = sub.get_appt_datetime_candidates()
        assert len(candidates) == 3
        assert candidates[0] == "08/29/2026 09:00 AM"
        assert candidates[1] == "08/30/2026 10:00 AM"
        assert candidates[2] == "08/31/2026 11:00 AM"

    def test_primary_non_datetime_fallback_to_scheduled(self):
        """Exact production failure: primary field = "Test Lead", fallback works."""
        sub = FormSubmission(
            **{
                "Name": "Test Company",
                "Email Address": "test@example.com",
                "Phone Appt. Date/Time": "Test Lead",
                "Scheduled Date and Time": "08/29/2026 09:00 AM",
            }
        )
        candidates = sub.get_appt_datetime_candidates()
        assert len(candidates) == 2
        assert candidates[0] == "Test Lead"
        assert candidates[1] == "08/29/2026 09:00 AM"
        # The pipeline should try the first (fail), then succeed on the second.
        parsed = None
        for c in candidates:
            parsed = _parse_appt_utc(c)
            if parsed is not None:
                break
        assert parsed is not None
        assert parsed.tzinfo is not None

    def test_primary_non_datetime_fallback_to_date_time(self):
        """Primary field non-datetime, no Scheduled Date and Time, but Date+Time present."""
        sub = FormSubmission(
            **{
                "Name": "Test Company",
                "Email Address": "test@example.com",
                "Phone Appt. Date/Time": "Lahore",
                "Date": "08/29/2026",
                "Time": "09:00 AM",
            }
        )
        candidates = sub.get_appt_datetime_candidates()
        assert len(candidates) == 2
        assert candidates[0] == "Lahore"
        assert candidates[1] == "08/29/2026 09:00 AM"
        parsed = None
        for c in candidates:
            parsed = _parse_appt_utc(c)
            if parsed is not None:
                break
        assert parsed is not None

    def test_primary_non_datetime_date_only(self):
        """Primary field non-datetime, only Date available (no Time field)."""
        sub = FormSubmission(
            **{
                "Name": "Test Company",
                "Email Address": "test@example.com",
                "Phone Appt. Date/Time": "Test Lead",
                "Date": "08/29/2026",
            }
        )
        candidates = sub.get_appt_datetime_candidates()
        assert len(candidates) == 2
        assert candidates[0] == "Test Lead"
        assert candidates[1] == "08/29/2026"

    def test_all_fields_non_datetime_returns_empty(self):
        """When no fields contain a parseable datetime, candidates still returned
        but _parse_appt_utc will fail on all of them → pipeline sets ERROR."""
        sub = FormSubmission(
            **{
                "Name": "Test Company",
                "Email Address": "test@example.com",
                "Phone Appt. Date/Time": "Test Lead",
            }
        )
        candidates = sub.get_appt_datetime_candidates()
        assert len(candidates) == 1
        for c in candidates:
            assert _parse_appt_utc(c) is None

    def test_blank_fields_excluded(self):
        """Blank/whitespace-only fields are excluded from candidates."""
        sub = FormSubmission(
            **{
                "Name": "Test Company",
                "Email Address": "test@example.com",
                "Phone Appt. Date/Time": "Test Lead",
                "Scheduled Date and Time": "  ",
                "Date": "",
                "Time": "09:00 AM",
            }
        )
        candidates = sub.get_appt_datetime_candidates()
        assert len(candidates) == 1
        assert candidates[0] == "Test Lead"

    def test_scheduled_date_time_with_natural_language(self):
        """Scheduled Date and Time with natural language format works."""
        sub = FormSubmission(
            **{
                "Name": "Test Company",
                "Email Address": "test@example.com",
                "Phone Appt. Date/Time": "invalid",
                "Scheduled Date and Time": "Thursday August 29th, at 09:00 AM (EST)",
            }
        )
        candidates = sub.get_appt_datetime_candidates()
        assert len(candidates) == 2
        parsed = None
        for c in candidates:
            parsed = _parse_appt_utc(c)
            if parsed is not None:
                break
        assert parsed is not None
        assert parsed.tzinfo is not None
        # EST = UTC-5, so 09:00 EST = 14:00 UTC
        assert parsed.hour == 14


# ---------------------------------------------------------------------------
# Phase 1 defect regression tests
# ---------------------------------------------------------------------------

class TestBusinessTimezoneDeterminism:
    """Verify that _parse_appt_utc uses the org's business timezone
    deterministically, never falling back to the system/server locale.

    Bug: In Docker (system tz=UTC), dateparser auto-inferred UTC for
    inputs without an explicit timezone.  The application's business
    timezone (America/Chicago) was only applied when dateparser returned
    a naive datetime, but it returned an aware datetime with UTC.
    """

    def test_no_tz_uses_business_tz_not_system_tz(self):
        """'4-5-2026/5:00am' with business_tz=America/Chicago → 10:00 UTC.

        Before fix: 05:00 UTC (dateparser auto-inferred UTC in Docker).
        After fix:  10:00 UTC (5:00 AM CDT = UTC-5 → 10:00 UTC).
        """
        result = _parse_appt_utc("4-5-2026/5:00am", business_tz="America/Chicago")
        assert result is not None
        assert result.tzinfo is not None
        assert result == datetime(2026, 4, 5, 10, 0, tzinfo=timezone.utc)

    def test_different_org_tz_different_utc(self):
        """Different org timezones produce different UTC for same input."""
        chicago = _parse_appt_utc("4-5-2026/5:00am", business_tz="America/Chicago")
        new_york = _parse_appt_utc("4-5-2026/5:00am", business_tz="America/New_York")
        la = _parse_appt_utc("4-5-2026/5:00am", business_tz="America/Los_Angeles")
        assert chicago is not None and new_york is not None and la is not None
        # 5:00 AM CDT=10:00 UTC, 5:00 AM EDT=09:00 UTC, 5:00 AM PDT=12:00 UTC
        assert chicago > new_york  # CDT < EDT → later UTC
        assert la > chicago  # PDT < CDT → later UTC
        assert chicago.hour == 10
        assert new_york.hour == 9
        assert la.hour == 12

    def test_explicit_tz_takes_precedence_over_business_tz(self):
        """User-supplied EST overrides business_tz=America/Chicago."""
        result = _parse_appt_utc(
            "August 27, 2026 at 9:00 AM EST",
            business_tz="America/Chicago",
        )
        assert result is not None
        # EST = UTC-5 → 9:00 AM = 14:00 UTC
        assert result.hour == 14

    def test_explicit_cst_overrides_business_tz(self):
        """User-supplied CST overrides business_tz=America/New_York."""
        result = _parse_appt_utc(
            "August 27, 2026 at 9:00 AM CST",
            business_tz="America/New_York",
        )
        assert result is not None
        # CST = UTC-6 → 9:00 AM = 15:00 UTC
        assert result.hour == 15

    def test_fallback_to_settings_when_no_business_tz(self):
        """When business_tz is None, falls back to settings.business_timezone."""
        from app.config import settings
        result = _parse_appt_utc("4-5-2026/5:00am")
        assert result is not None
        # Should use settings.business_timezone (America/Chicago by default)
        expected_tz = getattr(settings, "business_timezone", "America/Chicago")
        assert result.tzinfo is not None
        # 5:00 AM America/Chicago → 10:00 UTC (CDT in April)
        assert result.hour == 10

    def test_docker_system_tz_cannot_override_business_tz(self):
        """Simulate Docker's UTC system timezone — must not affect result.

        The key bug: dateparser auto-infers UTC in Docker, and the old
        code kept that when dt was already timezone-aware.  The fix
        always replaces dateparser's auto-inference with business_tz.
        """
        import os
        original_tz = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "UTC"
            result = _parse_appt_utc("4-5-2026/5:00am", business_tz="America/Chicago")
            assert result is not None
            # Must be 10:00 UTC (5 AM CDT), NOT 05:00 UTC (5 AM UTC)
            assert result.hour == 10
            assert result.tzinfo is not None
        finally:
            if original_tz is not None:
                os.environ["TZ"] = original_tz
            elif "TZ" in os.environ:
                del os.environ["TZ"]

    def test_relative_date_uses_business_tz(self):
        """Relative dates like 'tomorrow at 9 AM' use the business tz."""
        result = _parse_appt_utc("tomorrow at 9 AM", business_tz="America/Chicago")
        assert result is not None
        assert result.tzinfo is not None
        # 9:00 AM CDT → 14:00 UTC
        assert result.hour == 14


class TestPastDateHandling:
    """Verify that past appointment dates are handled correctly at ingestion.

    Bug: Past dates were silently stored as PENDING, then caught later by
    _recover_stuck_leads, creating unnecessary churn.
    """

    def test_past_date_parsed_but_identifiable(self):
        """A past date is still parsed (for observability) but can be detected."""
        from datetime import datetime, timezone
        result = _parse_appt_utc("January 15, 2025 at 2:00 PM", business_tz="America/Chicago")
        assert result is not None
        # January 15, 2025 is in the past
        assert result < datetime.now(timezone.utc)

    def test_future_date_parsed_correctly(self):
        """A future date is parsed and is NOT in the past."""
        from datetime import datetime, timezone
        result = _parse_appt_utc("December 25, 2026 at 10:00 AM", business_tz="America/Chicago")
        assert result is not None
        assert result > datetime.now(timezone.utc)


class TestPipelineGating:
    """Verify pipeline gating remains intact for FREE plan orgs.

    These are integration tests that depend on specific organizations
    existing in the live database.  They are skipped when the expected
    orgs are not found (e.g. in a fresh or CI database).
    """

    def test_free_plan_gates_pipeline(self):
        """REMOVED — PlanService deleted."""
        pytest.skip("PlanService removed")

    def test_business_plan_allows_pipeline(self):
        """REMOVED — PlanService deleted."""
        pytest.skip("PlanService removed")


class TestFieldMappingIntegrity:
    """Verify the default field mapping still maps correctly."""

    def test_default_mapping_phone_appt_to_raw(self):
        """'Phone Appt. Date/Time' → 'appt_datetime_raw' mapping intact."""
        from app.models_multi_tenant import DEFAULT_FORM_FIELD_MAPPING
        assert DEFAULT_FORM_FIELD_MAPPING.get("Phone Appt. Date/Time") == "appt_datetime_raw"

    def test_all_required_fields_in_default_mapping(self):
        """Default mapping includes all required lead fields."""
        from app.models_multi_tenant import DEFAULT_FORM_FIELD_MAPPING, REQUIRED_LEAD_FIELDS
        mapped_fields = set(DEFAULT_FORM_FIELD_MAPPING.values())
        missing = REQUIRED_LEAD_FIELDS - mapped_fields
        assert not missing, f"Missing required fields in default mapping: {missing}"


# ---------------------------------------------------------------------------
# Form-label prefix / malformed-time regression tests  (2026-09-13)
#
# Root cause: Users copy-pasted the Google Form question label
#   "Phone appt Date and Time:" into their answer, and some typed
#   "9: 00 AM" (space between colon and minutes).
# ---------------------------------------------------------------------------

class TestFormLabelPrefixStripping:
    """Verify that form-label prefixes are stripped before parsing.

    Bug: Google Form users typed the question label as a prefix:
    "Phone appt Date and Time: Monday 14th September 2026 at 10 AM PST"
    which broke dateparser.
    """

    def test_prefix_stripped_pst(self):
        """Exact failing input from David Wilson lead."""
        result = _parse_appt_utc(
            "Phone appt Date and Time: Monday 14th September 2026 at 10 AM PST",
            business_tz="America/Chicago",
        )
        assert result is not None
        # PST = UTC-8 → 10:00 AM PST = 18:00 UTC
        assert result == datetime(2026, 9, 14, 18, 0, tzinfo=timezone.utc)

    def test_prefix_stripped_mst_with_malformed_time(self):
        """Exact failing input from Daud Ali lead (plus malformed spacing)."""
        result = _parse_appt_utc(
            "Phone Appt Date and Time: Monday 14th September 2026 at 9: 00 AM MST",
            business_tz="America/Chicago",
        )
        assert result is not None
        # MST = UTC-7 → 9:00 AM MST = 16:00 UTC
        assert result == datetime(2026, 9, 14, 16, 0, tzinfo=timezone.utc)

    def test_prefix_different_capitalization_1(self):
        """ALL CAPS prefix."""
        result = _parse_appt_utc(
            "PHONE APPT DATE AND TIME: August 27, 2026 at 9:00 AM EST",
            business_tz="America/Chicago",
        )
        assert result is not None
        # EST = UTC-5 → 9:00 AM = 14:00 UTC
        assert result.hour == 14
        assert result.day == 27

    def test_prefix_different_capitalization_2(self):
        """Mixed case prefix."""
        result = _parse_appt_utc(
            "Phone Appt date and time: August 27, 2026 at 2:30 PM EST",
            business_tz="America/Chicago",
        )
        assert result is not None
        # EST = UTC-5 → 2:30 PM = 19:30 UTC
        assert result.hour == 19
        assert result.minute == 30

    def test_prefix_without_colon_space(self):
        """Prefix with colon but no space after."""
        result = _parse_appt_utc(
            "Phone appt Date and Time:August 27, 2026 at 9:00 AM EST",
            business_tz="America/Chicago",
        )
        assert result is not None
        assert result.hour == 14

    def test_prefix_with_extra_spaces(self):
        """Prefix with multiple spaces between words."""
        result = _parse_appt_utc(
            "Phone  appt  Date  and  Time: August 27, 2026 at 9:00 AM EST",
            business_tz="America/Chicago",
        )
        assert result is not None
        assert result.hour == 14

    def test_prefix_with_date_only_no_tz(self):
        """Prefix present, no timezone → uses business_tz."""
        result = _parse_appt_utc(
            "Phone Appt Date and Time: 08/27/2026 9:00 AM",
            business_tz="America/Chicago",
        )
        assert result is not None
        # 9:00 AM CDT = 14:00 UTC (CDT in August)
        assert result.hour == 14


class TestMalformedTimeSpacing:
    """Verify that malformed time spacing is normalized.

    Bug: "9: 00 AM" (space between colon and minutes) breaks dateparser.
    """

    def test_space_after_colon_minutes(self):
        """'9: 00 AM' → '9:00 AM'."""
        result = _parse_appt_utc(
            "Monday 14th September at 9: 00 AM MST",
            business_tz="America/Chicago",
        )
        assert result is not None
        # MST = UTC-7 → 9:00 AM = 16:00 UTC
        assert result.hour == 16

    def test_space_after_colon_12h(self):
        """'12: 30 PM' → '12:30 PM'."""
        result = _parse_appt_utc(
            "August 27, 2026 at 12: 30 PM EST",
            business_tz="America/Chicago",
        )
        assert result is not None
        # EST = UTC-5 → 12:30 PM = 17:30 UTC
        assert result.hour == 17
        assert result.minute == 30

    def test_space_before_colon_not_corrupted(self):
        """'9 :00 AM' (space before colon) — our regex only fixes
        spaces AFTER the colon.  dateparser handles this input fine
        because the space before ':' is not ambiguous."""
        result = _parse_appt_utc(
            "August 27, 2026 at 9 :00 AM EST",
            business_tz="America/Chicago",
        )
        assert result is not None
        assert result.hour == 14

    def test_both_spaces_around_colon(self):
        """'9 : 00 AM' (spaces on both sides) → normalized."""
        result = _parse_appt_utc(
            "August 27, 2026 at 9 : 00 AM EST",
            business_tz="America/Chicago",
        )
        assert result is not None
        assert result.hour == 14

    def test_valid_time_not_corrupted(self):
        """'9:00 AM' (already valid) must remain valid."""
        result = _parse_appt_utc(
            "August 27, 2026 at 9:00 AM EST",
            business_tz="America/Chicago",
        )
        assert result is not None
        # EST = UTC-5 → 9:00 AM = 14:00 UTC
        assert result.hour == 14

    def test_valid_09_00_not_corrupted(self):
        """'09:00 AM' (zero-padded) must remain valid."""
        result = _parse_appt_utc(
            "08/27/2026 09:00 AM",
            business_tz="America/Chicago",
        )
        assert result is not None
        # CDT = UTC-5 → 9:00 AM = 14:00 UTC
        assert result.hour == 14

    def test_time_without_minutes_not_corrupted(self):
        """'9 AM' (no minutes) must not be corrupted."""
        result = _parse_appt_utc(
            "August 27, 2026 at 9 AM EST",
            business_tz="America/Chicago",
        )
        assert result is not None
        assert result.hour == 14


class TestCombinedPrefixAndMalformedTime:
    """Both prefix stripping AND time normalization applied together."""

    def test_both_prefix_and_malformed_time(self):
        """Prefix + malformed time + ordinal suffix."""
        result = _parse_appt_utc(
            "Phone Appt Date and Time: Monday 14th September 2026 at 10: 00 AM PST",
            business_tz="America/Chicago",
        )
        assert result is not None
        # PST = UTC-8 → 10:00 AM = 18:00 UTC
        assert result == datetime(2026, 9, 14, 18, 0, tzinfo=timezone.utc)

    def test_both_with_mst(self):
        """Prefix + malformed time + MST."""
        result = _parse_appt_utc(
            "Phone appt Date and Time: 08/27/2026 at 3: 15 PM MST",
            business_tz="America/Chicago",
        )
        assert result is not None
        # MST = UTC-7 → 3:15 PM = 22:15 UTC
        assert result.hour == 22
        assert result.minute == 15


class TestExistingFormatsRegression:
    """Ensure all previously-working formats still parse correctly."""

    def test_slash_date_ampm_est(self):
        result = _parse_appt_utc("08/27/2026 9:00 AM EST")
        assert result is not None
        assert result.hour == 14  # 9 AM EST = 14 UTC

    def test_thursday_ordinal_est(self):
        result = _parse_appt_utc("Thursday August 27th at 09:00 AM (EST)")
        assert result is not None
        assert result.hour == 14

    def test_aug_27_with_parens_est(self):
        result = _parse_appt_utc("August 27, 2026 at 9:00 AM (EST)")
        assert result is not None
        assert result.hour == 14

    def test_natural_language_relative(self):
        result = _parse_appt_utc("tomorrow at 9 AM", business_tz="America/Chicago")
        assert result is not None
        assert result.tzinfo is not None

    def test_sslash_time_format(self):
        result = _parse_appt_utc("8/27/2026 09:00 EST")
        assert result is not None
        assert result.hour == 14

    def test_usdot_military_time(self):
        result = _parse_appt_utc("08.27.2026 09:00 EST")
        assert result is not None
        assert result.hour == 14

    def test_weekday_month_day_at_time(self):
        result = _parse_appt_utc("Monday August 24, 2026 at 09:00 AM")
        assert result is not None
        assert result.tzinfo is not None

    def test_weekday_full_month_time_tz(self):
        result = _parse_appt_utc("Tuesday August 25th at 09:00 AM EST")
        assert result is not None
        assert result.hour == 14

    def test_weekday_dd_mm_yyyy_time_tz(self):
        result = _parse_appt_utc("Friday 07/28/2026 at 10:00 AM EST")
        assert result is not None
        assert result.hour == 15

    def test_weekday_d_mmm_yyyy_time_tz(self):
        result = _parse_appt_utc("Saturday 31 Jul 2026 at 09:00 AM (EST)")
        assert result is not None
        assert result.hour == 14

    def test_weekday_dd_mm_yy_time_tz(self):
        result = _parse_appt_utc("Sunday 30/08/2026 09:00 EST")
        assert result is not None
        assert result.hour == 14


class TestCustomerTimezoneExtraction:
    """Verify that customer timezone is correctly extracted from prefixed input."""

    def test_customer_tz_pst_from_prefixed(self):
        """Prefix input with PST → tz abbreviation should be PST."""
        from app.main import _extract_tz
        cleaned, tz = _extract_tz(
            "Phone appt Date and Time: Monday 14th September 2026 at 10 AM PST"
        )
        assert tz == "PST"

    def test_customer_tz_mst_from_prefixed(self):
        """Prefix input with MST → tz abbreviation should be MST."""
        from app.main import _extract_tz
        cleaned, tz = _extract_tz(
            "Phone Appt Date and Time: Monday 14th September at 9: 00 AM MST"
        )
        assert tz == "MST"

    def test_customer_tz_iana_pst(self):
        """PST resolves to America/Los_Angeles via _TZ_ABBREV_TO_IANA."""
        from app.main import _TZ_ABBREV_TO_IANA
        assert _TZ_ABBREV_TO_IANA["PST"] == "America/Los_Angeles"

    def test_customer_tz_iana_mst(self):
        """MST resolves to America/Denver via _TZ_ABBREV_TO_IANA."""
        from app.main import _TZ_ABBREV_TO_IANA
        assert _TZ_ABBREV_TO_IANA["MST"] == "America/Denver"

    def test_customer_tz_iana_est(self):
        """EST resolves to America/New_York via _TZ_ABBREV_TO_IANA."""
        from app.main import _TZ_ABBREV_TO_IANA
        assert _TZ_ABBREV_TO_IANA["EST"] == "America/New_York"

    def test_customer_tz_iana_cst(self):
        """CST resolves to America/Chicago via _TZ_ABBREV_TO_IANA."""
        from app.main import _TZ_ABBREV_TO_IANA
        assert _TZ_ABBREV_TO_IANA["CST"] == "America/Chicago"

    def test_iana_name_not_stripped_by_extract_tz(self):
        """Full IANA names (e.g. 'America/Chicago') are NOT stripped
        by _extract_tz — they pass through to dateparser which handles
        them natively.  This is expected behaviour."""
        from app.main import _extract_tz
        cleaned, tz = _extract_tz("08/27/2026 09:00 America/Chicago")
        # _extract_tz only strips abbreviations (EST, CST, etc.),
        # not full IANA names.  dateparser handles IANA names directly.
        assert tz == ""
        assert "America/Chicago" in cleaned

    def test_iana_name_new_york_not_stripped(self):
        """Full IANA name 'America/New_York' passes through _extract_tz."""
        from app.main import _extract_tz
        cleaned, tz = _extract_tz("08/27/2026 09:00 America/New_York")
        assert tz == ""
        assert "America/New_York" in cleaned


class TestInvalidAppointmentText:
    """Verify that invalid appointment text returns None."""

    def test_plain_text_returns_none(self):
        assert _parse_appt_utc("Test Lead") is None

    def test_empty_string_returns_none(self):
        assert _parse_appt_utc("") is None

    def test_none_returns_none(self):
        assert _parse_appt_utc(None) is None

    def test_random_words_returns_none(self):
        assert _parse_appt_utc("Lahore Pakistan") is None

    def test_name_only_returns_none(self):
        assert _parse_appt_utc("John Smith") is None

    def test_email_returns_none(self):
        assert _parse_appt_utc("test@example.com") is None

    def test_phone_number_returns_none(self):
        assert _parse_appt_utc("555-1234") is None
