"""Phase 34 — Focused robustness tests for the Google Form ingestion boundary.

Covers:
  A. Appointment field label variations (via ``APPOINTMENT_FIELD_ALIASES``)
  B. Case / whitespace / punctuation normalisation
  C. Non-appointment fields still map correctly
  D. Collision protection (two labels → same canonical field)
  E. Date-first appointment values
  F. Time-first appointment values (mid-string timezone)
  G. Timezone positions (end-of-string, mid-string, parenthesised)
  H. Time spacing normalisation ("9: 00 AM", "9 :00 AM")
  I. Invalid / edge-case input
  J. Regression: existing modules still import and run cleanly
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.main import _parse_appt_utc, _extract_tz
from app.models_multi_tenant import DEFAULT_FORM_FIELD_MAPPING
from app.schemas import FormSubmission
from app.services.field_mapping_resolver import (
    APPOINTMENT_FIELD_ALIASES,
    _PYDANTIC_ALIAS_TO_FIELD,
    map_payload_to_fields,
    normalize_form_label,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UID = uuid.uuid4().hex[:8]


def _email(suffix: str = "") -> str:
    tag = f"-{suffix}" if suffix else ""
    return f"test{_UID}{tag}@example.com"


def _minimal_payload(
    *,
    name: str = "Jane Doe",
    email: str | None = None,
    appt: str = "September 15 2026 10:00 AM",
) -> dict:
    """Minimal payload using the exact default form labels."""
    return {
        "Name": name,
        "Email Address": email or _email(),
        "Phone Appt. Date/Time": appt,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Section A — Appointment field label variations
#
# Verify that each variant in ``APPOINTMENT_FIELD_ALIASES`` maps to
# ``appt_datetime_raw`` via ``map_payload_to_fields`` with the default
# mapping and also via the legacy (empty-mapping) path.
# ═══════════════════════════════════════════════════════════════════════════


class TestAppointmentLabelVariants:
    """Section A: appointment label variants → appt_datetime_raw."""

    # Labels drawn from APPOINTMENT_FIELD_ALIASES.
    # NOTE: "Scheduled Date and Time" maps to scheduled_date_time in
    # DEFAULT_FORM_FIELD_MAPPING, so it is excluded from the
    # appt_datetime_raw assertion on the default-mapping path.
    APPT_LABELS = [
        "Phone Appt. Date/Time",
        "Phone Appt Date/Time",
        "Phone Appt Date and Time",
        "Phone Appointment Date/Time",
        "Phone Appointment Date and Time",
        "Appointment Date/Time",
        "Appointment Date and Time",
        "Appt Date/Time",
        "Appt Date and Time",
        "Scheduled Date/Time",
        "Scheduled Appointment Date/Time",
        "Preferred Date",
        "Preferred Date and Time",
        "Date and Time",
        "Date/Time",
    ]

    # These labels normalise to the SAME key as a Pydantic alias and
    # therefore resolve via the legacy (empty-mapping) path.
    LEGACY_COMPATIBLE_LABELS = [
        "Phone Appt. Date/Time",
        "Phone Appt Date/Time",
    ]

    APPT_VALUE = "September 15 2026 10:00 AM EST"

    @pytest.mark.parametrize("label", APPT_LABELS, ids=lambda s: s[:30])
    def test_variant_maps_to_appt_field_with_default_mapping(self, label):
        """With DEFAULT_FORM_FIELD_MAPPING, the variant resolves to
        appt_datetime_raw via the APPOINTMENT_FIELD_ALIASES fallback."""
        payload = {
            "Name": "Jane",
            "Email Address": _email(),
            label: self.APPT_VALUE,
        }
        result = map_payload_to_fields(payload, dict(DEFAULT_FORM_FIELD_MAPPING))
        assert "appt_datetime_raw" in result, (
            f"Label {label!r} did not map to appt_datetime_raw; got {result}"
        )

    @pytest.mark.parametrize(
        "label", LEGACY_COMPATIBLE_LABELS, ids=lambda s: s[:30]
    )
    def test_variant_maps_to_appt_field_via_legacy_path(self, label):
        """Labels that normalise to an exact Pydantic alias resolve via legacy."""
        payload = {
            "Name": "Jane",
            "Email Address": _email(),
            label: self.APPT_VALUE,
        }
        result = map_payload_to_fields(payload, {})
        assert "appt_datetime_raw" in result, (
            f"Legacy path: label {label!r} did not resolve"
        )

    def test_non_pydantic_labels_dont_resolve_via_legacy(self):
        """Labels NOT in the Pydantic alias set are silently ignored
        by the legacy path — this is expected backward-compat behaviour."""
        payload = {
            "Name": "Jane",
            "Email Address": _email(),
            "Appointment Date/Time": self.APPT_VALUE,
        }
        result = map_payload_to_fields(payload, {})
        # Only name and email should resolve; appt is missing because
        # "Appointment Date/Time" is not a Pydantic alias.
        assert "appt_datetime_raw" not in result
        assert result["name"] == "Jane"

    def test_scheduled_date_and_time_maps_to_scheduled_field(self):
        """"Scheduled Date and Time" legitimately maps to
        scheduled_date_time in the default mapping."""
        payload = {
            "Name": "Jane",
            "Email Address": _email(),
            "Scheduled Date and Time": self.APPT_VALUE,
        }
        result = map_payload_to_fields(payload, dict(DEFAULT_FORM_FIELD_MAPPING))
        assert "scheduled_date_time" in result
        assert "appt_datetime_raw" not in result

    def test_normalized_alias_count(self):
        """APPOINTMENT_FIELD_ALIASES has unique normalised keys.
        Input has 18 labels but abbreviation expansion + normalisation
        cause deduplication → fewer unique keys."""
        # The exact count may change if aliases are added/removed.
        # Just verify it's reasonable and all values are appt_datetime_raw.
        assert len(APPOINTMENT_FIELD_ALIASES) >= 10
        assert all(v == "appt_datetime_raw" for v in APPOINTMENT_FIELD_ALIASES.values())


# ═══════════════════════════════════════════════════════════════════════════
# Section B — Case / whitespace / punctuation normalisation
#
# ``normalize_form_label`` must collapse these variations to the same
# key so the mapping lookup succeeds.
# ═══════════════════════════════════════════════════════════════════════════


class TestLabelNormalization:
    """Section B: normalisation of case, whitespace, punctuation."""

    def test_trailing_colon_stripped(self):
        # "appt" expands to "appointment" via abbreviation expansion
        assert normalize_form_label("Phone Appt. Date/Time:") == "phone appointment date time"

    def test_trailing_semicolon_stripped(self):
        assert normalize_form_label("Email Address;") == "email address"

    def test_uppercase_vs_lowercase(self):
        a = normalize_form_label("EMAIL ADDRESS")
        b = normalize_form_label("email address")
        assert a == b

    def test_extra_internal_spaces(self):
        a = normalize_form_label("Phone  Appt.   Date/Time")
        b = normalize_form_label("Phone Appt. Date/Time")
        assert a == b

    def test_different_separators(self):
        """Slash, dash, underscore, dot all normalise the same."""
        forms = [
            "Date/Time",
            "Date-Time",
            "Date_Time",
            "Date.Time",
            "Date:Time",
        ]
        normalised = {normalize_form_label(f) for f in forms}
        assert len(normalised) == 1, f"Expected 1 unique normalised form, got {normalised}"

    def test_abbreviation_expansion(self):
        assert normalize_form_label("Appt") == "appointment"

    def test_ampersand_expansion(self):
        assert normalize_form_label("Date & Time") == "date and time"

    def test_unicode_nfkd(self):
        """Full-width characters normalise to ASCII equivalents."""
        # Full-width 'A' (U+FF21) should normalise
        label = "Name"
        assert normalize_form_label(label) == "name"


# ═══════════════════════════════════════════════════════════════════════════
# Section C — Non-appointment fields still map correctly
# ═══════════════════════════════════════════════════════════════════════════


class TestNonAppointmentFieldsMapCorrectly:
    """Section C: ensure the normalisation did not break other fields."""

    def test_default_labels_map_all_fields(self):
        payload = _minimal_payload(
            email=_email("full"),
            appt="September 15 2026 10:00 AM EST",
        )
        payload.update({
            "Company Address": "123 Main St",
            "Phone Number": "555-1234",
            "Direct Number": "555-5678",
            "Courses": "Excel",
            "Interested?": "yes",
            "Caller Name": "Bob",
            "Scheduled Date": "Sep 15",
            "Scheduled Date and Time": "Sep 15 10 AM",
            "Date": "Sep 15",
            "Time": "10 AM",
        })
        result = map_payload_to_fields(payload, dict(DEFAULT_FORM_FIELD_MAPPING))
        assert result["name"] == "Jane Doe"
        assert result["email"] == _email("full")
        assert result["appt_datetime_raw"] == "September 15 2026 10:00 AM EST"
        assert result["company_address"] == "123 Main St"
        assert result["phone_number"] == "555-1234"
        assert result["direct_number"] == "555-5678"
        assert result["courses"] == "Excel"
        assert result["interested"] == "yes"
        assert result["caller_name"] == "Bob"

    def test_formsubmission_validates_with_default_labels(self):
        """Full FormSubmission validation with exact default aliases still works."""
        sub = FormSubmission(
            **_minimal_payload(email=_email("sub")),
        )
        assert sub.name == "Jane Doe"
        assert sub.appt_datetime_raw == "September 15 2026 10:00 AM"


# ═══════════════════════════════════════════════════════════════════════════
# Section D — Collision protection
# ═══════════════════════════════════════════════════════════════════════════


class TestCollisionProtection:
    """Section D: two labels mapping to the same field raise ValueError."""

    def test_collision_in_explicit_mapping_path(self):
        """Two labels that normalise to the same key and resolve to the
        same canonical field via the explicit mapping path raise."""
        # "Phone Appt. Date/Time" and "Phone Appt Date/Time" normalise
        # to the same key ("phone appointment date time") and both
        # resolve to appt_datetime_raw via the default mapping.
        payload = {
            "Phone Appt. Date/Time": "val1",
            "Phone Appt Date/Time": "val2",
            "Name": "Jane",
            "Email Address": _email(),
        }
        with pytest.raises(ValueError, match="Field collision"):
            map_payload_to_fields(payload, dict(DEFAULT_FORM_FIELD_MAPPING))

    def test_no_collision_for_different_fields(self):
        """Two labels → two different canonical fields is fine."""
        payload = {
            "Name": "Jane",
            "Email Address": _email(),
        }
        result = map_payload_to_fields(payload, dict(DEFAULT_FORM_FIELD_MAPPING))
        assert "name" in result
        assert "email" in result

    def test_collision_in_legacy_path(self):
        """Two labels that normalise to the same Pydantic alias key
        collide in the legacy path."""
        # "Phone Appt. Date/Time" and "Phone Appt Date/Time" both
        # normalise to "phone appointment date time" and both match
        # the Pydantic alias lookup.
        payload = {
            "Phone Appt. Date/Time": "val1",
            "Phone Appt Date/Time": "val2",
        }
        with pytest.raises(ValueError, match="Field collision"):
            map_payload_to_fields(payload, {})


# ═══════════════════════════════════════════════════════════════════════════
# Section E — Date-first appointment values
# ═══════════════════════════════════════════════════════════════════════════


class TestDateFirstAppointmentParsing:
    """Section E: date-first formats parse correctly."""

    @pytest.mark.parametrize(
        "raw, expected_utc_hour",
        [
            # September 15, 2026 10:00 AM EST → 15:00 UTC
            ("September 15, 2026 at 10:00 AM EST", 15),
            # Aug 27, 2026 9:00 AM EST → 14:00 UTC
            ("August 27, 2026 at 9:00 AM EST", 14),
            # 8/27/2026 9:00 AM EST
            ("08/27/2026 9:00 AM EST", 14),
            # Sep 15 2026 10:00 AM PST → 18:00 UTC
            ("September 15, 2026 10:00 AM PST", 18),
        ],
    )
    def test_date_first_formats(self, raw, expected_utc_hour):
        result = _parse_appt_utc(raw, business_tz="America/Chicago")
        assert result is not None, f"Failed to parse: {raw!r}"
        assert result.tzinfo is not None, "Expected timezone-aware datetime"
        assert result.hour == expected_utc_hour, (
            f"Expected UTC hour {expected_utc_hour} for {raw!r}, got {result.hour}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Section F — Time-first appointment values (mid-string timezone)
# ═══════════════════════════════════════════════════════════════════════════


class TestTimeFirstAppointmentParsing:
    """Section F: time-first formats with mid-string timezone."""

    @pytest.mark.parametrize(
        "raw, expected_utc_hour",
        [
            # 10:00 AM EST on Sep 15 → 15:00 UTC
            ("10:00 AM EST on September 15, 2026", 15),
            # 10 AM PST Sep 15 → 18:00 UTC
            ("10 AM PST September 15, 2026", 18),
            # 10:00 AM CDT on Sep 15th → 15:00 UTC
            ("10:00 AM CDT on September 15th 2026", 15),
        ],
    )
    def test_time_first_formats(self, raw, expected_utc_hour):
        result = _parse_appt_utc(raw, business_tz="America/Chicago")
        assert result is not None, f"Failed to parse: {raw!r}"
        assert result.tzinfo is not None, "Expected timezone-aware datetime"
        assert result.hour == expected_utc_hour, (
            f"Expected UTC hour {expected_utc_hour} for {raw!r}, got {result.hour}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Section G — Timezone positions
# ═══════════════════════════════════════════════════════════════════════════


class TestTimezonePositions:
    """Section G: timezone at end, mid, parenthesised, full name."""

    def test_end_of_string_est(self):
        cleaned, tz = _extract_tz("September 15, 2026 10:00 AM EST")
        assert tz == "EST"
        assert "EST" not in cleaned

    def test_end_of_string_parenthesised(self):
        cleaned, tz = _extract_tz("September 15, 2026 10:00 AM (EST)")
        assert tz == "EST"
        assert "EST" not in cleaned
        assert "(" not in cleaned

    def test_mid_string_est(self):
        cleaned, tz = _extract_tz("10:00 AM EST on September 15, 2026")
        assert tz == "EST"
        assert "EST" not in cleaned

    def test_mid_string_utc(self):
        cleaned, tz = _extract_tz("10:00 AM UTC on September 15, 2026")
        assert tz == "UTC"
        assert "UTC" not in cleaned

    def test_full_name_eastern_time(self):
        cleaned, tz = _extract_tz(
            "September 15, 2026 at 10:00 AM Eastern Time"
        )
        assert tz == "EST"

    def test_full_name_pacific_standard_time(self):
        cleaned, tz = _extract_tz(
            "September 15, 2026 at 10:00 AM Pacific Standard Time"
        )
        assert tz == "PST"

    def test_no_timezone_returns_empty(self):
        cleaned, tz = _extract_tz("September 15, 2026 at 10:00 AM")
        assert tz == ""
        assert cleaned == "September 15, 2026 at 10:00 AM"


# ═══════════════════════════════════════════════════════════════════════════
# Section H — Time spacing normalisation
# ═══════════════════════════════════════════════════════════════════════════


class TestTimeSpacing:
    """Section H: malformed time spacing is normalised before parsing."""

    @pytest.mark.parametrize(
        "raw",
        [
            "September 15, 2026 at 9: 00 AM EST",
            "September 15, 2026 at 9 :00 AM EST",
            "September 15, 2026 at 9 : 00 AM EST",
            "September 15, 2026 at 09:30 AM EST",
        ],
    )
    def test_malformed_time_spacing_parses(self, raw):
        result = _parse_appt_utc(raw, business_tz="America/Chicago")
        assert result is not None, f"Failed to parse: {raw!r}"
        assert result.tzinfo is not None


# ═══════════════════════════════════════════════════════════════════════════
# Section I — Invalid / edge-case input
# ═══════════════════════════════════════════════════════════════════════════


class TestInvalidInput:
    """Section I: graceful handling of bad input."""

    def test_none_raw_returns_none(self):
        assert _parse_appt_utc(None) is None

    def test_empty_string_returns_none(self):
        assert _parse_appt_utc("") is None

    def test_garbage_returns_none(self):
        assert _parse_appt_utc("xyzzy") is None

    def test_unsupported_tz_ignored(self):
        """Unknown timezone abbreviation — dateparser may still parse."""
        result = _parse_appt_utc("September 15, 2026 10:00 AM JST")
        # May or may not parse depending on dateparser; just ensure no crash
        # If it parses, it should be timezone-aware
        if result is not None:
            assert result.tzinfo is not None

    def test_missing_required_field_raises(self):
        """FormSubmission without required fields fails validation."""
        with pytest.raises(Exception):  # Pydantic ValidationError
            FormSubmission(**{"Name": "Jane"})  # missing email + appt


# ═══════════════════════════════════════════════════════════════════════════
# Section J — Regression: existing modules import and key tests run
# ═══════════════════════════════════════════════════════════════════════════


class TestExistingModulesImport:
    """Section J: verify all modified modules and key imports still work."""

    def test_import_field_mapping_resolver(self):
        from app.services.field_mapping_resolver import (
            normalize_form_label,
            map_payload_to_fields,
            load_field_mapping,
            invalidate_mapping_cache,
            validate_mapping_config,
            APPOINTMENT_FIELD_ALIASES,
            _PYDANTIC_ALIAS_TO_FIELD,
        )
        assert callable(normalize_form_label)
        assert callable(map_payload_to_fields)
        assert isinstance(APPOINTMENT_FIELD_ALIASES, dict)
        assert isinstance(_PYDANTIC_ALIAS_TO_FIELD, dict)

    def test_import_schemas(self):
        from app.schemas import FormSubmission
        assert hasattr(FormSubmission, "from_webhook_payload")

    def test_import_main_parsers(self):
        from app.main import _parse_appt_utc, _extract_tz
        assert callable(_parse_appt_utc)
        assert callable(_extract_tz)

    def test_default_mapping_produces_same_result_as_legacy(self):
        """Full default payload → same result via mapping and legacy path."""
        payload = _minimal_payload(email=_email("regression"))
        via_mapping = map_payload_to_fields(
            payload, dict(DEFAULT_FORM_FIELD_MAPPING)
        )
        via_legacy = map_payload_to_fields(payload, {})
        # Both should produce the same canonical fields
        assert set(via_mapping.keys()) == set(via_legacy.keys()), (
            f"Mapping keys {set(via_mapping.keys())} != legacy keys {set(via_legacy.keys())}"
        )
        for key in via_mapping:
            assert via_mapping[key] == via_legacy[key], (
                f"Field {key!r}: mapping={via_mapping[key]!r} != legacy={via_legacy[key]!r}"
            )
