"""Organization-scoped Google Form field mapping resolver.

Translates raw webhook payloads (keyed by Google Form question labels)
into canonical ``FormSubmission`` fields using per-organization mappings.

When an organization has NO custom mapping, the default mapping
(``DEFAULT_FORM_FIELD_MAPPING``) is used — preserving full backward
compatibility with the existing IT Training form.

Phase 29: Organization-scoped form field mapping.
Phase 34: Deterministic field-label normalization for robust external
form ingestion.  Incoming payload keys are normalized (lowercase,
punctuation-stripped) before matching, so harmless variations in
Google Form question labels (trailing colons, different separators,
capitalisation) no longer cause 422 validation errors.
"""
from __future__ import annotations

import logging
import re
import unicodedata
from typing import Any

from sqlalchemy.orm import Session

from app.models_multi_tenant import (
    DEFAULT_FORM_FIELD_MAPPING,
    REQUIRED_LEAD_FIELDS,
    VALID_LEAD_FIELDS,
    OrgFormFieldMapping,
)

logger = logging.getLogger(__name__)


# ── Deterministic field-label normalization ─────────────────────────────────
#
# Normalizes external Google Form question labels so that harmless
# variations in punctuation, capitalisation, spacing, and common
# abbreviations are matched to the same canonical field.
#
# This is used ONLY for field-name matching — never for mutating
# stored user data.
# ──────────────────────────────────────────────────────────────────────────

# Common appointment-field abbreviations that should normalise to the
# full word.  Only safe, unambiguous abbreviations are included.
_ABBREVIATIONS: dict[str, str] = {
    "appt": "appointment",
}


def normalize_form_label(label: str) -> str:
    """Deterministically normalise a form-label string for field matching.

    Steps:
      1. Unicode NFKD normalisation
      2. Lowercase
      3. Strip leading / trailing whitespace
      4. Expand common abbreviations (appt → appointment)
      5. Replace ``&`` → ``and``
      6. Collapse separators (``/`` ``-`` ``_`` ``.`` ``:``) to space
      7. Collapse repeated whitespace
      8. Strip trailing colons / semicolons

    The result is suitable for use as a dict lookup key.  It must NOT
    be stored or displayed to the user.
    """
    s = unicodedata.normalize("NFKD", label)
    s = s.strip().lower()

    # Expand abbreviations (word-boundary safe)
    for abbr, full in _ABBREVIATIONS.items():
        s = re.sub(rf"\b{abbr}\b", full, s)

    # & → and
    s = s.replace("&", " and ")

    # Collapse common separators to space
    s = re.sub(r"[/\-_.:;]+", " ", s)

    # Collapse repeated whitespace
    s = re.sub(r"\s+", " ", s).strip()

    return s


# ── Canonical alias map for appointment field ──────────────────────────────
#
# Explicitly lists reasonable external variants of the appointment
# datetime field label.  Any label that normalises to one of these
# keys will map to ``appt_datetime_raw``.  This is deliberately
# narrow — we do NOT want unrelated fields to collide.
# ──────────────────────────────────────────────────────────────────────────
APPOINTMENT_FIELD_ALIASES: dict[str, str] = {
    normalize_form_label(k): "appt_datetime_raw"
    for k in [
        "Phone Appt. Date/Time",
        "Phone Appt Date/Time",
        "Phone Appt Date and Time",
        "Phone Appointment Date/Time",
        "Phone Appointment Date and Time",
        "Appointment Date/Time",
        "Appointment Date and Time",
        "Appt Date/Time",
        "Appt Date and Time",
        "Appt. Date/Time",
        "Appt. Date and Time",
        "Scheduled Date and Time",
        "Scheduled Date/Time",
        "Scheduled Appointment Date/Time",
        "Preferred Date",
        "Preferred Date and Time",
        "Date and Time",
        "Date/Time",
    ]
}

# ── Pydantic alias → field name lookup (built at import time) ──────────────
#
# Maps BOTH the original Pydantic alias AND its normalised form to
# the canonical field name.  This ensures that payloads using the
# exact Pydantic alias (e.g. ``"Phone Appt. Date/Time"``) as well
# as normalised variants (e.g. ``"phone appt date time"``) are both
# resolved correctly.
# ──────────────────────────────────────────────────────────────────────────
_PYDANTIC_ALIAS_TO_FIELD: dict[str, str] = {}


def _build_pydantic_alias_lookup() -> dict[str, str]:
    """Build a lookup from normalised Pydantic alias → field name.

    Reads the actual alias values from ``FormSubmission`` at import
    time so there is a single source of truth.
    """
    from app.schemas import FormSubmission
    lookup: dict[str, str] = {}
    for field_name, field_info in FormSubmission.model_fields.items():
        alias = field_info.alias
        if alias:
            # Map the original alias (for exact matches)
            lookup[alias] = field_name
            # Map the normalised form (for fuzzy matches)
            lookup[normalize_form_label(alias)] = field_name
    return lookup


_PYDANTIC_ALIAS_TO_FIELD = _build_pydantic_alias_lookup()

# Simple in-memory cache for field mappings to avoid per-request DB hits.
# Keyed by organization_id string, value is (mapping_dict, timestamp).
# The cache is short-lived and refreshed on mutation.
_mapping_cache: dict[str, tuple[dict[str, str], float]] = {}
_CACHE_TTL_SECONDS = 300  # 5 minutes


def load_field_mapping(db: Session, organization_id) -> dict[str, str]:
    """Load the field mapping for an organization.

    Returns the custom mapping if configured, otherwise the default mapping.
    Results are cached for 5 minutes to avoid per-request DB hits.

    Args:
        db: Database session.
        organization_id: Organization UUID.

    Returns:
        Dict mapping form_label → lead_field (canonical field name).
    """
    import time

    org_key = str(organization_id)
    now = time.time()

    # Check cache
    if org_key in _mapping_cache:
        cached_mapping, cached_at = _mapping_cache[org_key]
        if now - cached_at < _CACHE_TTL_SECONDS:
            return cached_mapping

    # Load from DB
    mappings = (
        db.query(OrgFormFieldMapping)
        .filter(OrgFormFieldMapping.organization_id == organization_id)
        .order_by(OrgFormFieldMapping.display_order)
        .all()
    )

    if not mappings:
        # No custom mapping — use default (backward compatible)
        result = dict(DEFAULT_FORM_FIELD_MAPPING)
    else:
        result = {m.form_label: m.lead_field for m in mappings}

    # Cache the result
    _mapping_cache[org_key] = (result, now)
    return result


def invalidate_mapping_cache(organization_id) -> None:
    """Invalidate the cached mapping for an organization.

    Call this after creating, updating, or deleting mappings.
    """
    org_key = str(organization_id)
    _mapping_cache.pop(org_key, None)


def map_payload_to_fields(
    payload: dict[str, Any],
    field_mapping: dict[str, str],
) -> dict[str, Any]:
    """Translate a raw webhook payload into canonical field names.

    Uses the organization's field mapping to translate form question
    labels (the JSON keys) into canonical Lead model field names.

    **Phase 34**: Both the incoming payload keys and the mapping keys
    are normalised via ``normalize_form_label()`` before lookup, so
    harmless variations in punctuation, capitalisation, spacing, or
    common abbreviations no longer cause 422 validation errors.

    When ``field_mapping`` is empty (legacy / no custom mapping),
    falls back to the Pydantic alias lookup built from
    ``FormSubmission.model_fields`` — also using normalised keys.

    Collision protection: if two different payload keys normalise to
    the same canonical field, a ``ValueError`` is raised rather than
    silently overwriting data.

    Args:
        payload: Raw webhook payload keyed by form question labels.
        field_mapping: Dict mapping form_label → lead_field.
                       An empty dict triggers legacy Pydantic-alias fallback.

    Returns:
        Dict with canonical field names as keys.

    Raises:
        ValueError: If two payload keys normalise to the same field.
    """
    result: dict[str, Any] = {}
    normalised_used: list[str] = []  # tracks labels that were normalised

    if field_mapping:
        # ── Explicit mapping path ────────────────────────────────────────
        # Build a normalised-key → lead_field lookup from the mapping.
        norm_map: dict[str, str] = {
            normalize_form_label(k): v for k, v in field_mapping.items()
        }

        for form_label, value in payload.items():
            norm_key = normalize_form_label(form_label)
            lead_field = norm_map.get(norm_key)
            # Phase 34: If the normalised mapping key didn't match, also
            # check APPOINTMENT_FIELD_ALIASES (and any future alias maps)
            # so that reasonable label variations like
            # "Phone Appt. Date/Time:" resolve even when the DB mapping
            # uses a different abbreviation (e.g. "Phone Appt Date/Time").
            if lead_field is None:
                lead_field = APPOINTMENT_FIELD_ALIASES.get(norm_key)
            if lead_field is not None:
                if lead_field in result:
                    raise ValueError(
                        f"Field collision: labels '{form_label}' and a previous "
                        f"label both normalise to '{lead_field}'. "
                        "Only one value per canonical field is allowed."
                    )
                result[lead_field] = value
                if norm_key != form_label:
                    normalised_used.append(form_label)

        # Diagnostic: warn about unmapped labels
        unmapped = set(payload.keys()) - set(field_mapping.keys())
        # Also check normalised forms for labels that differ from mapping keys
        mapped_norm_keys = {normalize_form_label(k) for k in field_mapping.keys()}
        unmapped_norm = [
            k for k in payload.keys()
            if normalize_form_label(k) not in mapped_norm_keys
        ]
        if unmapped_norm:
            logger.warning(
                "Unmapped form labels ignored: %s (org mapping has %d entries)",
                sorted(unmapped_norm),
                len(field_mapping),
            )
    else:
        # ── Legacy / no-mapping path ─────────────────────────────────────
        # Fall back to the Pydantic alias lookup.
        for form_label, value in payload.items():
            norm_key = normalize_form_label(form_label)
            lead_field = _PYDANTIC_ALIAS_TO_FIELD.get(norm_key)
            if lead_field is not None:
                if lead_field in result:
                    raise ValueError(
                        f"Field collision: labels '{form_label}' and a previous "
                        f"label both normalise to '{lead_field}'. "
                        "Only one value per canonical field is allowed."
                    )
                result[lead_field] = value
                if norm_key != form_label:
                    normalised_used.append(form_label)

    if normalised_used:
        logger.info(
            "field_normalization_applied labels=%s",
            normalised_used,
        )

    return result


def validate_mapping_config(
    mappings: list[dict[str, Any]],
) -> list[str]:
    """Validate a proposed field mapping configuration.

    Checks:
    - All lead_field values are valid canonical field names.
    - Required fields (name, email, appt_datetime_raw) are included.
    - No duplicate lead_field values.
    - form_label is non-empty.

    Args:
        mappings: List of dicts with 'form_label', 'lead_field', and
                  optionally 'is_required' and 'display_order'.

    Returns:
        List of validation error messages. Empty if valid.
    """
    errors: list[str] = []
    seen_fields: set[str] = set()
    seen_labels: set[str] = set()

    for i, m in enumerate(mappings):
        form_label = (m.get("form_label") or "").strip()
        lead_field = (m.get("lead_field") or "").strip()

        if not form_label:
            errors.append(f"Row {i + 1}: form_label is required")
            continue

        if not lead_field:
            errors.append(f"Row {i + 1}: lead_field is required for '{form_label}'")
            continue

        if lead_field not in VALID_LEAD_FIELDS:
            errors.append(
                f"Row {i + 1}: '{lead_field}' is not a valid system field. "
                f"Valid fields: {', '.join(sorted(VALID_LEAD_FIELDS))}"
            )
            continue

        if lead_field in seen_fields:
            errors.append(
                f"Row {i + 1}: duplicate system field '{lead_field}'"
            )
        seen_fields.add(lead_field)

        if form_label in seen_labels:
            errors.append(
                f"Row {i + 1}: duplicate form label '{form_label}'"
            )
        seen_labels.add(form_label)

    # Check required fields are present
    mapped_fields = {m.get("lead_field", "").strip() for m in mappings}
    missing_required = REQUIRED_LEAD_FIELDS - mapped_fields
    if missing_required:
        errors.append(
            f"Missing required system fields: {', '.join(sorted(missing_required))}"
        )

    return errors
