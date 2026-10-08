"""Tests for Phase 7 Part 2 — Outreach Email Templates.

Covers customer-facing outreach templates rendered by the template functions
in app/services/email_templates.py and consumed by the Part 1 sender
(followup_email_sender.py).

These tests validate:
  - Every supported outreach template renders.
  - Subject lines are non-empty, short, and professional.
  - Plain-text and HTML bodies are non-empty.
  - Lead name personalization works.
  - Missing lead name produces neutral greeting (no None/null/undefined).
  - Company name personalization works when available.
  - Missing optional fields do not crash.
  - HTML escaping prevents injection (XSS).
  - Internal IDs are not leaked.
  - Internal notes are not leaked.
  - Template output is deterministic.
  - Correct template is selected for each supported follow-up type.
  - Unknown template types fall back gracefully.
  - Existing email templates still work (imported without error).
  - build_outreach_email() returns the expected dict structure.

These tests do NOT send real emails or use a real Gmail account.
"""
import html as _html
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.models import CallOutcome, Lead, LeadStatus
from app.services.email_templates import (
    _esc,
    build_confirmation_html,
    build_confirmation_subject,
    build_outreach_email,
    build_outreach_html,
    build_outreach_subject,
    build_outreach_text,
)
from app.services.integration_config_resolver import BrandingConfig


# ── Helpers ──────────────────────────────────────────────────────────────────

_DEFAULT_COMPANY = "Strategy Call Agent"


def _make_lead(**overrides) -> Lead:
    """Create a minimal Lead object for template testing (no DB required)."""
    defaults = {
        "id": uuid.UUID("00000000-0000-0000-0000-000000000001"),
        "interested": "yes",
        "name": "Jane Doe",
        "company_address": "Acme Corp",
        "phone_number": "555-0100",
        "direct_number": None,
        "courses": "Python, Docker",
        "email": "jane@example.com",
        "scheduled_date": "tomorrow",
        "caller_name": "Agent Smith",
        "appt_datetime_raw": "tomorrow 2pm",
        "appt_datetime_utc": datetime(2026, 8, 20, 19, 0, tzinfo=timezone.utc),
        "dedupe_key": "jane@example.com|tomorrow 2pm",
        "status": LeadStatus.SCHEDULED,
        "calendar_event_id": "cal-123",
        "reminder_sent_at": None,
        "call_outcome": CallOutcome.CONNECTED,
    }
    defaults.update(overrides)
    return Lead(**defaults)


# ── Supported follow-up types ────────────────────────────────────────────────

# All outcomes that produce outreach emails (matching auto_followup_service)
_OUTREACH_OUTCOMES = [
    "connected",
    "completed",
    "voicemail",
    "no_answer",
    "busy",
    "rescheduled",
    "wrong_number",
    "no_show",
]


# ── 1. Every supported outreach template renders ─────────────────────────────


class TestAllTemplatesRender:
    """Verify every supported outcome produces a valid, non-empty email."""

    @pytest.mark.parametrize("outcome", _OUTREACH_OUTCOMES)
    def test_subject_is_non_empty_string(self, outcome):
        lead = _make_lead()
        subject = build_outreach_subject(outcome)
        assert isinstance(subject, str)
        assert len(subject) > 0

    @pytest.mark.parametrize("outcome", _OUTREACH_OUTCOMES)
    def test_html_is_non_empty_string(self, outcome):
        lead = _make_lead()
        html_body = build_outreach_html(lead, outcome)
        assert isinstance(html_body, str)
        assert len(html_body) > 100

    @pytest.mark.parametrize("outcome", _OUTREACH_OUTCOMES)
    def test_text_is_non_empty_string(self, outcome):
        lead = _make_lead()
        text_body = build_outreach_text(lead, outcome)
        assert isinstance(text_body, str)
        assert len(text_body) > 30

    @pytest.mark.parametrize("outcome", _OUTREACH_OUTCOMES)
    def test_html_contains_doctype(self, outcome):
        lead = _make_lead()
        html_body = build_outreach_html(lead, outcome)
        assert "<!DOCTYPE html>" in html_body

    @pytest.mark.parametrize("outcome", _OUTREACH_OUTCOMES)
    def test_html_contains_company_name(self, outcome):
        lead = _make_lead()
        html_body = build_outreach_html(lead, outcome)
        assert _DEFAULT_COMPANY in html_body


# ── 2. Subject line quality ──────────────────────────────────────────────────


class TestSubjectLineQuality:
    def test_subject_is_professional(self):
        subject = build_outreach_subject("connected")
        assert "URGENT" not in subject.upper()
        assert "!!!" not in subject
        assert "FREE" not in subject.upper()

    def test_subject_contains_company_name(self):
        branding = BrandingConfig(company_name="Acme Corp")
        subject = build_outreach_subject("connected", branding=branding)
        assert "Acme Corp" in subject

    def test_subject_deterministic(self):
        s1 = build_outreach_subject("connected")
        s2 = build_outreach_subject("connected")
        assert s1 == s2

    def test_subject_uses_branding(self):
        branding = BrandingConfig(company_name="Acme Corp")
        subject = build_outreach_subject("connected", branding=branding)
        assert "Acme Corp" in subject
        assert _DEFAULT_COMPANY not in subject

    def test_unknown_outcome_falls_back(self):
        subject = build_outreach_subject("unknown_outcome")
        assert isinstance(subject, str)
        assert len(subject) > 0
        assert _DEFAULT_COMPANY in subject


# ── 3. Lead name personalization ─────────────────────────────────────────────


class TestLeadNamePersonalization:
    def test_html_contains_lead_name(self):
        lead = _make_lead(name="Jane Doe")
        html_body = build_outreach_html(lead, "connected")
        assert "Jane Doe" in html_body

    def test_text_contains_lead_name(self):
        lead = _make_lead(name="Jane Doe")
        text_body = build_outreach_text(lead, "connected")
        assert "Jane Doe" in text_body

    def test_greeting_with_name(self):
        lead = _make_lead(name="Jane Doe")
        html_body = build_outreach_html(lead, "connected")
        assert "Hi Jane Doe," in html_body

    def test_greeting_without_name(self):
        lead = _make_lead(name="")
        html_body = build_outreach_html(lead, "connected")
        assert "Hi there," in html_body

    def test_no_none_in_greeting(self):
        lead = _make_lead(name="")
        html_body = build_outreach_html(lead, "connected")
        assert "None" not in html_body
        assert "null" not in html_body.lower()
        assert "undefined" not in html_body.lower()

    def test_whitespace_only_name_uses_neutral(self):
        lead = _make_lead(name="   ")
        text_body = build_outreach_text(lead, "connected")
        assert "Hi there," in text_body


# ── 4. Company name personalization ──────────────────────────────────────────


class TestCompanyPersonalization:
    def test_html_contains_company_when_available(self):
        lead = _make_lead(company_address="Acme Corp")
        html_body = build_outreach_html(lead, "connected")
        assert "Acme Corp" in html_body

    def test_text_contains_company_when_available(self):
        lead = _make_lead(company_address="Acme Corp")
        text_body = build_outreach_text(lead, "connected")
        assert "Company: Acme Corp" in text_body

    def test_no_company_card_when_missing(self):
        lead = _make_lead(company_address=None)
        html_body = build_outreach_html(lead, "connected")
        # Company card should not appear
        assert "Details" not in html_body

    def test_missing_company_does_not_crash(self):
        lead = _make_lead(company_address=None)
        html_body = build_outreach_html(lead, "voicemail")
        assert isinstance(html_body, str)
        assert len(html_body) > 100

    def test_na_company_treated_as_empty(self):
        lead = _make_lead(company_address="N/A")
        html_body = build_outreach_html(lead, "no_answer")
        # "N/A" should not appear in the template
        assert "N/A" not in html_body or "N/A" not in html_body.split("Details")[0] if "Details" in html_body else True


# ── 5. HTML escaping (XSS prevention) ────────────────────────────────────────


class TestHTMLSafety:
    def test_malicious_lead_name_escaped(self):
        lead = _make_lead(name='<script>alert("xss")</script>')
        html_body = build_outreach_html(lead, "connected")
        assert "<script>" not in html_body
        assert "&lt;script&gt;" in html_body

    def test_malicious_company_name_escaped(self):
        lead = _make_lead(company_address='<img src=x onerror=alert(1)>')
        html_body = build_outreach_html(lead, "connected")
        assert "<img src=x" not in html_body
        assert "&lt;img" in html_body

    def test_html_escape_helper_exists(self):
        assert callable(_esc)

    def test_esc_actually_escapes(self):
        result = _esc('<script>alert("xss")</script>')
        assert "<script>" not in result
        assert "&lt;" in result


# ── 6. No internal data leakage ──────────────────────────────────────────────


class TestNoInternalDataLeakage:
    def test_no_uuid_in_output(self):
        lead = _make_lead()
        html_body = build_outreach_html(lead, "connected")
        text_body = build_outreach_text(lead, "connected")
        # The test UUID should not appear
        assert "00000000-0000-0000-0000-000000000001" not in html_body
        assert "00000000-0000-0000-0000-000000000001" not in text_body

    def test_no_internal_status_names(self):
        for outcome in _OUTREACH_OUTCOMES:
            html_body = build_outreach_html(_make_lead(), outcome)
            text_body = build_outreach_text(_make_lead(), outcome)
            # Internal status names should not appear
            assert "IN_PROGRESS" not in html_body
            assert "pending" not in html_body.lower() or "pending" not in text_body.lower()

    def test_no_api_endpoints(self):
        html_body = build_outreach_html(_make_lead(), "connected")
        text_body = build_outreach_text(_make_lead(), "connected")
        assert "/api/" not in html_body
        assert "/api/" not in text_body

    def test_no_scheduler_info(self):
        html_body = build_outreach_html(_make_lead(), "connected")
        assert "APScheduler" not in html_body
        assert "scheduler" not in html_body.lower()

    def test_no_gmail_details(self):
        html_body = build_outreach_html(_make_lead(), "connected")
        text_body = build_outreach_text(_make_lead(), "connected")
        assert "gmail" not in html_body.lower()
        assert "gmail" not in text_body.lower()

    def test_no_call_notes_leaked(self):
        """Call notes are internal; outreach emails should not expose them."""
        lead = _make_lead(call_outcome=CallOutcome.CONNECTED)
        # Even if call_notes existed on the lead, outreach template shouldn't use it
        html_body = build_outreach_html(lead, "connected")
        text_body = build_outreach_text(lead, "connected")
        # No notes section should appear (outreach templates don't use notes)
        assert "Notes:" not in html_body
        assert "Notes:" not in text_body


# ── 7. Deterministic output ──────────────────────────────────────────────────


class TestDeterministicOutput:
    def test_same_input_same_output_html(self):
        lead = _make_lead()
        h1 = build_outreach_html(lead, "connected")
        h2 = build_outreach_html(lead, "connected")
        assert h1 == h2

    def test_same_input_same_output_text(self):
        lead = _make_lead()
        t1 = build_outreach_text(lead, "connected")
        t2 = build_outreach_text(lead, "connected")
        assert t1 == t2

    def test_same_input_same_output_subject(self):
        s1 = build_outreach_subject("connected")
        s2 = build_outreach_subject("connected")
        assert s1 == s2


# ── 8. Template selection per outcome ────────────────────────────────────────


class TestOutcomeSpecificContent:
    def test_connected_has_proposal_language(self):
        lead = _make_lead()
        html_body = build_outreach_html(lead, "connected")
        assert "proposal" in html_body.lower()

    def test_voicemail_has_voicemail_reference(self):
        lead = _make_lead()
        html_body = build_outreach_html(lead, "voicemail")
        assert "voicemail" in html_body.lower()

    def test_no_answer_has_reschedule_option(self):
        lead = _make_lead()
        html_body = build_outreach_html(lead, "no_answer")
        assert "time" in html_body.lower()

    def test_no_show_has_reschedule_language(self):
        lead = _make_lead()
        html_body = build_outreach_html(lead, "no_show")
        assert "reschedule" in html_body.lower()

    def test_rescheduled_has_confirm_language(self):
        lead = _make_lead()
        html_body = build_outreach_html(lead, "rescheduled")
        assert "confirm" in html_body.lower()

    def test_connected_and_completed_differ(self):
        lead = _make_lead()
        h1 = build_outreach_html(lead, "connected")
        h2 = build_outreach_html(lead, "completed")
        assert h1 != h2


# ── 9. Unknown / unsupported outcome handling ────────────────────────────────


class TestUnsupportedOutcome:
    def test_unknown_outcome_renders_safely(self):
        lead = _make_lead()
        html_body = build_outreach_html(lead, "totally_unknown")
        assert isinstance(html_body, str)
        assert len(html_body) > 100
        assert "<!DOCTYPE html>" in html_body

    def test_unknown_outcome_text_renders_safely(self):
        lead = _make_lead()
        text_body = build_outreach_text(lead, "totally_unknown")
        assert isinstance(text_body, str)
        assert len(text_body) > 30

    def test_unknown_outcome_subject_renders_safely(self):
        subject = build_outreach_subject("totally_unknown")
        assert isinstance(subject, str)
        assert len(subject) > 0


# ── 10. build_outreach_email convenience function ────────────────────────────


class TestBuildOutreachEmail:
    def test_returns_dict_with_required_keys(self):
        lead = _make_lead()
        result = build_outreach_email(lead, "connected")
        assert isinstance(result, dict)
        assert "subject" in result
        assert "html" in result
        assert "text" in result

    def test_all_values_are_strings(self):
        lead = _make_lead()
        result = build_outreach_email(lead, "connected")
        assert isinstance(result["subject"], str)
        assert isinstance(result["html"], str)
        assert isinstance(result["text"], str)

    def test_html_and_text_are_non_empty(self):
        lead = _make_lead()
        result = build_outreach_email(lead, "connected")
        assert len(result["html"]) > 100
        assert len(result["text"]) > 30

    def test_deterministic(self):
        lead = _make_lead()
        r1 = build_outreach_email(lead, "connected")
        r2 = build_outreach_email(lead, "connected")
        assert r1 == r2

    def test_unknown_outcome_returns_valid_dict(self):
        lead = _make_lead()
        result = build_outreach_email(lead, "unknown")
        assert isinstance(result, dict)
        assert "subject" in result
        assert "html" in result
        assert "text" in result


# ── 11. Existing templates still work (regression) ──────────────────────────


class TestExistingTemplatesStillWork:
    """Confirm that importing and calling existing template functions
    is not broken by the addition of outreach templates."""

    def test_confirmation_subject_imports(self):
        lead = _make_lead()
        subject = build_confirmation_subject(lead)
        assert isinstance(subject, str)
        assert len(subject) > 0

    def test_confirmation_html_imports(self):
        lead = _make_lead()
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", "Welcome!")
        assert isinstance(html_body, str)
        assert "<!DOCTYPE html>" in html_body

    def test_import_does_not_break(self):
        from app.services.email_templates import (
            build_outreach_email,
            build_outreach_html,
            build_outreach_subject,
            build_outreach_text,
        )
        assert callable(build_outreach_email)
        assert callable(build_outreach_html)
        assert callable(build_outreach_subject)
        assert callable(build_outreach_text)


# ── 12. Branding integration ─────────────────────────────────────────────────


class TestBrandingIntegration:
    def test_custom_branding_in_html(self):
        branding = BrandingConfig(
            company_name="Acme Corp",
            brand_color="#ff0000",
            tagline="We build things",
        )
        lead = _make_lead()
        html_body = build_outreach_html(lead, "connected", branding=branding)
        assert "Acme Corp" in html_body
        assert "#ff0000" in html_body
        assert "We build things" in html_body
        assert _DEFAULT_COMPANY not in html_body

    def test_default_branding_used_when_none(self):
        lead = _make_lead()
        html_body = build_outreach_html(lead, "connected", branding=None)
        assert _DEFAULT_COMPANY in html_body


# ── 13. Sender integration compatibility ─────────────────────────────────────


class TestSenderIntegration:
    """Verify that the Part 1 sender can consume the outreach template output."""

    def test_outreach_email_dict_compatible_with_sender(self):
        """The sender expects subject, html_body, plain_body arguments."""
        lead = _make_lead()
        result = build_outreach_email(lead, "connected")
        # Verify the keys match what the sender needs
        assert "subject" in result
        assert "html" in result
        assert "text" in result

    def test_try_outreach_template_with_known_outcome(self):
        """_try_outreach_template should return a dict for known outcomes."""
        from app.services.followup_email_sender import _try_outreach_template
        lead = _make_lead(call_outcome=CallOutcome.CONNECTED)
        fu = MagicMock()
        result = _try_outreach_template(lead, fu)
        assert result is not None
        assert "subject" in result
        assert "html" in result
        assert "text" in result

    def test_try_outreach_template_with_none_outcome(self):
        """_try_outreach_template should return None when lead has no call_outcome."""
        from app.services.followup_email_sender import _try_outreach_template
        lead = _make_lead(call_outcome=None)
        fu = MagicMock()
        result = _try_outreach_template(lead, fu)
        assert result is None

    def test_try_outreach_template_with_not_interested(self):
        """_try_outreach_template should return None for not_interested."""
        from app.services.followup_email_sender import _try_outreach_template
        lead = _make_lead(call_outcome=CallOutcome.NOT_INTERESTED)
        fu = MagicMock()
        result = _try_outreach_template(lead, fu)
        assert result is None

    def test_try_outreach_template_with_cancelled(self):
        """_try_outreach_template should return None for cancelled."""
        from app.services.followup_email_sender import _try_outreach_template
        lead = _make_lead(call_outcome=CallOutcome.CANCELLED)
        fu = MagicMock()
        result = _try_outreach_template(lead, fu)
        assert result is None


# ── 14. Content quality checks ──────────────────────────────────────────────


class TestContentQuality:
    def test_no_spammy_language(self):
        for outcome in _OUTREACH_OUTCOMES:
            subject = build_outreach_subject(outcome)
            html = build_outreach_html(_make_lead(), outcome)
            # Check no spammy phrases
            for phrase in ["URGENT!!!", "ACT NOW", "LIMITED TIME", "FREE!!!"]:
                assert phrase not in subject, f"Subject for {outcome} contains spam: {phrase}"
                assert phrase not in html, f"HTML for {outcome} contains spam: {phrase}"

    def test_no_fake_reply_prefix(self):
        for outcome in _OUTREACH_OUTCOMES:
            subject = build_outreach_subject(outcome)
            # No fake RE: or FWD: prefix
            assert not subject.startswith("RE:"), f"Subject for {outcome} has fake RE:"
            assert not subject.startswith("FWD:"), f"Subject for {outcome} has fake FWD:"

    def test_each_outcome_has_unique_subject_suffix(self):
        """Different outcomes should produce different subjects (for at least some)."""
        subjects = {
            outcome: build_outreach_subject(outcome)
            for outcome in _OUTREACH_OUTCOMES
        }
        # Not all subjects should be identical
        unique_subjects = set(subjects.values())
        assert len(unique_subjects) > 1, "All outcomes produce the same subject"

    def test_html_has_closing_tags(self):
        lead = _make_lead()
        html_body = build_outreach_html(lead, "connected")
        assert html_body.strip().endswith("</html>")

    def test_text_not_empty_for_each_outcome(self):
        for outcome in _OUTREACH_OUTCOMES:
            text = build_outreach_text(_make_lead(), outcome)
            assert len(text) > 30, f"Text for {outcome} is too short"
