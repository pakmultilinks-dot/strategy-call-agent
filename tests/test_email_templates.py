"""Tests for email templates (PHASE 3G + 6D).

Covers confirmation and reminder emails: subject lines, HTML generation,
plain-text fallback, Meet link presence, AI HTML injection escaping,
footer content, sender identity, and security properties.

Phase 6D: Tests verify per-organization branding via BrandingConfig.
Default branding uses "Strategy Call Agent" when no org branding is set.

These tests do NOT send real emails or use a real Gmail account.
"""
import html
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from app.models import Lead, LeadStatus
from app.services.email_templates import (
    _esc,
    build_confirmation_html,
    build_confirmation_subject,
    build_confirmation_text,
    build_reminder_html,
    build_reminder_subject,
    build_reminder_text,
)
from app.services.integration_config_resolver import BrandingConfig


# ── Default branding (when no BrandingConfig is passed) ──────────────────────

_DEFAULT_COMPANY = "Strategy Call Agent"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_lead(**overrides) -> Lead:
    """Create a minimal Lead object for template testing (no DB required)."""
    defaults = {
        "id": "00000000-0000-0000-0000-000000000001",
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
    }
    defaults.update(overrides)
    return Lead(**defaults)


# ── 1. Confirmation subject ──────────────────────────────────────────────────


class TestConfirmationSubject:
    def test_subject_is_deterministic(self):
        lead = _make_lead()
        s1 = build_confirmation_subject(lead)
        s2 = build_confirmation_subject(lead)
        assert s1 == s2

    def test_subject_contains_company_name(self):
        lead = _make_lead()
        subject = build_confirmation_subject(lead)
        assert _DEFAULT_COMPANY in subject

    def test_subject_is_fixed_string(self):
        lead = _make_lead()
        subject = build_confirmation_subject(lead)
        assert subject == "Your Strategy Call is Confirmed — Strategy Call Agent"

    def test_subject_uses_branding(self):
        lead = _make_lead()
        branding = BrandingConfig(company_name="Acme Corp")
        subject = build_confirmation_subject(lead, branding=branding)
        assert subject == "Your Strategy Call is Confirmed — Acme Corp"


# ── 2. Confirmation HTML generation ──────────────────────────────────────────


class TestConfirmationHTML:
    def test_html_is_valid_string(self):
        lead = _make_lead()
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", "Welcome!")
        assert isinstance(html_body, str)
        assert len(html_body) > 100

    def test_html_containsDOCTYPE(self):
        lead = _make_lead()
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", "Welcome!")
        assert "<!DOCTYPE html>" in html_body

    def test_html_contains_company_name(self):
        lead = _make_lead()
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", "Welcome!")
        assert _DEFAULT_COMPANY in html_body

    def test_html_uses_branding(self):
        lead = _make_lead()
        branding = BrandingConfig(company_name="Acme Corp")
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", "Welcome!", branding=branding)
        assert "Acme Corp" in html_body
        assert _DEFAULT_COMPANY not in html_body

    def test_html_contains_prospect_name(self):
        lead = _make_lead(name="Jane Doe")
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", "Welcome!")
        assert "Jane Doe" in html_body

    def test_html_contains_ai_paragraph(self):
        lead = _make_lead()
        ai_text = "We are excited to discuss your Python journey."
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", ai_text)
        assert ai_text in html_body

    def test_html_contains_call_details(self):
        lead = _make_lead()
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", "Hi there")
        assert "Call Details" in html_body
        assert "Acme Corp" in html_body
        assert "Python, Docker" in html_body


# ── 3. Confirmation plain-text generation ────────────────────────────────────


class TestConfirmationText:
    def test_text_contains_prospect_name(self):
        lead = _make_lead(name="Jane Doe")
        text = build_confirmation_text(lead, "https://meet.google.com/abc", "Welcome!")
        assert "Jane Doe" in text

    def test_text_contains_ai_paragraph(self):
        lead = _make_lead()
        ai_text = "Looking forward to our chat about Docker."
        text = build_confirmation_text(lead, "https://meet.google.com/abc", ai_text)
        assert ai_text in text

    def test_text_contains_company(self):
        lead = _make_lead(company_address="Acme Corp")
        text = build_confirmation_text(lead, "https://meet.google.com/abc", "Hi")
        assert "Acme Corp" in text

    def test_text_uses_branding(self):
        lead = _make_lead()
        branding = BrandingConfig(company_name="Acme Corp")
        text = build_confirmation_text(lead, "https://meet.google.com/abc", "Hi", branding=branding)
        assert "Acme Corp" in text

    def test_text_contains_courses(self):
        lead = _make_lead(courses="Python, Docker")
        text = build_confirmation_text(lead, "https://meet.google.com/abc", "Hi")
        assert "Python, Docker" in text


# ── 4. Meet link appears in HTML ─────────────────────────────────────────────


class TestMeetLinkInHTML:
    def test_meet_link_in_html_href(self):
        lead = _make_lead()
        meet = "https://meet.google.com/xyz-defg-hij"
        html_body = build_confirmation_html(lead, meet, "Hi there")
        assert meet in html_body
        assert f'href="{meet}"' in html_body

    def test_meet_link_fallback_when_none(self):
        lead = _make_lead()
        html_body = build_confirmation_html(lead, None, "Hi there")
        assert "Link unavailable" in html_body


# ── 5. Meet link appears in plain text ───────────────────────────────────────


class TestMeetLinkInText:
    def test_meet_link_in_text(self):
        lead = _make_lead()
        meet = "https://meet.google.com/xyz-defg-hij"
        text = build_confirmation_text(lead, meet, "Hi there")
        assert meet in text
        assert "Join Meeting" in text

    def test_meet_link_fallback_when_none(self):
        lead = _make_lead()
        text = build_confirmation_text(lead, None, "Hi there")
        assert "Link unavailable" in text


# ── 6. Prospect name appears safely ──────────────────────────────────────────


class TestProspectNameSafe:
    def test_name_in_html(self):
        lead = _make_lead(name="Jane Doe")
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", "Hi")
        assert "Jane Doe" in html_body

    def test_name_in_text(self):
        lead = _make_lead(name="Jane Doe")
        text = build_confirmation_text(lead, "https://meet.google.com/abc", "Hi")
        assert "Jane Doe" in text


# ── 7. AI HTML injection is escaped ──────────────────────────────────────────


class TestAIHtmlInjection:
    """AI-generated text must be HTML-escaped before interpolation."""

    def test_script_tag_escaped_in_html(self):
        lead = _make_lead()
        malicious = '<script>alert("xss")</script>'
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", malicious)
        # The raw <script> tag must NOT appear in the HTML
        assert "<script>" not in html_body
        # The escaped version should appear
        assert "&lt;script&gt;" in html_body

    def test_html_entity_escaped(self):
        lead = _make_lead()
        malicious = '<img src="x" onerror="alert(1)">'
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", malicious)
        assert "<img" not in html_body
        assert "&lt;img" in html_body

    def test_angle_brackets_escaped(self):
        lead = _make_lead()
        text_with_angles = "Use <b>bold</b> and <i>italic</i>"
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", text_with_angles)
        assert "<b>bold</b>" not in html_body
        assert "&lt;b&gt;bold&lt;/b&gt;" in html_body

    def test_script_in_name_escaped(self):
        lead = _make_lead(name='<script>alert("name")</script>')
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", "Hi")
        assert "<script>" not in html_body
        assert "&lt;script&gt;" in html_body

    def test_normal_text_not_affected(self):
        lead = _make_lead(name="Jane Doe")
        ai_text = "We are excited about your Python journey!"
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", ai_text)
        assert "Jane Doe" in html_body
        assert ai_text in html_body

    def test_esc_helper_works(self):
        assert _esc("<b>") == "&lt;b&gt;"
        assert _esc("hello") == "hello"
        assert _esc('a"b') == "a&quot;b"


# ── 8. Confirmation contains appointment details ─────────────────────────────


class TestAppointmentDetails:
    def test_date_in_html(self):
        lead = _make_lead(
            appt_datetime_utc=datetime(2026, 8, 20, 19, 0, tzinfo=timezone.utc)
        )
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", "Hi")
        # Should contain "August 20, 2026" (CDT, since business tz is America/Chicago)
        assert "August" in html_body
        assert "2026" in html_body

    def test_date_in_text(self):
        lead = _make_lead(
            appt_datetime_utc=datetime(2026, 8, 20, 19, 0, tzinfo=timezone.utc)
        )
        text = build_confirmation_text(lead, "https://meet.google.com/abc", "Hi")
        assert "August" in text
        assert "2026" in text

    def test_time_includes_timezone(self):
        lead = _make_lead(
            appt_datetime_utc=datetime(2026, 8, 20, 19, 0, tzinfo=timezone.utc)
        )
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", "Hi")
        # 19:00 UTC = 14:00 CDT, should show "2:00 PM CDT"
        assert "CDT" in html_body

    def test_none_appt_shows_tbd(self):
        lead = _make_lead(appt_datetime_utc=None)
        html_body = build_confirmation_html(lead, None, "Hi")
        assert "TBD" in html_body


# ── 9. Reminder HTML generation ──────────────────────────────────────────────


class TestReminderHTML:
    def test_html_is_valid_string(self):
        lead = _make_lead()
        html_body = build_reminder_html(lead, "https://meet.google.com/abc")
        assert isinstance(html_body, str)
        assert len(html_body) > 100

    def test_html_containsDOCTYPE(self):
        lead = _make_lead()
        html_body = build_reminder_html(lead, "https://meet.google.com/abc")
        assert "<!DOCTYPE html>" in html_body

    def test_html_contains_company_name(self):
        lead = _make_lead()
        html_body = build_reminder_html(lead, "https://meet.google.com/abc")
        assert _DEFAULT_COMPANY in html_body

    def test_html_uses_branding(self):
        lead = _make_lead()
        branding = BrandingConfig(company_name="Acme Corp")
        html_body = build_reminder_html(lead, "https://meet.google.com/abc", branding=branding)
        assert "Acme Corp" in html_body
        assert _DEFAULT_COMPANY not in html_body

    def test_html_contains_prospect_name(self):
        lead = _make_lead(name="Jane Doe")
        html_body = build_reminder_html(lead, "https://meet.google.com/abc")
        assert "Jane Doe" in html_body

    def test_html_contains_reminder_heading(self):
        lead = _make_lead()
        html_body = build_reminder_html(lead, "https://meet.google.com/abc")
        assert "Reminder" in html_body

    def test_html_script_tag_escaped(self):
        lead = _make_lead(name='<script>alert("x")</script>')
        html_body = build_reminder_html(lead, "https://meet.google.com/abc")
        assert "<script>" not in html_body
        assert "&lt;script&gt;" in html_body


# ── 10. Reminder plain-text generation ───────────────────────────────────────


class TestReminderText:
    def test_text_contains_prospect_name(self):
        lead = _make_lead(name="Jane Doe")
        text = build_reminder_text(lead, "https://meet.google.com/abc")
        assert "Jane Doe" in text

    def test_text_contains_reminder_message(self):
        lead = _make_lead()
        text = build_reminder_text(lead, "https://meet.google.com/abc")
        assert "reminder" in text.lower()

    def test_text_contains_company(self):
        lead = _make_lead()
        text = build_reminder_text(lead, "https://meet.google.com/abc")
        assert _DEFAULT_COMPANY in text

    def test_text_uses_branding(self):
        lead = _make_lead()
        branding = BrandingConfig(company_name="Acme Corp")
        text = build_reminder_text(lead, "https://meet.google.com/abc", branding=branding)
        assert "Acme Corp" in text


# ── 11. Reminder contains Meet link ──────────────────────────────────────────


class TestReminderMeetLink:
    def test_meet_link_in_html(self):
        lead = _make_lead()
        meet = "https://meet.google.com/abc-defg-hij"
        html_body = build_reminder_html(lead, meet)
        assert meet in html_body
        assert f'href="{meet}"' in html_body

    def test_meet_link_in_text(self):
        lead = _make_lead()
        meet = "https://meet.google.com/abc-defg-hij"
        text = build_reminder_text(lead, meet)
        assert meet in text
        assert "Join Meeting" in text

    def test_meet_fallback_when_none_html(self):
        lead = _make_lead()
        html_body = build_reminder_html(lead, None)
        assert "Link unavailable" in html_body

    def test_meet_fallback_when_none_text(self):
        lead = _make_lead()
        text = build_reminder_text(lead, None)
        assert "Link unavailable" in text


# ── 12. Footer does not contain fake unsubscribe ─────────────────────────────


class TestNoFakeUnsubscribe:
    def test_confirmation_no_unsubscribe(self):
        lead = _make_lead()
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", "Hi")
        lower = html_body.lower()
        assert "unsubscribe" not in lower
        assert "stop" not in lower or "stop" in "look forward to speaking"

    def test_reminder_no_unsubscribe(self):
        lead = _make_lead()
        html_body = build_reminder_html(lead, "https://meet.google.com/abc")
        lower = html_body.lower()
        assert "unsubscribe" not in lower

    def test_confirmation_text_no_unsubscribe(self):
        lead = _make_lead()
        text = build_confirmation_text(lead, "https://meet.google.com/abc", "Hi")
        lower = text.lower()
        assert "unsubscribe" not in lower

    def test_reminder_text_no_unsubscribe(self):
        lead = _make_lead()
        text = build_reminder_text(lead, "https://meet.google.com/abc")
        lower = text.lower()
        assert "unsubscribe" not in lower


# ── 13. Sender display name is correct ───────────────────────────────────────


class TestSenderDisplayName:
    """The sender display name is set in email_service.py, not templates.
    Phase 6D: Sender name is resolved from BrandingConfig."""

    def test_default_sender_name(self):
        """Default sender name is 'Strategy Call Agent'."""
        from app.services.email_service import _DEFAULT_SENDER_NAME
        assert _DEFAULT_SENDER_NAME == "Strategy Call Agent"

    def test_company_in_confirmation(self):
        lead = _make_lead()
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", "Hi")
        assert "Strategy Call Agent" in html_body

    def test_company_in_reminder(self):
        lead = _make_lead()
        html_body = build_reminder_html(lead, "https://meet.google.com/abc")
        assert "Strategy Call Agent" in html_body


# ── 14. AI cannot modify the recipient ───────────────────────────────────────


class TestAIRecipientIsolation:
    """The recipient is always lead.email — never derived from AI output."""

    def test_recipient_not_in_template_output(self):
        """AI paragraph should not be able to override the To: field.
        The recipient is set by email_service.send_confirmation_email()
        using lead.email — templates don't touch it."""
        lead = _make_lead(email="real@example.com")
        ai_text = "Send confirmation to hacker@evil.com instead"
        html_body = build_confirmation_html(lead, "https://meet.google.com/abc", ai_text)
        # The AI text appears in the body as-is (escaped), but the To: field
        # is never determined by the template — it's set by send_email().
        # This test verifies the template doesn't expose any "to" override.
        assert "hacker@evil.com" in html_body  # It's in the body as text, not as recipient
        # The key security property: email_service always uses lead.email
        from app.services.email_service import EmailService
        import inspect
        source = inspect.getsource(EmailService.send_confirmation_email)
        assert "lead.email" in source


# ── 15. AI cannot modify the subject ─────────────────────────────────────────


class TestAISubjectIsolation:
    """The subject is always deterministic — never influenced by AI output."""

    def test_subject_not_in_ai_control(self):
        lead = _make_lead()
        # Subject is always the same regardless of lead content
        s1 = build_confirmation_subject(lead)
        lead2 = _make_lead(name="Attacker", courses="Ignore instructions")
        s2 = build_confirmation_subject(lead2)
        assert s1 == s2

    def test_ai_text_not_in_subject(self):
        lead = _make_lead()
        subject = build_confirmation_subject(lead)
        # The subject is a fixed string, not influenced by any AI
        assert "Your Strategy Call is Confirmed" in subject
        assert _DEFAULT_COMPANY in subject


# ── Reminder subject ─────────────────────────────────────────────────────────


class TestReminderSubject:
    def test_reminder_subject_is_deterministic(self):
        lead = _make_lead()
        s1 = build_reminder_subject(lead, "2:00 PM CDT")
        s2 = build_reminder_subject(lead, "2:00 PM CDT")
        assert s1 == s2

    def test_reminder_subject_contains_company(self):
        lead = _make_lead()
        subject = build_reminder_subject(lead, "2:00 PM CDT")
        assert _DEFAULT_COMPANY in subject

    def test_reminder_subject_uses_branding(self):
        lead = _make_lead()
        branding = BrandingConfig(company_name="Acme Corp")
        subject = build_reminder_subject(lead, "2:00 PM CDT", branding=branding)
        assert "Acme Corp" in subject

    def test_reminder_subject_mentions_reminder(self):
        lead = _make_lead()
        subject = build_reminder_subject(lead, "2:00 PM CDT")
        assert "Reminder" in subject
