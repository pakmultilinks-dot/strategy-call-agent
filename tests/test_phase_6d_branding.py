"""Tests for Phase 6D — Service Layer Completion (org-specific branding).

Covers:
  1. BrandingConfig dataclass defaults and custom values
  2. MeetingConfig dataclass defaults
  3. IntegrationConfigResolver.resolve_branding() — org fields, fallback, missing org
  4. IntegrationConfigResolver.resolve_meeting_config() — org duration, fallback
  5. Email templates accept custom BrandingConfig
  6. EmailService sender name resolution from BrandingConfig
  7. AIService dynamic system prompt and fallback with org company name
  8. CalendarService event summary uses org company name
  9. CalendarService uses org meeting duration
"""
import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.services.integration_config_resolver import (
    BrandingConfig,
    IntegrationConfigResolver,
    MeetingConfig,
)

# ── Constants ────────────────────────────────────────────────────────────────

_TEST_ORG_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")


# ── 1. BrandingConfig dataclass ──────────────────────────────────────────────


class TestBrandingConfig:
    def test_default_values(self):
        b = BrandingConfig()
        assert b.company_name == "Strategy Call Agent"
        assert b.sender_name == "Strategy Call Agent"
        assert b.brand_color == "#1a73e8"
        assert b.tagline == ""

    def test_custom_values(self):
        b = BrandingConfig(
            company_name="Acme Corp",
            sender_name="Acme Sales",
            brand_color="#ff0000",
            tagline="Innovation • Excellence",
        )
        assert b.company_name == "Acme Corp"
        assert b.sender_name == "Acme Sales"
        assert b.brand_color == "#ff0000"
        assert b.tagline == "Innovation • Excellence"

    def test_frozen(self):
        b = BrandingConfig()
        with pytest.raises(AttributeError):
            b.company_name = "Changed"

    def test_partial_override(self):
        b = BrandingConfig(company_name="Acme Corp", brand_color="#00ff00")
        assert b.company_name == "Acme Corp"
        assert b.sender_name == "Strategy Call Agent"  # default
        assert b.brand_color == "#00ff00"
        assert b.tagline == ""  # default


# ── 2. MeetingConfig dataclass ──────────────────────────────────────────────


class TestMeetingConfig:
    def test_default_duration(self):
        m = MeetingConfig()
        assert m.duration_minutes == 30

    def test_custom_duration(self):
        m = MeetingConfig(duration_minutes=60)
        assert m.duration_minutes == 60

    def test_frozen(self):
        m = MeetingConfig()
        with pytest.raises(AttributeError):
            m.duration_minutes = 45


# ── 3. IntegrationConfigResolver.resolve_branding() ─────────────────────────


class TestResolveBranding:
    """Tests for IntegrationConfigResolver.resolve_branding()."""

    def test_missing_org_returns_defaults(self):
        """When the org doesn't exist, return default BrandingConfig."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        b = IntegrationConfigResolver.resolve_branding(db, _TEST_ORG_ID)
        assert b.company_name == "Strategy Call Agent"
        assert b.sender_name == "Strategy Call Agent"
        assert b.brand_color == "#1a73e8"
        assert b.tagline == ""

    def test_org_name_used_as_company(self):
        """Organization.name always populates company_name."""
        db = MagicMock()
        org = MagicMock()
        org.name = "Acme Corp"
        org.sender_name = None
        org.brand_color = None
        org.tagline = None
        db.query.return_value.filter.return_value.first.return_value = org

        b = IntegrationConfigResolver.resolve_branding(db, _TEST_ORG_ID)
        assert b.company_name == "Acme Corp"
        # sender_name falls back to org.name when org.sender_name is None
        assert b.sender_name == "Acme Corp"
        assert b.brand_color == "#1a73e8"  # default
        assert b.tagline == ""  # default

    def test_org_sender_name_used(self):
        """Organization.sender_name takes precedence over org.name."""
        db = MagicMock()
        org = MagicMock()
        org.name = "Acme Corp"
        org.sender_name = "Acme Sales Team"
        org.brand_color = None
        org.tagline = None
        db.query.return_value.filter.return_value.first.return_value = org

        b = IntegrationConfigResolver.resolve_branding(db, _TEST_ORG_ID)
        assert b.sender_name == "Acme Sales Team"

    def test_org_brand_color_used(self):
        """Organization.brand_color is used when set."""
        db = MagicMock()
        org = MagicMock()
        org.name = "Acme Corp"
        org.sender_name = None
        org.brand_color = "#ff0000"
        org.tagline = None
        db.query.return_value.filter.return_value.first.return_value = org

        b = IntegrationConfigResolver.resolve_branding(db, _TEST_ORG_ID)
        assert b.brand_color == "#ff0000"

    def test_org_tagline_used(self):
        """Organization.tagline is used when set."""
        db = MagicMock()
        org = MagicMock()
        org.name = "Acme Corp"
        org.sender_name = None
        org.brand_color = None
        org.tagline = "Cloud Computing • Data Analytics"
        db.query.return_value.filter.return_value.first.return_value = org

        b = IntegrationConfigResolver.resolve_branding(db, _TEST_ORG_ID)
        assert b.tagline == "Cloud Computing • Data Analytics"

    def test_all_org_fields_set(self):
        """When all org branding fields are set, use them all."""
        db = MagicMock()
        org = MagicMock()
        org.name = "Acme Corp"
        org.sender_name = "Acme Sales"
        org.brand_color = "#ff5500"
        org.tagline = "Innovation First"
        db.query.return_value.filter.return_value.first.return_value = org

        b = IntegrationConfigResolver.resolve_branding(db, _TEST_ORG_ID)
        assert b.company_name == "Acme Corp"
        assert b.sender_name == "Acme Sales"
        assert b.brand_color == "#ff5500"
        assert b.tagline == "Innovation First"

    def test_empty_sender_name_falls_back_to_org_name(self):
        """Empty string sender_name should fall back to org.name."""
        db = MagicMock()
        org = MagicMock()
        org.name = "Acme Corp"
        org.sender_name = ""
        org.brand_color = None
        org.tagline = None
        db.query.return_value.filter.return_value.first.return_value = org

        b = IntegrationConfigResolver.resolve_branding(db, _TEST_ORG_ID)
        assert b.sender_name == "Acme Corp"

    def test_empty_company_name_falls_back(self):
        """Empty org.name falls back to default."""
        db = MagicMock()
        org = MagicMock()
        org.name = ""
        org.sender_name = None
        org.brand_color = None
        org.tagline = None
        db.query.return_value.filter.return_value.first.return_value = org

        b = IntegrationConfigResolver.resolve_branding(db, _TEST_ORG_ID)
        assert b.company_name == "Strategy Call Agent"
        assert b.sender_name == "Strategy Call Agent"


# ── 4. IntegrationConfigResolver.resolve_meeting_config() ───────────────────


class TestResolveMeetingConfig:
    def test_missing_config_returns_defaults(self):
        """When OrgScheduleConfig doesn't exist, return default 30 min."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        m = IntegrationConfigResolver.resolve_meeting_config(db, _TEST_ORG_ID)
        assert m.duration_minutes == 30

    def test_org_duration_used(self):
        """Organization's meeting_duration_minutes is used when set."""
        db = MagicMock()
        cfg = MagicMock()
        cfg.meeting_duration_minutes = 45
        db.query.return_value.filter.return_value.first.return_value = cfg

        m = IntegrationConfigResolver.resolve_meeting_config(db, _TEST_ORG_ID)
        assert m.duration_minutes == 45

    def test_null_duration_falls_back_to_default(self):
        """NULL meeting_duration_minutes falls back to 30."""
        db = MagicMock()
        cfg = MagicMock()
        cfg.meeting_duration_minutes = None
        db.query.return_value.filter.return_value.first.return_value = cfg

        m = IntegrationConfigResolver.resolve_meeting_config(db, _TEST_ORG_ID)
        assert m.duration_minutes == 30

    def test_zero_duration(self):
        """Zero is a valid value (edge case)."""
        db = MagicMock()
        cfg = MagicMock()
        cfg.meeting_duration_minutes = 0
        db.query.return_value.filter.return_value.first.return_value = cfg

        m = IntegrationConfigResolver.resolve_meeting_config(db, _TEST_ORG_ID)
        assert m.duration_minutes == 0


# ── 5. Email templates with BrandingConfig ──────────────────────────────────


class TestTemplatesWithBranding:
    """Verify that email template functions accept and use BrandingConfig."""

    def test_confirmation_subject_with_branding(self):
        from app.services.email_templates import build_confirmation_subject
        from app.models import Lead, LeadStatus
        from datetime import datetime, timezone

        lead = Lead(
            id="00000000-0000-0000-0000-000000000001",
            interested="yes",
            name="Jane Doe",
            company_address="Acme Corp",
            phone_number="555-0100",
            direct_number=None,
            courses="Python",
            email="jane@example.com",
            scheduled_date="tomorrow",
            caller_name="Agent",
            appt_datetime_raw="tomorrow 2pm",
            appt_datetime_utc=datetime(2026, 8, 20, 19, 0, tzinfo=timezone.utc),
            dedupe_key="jane@example.com|tomorrow 2pm",
            status=LeadStatus.SCHEDULED,
            calendar_event_id="cal-123",
            reminder_sent_at=None,
        )
        branding = BrandingConfig(company_name="Acme Corp")
        subject = build_confirmation_subject(lead, branding=branding)
        assert "Acme Corp" in subject
        assert "Your Strategy Call is Confirmed" in subject

    def test_confirmation_html_brand_color(self):
        """BrandingConfig.brand_color appears in the HTML header."""
        from app.services.email_templates import build_confirmation_html
        from app.models import Lead, LeadStatus
        from datetime import datetime, timezone

        lead = Lead(
            id="00000000-0000-0000-0000-000000000001",
            interested="yes",
            name="Jane Doe",
            company_address="Acme Corp",
            phone_number="555-0100",
            direct_number=None,
            courses="Python",
            email="jane@example.com",
            scheduled_date="tomorrow",
            caller_name="Agent",
            appt_datetime_raw="tomorrow 2pm",
            appt_datetime_utc=datetime(2026, 8, 20, 19, 0, tzinfo=timezone.utc),
            dedupe_key="jane@example.com|tomorrow 2pm",
            status=LeadStatus.SCHEDULED,
            calendar_event_id="cal-123",
            reminder_sent_at=None,
        )
        branding = BrandingConfig(brand_color="#ff5500")
        html_body = build_confirmation_html(
            lead, "https://meet.google.com/abc", "Welcome!", branding=branding
        )
        assert "#ff5500" in html_body

    def test_reminder_html_with_tagline(self):
        """BrandingConfig.tagline appears in the reminder HTML when set."""
        from app.services.email_templates import build_reminder_html
        from app.models import Lead, LeadStatus
        from datetime import datetime, timezone

        lead = Lead(
            id="00000000-0000-0000-0000-000000000001",
            interested="yes",
            name="Jane Doe",
            company_address="Acme Corp",
            phone_number="555-0100",
            direct_number=None,
            courses="Python",
            email="jane@example.com",
            scheduled_date="tomorrow",
            caller_name="Agent",
            appt_datetime_raw="tomorrow 2pm",
            appt_datetime_utc=datetime(2026, 8, 20, 19, 0, tzinfo=timezone.utc),
            dedupe_key="jane@example.com|tomorrow 2pm",
            status=LeadStatus.SCHEDULED,
            calendar_event_id="cal-123",
            reminder_sent_at=None,
        )
        branding = BrandingConfig(tagline="Innovation • Excellence")
        html_body = build_reminder_html(
            lead, "https://meet.google.com/abc", branding=branding
        )
        assert "Innovation • Excellence" in html_body

    def test_reminder_subject_with_branding(self):
        from app.services.email_templates import build_reminder_subject
        from app.models import Lead, LeadStatus
        from datetime import datetime, timezone

        lead = Lead(
            id="00000000-0000-0000-0000-000000000001",
            interested="yes",
            name="Jane Doe",
            company_address="Acme Corp",
            phone_number="555-0100",
            direct_number=None,
            courses="Python",
            email="jane@example.com",
            scheduled_date="tomorrow",
            caller_name="Agent",
            appt_datetime_raw="tomorrow 2pm",
            appt_datetime_utc=datetime(2026, 8, 20, 19, 0, tzinfo=timezone.utc),
            dedupe_key="jane@example.com|tomorrow 2pm",
            status=LeadStatus.SCHEDULED,
            calendar_event_id="cal-123",
            reminder_sent_at=None,
        )
        branding = BrandingConfig(company_name="Acme Corp")
        subject = build_reminder_subject(lead, "2:00 PM CDT", branding=branding)
        assert "Acme Corp" in subject
        assert "Reminder" in subject


# ── 6. AIService dynamic prompts ────────────────────────────────────────────


class TestAIServicePrompts:
    """Verify AIService builds dynamic system prompt and fallback."""

    def test_system_prompt_contains_company(self):
        from app.services.ai_service import _build_system_prompt

        prompt = _build_system_prompt("Acme Corp")
        assert "Acme Corp" in prompt
        assert "strategy call confirmation email" in prompt.lower()

    def test_fallback_contains_company(self):
        from app.services.ai_service import _build_fallback_message

        msg = _build_fallback_message("Acme Corp")
        assert "Acme Corp" in msg

    def test_system_prompt_with_default_company(self):
        from app.services.ai_service import _build_system_prompt

        prompt = _build_system_prompt("Strategy Call Agent")
        assert "Strategy Call Agent" in prompt

    def test_fallback_with_default_company(self):
        from app.services.ai_service import _build_fallback_message

        msg = _build_fallback_message("Strategy Call Agent")
        assert "Strategy Call Agent" in msg


# ── 7. EmailService sender name resolution ──────────────────────────────────


class TestEmailServiceSenderName:
    def test_default_sender_name(self):
        from app.services.email_service import _DEFAULT_SENDER_NAME
        assert _DEFAULT_SENDER_NAME == "Strategy Call Agent"

    def test_email_service_uses_branding(self):
        """EmailService resolves BrandingConfig in __init__."""
        from app.services.email_service import EmailService
        from app.services.integration_config_resolver import BrandingConfig

        # Verify that the EmailService __init__ calls resolve_branding
        # by inspecting source code
        import inspect
        source = inspect.getsource(EmailService.__init__)
        assert "resolve_branding" in source

        # Verify that send_email uses self._branding.sender_name
        send_source = inspect.getsource(EmailService.send_email)
        assert "self._branding" in send_source

        # Verify that send_confirmation_email passes branding to template
        confirm_source = inspect.getsource(EmailService.send_confirmation_email)
        assert "branding=self._branding" in confirm_source


# ── 8. CalendarService event summary ────────────────────────────────────────


class TestCalendarServiceBranding:
    def test_event_summary_uses_company_name(self):
        """CalendarService.create_event() uses branding.company_name."""
        from app.services.calendar_service import CalendarService

        # We just verify the code path by checking the format string
        # in the source uses branding.company_name
        import inspect
        source = inspect.getsource(CalendarService.create_event)
        assert "self._branding.company_name" in source

    def test_event_summary_format(self):
        """The event summary format includes the org company name."""
        from app.services.calendar_service import CalendarService

        import inspect
        source = inspect.getsource(CalendarService.create_event)
        assert 'f"Strategy Call:' in source
        assert "self._branding.company_name" in source

    def test_meeting_duration_used(self):
        """CalendarService uses self._meeting_duration."""
        from app.services.calendar_service import CalendarService

        import inspect
        source = inspect.getsource(CalendarService.create_event)
        assert "self._meeting_duration" in source

    def test_init_resolves_branding(self):
        """CalendarService.__init__ resolves branding when org_context is set."""
        from app.services.calendar_service import CalendarService

        import inspect
        source = inspect.getsource(CalendarService.__init__)
        assert "resolve_branding" in source
        assert "resolve_meeting_config" in source

    def test_default_duration(self):
        from app.services.calendar_service import _DEFAULT_MEETING_DURATION_MINUTES
        assert _DEFAULT_MEETING_DURATION_MINUTES == 30


# ── 9. Backward compatibility ───────────────────────────────────────────────


class TestBackwardCompatibility:
    """All template functions still work without passing branding."""

    def test_confirmation_subject_no_branding(self):
        from app.services.email_templates import build_confirmation_subject
        from app.models import Lead, LeadStatus
        from datetime import datetime, timezone

        lead = Lead(
            id="00000000-0000-0000-0000-000000000001",
            interested="yes",
            name="Jane Doe",
            company_address="Acme Corp",
            phone_number="555-0100",
            direct_number=None,
            courses="Python",
            email="jane@example.com",
            scheduled_date="tomorrow",
            caller_name="Agent",
            appt_datetime_raw="tomorrow 2pm",
            appt_datetime_utc=datetime(2026, 8, 20, 19, 0, tzinfo=timezone.utc),
            dedupe_key="jane@example.com|tomorrow 2pm",
            status=LeadStatus.SCHEDULED,
            calendar_event_id="cal-123",
            reminder_sent_at=None,
        )
        subject = build_confirmation_subject(lead)
        assert "Strategy Call Agent" in subject

    def test_reminder_html_no_branding(self):
        from app.services.email_templates import build_reminder_html
        from app.models import Lead, LeadStatus
        from datetime import datetime, timezone

        lead = Lead(
            id="00000000-0000-0000-0000-000000000001",
            interested="yes",
            name="Jane Doe",
            company_address="Acme Corp",
            phone_number="555-0100",
            direct_number=None,
            courses="Python",
            email="jane@example.com",
            scheduled_date="tomorrow",
            caller_name="Agent",
            appt_datetime_raw="tomorrow 2pm",
            appt_datetime_utc=datetime(2026, 8, 20, 19, 0, tzinfo=timezone.utc),
            dedupe_key="jane@example.com|tomorrow 2pm",
            status=LeadStatus.SCHEDULED,
            calendar_event_id="cal-123",
            reminder_sent_at=None,
        )
        html_body = build_reminder_html(lead, "https://meet.google.com/abc")
        assert "Strategy Call Agent" in html_body
