"""Tests for Calendar event timezone display (Step 2 — CORRECTED).

Architecture rule (verbatim):
    Google Calendar must ALWAYS be anchored/displayed in fixed IANA timezone:
    America/New_York. The customer's timezone is ONLY for customer-facing
    emails/reminders and must NOT control Google Calendar display timezone.

Verifies that:
  1. create_event() ALWAYS uses America/New_York for Calendar display,
     regardless of what lead.customer_timezone contains.
  2. Calendar dateTime contains no UTC offset (naive local datetime).
  3. Calendar payload preserves the original UTC instant.
  4. timeZone field in the payload is ALWAYS America/New_York.
  5. update_event_reschedule() ALWAYS uses America/New_York.
  6. check_slot_available() still uses UTC (unchanged).
  7. customer_timezone column remains stored on the Lead model (for Step 3
     email/reminder work).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from zoneinfo import ZoneInfo

from app.models import Lead, LeadStatus
from app.services.calendar_service import CALENDAR_DISPLAY_TZ, CalendarService

# The constant MUST be America/New_York
assert CALENDAR_DISPLAY_TZ == "America/New_York"

NY = ZoneInfo("America/New_York")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_lead(
    org_id: uuid.UUID | None = None,
    appt_utc: datetime | None = None,
    customer_timezone: str | None = None,
    email: str = "tz-test@example.com",
) -> Lead:
    """Build a lightweight Lead with the fields CalendarService reads."""
    return Lead(
        id=uuid.uuid4(),
        name="TZ Test Lead",
        email=email,
        company_address="123 Test St",
        courses="Course A",
        phone_number="555-0100",
        direct_number="555-0101",
        caller_name="Test Caller",
        appt_datetime_raw="09/11/2026 9:00 AM EST",
        appt_datetime_utc=appt_utc or datetime(2026, 9, 11, 14, 0, tzinfo=timezone.utc),
        customer_timezone=customer_timezone,
        status=LeadStatus.PENDING,
        organization_id=org_id or uuid.uuid4(),
        dedupe_key="test@test.com|09/11/2026 9:00 am est",
    )


def _capture_event_body(mock_insert: MagicMock) -> dict:
    """Extract the body dict passed to _insert_event()."""
    mock_insert.assert_called_once()
    return mock_insert.call_args[0][0]  # first positional arg


def _make_service(**kwargs) -> CalendarService:
    """Build a CalendarService with mocked internals (no real Google API)."""
    svc = object.__new__(CalendarService)
    svc._calendar_id = "test-calendar-id"
    svc._org_id = uuid.uuid4()
    svc._meeting_duration = kwargs.get("meeting_duration", 30)
    svc._branding = MagicMock()
    svc._branding.company_name = "Test Co"
    svc._service = MagicMock()
    return svc


def _parse_local_dt(dt_str: str, tz: ZoneInfo) -> datetime:
    """Parse 'YYYY-MM-DDTHH:MM:SS' into a timezone-aware datetime."""
    date_parts, time_parts = dt_str.split("T")
    y, m, d = [int(x) for x in date_parts.split("-")]
    H, M, S = [int(x) for x in time_parts.split(":")]
    return datetime(y, m, d, H, M, S, tzinfo=tz)


# ══════════════════════════════════════════════════════════════════════════════
# 1. create_event ALWAYS uses America/New_York for Calendar display
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateEventAlwaysNewYork:
    """create_event() must ALWAYS display in America/New_York, regardless
    of what lead.customer_timezone says."""

    @pytest.mark.parametrize("customer_tz", [
        "America/New_York",       # A. Customer in Eastern → same
        "America/Chicago",        # B. Customer in Central → offset
        "America/Los_Angeles",    # C. Customer in Pacific → 3h offset
        "Asia/Karachi",           # D. Customer in Pakistan  → big offset
        "UTC",                    # E. Customer in UTC
        None,                     # F. No customer timezone stored
    ])
    def test_timeZone_field_always_new_york(self, customer_tz):
        """The timeZone field in the Calendar payload is ALWAYS America/New_York."""
        lead = _make_lead(customer_timezone=customer_tz)
        svc = _make_service()
        db = MagicMock()

        with patch.object(svc, "_insert_event", return_value={"id": "evt_1"}) as mock_ins:
            with patch.object(svc, "check_slot_available", return_value=True):
                svc.create_event(lead, db)

        body = _capture_event_body(mock_ins)
        assert body["start"]["timeZone"] == "America/New_York"
        assert body["end"]["timeZone"] == "America/New_York"

    @pytest.mark.parametrize("customer_tz", [
        "America/New_York",
        "America/Chicago",
        "America/Los_Angeles",
        "Asia/Karachi",
        "UTC",
        None,
    ])
    def test_dateTime_local_in_eastern(self, customer_tz):
        """dateTime must reflect the Eastern local time, NOT the customer tz.

        UTC 14:00 → Eastern 10:00 (EDT, UTC-4 in September).
        """
        lead = _make_lead(customer_timezone=customer_tz)
        svc = _make_service()
        db = MagicMock()

        with patch.object(svc, "_insert_event", return_value={"id": "evt_1"}) as mock_ins:
            with patch.object(svc, "check_slot_available", return_value=True):
                svc.create_event(lead, db)

        body = _capture_event_body(mock_ins)
        # 14:00 UTC in America/New_York (EDT) = 10:00
        assert body["start"]["dateTime"] == "2026-09-11T10:00:00"
        # 14:30 UTC in America/New_York (EDT) = 10:30
        assert body["end"]["dateTime"] == "2026-09-11T10:30:00"


# ══════════════════════════════════════════════════════════════════════════════
# 2. dateTime contains no offset
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateEventNoOffset:
    """Calendar dateTime must never contain +00:00 or any offset."""

    def test_dateTime_has_no_offset(self):
        lead = _make_lead(customer_timezone="America/Chicago")
        svc = _make_service()
        db = MagicMock()

        with patch.object(svc, "_insert_event", return_value={"id": "evt_1"}) as mock_ins:
            with patch.object(svc, "check_slot_available", return_value=True):
                svc.create_event(lead, db)

        body = _capture_event_body(mock_ins)
        for key in ("start", "end"):
            dt_str = body[key]["dateTime"]
            assert "+" not in dt_str, f"{key}.dateTime contains +: {dt_str}"
            assert not dt_str.endswith("Z"), f"{key}.dateTime ends with Z: {dt_str}"
            parts = dt_str.split("T")
            assert len(parts) == 2, f"{key}.dateTime is not ISO format: {dt_str}"
            assert len(parts[0]) == 10  # YYYY-MM-DD
            assert len(parts[1]) == 8   # HH:MM:SS


# ══════════════════════════════════════════════════════════════════════════════
# 3. Payload preserves the exact UTC instant
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateEventPreservesUtcInstant:
    """dateTime + timeZone must resolve to the same UTC instant regardless
    of what customer_timezone was set on the lead."""

    @pytest.mark.parametrize("customer_tz", [
        "America/New_York",
        "America/Chicago",
        "America/Los_Angeles",
        "Asia/Karachi",
        "UTC",
        None,
    ])
    def test_utc_invariant(self, customer_tz):
        """Convert (naive dateTime in America/New_York) back to UTC → must match."""
        lead = _make_lead(customer_timezone=customer_tz)
        svc = _make_service()
        db = MagicMock()

        with patch.object(svc, "_insert_event", return_value={"id": "evt_1"}) as mock_ins:
            with patch.object(svc, "check_slot_available", return_value=True):
                svc.create_event(lead, db)

        body = _capture_event_body(mock_ins)

        # Reconstruct: naive dateTime in America/New_York → UTC
        local_dt = _parse_local_dt(body["start"]["dateTime"], NY)
        reconstructed_utc = local_dt.astimezone(timezone.utc)

        assert reconstructed_utc == lead.appt_datetime_utc, (
            f"Customer tz={customer_tz}: reconstructed UTC {reconstructed_utc} "
            f"!= original UTC {lead.appt_datetime_utc}"
        )

    def test_end_time_preserves_utc_instant(self):
        """End time also preserves the UTC instant correctly."""
        lead = _make_lead(customer_timezone="Asia/Karachi")
        svc = _make_service(meeting_duration=30)
        db = MagicMock()

        with patch.object(svc, "_insert_event", return_value={"id": "evt_1"}) as mock_ins:
            with patch.object(svc, "check_slot_available", return_value=True):
                svc.create_event(lead, db)

        body = _capture_event_body(mock_ins)

        end_utc = _parse_local_dt(body["end"]["dateTime"], NY).astimezone(timezone.utc)
        expected_end_utc = lead.appt_datetime_utc + timedelta(minutes=30)
        assert end_utc == expected_end_utc


# ══════════════════════════════════════════════════════════════════════════════
# 4. Customer-specific scenarios
# ══════════════════════════════════════════════════════════════════════════════

class TestCustomerScenarios:
    """Concrete scenarios mapping customer timezone → Calendar display."""

    def test_a_customer_in_new_york(self):
        """Customer submits 9 AM Eastern → Calendar shows 9 AM Eastern."""
        utc_time = datetime(2026, 9, 11, 13, 0, tzinfo=timezone.utc)
        lead = _make_lead(appt_utc=utc_time, customer_timezone="America/New_York")
        svc = _make_service()
        db = MagicMock()

        with patch.object(svc, "_insert_event", return_value={"id": "evt_1"}) as mock_ins:
            with patch.object(svc, "check_slot_available", return_value=True):
                svc.create_event(lead, db)

        body = _capture_event_body(mock_ins)
        assert body["start"]["dateTime"] == "2026-09-11T09:00:00"
        assert body["start"]["timeZone"] == "America/New_York"

    def test_b_customer_in_chicago(self):
        """Customer submits 9 AM Central → Calendar shows 10 AM Eastern.

        9 AM CDT = 14:00 UTC. 14:00 UTC in Eastern = 10:00 AM EDT.
        """
        utc_time = datetime(2026, 9, 11, 14, 0, tzinfo=timezone.utc)
        lead = _make_lead(appt_utc=utc_time, customer_timezone="America/Chicago")
        svc = _make_service()
        db = MagicMock()

        with patch.object(svc, "_insert_event", return_value={"id": "evt_1"}) as mock_ins:
            with patch.object(svc, "check_slot_available", return_value=True):
                svc.create_event(lead, db)

        body = _capture_event_body(mock_ins)
        assert body["start"]["dateTime"] == "2026-09-11T10:00:00"
        assert body["start"]["timeZone"] == "America/New_York"

    def test_c_customer_in_la(self):
        """Customer submits 9 AM Pacific → Calendar shows 12 PM Eastern.

        9 AM PDT = 16:00 UTC. 16:00 UTC in Eastern = 12:00 PM EDT.
        """
        utc_time = datetime(2026, 9, 11, 16, 0, tzinfo=timezone.utc)
        lead = _make_lead(appt_utc=utc_time, customer_timezone="America/Los_Angeles")
        svc = _make_service()
        db = MagicMock()

        with patch.object(svc, "_insert_event", return_value={"id": "evt_1"}) as mock_ins:
            with patch.object(svc, "check_slot_available", return_value=True):
                svc.create_event(lead, db)

        body = _capture_event_body(mock_ins)
        assert body["start"]["dateTime"] == "2026-09-11T12:00:00"
        assert body["start"]["timeZone"] == "America/New_York"

    def test_d_customer_in_pakistan(self):
        """Customer submits 9 AM PKT → Calendar shows correct Eastern time.

        9 AM PKT = 04:00 UTC. 04:00 UTC in Eastern = 12:00 AM EDT.
        """
        utc_time = datetime(2026, 9, 11, 4, 0, tzinfo=timezone.utc)
        lead = _make_lead(appt_utc=utc_time, customer_timezone="Asia/Karachi")
        svc = _make_service()
        db = MagicMock()

        with patch.object(svc, "_insert_event", return_value={"id": "evt_1"}) as mock_ins:
            with patch.object(svc, "check_slot_available", return_value=True):
                svc.create_event(lead, db)

        body = _capture_event_body(mock_ins)
        assert body["start"]["dateTime"] == "2026-09-11T00:00:00"
        assert body["start"]["timeZone"] == "America/New_York"


# ══════════════════════════════════════════════════════════════════════════════
# 5. update_event_reschedule ALWAYS uses America/New_York
# ══════════════════════════════════════════════════════════════════════════════

class TestRescheduleAlwaysNewYork:
    """update_event_reschedule() must ALWAYS use America/New_York.
    No customer_timezone parameter is accepted anymore."""

    def _call_reschedule(self, new_start_utc: datetime) -> dict:
        """Run update_event_reschedule and capture the patch body."""
        svc = _make_service(meeting_duration=30)
        db = MagicMock()

        captured = {}

        def fake_patch(event_id, body):
            captured["body"] = body
            return {}

        with patch.object(svc, "_patch_event", side_effect=fake_patch):
            svc.update_event_reschedule(
                "evt_123",
                new_start_utc,
                30,
                "Strategy Call: Test",
                db,
            )
        return captured["body"]

    def test_reschedule_timeZone_field(self):
        """timeZone is ALWAYS America/New_York in reschedule payload."""
        body = self._call_reschedule(datetime(2026, 9, 18, 14, 0, tzinfo=timezone.utc))
        assert body["start"]["timeZone"] == "America/New_York"
        assert body["end"]["timeZone"] == "America/New_York"

    def test_reschedule_dateTime_local(self):
        """14:00 UTC in Eastern = 10:00 AM EDT."""
        body = self._call_reschedule(datetime(2026, 9, 18, 14, 0, tzinfo=timezone.utc))
        assert body["start"]["dateTime"] == "2026-09-18T10:00:00"
        assert body["end"]["dateTime"] == "2026-09-18T10:30:00"

    def test_reschedule_no_offset(self):
        """dateTime never contains a UTC offset."""
        body = self._call_reschedule(datetime(2026, 9, 18, 14, 0, tzinfo=timezone.utc))
        assert "+" not in body["start"]["dateTime"]
        assert "+" not in body["end"]["dateTime"]

    def test_reschedule_preserves_utc_instant(self):
        """Reconstructing from naive dateTime + America/New_York → original UTC."""
        body = self._call_reschedule(datetime(2026, 9, 18, 14, 0, tzinfo=timezone.utc))
        local_dt = _parse_local_dt(body["start"]["dateTime"], NY)
        reconstructed_utc = local_dt.astimezone(timezone.utc)
        assert reconstructed_utc == datetime(2026, 9, 18, 14, 0, tzinfo=timezone.utc)

    def test_reschedule_different_utc_times(self):
        """Verify conversion for various UTC instants (winter EST + summer EDT)."""
        cases = [
            (datetime(2026, 12, 15, 17, 0, tzinfo=timezone.utc), "2026-12-15T12:00:00"),  # EST = UTC-5
            (datetime(2026, 7, 4, 18, 0, tzinfo=timezone.utc),   "2026-07-04T14:00:00"),  # EDT = UTC-4
        ]
        for utc_in, expected_ny in cases:
            body = self._call_reschedule(utc_in)
            assert body["start"]["dateTime"] == expected_ny


class TestRescheduleNoCustomerTimezoneParam:
    """update_event_reschedule() no longer accepts a customer_timezone param."""

    def test_no_customer_timezone_arg(self):
        """Calling without any timezone arg works — America/New_York is hardcoded."""
        new_start_utc = datetime(2026, 9, 18, 14, 0, tzinfo=timezone.utc)
        svc = _make_service(meeting_duration=30)
        db = MagicMock()

        captured = {}

        def fake_patch(event_id, body):
            captured["body"] = body
            return {}

        with patch.object(svc, "_patch_event", side_effect=fake_patch):
            svc.update_event_reschedule(
                "evt_123",
                new_start_utc,
                30,
                "Strategy Call: Test",
                db,
            )

        body = captured["body"]
        assert body["start"]["timeZone"] == "America/New_York"
        assert body["start"]["dateTime"] == "2026-09-18T10:00:00"


# ══════════════════════════════════════════════════════════════════════════════
# 6. check_slot_available still uses UTC
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckSlotAvailableStillUtc:
    """check_slot_available() must always query in UTC regardless of customer tz."""

    def test_freebusy_query_uses_utc(self):
        svc = _make_service()
        start = datetime(2026, 9, 11, 14, 0, tzinfo=timezone.utc)
        end = datetime(2026, 9, 11, 14, 30, tzinfo=timezone.utc)

        captured = {}

        def fake_query(body):
            captured["body"] = body
            return {"calendars": {"test-calendar-id": {"busy": []}}}

        with patch.object(svc, "_freebusy_query", side_effect=fake_query):
            result = svc.check_slot_available(start, end)

        assert result is True
        assert captured["body"]["timeZone"] == "UTC"
        assert "+00:00" in captured["body"]["timeMin"]
        assert "+00:00" in captured["body"]["timeMax"]


# ══════════════════════════════════════════════════════════════════════════════
# 7. customer_timezone remains stored on Lead (for Step 3 email/reminder)
# ══════════════════════════════════════════════════════════════════════════════

class TestCustomerTimezoneStillStored:
    """The customer_timezone column must remain on Lead — it is NOT removed.
    It will be used in Step 3 for customer-facing emails/reminders."""

    def test_lead_has_customer_timezone_field(self):
        """Lead model exposes customer_timezone."""
        lead = _make_lead(customer_timezone="America/Chicago")
        assert lead.customer_timezone == "America/Chicago"

    def test_customer_timezone_none_valid(self):
        """NULL customer_timezone is a valid value."""
        lead = _make_lead(customer_timezone=None)
        assert lead.customer_timezone is None

    def test_calendar_ignores_customer_timezone(self):
        """Calendar display does NOT read customer_timezone, even when set."""
        lead = _make_lead(customer_timezone="Asia/Tokyo")
        svc = _make_service()
        db = MagicMock()

        with patch.object(svc, "_insert_event", return_value={"id": "evt_1"}) as mock_ins:
            with patch.object(svc, "check_slot_available", return_value=True):
                svc.create_event(lead, db)

        body = _capture_event_body(mock_ins)
        # Despite customer_timezone being Asia/Tokyo, Calendar uses New York
        assert body["start"]["timeZone"] == "America/New_York"
        assert body["start"]["timeZone"] != "Asia/Tokyo"
