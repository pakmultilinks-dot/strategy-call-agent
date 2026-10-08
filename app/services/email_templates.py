"""Reusable HTML + plain-text email templates.

All layout and deterministic content lives here.  Branding (company name,
sender name, colors, tagline) is resolved per-organization via
``BrandingConfig`` and passed into every template function.

AI is NOT involved in template rendering — only the personalized greeting
paragraph is injected as data.

HTML uses inline CSS and table-based layout for maximum Gmail compatibility.
All user/AI-provided text is HTML-escaped before interpolation to prevent
injection (XSS in email clients).
"""
import html as _html
from datetime import datetime
from zoneinfo import ZoneInfo

from app.config import settings
from app.models import Lead
from app.services.integration_config_resolver import BrandingConfig

# ── Design constants (not branding — shared across all orgs) ──────────────────

_DARK_BG = "#f8f9fa"
_WHITE = "#ffffff"
_TEXT_DARK = "#202124"
_TEXT_MID = "#5f6368"
_TEXT_LIGHT = "#ffffff"
_BORDER = "#dadce0"
_MEETING_COLOR = "#0d652d"     # Google-green for the Meet button
_FOOTER_BG = "#f1f3f4"


def _meeting_button_label(meeting_provider: str | None) -> str:
    """Return the provider-appropriate meeting button label.

    Args:
        meeting_provider: One of 'zoom', 'google_meet', or None/unknown.

    Returns:
        'Join Zoom Meeting' for Zoom, 'Join Google Meet' for Google Meet,
        'Join Meeting' for unknown/unrecognized providers.
    """
    if meeting_provider == "zoom":
        return "Join Zoom Meeting"
    if meeting_provider == "google_meet":
        return "Join Google Meet"
    return "Join Meeting"


def _fmt_datetime_local(dt_utc: datetime | None, tz: ZoneInfo) -> tuple[str, str]:
    """Return (date_str, time_str) in the business timezone.

    Date: "August 25, 2026"
    Time: "2:00 PM CDT"
    """
    if dt_utc is None:
        return ("TBD", "TBD")
    local = dt_utc.astimezone(tz)
    date_str = local.strftime("%B %d, %Y").lstrip("0")
    hour = local.hour % 12 or 12
    ampm = "AM" if local.hour < 12 else "PM"
    time_str = f"{hour}:{local.minute:02d} {ampm} {local.tzname()}"
    return (date_str, time_str)


def _clean(value: str | None) -> str:
    """Return a safe display string, never empty."""
    if not value or str(value).strip() in ("", "N/A", "None"):
        return ""
    return str(value).strip()


def _esc(value: str) -> str:
    """HTML-escape a user/AI-provided string for safe interpolation into HTML."""
    return _html.escape(value, quote=True)


# ── Confirmation email ────────────────────────────────────────────────────────

def build_confirmation_subject(
    lead: Lead,
    branding: BrandingConfig | None = None,
) -> str:
    """Deterministic confirmation email subject."""
    b = branding or BrandingConfig()
    return f"Your Strategy Call is Confirmed — {b.company_name}"


def build_confirmation_html(
    lead: Lead,
    meet_link: str | None,
    ai_paragraph: str,
    tz: ZoneInfo | None = None,
    branding: BrandingConfig | None = None,
    meeting_provider: str | None = None,
    rsvp_accept_url: str | None = None,
    rsvp_decline_url: str | None = None,
) -> str:
    """Return a complete HTML email body for the confirmation email.

    ``ai_paragraph`` is the short AI-generated greeting; the rest is
    deterministic template code.

    Phase 4: When ``rsvp_accept_url`` and ``rsvp_decline_url`` are
    provided, Accept/Decline RSVP buttons are included below the
    Meet button.
    """
    b = branding or BrandingConfig()
    tz = tz or ZoneInfo(settings.business_timezone)
    date_str, time_str = _fmt_datetime_local(lead.appt_datetime_utc, tz)
    company = _clean(lead.company_address)
    courses = _clean(lead.courses)

    # Detail rows — only include rows that have data
    detail_rows = ""
    detail_rows += _detail_row("Date", date_str)
    detail_rows += _detail_row("Time", time_str)
    detail_rows += _detail_row("Attendee", lead.name)
    if company:
        detail_rows += _detail_row("Company", company)
    if courses:
        detail_rows += _detail_row("Courses", courses)

    meet_url = meet_link or "#"
    meet_display = meet_link or "Link unavailable"
    button_label = _meeting_button_label(meeting_provider)

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:{_DARK_BG};font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background-color:{_DARK_BG};padding:24px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:{_WHITE};border-radius:8px;overflow:hidden;">

  <!-- HEADER -->
  <tr><td style="background-color:{b.brand_color};padding:28px 32px;text-align:center;">
    <div style="font-size:22px;font-weight:700;color:{_TEXT_LIGHT};letter-spacing:0.3px;">{_esc(b.company_name)}</div>
    <div style="font-size:13px;color:rgba(255,255,255,0.85);margin-top:6px;">{_esc(b.tagline) if b.tagline else ""}</div>
  </td></tr>

  <!-- HEADING -->
  <tr><td style="padding:32px 32px 0;">
    <div style="font-size:22px;font-weight:700;color:{_TEXT_DARK};margin-bottom:4px;">Strategy Call Confirmed</div>
    <div style="font-size:14px;color:{_TEXT_MID};">Your appointment has been scheduled successfully.</div>
  </td></tr>

  <!-- PERSONAL MESSAGE -->
  <tr><td style="padding:20px 32px 0;">
    <div style="font-size:15px;color:{_TEXT_DARK};line-height:1.6;">
      Hi {_esc(lead.name)},<br><br>
      {_esc(ai_paragraph)}
    </div>
  </td></tr>

  <!-- CALL DETAILS CARD -->
  <tr><td style="padding:24px 32px 0;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid {_BORDER};border-radius:8px;overflow:hidden;">
      <tr><td style="background-color:{_DARK_BG};padding:12px 16px;border-bottom:1px solid {_BORDER};">
        <span style="font-size:13px;font-weight:700;color:{_TEXT_MID};text-transform:uppercase;letter-spacing:0.5px;">Call Details</span>
      </td></tr>
      <tr><td style="padding:0;">
        <table width="100%" cellpadding="0" cellspacing="0">
          {detail_rows}
        </table>
      </td></tr>
    </table>
  </td></tr>

  <!-- MEET BUTTON -->
  <tr><td style="padding:28px 32px 0;text-align:center;">
    <table cellpadding="0" cellspacing="0" style="margin:0 auto;"><tr>
      <td style="border-radius:6px;background-color:{_MEETING_COLOR};">
        <a href="{meet_url}" target="_blank" style="display:inline-block;padding:14px 40px;font-size:16px;font-weight:700;color:{_TEXT_LIGHT};text-decoration:none;">
          &#9654;&nbsp; {_esc(button_label)}
        </a>
      </td>
    </tr></table>
    <div style="margin-top:12px;font-size:12px;color:{_TEXT_MID};word-break:break-all;">
      {_esc(meet_display)}
    </div>
  </td></tr>

  {"<!-- RSVP BUTTONS -->" if rsvp_accept_url and rsvp_decline_url else ""}
  {f'''<tr><td style="padding:28px 32px 0;text-align:center;">
    <div style="font-size:14px;color:{_TEXT_MID};margin-bottom:16px;">Please let us know if you plan to attend:</div>
    <table cellpadding="0" cellspacing="0" style="margin:0 auto;"><tr>
      <td style="padding-right:12px;">
        <a href="{rsvp_accept_url}" style="display:inline-block;padding:12px 28px;font-size:14px;font-weight:700;color:#ffffff;background-color:#0d652d;border-radius:6px;text-decoration:none;">&#9989;&nbsp; Accept</a>
      </td>
      <td>
        <a href="{rsvp_decline_url}" style="display:inline-block;padding:12px 28px;font-size:14px;font-weight:700;color:#5f6368;background-color:#f1f3f4;border-radius:6px;text-decoration:none;">&#10060;&nbsp; Decline</a>
      </td>
    </tr></table>
  </td></tr>''' if rsvp_accept_url and rsvp_decline_url else ""}

  <!-- CLOSING -->
  <tr><td style="padding:28px 32px 0;">
    <div style="font-size:14px;color:{_TEXT_DARK};line-height:1.6;">
      We look forward to speaking with you and learning more about your goals.
    </div>
    <div style="font-size:14px;color:{_TEXT_DARK};margin-top:16px;">
      Best regards,<br>
      <strong>{_esc(b.company_name)}</strong>
    </div>
  </td></tr>

  <!-- FOOTER -->
  <tr><td style="padding:32px 32px 0;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid {_BORDER};">
      <tr><td style="padding:20px 0 0;">
        <div style="font-size:13px;color:{_TEXT_MID};line-height:1.6;">
          <strong>{_esc(b.company_name)}</strong><br>
          Strategy Call Team
        </div>
        <div style="font-size:13px;color:{_TEXT_MID};margin-top:10px;line-height:1.6;">
          If you need to reschedule or have questions, simply reply to this email.
        </div>
      </td></tr>
    </table>
  </td></tr>

  <!-- BOTTOM SPACER -->
  <tr><td style="height:24px;"></td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""


def _detail_row(label: str, value: str) -> str:
    """Single row for the call-details card. Value is HTML-escaped."""
    return (
        f'<tr><td style="padding:10px 16px;border-bottom:1px solid {_BORDER};width:130px;'
        f'font-size:13px;color:{_TEXT_MID};vertical-align:top;">{label}</td>'
        f'<td style="padding:10px 16px;border-bottom:1px solid {_BORDER};'
        f'font-size:14px;color:{_TEXT_DARK};font-weight:600;">{_esc(value)}</td></tr>'
    )


def build_confirmation_text(
    lead: Lead,
    meet_link: str | None,
    ai_paragraph: str,
    tz: ZoneInfo | None = None,
    branding: BrandingConfig | None = None,
    meeting_provider: str | None = None,
    rsvp_accept_url: str | None = None,
    rsvp_decline_url: str | None = None,
) -> str:
    """Return a clean plain-text fallback for the confirmation email.

    Phase 4: When ``rsvp_accept_url`` and ``rsvp_decline_url`` are
    provided, RSVP links are included in the plain-text body.
    """
    b = branding or BrandingConfig()
    tz = tz or ZoneInfo(settings.business_timezone)
    date_str, time_str = _fmt_datetime_local(lead.appt_datetime_utc, tz)
    company = _clean(lead.company_address)
    courses = _clean(lead.courses)
    meet_url = meet_link or "Link unavailable"

    lines = [
        f"Hi {lead.name},",
        "",
        ai_paragraph,
        "",
        "--- Call Details ---",
        f"Date:      {date_str}",
        f"Time:      {time_str}",
        f"Attendee:  {lead.name}",
    ]
    if company:
        lines.append(f"Company:   {company}")
    button_label = _meeting_button_label(meeting_provider)
    if courses:
        lines.append(f"Courses:   {courses}")
    lines += [
        "",
        f"{button_label}: {meet_url}",
        "",
    ]
    if rsvp_accept_url and rsvp_decline_url:
        lines += [
            "Please let us know if you plan to attend:",
            f"  Accept: {rsvp_accept_url}",
            f"  Decline: {rsvp_decline_url}",
            "",
        ]
    lines += [
        "We look forward to speaking with you.",
        "",
        "Best regards,",
        f"{b.company_name}",
        "",
        "---",
        f"{b.company_name}",
        "Strategy Call Team",
        "",
        "If you need to reschedule or have questions, simply reply to this email.",
    ]
    return "\n".join(lines)


# ── Reminder email ────────────────────────────────────────────────────────────

def build_reminder_subject(
    lead: Lead,
    local_time_str: str,
    branding: BrandingConfig | None = None,
) -> str:
    """Deterministic reminder email subject.

    Uses 'Today' because the daily 08:00 AM job sends same-day reminders.
    """
    b = branding or BrandingConfig()
    return f"Reminder: Your Strategy Call is Today — {b.company_name}"


def build_reminder_html(
    lead: Lead,
    meet_link: str | None,
    tz: ZoneInfo | None = None,
    branding: BrandingConfig | None = None,
    meeting_provider: str | None = None,
) -> str:
    """Return a complete HTML email body for the reminder email."""
    b = branding or BrandingConfig()
    tz = tz or ZoneInfo(settings.business_timezone)
    date_str, time_str = _fmt_datetime_local(lead.appt_datetime_utc, tz)
    courses = _clean(lead.courses)

    detail_rows = _detail_row("Date", date_str) + _detail_row("Time", time_str)
    if courses:
        detail_rows += _detail_row("Courses", courses)

    meet_url = meet_link or "#"
    meet_display = meet_link or "Link unavailable"
    button_label = _meeting_button_label(meeting_provider)

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:{_DARK_BG};font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background-color:{_DARK_BG};padding:24px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:{_WHITE};border-radius:8px;overflow:hidden;">

  <!-- HEADER -->
  <tr><td style="background-color:{b.brand_color};padding:28px 32px;text-align:center;">
    <div style="font-size:22px;font-weight:700;color:{_TEXT_LIGHT};letter-spacing:0.3px;">{_esc(b.company_name)}</div>
    <div style="font-size:13px;color:rgba(255,255,255,0.85);margin-top:6px;">{_esc(b.tagline) if b.tagline else ""}</div>
  </td></tr>

  <!-- HEADING -->
  <tr><td style="padding:32px 32px 0;">
    <div style="font-size:22px;font-weight:700;color:{_TEXT_DARK};margin-bottom:4px;">&#9200; Strategy Call Reminder</div>
    <div style="font-size:14px;color:{_TEXT_MID};">This is a friendly reminder about your upcoming call.</div>
  </td></tr>

  <!-- GREETING -->
  <tr><td style="padding:20px 32px 0;">
    <div style="font-size:15px;color:{_TEXT_DARK};line-height:1.6;">
      Hi {_esc(lead.name)},<br><br>
      This is a friendly reminder about your strategy call with {_esc(b.company_name)}. We look forward to speaking with you!
    </div>
  </td></tr>

  <!-- CALL DETAILS CARD -->
  <tr><td style="padding:24px 32px 0;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid {_BORDER};border-radius:8px;overflow:hidden;">
      <tr><td style="background-color:{_DARK_BG};padding:12px 16px;border-bottom:1px solid {_BORDER};">
        <span style="font-size:13px;font-weight:700;color:{_TEXT_MID};text-transform:uppercase;letter-spacing:0.5px;">Call Details</span>
      </td></tr>
      <tr><td style="padding:0;">
        <table width="100%" cellpadding="0" cellspacing="0">
          {detail_rows}
        </table>
      </td></tr>
    </table>
  </td></tr>

  <!-- MEET BUTTON -->
  <tr><td style="padding:28px 32px 0;text-align:center;">
    <table cellpadding="0" cellspacing="0" style="margin:0 auto;"><tr>
      <td style="border-radius:6px;background-color:{_MEETING_COLOR};">
        <a href="{meet_url}" target="_blank" style="display:inline-block;padding:14px 40px;font-size:16px;font-weight:700;color:{_TEXT_LIGHT};text-decoration:none;">
          &#9654;&nbsp; {_esc(button_label)}
        </a>
      </td>
    </tr></table>
    <div style="margin-top:12px;font-size:12px;color:{_TEXT_MID};word-break:break-all;">
      {_esc(meet_display)}
    </div>
  </td></tr>

  <!-- CLOSING -->
  <tr><td style="padding:28px 32px 0;">
    <div style="font-size:14px;color:{_TEXT_DARK};line-height:1.6;">
      If you need to reschedule or have questions, simply reply to this email.
    </div>
    <div style="font-size:14px;color:{_TEXT_DARK};margin-top:16px;">
      Best regards,<br>
      <strong>{_esc(b.company_name)}</strong>
    </div>
  </td></tr>

  <!-- FOOTER -->
  <tr><td style="padding:32px 32px 0;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid {_BORDER};">
      <tr><td style="padding:20px 0 0;">
        <div style="font-size:13px;color:{_TEXT_MID};line-height:1.6;">
          <strong>{_esc(b.company_name)}</strong><br>
          Strategy Call Team
        </div>
      </td></tr>
    </table>
  </td></tr>

  <tr><td style="height:24px;"></td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""


def build_reminder_text(
    lead: Lead,
    meet_link: str | None,
    tz: ZoneInfo | None = None,
    branding: BrandingConfig | None = None,
    meeting_provider: str | None = None,
) -> str:
    """Return a clean plain-text fallback for the reminder email."""
    b = branding or BrandingConfig()
    tz = tz or ZoneInfo(settings.business_timezone)
    date_str, time_str = _fmt_datetime_local(lead.appt_datetime_utc, tz)
    courses = _clean(lead.courses)
    meet_url = meet_link or "Link unavailable"

    lines = [
        f"Hi {lead.name},",
        "",
        "This is a friendly reminder about your strategy call with "
        f"{b.company_name}.",
        "",
        f"Date:  {date_str}",
        f"Time:  {time_str}",
    ]
    button_label = _meeting_button_label(meeting_provider)
    if courses:
        lines.append(f"Courses: {courses}")
    lines += [
        "",
        f"{button_label}: {meet_url}",
        "",
        "If you need to reschedule or have questions, simply reply to this email.",
        "",
        "Best regards,",
        f"{b.company_name}",
    ]
    return "\n".join(lines)


# ── Overdue follow-up email ──────────────────────────────────────────────────


def build_overdue_followup_subject(
    followup_title: str,
    lead_name: str,
    branding: BrandingConfig | None = None,
) -> str:
    """Deterministic subject line for overdue follow-up notification."""
    b = branding or BrandingConfig()
    return f"Overdue Follow-Up: {followup_title} ({lead_name}) — {b.company_name}"


def build_overdue_followup_html(
    followup_title: str,
    lead_name: str,
    due_at_utc: datetime | None,
    priority: str,
    notes: str | None,
    tz: ZoneInfo | None = None,
    branding: BrandingConfig | None = None,
) -> str:
    """Return a complete HTML email body for the overdue follow-up notification.

    This email is sent to the team (assigned user or owner) to notify them
    that a follow-up task is past due and needs attention.
    """
    b = branding or BrandingConfig()
    tz = tz or ZoneInfo(settings.business_timezone)
    due_date_str, due_time_str = _fmt_datetime_local(due_at_utc, tz)

    # Priority badge color
    priority_colors = {
        "low": "#5f6368",
        "medium": "#1a73e8",
        "high": "#e37400",
        "urgent": "#d93025",
    }
    priority_color = priority_colors.get(priority, "#5f6368")

    # Detail rows
    detail_rows = ""
    detail_rows += _detail_row("Follow-Up", followup_title)
    detail_rows += _detail_row("Lead", lead_name)
    detail_rows += _detail_row("Due Date", due_date_str)
    detail_rows += _detail_row("Due Time", due_time_str)
    detail_rows += (
        f'<tr><td style="padding:10px 16px;border-bottom:1px solid {_BORDER};width:130px;'
        f'font-size:13px;color:{_TEXT_MID};vertical-align:top;">Priority</td>'
        f'<td style="padding:10px 16px;border-bottom:1px solid {_BORDER};'
        f'font-size:14px;color:{priority_color};font-weight:700;">{_esc(priority.upper())}</td></tr>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:{_DARK_BG};font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background-color:{_DARK_BG};padding:24px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:{_WHITE};border-radius:8px;overflow:hidden;">

  <!-- HEADER -->
  <tr><td style="background-color:{b.brand_color};padding:28px 32px;text-align:center;">
    <div style="font-size:22px;font-weight:700;color:{_TEXT_LIGHT};letter-spacing:0.3px;">{_esc(b.company_name)}</div>
    <div style="font-size:13px;color:rgba(255,255,255,0.85);margin-top:6px;">{_esc(b.tagline) if b.tagline else ""}</div>
  </td></tr>

  <!-- HEADING -->
  <tr><td style="padding:32px 32px 0;">
    <div style="font-size:22px;font-weight:700;color:#d93025;margin-bottom:4px;">&#9888;&#65039; Overdue Follow-Up</div>
    <div style="font-size:14px;color:{_TEXT_MID};">A follow-up task is past due and needs your attention.</div>
  </td></tr>

  <!-- GREETING -->
  <tr><td style="padding:20px 32px 0;">
    <div style="font-size:15px;color:{_TEXT_DARK};line-height:1.6;">
      Hi,<br><br>
      The following follow-up task associated with <strong>{_esc(lead_name)}</strong> is overdue.
      Please review and take appropriate action.
    </div>
  </td></tr>

  <!-- FOLLOW-UP DETAILS CARD -->
  <tr><td style="padding:24px 32px 0;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid {_BORDER};border-radius:8px;overflow:hidden;">
      <tr><td style="background-color:{_DARK_BG};padding:12px 16px;border-bottom:1px solid {_BORDER};">
        <span style="font-size:13px;font-weight:700;color:{_TEXT_MID};text-transform:uppercase;letter-spacing:0.5px;">Follow-Up Details</span>
      </td></tr>
      <tr><td style="padding:0;">
        <table width="100%" cellpadding="0" cellspacing="0">
          {detail_rows}
        </table>
      </td></tr>
    </table>
  </td></tr>

  {"<!-- NOTES -->" if notes else ""}
  {f'''<tr><td style="padding:20px 32px 0;">
    <div style="font-size:14px;color:{_TEXT_DARK};line-height:1.6;">
      <strong>Notes:</strong><br>
      {_esc(notes)}
    </div>
  </td></tr>''' if notes else ""}

  <!-- CLOSING -->
  <tr><td style="padding:28px 32px 0;">
    <div style="font-size:14px;color:{_TEXT_DARK};line-height:1.6;">
      Please log in to the dashboard to review and update this follow-up.
    </div>
    <div style="font-size:14px;color:{_TEXT_DARK};margin-top:16px;">
      Best regards,<br>
      <strong>{_esc(b.company_name)}</strong>
    </div>
  </td></tr>

  <!-- FOOTER -->
  <tr><td style="padding:32px 32px 0;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid {_BORDER};">
      <tr><td style="padding:20px 0 0;">
        <div style="font-size:13px;color:{_TEXT_MID};line-height:1.6;">
          <strong>{_esc(b.company_name)}</strong><br>
          Strategy Call Team
        </div>
      </td></tr>
    </table>
  </td></tr>

  <tr><td style="height:24px;"></td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""


def build_overdue_followup_text(
    followup_title: str,
    lead_name: str,
    due_at_utc: datetime | None,
    priority: str,
    notes: str | None,
    tz: ZoneInfo | None = None,
    branding: BrandingConfig | None = None,
) -> str:
    """Return a clean plain-text fallback for the overdue follow-up email."""
    b = branding or BrandingConfig()
    tz = tz or ZoneInfo(settings.business_timezone)
    due_date_str, due_time_str = _fmt_datetime_local(due_at_utc, tz)

    lines = [
        "Hi,",
        "",
        f"The following follow-up task associated with {lead_name} is overdue.",
        "Please review and take appropriate action.",
        "",
        "--- Follow-Up Details ---",
        f"Follow-Up:  {followup_title}",
        f"Lead:       {lead_name}",
        f"Due Date:   {due_date_str}",
        f"Due Time:   {due_time_str}",
        f"Priority:   {priority.upper()}",
    ]
    if notes:
        lines += ["", "Notes:", notes]
    lines += [
        "",
        "Please log in to the dashboard to review and update this follow-up.",
        "",
        "Best regards,",
        f"{b.company_name}",
    ]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# PASSWORD RESET EMAIL (Phase 20 P1-A)
# ══════════════════════════════════════════════════════════════════════════════


def build_password_reset_subject() -> str:
    """Subject line for password reset email."""
    return "Reset Your Password"


def build_password_reset_html(
    reset_url: str,
    b: BrandingConfig,
    expiry_minutes: int = 30,
) -> str:
    """HTML body for password reset email.

    Args:
        reset_url: Full URL containing the reset token.
        b: Branding configuration (company name, brand color, etc.).
        expiry_minutes: Token expiry in minutes (for display).

    Returns:
        Complete HTML email body.
    """
    brand_color = _html.escape(b.brand_color or settings.brand_color_default)
    company = _html.escape(b.company_name)
    tagline = _html.escape(b.tagline) if b.tagline else ""

    return f"""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:{_DARK_BG};font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:{_DARK_BG};padding:24px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:{_WHITE};border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.12);">
  <!-- Header -->
  <tr><td style="background:{brand_color};padding:24px 32px;">
    <h1 style="margin:0;color:{_TEXT_LIGHT};font-size:20px;font-weight:600;">
      Password Reset Request
    </h1>
    <p style="margin:4px 0 0;color:rgba(255,255,255,0.85);font-size:13px;">
      {company}
    </p>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:32px;">
    <p style="margin:0 0 16px;color:{_TEXT_DARK};font-size:15px;line-height:1.5;">
      We received a request to reset the password for your account.
    </p>
    <p style="margin:0 0 24px;color:{_TEXT_DARK};font-size:15px;line-height:1.5;">
      Click the button below to choose a new password. This link expires
      in <strong>{expiry_minutes} minutes</strong>.
    </p>
    <table cellpadding="0" cellspacing="0" style="margin:0 auto;">
      <tr><td style="background:{brand_color};border-radius:6px;">
        <a href="{_html.escape(reset_url)}"
           style="display:inline-block;padding:12px 32px;color:{_TEXT_LIGHT};
                  font-size:15px;font-weight:600;text-decoration:none;">
          Reset Password
        </a>
      </td></tr>
    </table>
    <p style="margin:24px 0 0;color:{_TEXT_MID};font-size:13px;line-height:1.5;">
      If you did not request a password reset, you can safely ignore this
      email. Your password will not be changed.
    </p>
  </td></tr>

  <!-- Footer -->
  <tr><td style="background:{_FOOTER_BG};padding:16px 32px;border-top:1px solid {_BORDER};">
    <p style="margin:0;color:{_TEXT_MID};font-size:12px;text-align:center;">
      {company}
      {f'&nbsp;&bull;&nbsp;{_html.escape(tagline)}' if tagline else ''}
    </p>
  </td></tr>
</table>
</td></tr>
</table>
</body>
</html>"""


def build_password_reset_text(
    reset_url: str,
    b: BrandingConfig,
    expiry_minutes: int = 30,
) -> str:
    """Plain-text body for password reset email.

    Args:
        reset_url: Full URL containing the reset token.
        b: Branding configuration.
        expiry_minutes: Token expiry in minutes (for display).

    Returns:
        Plain-text email body.
    """
    lines = [
        "Password Reset Request",
        "",
        "We received a request to reset the password for your account.",
        "",
        "Click the link below to choose a new password. This link expires",
        f"in {expiry_minutes} minutes:",
        "",
        f"  {reset_url}",
        "",
        "If you did not request a password reset, you can safely ignore this",
        "email. Your password will not be changed.",
        "",
        "Best regards,",
        f"{b.company_name}",
    ]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# OUTREACH EMAIL TEMPLATES (Phase 7 Part 2)
# ══════════════════════════════════════════════════════════════════════════════

# Mapping from call outcome → outreach content.
# Each entry provides:
#   - subject_suffix: appended after "Following Up — " to form the subject
#   - greeting: greeting prefix shown before lead name (HTML-safe)
#   - body_paragraph: main customer-facing body content
_OUTREACH_CONTENT: dict[str, dict[str, str]] = {
    "connected": {
        "subject_suffix": "Great Talking With You",
        "greeting": "Thank you for taking the time to speak with us.",
        "body_paragraph": (
            "We enjoyed learning about your goals and believe we can help. "
            "As discussed, we would love to share a tailored proposal "
            "that outlines how we can support you."
        ),
    },
    "completed": {
        "subject_suffix": "Next Steps",
        "greeting": "Thank you for the productive conversation.",
        "body_paragraph": (
            "We appreciate you sharing your objectives with us. "
            "We will be following up shortly with a proposal that "
            "addresses your specific needs."
        ),
    },
    "voicemail": {
        "subject_suffix": "Trying to Reach You",
        "greeting": "We tried reaching you but were unable to connect.",
        "body_paragraph": (
            "We left a voicemail and wanted to follow up via email as well. "
            "Please let us know a convenient time to reconnect, or feel free "
            "to reply to this email and we will get back to you."
        ),
    },
    "no_answer": {
        "subject_suffix": "Following Up on Our Call",
        "greeting": "We were unable to reach you by phone.",
        "body_paragraph": (
            "We understand schedules can be busy. If you are still interested "
            "in learning about our services, please let us know a time that "
            "works better for you, or feel free to reply to this email."
        ),
    },
    "busy": {
        "subject_suffix": "Following Up on Our Call",
        "greeting": "We understand you were unavailable when we called.",
        "body_paragraph": (
            "We wanted to follow up to see if there is a better time to "
            "connect. Please let us know when you are available, or feel "
            "free to reply to this email."
        ),
    },
    "rescheduled": {
        "subject_suffix": "Confirming Your Updated Appointment",
        "greeting": "We wanted to confirm the updated details of your call.",
        "body_paragraph": (
            "Your appointment has been rescheduled. Please verify the new "
            "date and time below. If anything has changed, simply reply to "
            "this email and we will be happy to accommodate."
        ),
    },
    "wrong_number": {
        "subject_suffix": "Verifying Your Contact Information",
        "greeting": "It looks like we may have reached the wrong number.",
        "body_paragraph": (
            "We want to make sure we have the correct contact details for "
            "you. If this was a mistake, no action is needed. If you would "
            "still like to connect, please reply to this email with your "
            "preferred contact information."
        ),
    },
    "no_show": {
        "subject_suffix": "Would Like to Reschedule",
        "greeting": "We missed you at your scheduled call.",
        "body_paragraph": (
            "We understand things come up. We would love to reschedule at a "
            "time that works better for you. Please reply with your "
            "preferred date and time, and we will make it happen."
        ),
    },
}


def _greeting(lead_name: str | None) -> str:
    """Return a safe, personalized greeting.  Never returns empty."""
    if lead_name and str(lead_name).strip():
        return f"Hi {_esc(lead_name.strip())},"
    return "Hi there,"


def _greeting_text(lead_name: str | None) -> str:
    """Return a plain-text greeting.  Never returns empty."""
    if lead_name and str(lead_name).strip():
        return f"Hi {lead_name.strip()},"
    return "Hi there,"


def _safe_company(lead: Lead) -> str:
    """Return raw company name or empty string.

    Note: the value is NOT HTML-escaped here because _detail_row()
    applies _esc() itself.  Returning pre-escaped text would cause
    double-escaping (e.g. ``&amp;amp;``).
    """
    val = getattr(lead, "company_address", None)
    if val and str(val).strip() and str(val).strip() not in ("", "N/A", "None"):
        return str(val).strip()
    return ""


def _safe_company_text(lead: Lead) -> str:
    """Return plain-text company name or empty string."""
    val = getattr(lead, "company_address", None)
    if val and str(val).strip() and str(val).strip() not in ("", "N/A", "None"):
        return str(val).strip()
    return ""


def build_outreach_subject(
    call_outcome: str,
    branding: BrandingConfig | None = None,
) -> str:
    """Deterministic subject line for a customer-facing outreach email.

    Returns a professional subject based on the call outcome.
    Falls back to a generic subject for unrecognized outcomes.
    """
    b = branding or BrandingConfig()
    content = _OUTREACH_CONTENT.get(call_outcome)
    if content:
        return f"Following Up — {content['subject_suffix']} — {b.company_name}"
    return f"Following Up — {b.company_name}"


def build_outreach_html(
    lead: Lead,
    call_outcome: str,
    branding: BrandingConfig | None = None,
) -> str:
    """Return a complete branded HTML email body for a customer-facing outreach.

    The template is outcome-aware: different call outcomes produce different
    body copy.  Lead data is safely escaped.  Missing optional fields are
    gracefully handled.
    """
    b = branding or BrandingConfig()
    _greeting(lead.name)
    content = _OUTREACH_CONTENT.get(call_outcome)

    if content:
        subject_line = f"Following Up — {content['subject_suffix']}"
        body_paragraph = _esc(content["body_paragraph"])
    else:
        subject_line = "Following Up"
        body_paragraph = "This is a follow-up from our team."

    company = _safe_company(lead)

    # If a name was used, greeting is "Hi {name}," — else "Hi there,"
    if lead.name and str(lead.name).strip():
        greeting_display = f"Hi {_esc(lead.name.strip())},"
    else:
        greeting_display = "Hi there,"

    company_row = ""
    if company:
        company_row = _detail_row("Company", company)

    # Determine body intro based on outcome
    if content:
        body_intro = _esc(content["greeting"])
    else:
        body_intro = "We wanted to follow up regarding your recent inquiry."

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:{_DARK_BG};font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background-color:{_DARK_BG};padding:24px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:{_WHITE};border-radius:8px;overflow:hidden;">

  <!-- HEADER -->
  <tr><td style="background-color:{b.brand_color};padding:28px 32px;text-align:center;">
    <div style="font-size:22px;font-weight:700;color:{_TEXT_LIGHT};letter-spacing:0.3px;">{_esc(b.company_name)}</div>
    <div style="font-size:13px;color:rgba(255,255,255,0.85);margin-top:6px;">{_esc(b.tagline) if b.tagline else ""}</div>
  </td></tr>

  <!-- HEADING -->
  <tr><td style="padding:32px 32px 0;">
    <div style="font-size:22px;font-weight:700;color:{_TEXT_DARK};margin-bottom:4px;">{_esc(subject_line)}</div>
  </td></tr>

  <!-- PERSONAL MESSAGE -->
  <tr><td style="padding:20px 32px 0;">
    <div style="font-size:15px;color:{_TEXT_DARK};line-height:1.6;">
      {greeting_display}<br><br>
      {body_intro}
    </div>
  </td></tr>

  <!-- BODY PARAGRAPH -->
  <tr><td style="padding:20px 32px 0;">
    <div style="font-size:15px;color:{_TEXT_DARK};line-height:1.6;">
      {body_paragraph}
    </div>
  </td></tr>

  <!-- COMPANY CARD (if available) -->
  {f'''<tr><td style="padding:24px 32px 0;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid {_BORDER};border-radius:8px;overflow:hidden;">
      <tr><td style="background-color:{_DARK_BG};padding:12px 16px;border-bottom:1px solid {_BORDER};">
        <span style="font-size:13px;font-weight:700;color:{_TEXT_MID};text-transform:uppercase;letter-spacing:0.5px;">Details</span>
      </td></tr>
      <tr><td style="padding:0;">
        <table width="100%" cellpadding="0" cellspacing="0">
          {company_row}
        </table>
      </td></tr>
    </table>
  </td></tr>''' if company else ""}

  <!-- CLOSING -->
  <tr><td style="padding:28px 32px 0;">
    <div style="font-size:14px;color:{_TEXT_DARK};line-height:1.6;">
      If you have any questions, simply reply to this email and we will
      be happy to help.
    </div>
    <div style="font-size:14px;color:{_TEXT_DARK};margin-top:16px;">
      Best regards,<br>
      <strong>{_esc(b.company_name)}</strong>
    </div>
  </td></tr>

  <!-- FOOTER -->
  <tr><td style="padding:32px 32px 0;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid {_BORDER};">
      <tr><td style="padding:20px 0 0;">
        <div style="font-size:13px;color:{_TEXT_MID};line-height:1.6;">
          <strong>{_esc(b.company_name)}</strong><br>
          Strategy Call Team
        </div>
        <div style="font-size:13px;color:{_TEXT_MID};margin-top:10px;line-height:1.6;">
          If you need to reschedule or have questions, simply reply to this email.
        </div>
      </td></tr>
    </table>
  </td></tr>

  <tr><td style="height:24px;"></td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""


def build_outreach_text(
    lead: Lead,
    call_outcome: str,
    branding: BrandingConfig | None = None,
) -> str:
    """Return a plain-text body for a customer-facing outreach email.

    Matches the content of :func:`build_outreach_html` but in plain-text format.
    """
    b = branding or BrandingConfig()
    name_text = _greeting_text(lead.name)
    content = _OUTREACH_CONTENT.get(call_outcome)
    company = _safe_company_text(lead)

    if content:
        f"Following Up — {content['subject_suffix']}"
        body_intro = content["greeting"]
        body_paragraph = content["body_paragraph"]
    else:
        body_intro = "We wanted to follow up regarding your recent inquiry."
        body_paragraph = "This is a follow-up from our team."

    lines = [
        name_text,
        "",
        body_intro,
        "",
        body_paragraph,
    ]

    if company:
        lines += [
            "",
            f"Company: {company}",
        ]

    lines += [
        "",
        "If you have any questions, simply reply to this email and we will "
        "be happy to help.",
        "",
        "Best regards,",
        f"{b.company_name}",
        "",
        "---",
        f"{b.company_name}",
        "Strategy Call Team",
        "",
        "If you need to reschedule or have questions, simply reply to this email.",
    ]
    return "\n".join(lines)


def build_outreach_email(
    lead: Lead,
    call_outcome: str,
    branding: BrandingConfig | None = None,
) -> dict[str, str]:
    """Convenience function: render a complete outreach email as a dict.

    Returns::

        {
            "subject": "...",
            "html": "...",
            "text": "...",
        }

    This is the primary integration point for the Part 1 email sender.
    """
    return {
        "subject": build_outreach_subject(call_outcome, branding),
        "html": build_outreach_html(lead, call_outcome, branding),
        "text": build_outreach_text(lead, call_outcome, branding),
    }
