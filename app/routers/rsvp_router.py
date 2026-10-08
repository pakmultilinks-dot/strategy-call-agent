"""Public RSVP routes for customer Accept/Decline workflow (Phase 4).

These routes are UNAUTHENTICATED — security is provided by the
cryptographic RSVP tokens embedded in confirmation emails.

Routes:
  GET /rsvp/{token} — Process RSVP and show landing page.

Token security:
  - SHA-256 hashed lookup (not plaintext).
  - Single-use (consumed=True after use).
  - Time-limited (30-day expiry).
  - Scoped to a specific lead + organization.
"""
from __future__ import annotations

import logging
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.config import settings

logger = logging.getLogger("strategy-call-agent.rsvp-router")

router = APIRouter(tags=["rsvp"])


@router.get("/rsvp/{token}", response_class=HTMLResponse)
def process_rsvp(token: str, request: Request) -> HTMLResponse:
    """Validate an RSVP token and show the result landing page.

    The token is a random URL-safe string generated during pipeline
    completion and embedded in the confirmation email's Accept/Decline
    buttons.

    Security:
      - Token is hashed (SHA-256) for DB lookup.
      - Single-use: once consumed, re-clicking shows 'already processed'.
      - Time-limited: expired tokens show 'link expired'.
      - Scoped: each token is tied to a specific lead + org.
    """
    from app.database import SessionLocal
    from app.services.rsvp_token_service import validate_and_process_rsvp

    db = SessionLocal()
    try:
        result = validate_and_process_rsvp(db, token)
    finally:
        db.close()

    # Build the HTML landing page
    tz = ZoneInfo(settings.business_timezone)

    if result.not_found:
        return HTMLResponse(
            content=_build_landing_page(
                title="Invalid Link",
                heading="Invalid RSVP Link",
                heading_color="#d93025",
                icon="&#10060;",
                message="This RSVP link is not valid. Please check the link in your confirmation email.",
            ),
            status_code=404,
        )

    if result.expired:
        return HTMLResponse(
            content=_build_landing_page(
                title="Link Expired",
                heading="RSVP Link Expired",
                heading_color="#d93025",
                icon="&#9200;",
                message="This RSVP link has expired. Please contact us to schedule a new call.",
            ),
            status_code=410,
        )

    if result.already_used:
        if result.choice == "accept":
            return HTMLResponse(
                content=_build_landing_page(
                    title="Already Confirmed",
                    heading="Already Confirmed",
                    heading_color="#0d652d",
                    icon="&#9989;",
                    message="You have already confirmed this strategy call. We look forward to speaking with you!",
                ),
                status_code=200,
            )
        else:
            return HTMLResponse(
                content=_build_landing_page(
                    title="Already Declined",
                    heading="Already Declined",
                    heading_color="#5f6368",
                    icon="&#10060;",
                    message="You have already declined this strategy call. If this was a mistake, please contact us.",
                ),
                status_code=200,
            )

    if result.error and not result.success:
        return HTMLResponse(
            content=_build_landing_page(
                title="RSVP Error",
                heading="Unable to Process RSVP",
                heading_color="#d93025",
                icon="&#9888;&#65039;",
                message=result.error,
            ),
            status_code=400,
        )

    # Success
    if result.choice == "accept":
        return HTMLResponse(
            content=_build_landing_page(
                title="Call Confirmed",
                heading="Strategy Call Confirmed!",
                heading_color="#0d652d",
                icon="&#9989;",
                message=(
                    f"Thank you, {result.lead_name}! Your strategy call has been confirmed. "
                    "We look forward to speaking with you."
                ),
                show_details=True,
                lead_name=result.lead_name,
                company_address=result.company_address,
                appt_datetime_utc=result.appt_datetime_utc,
                tz=tz,
            ),
            status_code=200,
        )
    else:
        return HTMLResponse(
            content=_build_landing_page(
                title="Call Declined",
                heading="Strategy Call Declined",
                heading_color="#5f6368",
                icon="&#10060;",
                message=(
                    f"Thank you, {result.lead_name}. We've noted that you won't be "
                    "attending this strategy call. If this was a mistake, please "
                    "contact us to reschedule."
                ),
            ),
            status_code=200,
        )


def _fmt_datetime_local(dt_utc, tz: ZoneInfo) -> tuple[str, str]:
    """Return (date_str, time_str) in the given timezone."""
    if dt_utc is None:
        return ("TBD", "TBD")
    local = dt_utc.astimezone(tz)
    date_str = local.strftime("%B %d, %Y").lstrip("0")
    hour = local.hour % 12 or 12
    ampm = "AM" if local.hour < 12 else "PM"
    time_str = f"{hour}:{local.minute:02d} {ampm} {local.tzname()}"
    return (date_str, time_str)


def _build_landing_page(
    title: str,
    heading: str,
    heading_color: str,
    icon: str,
    message: str,
    show_details: bool = False,
    lead_name: str | None = None,
    company_address: str | None = None,
    appt_datetime_utc=None,
    tz: ZoneInfo | None = None,
) -> str:
    """Build a clean, branded HTML landing page for RSVP results."""
    import html as _html
    def _esc(v: str) -> str:
        return _html.escape(v, quote=True)

    details_html = ""
    if show_details and appt_datetime_utc and tz:
        date_str, time_str = _fmt_datetime_local(appt_datetime_utc, tz)
        details_html = f"""
    <!-- DETAILS CARD -->
    <div style="margin-top:24px;padding:16px;background-color:#f8f9fa;border:1px solid #dadce0;border-radius:8px;text-align:left;">
      <div style="font-size:13px;font-weight:700;color:#5f6368;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px;">Appointment Details</div>
      <div style="font-size:14px;color:#202124;line-height:1.8;">
        <strong>Date:</strong> {_esc(date_str)}<br>
        <strong>Time:</strong> {_esc(time_str)}<br>
        {"<strong>Company:</strong> " + _esc(company_address) + "<br>" if company_address else ""}
      </div>
    </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_esc(title)} — Strategy Call Agent</title>
</head>
<body style="margin:0;padding:0;background-color:#f8f9fa;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f8f9fa;padding:24px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#ffffff;border-radius:8px;overflow:hidden;">

  <!-- HEADING -->
  <tr><td style="padding:40px 32px 0;text-align:center;">
    <div style="font-size:48px;margin-bottom:16px;">{icon}</div>
    <div style="font-size:24px;font-weight:700;color:{heading_color};margin-bottom:8px;">{_esc(heading)}</div>
    <div style="font-size:15px;color:#5f6368;line-height:1.6;">{_esc(message)}</div>
    {details_html}
  </td></tr>

  <!-- FOOTER -->
  <tr><td style="padding:40px 32px 0;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #dadce0;">
      <tr><td style="padding:20px 0 0;">
        <div style="font-size:13px;color:#5f6368;line-height:1.6;">
          Strategy Call Agent
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
