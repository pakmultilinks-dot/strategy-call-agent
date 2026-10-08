"""Org notification when a prospect declines (Phase 4).

Sends an email to the organization's configured notification address
(or fallback owner email) when a lead declines their strategy call via
the RSVP link.

This is a best-effort notification — failures are logged but never
block the RSVP processing flow.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Lead
from app.services.email_service import EmailService
from app.services.integration_config_resolver import BrandingConfig
from app.services.org_context import OrganizationContext

logger = logging.getLogger("strategy-call-agent.decline-notification")


def send_decline_notification(
    db: Session,
    lead: Lead,
) -> None:
    """Send an org notification email when a lead declines.

    Sends to the organization's configured notification email (if any)
    or falls back to the platform admin.  Never raises — all exceptions
    are caught and logged.

    Args:
        db: Database session.
        lead: The lead that declined.
    """
    if lead.organization_id is None:
        logger.warning(
            "send_decline_notification: lead %s has no organization_id", lead.id
        )
        return

    # Resolve org context and branding
    org_ctx = OrganizationContext.from_id(lead.organization_id)
    branding = BrandingConfig()
    sender_email = settings.gmail_sender
    notification_email = None

    if org_ctx is not None:
        try:
            from app.services.integration_config_resolver import (
                IntegrationConfigResolver,
            )
            branding = IntegrationConfigResolver.resolve_branding(
                db, lead.organization_id
            )
            gmail_config = IntegrationConfigResolver.resolve_gmail_config(
                db, lead.organization_id
            )
            sender_email = gmail_config.sender_email
        except Exception:
            logger.debug(
                "could not resolve org branding for decline notification; "
                "using platform defaults"
            )

    # Determine notification recipient
    # Use the org's sender_email as the notification target (it's the
    # business owner's configured email).  Fall back to platform gmail_sender.
    notification_email = sender_email

    if not notification_email:
        logger.warning(
            "send_decline_notification: no notification email for lead %s org=%s",
            lead.id, lead.organization_id,
        )
        return

    # Format appointment time
    tz = ZoneInfo(settings.business_timezone)
    appt_str = "N/A"
    if lead.appt_datetime_utc:
        local = lead.appt_datetime_utc.astimezone(tz)
        appt_str = local.strftime("%B %d, %Y at %I:%M %p %Z").lstrip("0")

    subject = f"Declined: {lead.name} declined their strategy call — {branding.company_name}"

    # Build HTML email
    html_body = _build_decline_notification_html(
        lead_name=lead.name or "Unknown",
        company_address=lead.company_address or "",
        lead_email=lead.email or "N/A",
        appt_str=appt_str,
        branding=branding,
    )

    # Build plain-text fallback
    text_body = _build_decline_notification_text(
        lead_name=lead.name or "Unknown",
        company_address=lead.company_address or "",
        lead_email=lead.email or "N/A",
        appt_str=appt_str,
        branding=branding,
    )

    try:
        svc = EmailService(org_context=org_ctx, db=db)
        msg_id = svc.send_email(
            to=notification_email,
            subject=subject,
            plain_body=text_body,
            db=db,
            html_body=html_body,
        )
        logger.info(
            "decline notification sent: lead=%s to=%s msg_id=%s",
            lead.id, notification_email, msg_id,
        )
    except Exception as exc:
        logger.warning(
            "decline notification send failed for lead %s: %s",
            lead.id, exc,
        )


# ── HTML template ────────────────────────────────────────────────────────────

_DARK_BG = "#f8f9fa"
_WHITE = "#ffffff"
_TEXT_DARK = "#202124"
_TEXT_MID = "#5f6368"
_TEXT_LIGHT = "#ffffff"
_BORDER = "#dadce0"


def _build_decline_notification_html(
    lead_name: str,
    company_address: str,
    lead_email: str,
    appt_str: str,
    branding: BrandingConfig,
) -> str:
    """Build HTML email for org decline notification."""
    import html as _html
    def _esc(v: str) -> str:
        return _html.escape(v, quote=True)

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:{_DARK_BG};font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background-color:{_DARK_BG};padding:24px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:{_WHITE};border-radius:8px;overflow:hidden;">

  <!-- HEADER -->
  <tr><td style="background-color:{branding.brand_color};padding:28px 32px;text-align:center;">
    <div style="font-size:22px;font-weight:700;color:{_TEXT_LIGHT};letter-spacing:0.3px;">{_esc(branding.company_name)}</div>
  </td></tr>

  <!-- HEADING -->
  <tr><td style="padding:32px 32px 0;">
    <div style="font-size:22px;font-weight:700;color:#d93025;margin-bottom:4px;">&#10060; Strategy Call Declined</div>
    <div style="font-size:14px;color:{_TEXT_MID};">A prospect has declined their scheduled strategy call.</div>
  </td></tr>

  <!-- DETAILS CARD -->
  <tr><td style="padding:24px 32px 0;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid {_BORDER};border-radius:8px;overflow:hidden;">
      <tr><td style="background-color:{_DARK_BG};padding:12px 16px;border-bottom:1px solid {_BORDER};">
        <span style="font-size:13px;font-weight:700;color:{_TEXT_MID};text-transform:uppercase;letter-spacing:0.5px;">Declined Details</span>
      </td></tr>
      <tr><td style="padding:0;">
        <table width="100%" cellpadding="0" cellspacing="0">
          {f'<tr><td style="padding:10px 16px;border-bottom:1px solid {_BORDER};width:130px;font-size:13px;color:{_TEXT_MID};vertical-align:top;">Prospect</td><td style="padding:10px 16px;border-bottom:1px solid {_BORDER};font-size:14px;color:{_TEXT_DARK};font-weight:600;">{_esc(lead_name)}</td></tr>'}
          {f'<tr><td style="padding:10px 16px;border-bottom:1px solid {_BORDER};width:130px;font-size:13px;color:{_TEXT_MID};vertical-align:top;">Email</td><td style="padding:10px 16px;border-bottom:1px solid {_BORDER};font-size:14px;color:{_TEXT_DARK};font-weight:600;">{_esc(lead_email)}</td></tr>' if lead_email and lead_email != "N/A" else ""}
          {f'<tr><td style="padding:10px 16px;border-bottom:1px solid {_BORDER};width:130px;font-size:13px;color:{_TEXT_MID};vertical-align:top;">Company</td><td style="padding:10px 16px;border-bottom:1px solid {_BORDER};font-size:14px;color:{_TEXT_DARK};font-weight:600;">{_esc(company_address)}</td></tr>' if company_address else ""}
          {f'<tr><td style="padding:10px 16px;border-bottom:1px solid {_BORDER};width:130px;font-size:13px;color:{_TEXT_MID};vertical-align:top;">Appointment</td><td style="padding:10px 16px;border-bottom:1px solid {_BORDER};font-size:14px;color:{_TEXT_DARK};font-weight:600;">{_esc(appt_str)}</td></tr>'}
        </table>
      </td></tr>
    </table>
  </td></tr>

  <!-- CLOSING -->
  <tr><td style="padding:28px 32px 0;">
    <div style="font-size:14px;color:{_TEXT_DARK};line-height:1.6;">
      The calendar event has been removed and the time slot is now available.
      No further follow-up emails will be sent to this prospect.
    </div>
    <div style="font-size:14px;color:{_TEXT_DARK};margin-top:16px;">
      Best regards,<br>
      <strong>{_esc(branding.company_name)}</strong>
    </div>
  </td></tr>

  <!-- FOOTER -->
  <tr><td style="padding:32px 32px 0;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid {_BORDER};">
      <tr><td style="padding:20px 0 0;">
        <div style="font-size:13px;color:{_TEXT_MID};line-height:1.6;">
          <strong>{_esc(branding.company_name)}</strong><br>
          Strategy Call Agent — Automated Notification
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


def _build_decline_notification_text(
    lead_name: str,
    company_address: str,
    lead_email: str,
    appt_str: str,
    branding: BrandingConfig,
) -> str:
    """Build plain-text email for org decline notification."""
    lines = [
        "Strategy Call Declined",
        "",
        f"A prospect has declined their scheduled strategy call.",
        "",
        "--- Declined Details ---",
        f"Prospect:   {lead_name}",
    ]
    if lead_email and lead_email != "N/A":
        lines.append(f"Email:      {lead_email}")
    if company_address:
        lines.append(f"Company:    {company_address}")
    lines += [
        f"Appointment: {appt_str}",
        "",
        "The calendar event has been removed and the time slot is now available.",
        "No further follow-up emails will be sent to this prospect.",
        "",
        "Best regards,",
        f"{branding.company_name}",
        "",
        "---",
        f"{branding.company_name}",
        "Strategy Call Agent — Automated Notification",
    ]
    return "\n".join(lines)
