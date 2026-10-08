"""Gmail integration (Phase 1 + 6B.4 + 6D).

Sends HTML + plain-text emails via the Gmail API.

Phase 6B.4: Supports organization-specific credentials via
IntegrationConfigResolver. Falls back to platform defaults when
org-specific credentials are not configured.

Phase 6D: Sender display name is resolved per-organization via
BrandingConfig.  Falls back to "Strategy Call Agent" when the org
has not configured a custom sender name.

Credential resolution order:
  1. Organization-specific Google OAuth tokens (from credential vault)
  2. Platform default token.json (backward compatibility)
"""
import base64
import json
import logging
from email.message import EmailMessage

from googleapiclient.discovery import build
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Lead
from app.services.google_auth import get_google_credentials
from app.services.integration_config_resolver import BrandingConfig
from app.services.org_context import OrganizationContext
from app.services.retry import external_call_retry, record_failed_job

logger = logging.getLogger(__name__)

_DEFAULT_SENDER_NAME = "Strategy Call Agent"


class EmailService:
    """Wraps the Gmail API.

    Phase 6B.4: Accepts optional org_context and db for credential resolution.
    When org_context is provided, credentials are resolved from the
    organization's configured integrations, falling back to platform defaults.
    When org_context is None, the original global-config behavior is preserved.
    """

    def __init__(
        self,
        org_context: OrganizationContext | None = None,
        db: Session | None = None,
    ) -> None:
        if org_context is not None and db is not None:
            # Organization-aware credential resolution
            from app.services.integration_config_resolver import (
                IntegrationConfigResolver,
            )

            oauth_config = IntegrationConfigResolver.resolve_google_oauth(db, org_context.organization_id)
            gmail_config = IntegrationConfigResolver.resolve_gmail_config(db, org_context.organization_id)
            self._branding = IntegrationConfigResolver.resolve_branding(db, org_context.organization_id)
            self._org_id = org_context.organization_id

            creds = get_google_credentials(
                client_id=oauth_config.client_id,
                client_secret=oauth_config.client_secret,
                refresh_token=oauth_config.refresh_token,
            )
            self._sender_email = gmail_config.sender_email
        else:
            # Platform default: backward-compatible with original behavior
            creds = get_google_credentials()
            self._sender_email = settings.gmail_sender
            self._org_id = None
            self._branding = BrandingConfig()

        self._credentials = creds
        self._service = build("gmail", "v1", credentials=creds, cache_discovery=True)

    @external_call_retry
    def _send(self, raw: str) -> dict:
        return (
            self._service.users()
            .messages()
            .send(userId="me", body={"raw": raw})
            .execute()
        )

    def send_email(
        self,
        to: str,
        subject: str,
        plain_body: str,
        db: Session,
        html_body: str | None = None,
    ) -> str:
        """Send an email via Gmail. Returns the Gmail message id.

        If ``html_body`` is provided the email is sent as multipart/alternative
        with both text/plain and text/html parts (Gmail renders the HTML).
        Otherwise a plain-text-only message is sent.

        The sender display name is resolved from the organization's branding
        configuration (Phase 6D).  Falls back to "Strategy Call Agent" when
        no org-specific name is configured.

        Phase 10B: Raises ValueError if ``to`` is None or empty to prevent
        a TypeError on ``msg["To"] = to`` and to provide a clear error message.
        """
        if not to:
            raise ValueError(
                "Cannot send email: recipient address ('to') is None or empty"
            )

        msg = EmailMessage()
        msg["To"] = to
        msg["From"] = f"{self._branding.sender_name} <{self._sender_email}>"
        msg["Subject"] = subject
        msg.set_content(plain_body)

        if html_body:
            msg.add_alternative(html_body, subtype="html")

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
        try:
            sent = self._send(raw)
        except Exception as exc:
            record_failed_job(
                db,
                job_type="email_send",
                payload=json.dumps({"to": to, "subject": subject}),
                error=str(exc),
                organization_id=self._org_id,
            )
            raise
        return sent.get("id", "")

    def send_confirmation_email(self, lead: Lead, plain_body: str, html_body: str, db: Session) -> str:
        """Send the confirmation email. Returns the Gmail message id.

        The recipient is ALWAYS lead.email, decided by code - never derived
        from the AI-generated body.
        """
        from app.services.email_templates import build_confirmation_subject

        subject = build_confirmation_subject(lead, branding=self._branding)
        return self.send_email(lead.email, subject, plain_body, db, html_body=html_body)
