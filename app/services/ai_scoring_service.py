"""AI lead scoring and summary service (Phase 23).

Provides:
  - ``score_lead``: Rule-based lead quality score (1–100).
  - ``generate_lead_summary``: AI-generated 2–3 sentence lead overview.
  - ``generate_call_summary``: AI-generated structured call summary.
  - ``get_next_best_action``: Rule-based next-action recommendation.

AI calls are wrapped in try/except and never raise on failure — a
graceful fallback is always returned instead.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models import CallOutcome, Lead, LeadStatus
from app.services.org_context import OrganizationContext

logger = logging.getLogger("strategy-call-agent.ai_scoring")


# ---------------------------------------------------------------------------
# Scoring Weights
# ---------------------------------------------------------------------------

# Data completeness: each present field adds points toward a max of 30.
_COMPLETENESS_FIELDS = {
    "phone_number": 6,
    "email": 4,
    "company_address": 6,
    "courses": 7,
    "direct_number": 4,
    "caller_name": 3,
}

# Recency: leads submitted within N days get up to 25 points (linear decay).
_RECENCY_MAX = 25
_RECENCY_WINDOW_DAYS = 30  # Full points within this window.

# Engagement: bonus points for calendar + call signals.
_ENGAGEMENT_POINTS = {
    "calendar_created": 20,
    "call_connected": 15,
    "call_completed": 15,
    "has_call_notes": 10,
    "has_reminder": 5,
}

# Negative signals reduce the score.
_NEGATIVE_SIGNALS = {
    "declined": -20,
    "not_interested": -40,
    "error": -15,
    "no_answer": -5,
    "voicemail": -3,
    "busy": -3,
    "wrong_number": -10,
    "cancelled": -15,
    "no_show": -10,
}


def score_lead(
    db: Session,
    lead: Lead,
    org_context: OrganizationContext | None = None,
) -> dict[str, Any]:
    """Score a lead from 1 to 100 using rule-based heuristics.

    Scoring breakdown:
        - **Data completeness** (0–30): presence of phone, email, company,
          courses, direct number, and caller name.
        - **Lead recency** (0–25): linear decay over a 30-day window from
          submission date.
        - **Engagement signals** (0–50): calendar event created, call
          outcome, call notes, reminder sent.
        - **Negative signals**: deductions for terminal or negative states.

    The final score is clamped to the range [1, 100].

    Args:
        db: Active database session.
        lead: The ``Lead`` ORM instance to score.
        org_context: Optional organization context (reserved for future
            org-specific scoring rules).

    Returns:
        Dict with keys ``score`` (int 1–100), ``factors`` (breakdown
        dict), and ``recommendation`` (human-readable action string).
    """
    factors: dict[str, int] = {}

    # --- Data Completeness (0–30) ---
    completeness = 0
    for field_name, points in _COMPLETENESS_FIELDS.items():
        value = getattr(lead, field_name, None)
        if value and str(value).strip():
            completeness += points
            factors[f"has_{field_name}"] = points
    factors["data_completeness"] = completeness

    # --- Lead Recency (0–25) ---
    recency = 0
    if lead.created_at:
        now = datetime.now(timezone.utc)
        # Ensure created_at is timezone-aware for comparison.
        created = lead.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (now - created).total_seconds() / 86400
        if age_days <= _RECENCY_WINDOW_DAYS:
            # Linear: full points at 0 days, 0 points at 30 days.
            recency = int(_RECENCY_MAX * (1 - age_days / _RECENCY_WINDOW_DAYS))
        recency = max(0, recency)
    factors["lead_recency"] = recency

    # --- Engagement Signals (up to ~50) ---
    engagement = 0

    if lead.calendar_event_id:
        pts = _ENGAGEMENT_POINTS["calendar_created"]
        engagement += pts
        factors["calendar_created"] = pts

    if lead.call_outcome:
        outcome_val = lead.call_outcome.value if hasattr(lead.call_outcome, "value") else str(lead.call_outcome)
        if lead.call_outcome in (CallOutcome.CONNECTED, CallOutcome.COMPLETED):
            pts = _ENGAGEMENT_POINTS["call_completed"]
            engagement += pts
            factors["call_completed"] = pts
        else:
            # Apply negative signal for suboptimal outcomes.
            neg = _NEGATIVE_SIGNALS.get(outcome_val, 0)
            if neg:
                engagement += neg
                factors[f"outcome_{outcome_val}"] = neg

    if lead.call_notes and lead.call_notes.strip():
        pts = _ENGAGEMENT_POINTS["has_call_notes"]
        engagement += pts
        factors["has_call_notes"] = pts

    if lead.reminder_sent_at:
        pts = _ENGAGEMENT_POINTS["has_reminder"]
        engagement += pts
        factors["reminder_sent"] = pts

    factors["engagement"] = engagement

    # --- Terminal / Negative State Deductions ---
    state_adj = 0
    if lead.status:
        status_val = lead.status.value if hasattr(lead.status, "value") else str(lead.status)
        neg = _NEGATIVE_SIGNALS.get(status_val, 0)
        if neg:
            state_adj += neg
            factors[f"status_{status_val}"] = neg
    factors["state_adjustment"] = state_adj

    # --- Final Score ---
    raw = completeness + recency + engagement + state_adj
    score = max(1, min(100, raw))
    factors["raw_score"] = raw

    # --- Recommendation ---
    recommendation = _derive_recommendation(score, lead)

    return {
        "score": score,
        "factors": factors,
        "recommendation": recommendation,
    }


def _derive_recommendation(score: int, lead: Lead) -> str:
    """Map a numeric score to a human-readable recommendation.

    Args:
        score: Clamped lead score (1–100).
        lead: The lead instance (for status context).

    Returns:
        A short recommendation string.
    """
    # Terminal states override score-based recommendations.
    if lead.status in (LeadStatus.DECLINED, LeadStatus.NOT_INTERESTED):
        return "Archived — prospect has declined or expressed no interest."
    if lead.status == LeadStatus.COMPLETED:
        return "Completed — follow up for referral or nurture campaign."
    if lead.status == LeadStatus.ERROR:
        return "Needs attention — processing error encountered."

    if score >= 80:
        return "High priority — engage immediately with a personal call."
    if score >= 60:
        return "Good lead — schedule a follow-up call within 24 hours."
    if score >= 40:
        return "Moderate potential — send a personalized email to gauge interest."
    if score >= 20:
        return "Low engagement — consider a nurturing sequence before direct outreach."
    return "Very low score — data is incomplete; attempt to enrich before acting."


# ---------------------------------------------------------------------------
# AI-Generated Lead Summary
# ---------------------------------------------------------------------------


def generate_lead_summary(
    db: Session,
    lead: Lead,
    org_context: OrganizationContext | None = None,
) -> dict[str, Any]:
    """Generate an AI-powered 2–3 sentence lead summary.

    Sends the lead's key data points to the AI service and requests a
    concise overview suitable for quick CRM review.

    On AI failure, returns a deterministic fallback summary built from
    the lead's data rather than raising an exception.

    Args:
        db: Active database session.
        lead: The ``Lead`` ORM instance.
        org_context: Optional organization context for credential resolution.

    Returns:
        Dict with ``summary`` (str) and ``model_used`` (str).
    """
    # Build the prompt.
    lead_data = _format_lead_for_prompt(lead)
    system_prompt = (
        "You are a CRM assistant. Write a brief 2–3 sentence summary of "
        "this lead based on the data provided. Be factual — do not invent "
        "information that isn't present. Highlight the most important "
        "details: who they are, what they're interested in, and their "
        "current status."
    )
    user_prompt = (
        "Summarize this lead:\n\n"
        f"{lead_data}\n\n"
        "Write 2–3 concise sentences."
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    try:
        from app.services.ai_service import AIService

        ai = AIService(org_context=org_context, db=db)
        # Reuse the internal chat completion via generate_confirmation_email
        # pattern — we call the private _chat_completion directly.
        from app.services.ai_service import _chat_completion

        body = _chat_completion(
            ai._primary_url, ai._primary_key, ai._primary_model, messages
        )
        logger.info("lead summary generated for lead %s", lead.id)
        return {"summary": body, "model_used": ai._primary_model}
    except Exception as exc:
        logger.warning(
            "AI lead summary failed for lead %s: %s", lead.id, str(exc)[:200]
        )
        fallback = _build_fallback_summary(lead)
        return {"summary": fallback, "model_used": "fallback:static"}


def _format_lead_for_prompt(lead: Lead) -> str:
    """Format a lead's key fields into a readable string for AI prompts."""
    parts = [
        f"Name: {lead.name or 'N/A'}",
        f"Email: {lead.email or 'N/A'}",
        f"Company: {lead.company_address or 'N/A'}",
        f"Phone: {lead.phone_number or 'N/A'}",
        f"Direct Number: {lead.direct_number or 'N/A'}",
        f"Courses of Interest: {lead.courses or 'N/A'}",
        f"Status: {lead.status.value if lead.status else 'N/A'}",
        f"Call Outcome: {lead.call_outcome.value if lead.call_outcome else 'N/A'}",
        f"Appointment (UTC): {lead.appt_datetime_utc.isoformat() if lead.appt_datetime_utc else 'N/A'}",
        f"Created: {lead.created_at.isoformat() if lead.created_at else 'N/A'}",
    ]
    if lead.call_notes:
        parts.append(f"Call Notes: {lead.call_notes[:500]}")
    return "\n".join(parts)


def _build_fallback_summary(lead: Lead) -> str:
    """Build a deterministic summary from lead data when AI is unavailable."""
    status_str = lead.status.value if lead.status else "unknown"
    parts = [
        f"{lead.name} ({lead.email})",
    ]
    if lead.company_address:
        parts.append(f"from {lead.company_address}")
    parts.append(f"is currently {status_str}")
    if lead.courses:
        parts.append(f"and is interested in {lead.courses}")
    if lead.call_outcome:
        parts.append(f"(last call outcome: {lead.call_outcome.value})")
    return " ".join(parts) + "."


# ---------------------------------------------------------------------------
# AI-Generated Call Summary
# ---------------------------------------------------------------------------


def generate_call_summary(
    db: Session,
    lead: Lead,
    org_context: OrganizationContext | None = None,
) -> dict[str, Any]:
    """Generate an AI-structured call summary from call notes.

    Only works when the lead has non-empty ``call_notes``. Parses the
    free-text notes into a structured summary with key points and
    recommended next actions.

    On AI failure, returns a basic fallback with the raw notes.

    Args:
        db: Active database session.
        lead: The ``Lead`` ORM instance (must have ``call_notes``).
        org_context: Optional organization context for credential resolution.

    Returns:
        Dict with ``summary`` (str), ``key_points`` (list[str]),
        ``next_actions`` (list[str]), and ``model_used`` (str).
    """
    if not lead.call_notes or not lead.call_notes.strip():
        return {
            "summary": "No call notes available to summarize.",
            "key_points": [],
            "next_actions": [],
            "model_used": "none",
        }

    system_prompt = (
        "You are a CRM assistant that structures call notes into a "
        "professional summary. Given raw call notes, produce:\n"
        "1. A 2–3 sentence summary of the call.\n"
        "2. A list of key points discussed (3–5 bullet points).\n"
        "3. A list of recommended next actions (1–3 items).\n\n"
        "Return your response as plain text in this exact format:\n"
        "SUMMARY: <your summary>\n"
        "KEY_POINTS:\n- <point 1>\n- <point 2>\n...\n"
        "NEXT_ACTIONS:\n- <action 1>\n- <action 2>\n..."
    )
    user_prompt = (
        f"Call notes for {lead.name}:\n\n"
        f"{lead.call_notes[:2000]}\n\n"
        "Structure these into summary, key points, and next actions."
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    try:
        from app.services.ai_service import AIService, _chat_completion

        ai = AIService(org_context=org_context, db=db)
        raw_response = _chat_completion(
            ai._primary_url, ai._primary_key, ai._primary_model, messages
        )
        parsed = _parse_call_summary_response(raw_response)
        parsed["model_used"] = ai._primary_model
        logger.info("call summary generated for lead %s", lead.id)
        return parsed
    except Exception as exc:
        logger.warning(
            "AI call summary failed for lead %s: %s", lead.id, str(exc)[:200]
        )
        return {
            "summary": lead.call_notes[:300],
            "key_points": [],
            "next_actions": [],
            "model_used": "fallback:static",
        }


def _parse_call_summary_response(raw: str) -> dict[str, Any]:
    """Parse the AI response into structured call summary fields.

    Expects the format:
        SUMMARY: ...\nKEY_POINTS:\n- ...\nNEXT_ACTIONS:\n- ...
    Falls back to treating the entire response as a summary if parsing fails.
    """
    summary = ""
    key_points: list[str] = []
    next_actions: list[str] = []

    try:
        lines = raw.strip().split("\n")
        section = None

        for line in lines:
            stripped = line.strip()
            if stripped.upper().startswith("SUMMARY:"):
                summary = stripped[len("SUMMARY:"):].strip()
                section = None
            elif stripped.upper().startswith("KEY_POINTS:"):
                section = "key_points"
            elif stripped.upper().startswith("NEXT_ACTIONS:"):
                section = "next_actions"
            elif section == "key_points" and stripped.startswith("- "):
                key_points.append(stripped[2:].strip())
            elif section == "next_actions" and stripped.startswith("- "):
                next_actions.append(stripped[2:].strip())

        if not summary:
            summary = raw[:300]
    except Exception:
        summary = raw[:300]

    return {
        "summary": summary,
        "key_points": key_points,
        "next_actions": next_actions,
    }


# ---------------------------------------------------------------------------
# Next Best Action (Rule-Based)
# ---------------------------------------------------------------------------


def get_next_best_action(
    db: Session,
    lead: Lead,
) -> dict[str, str]:
    """Determine the next best action for a lead based on its current state.

    Uses a decision tree on ``lead.status`` and ``lead.call_outcome`` to
    suggest the highest-value next step.

    Args:
        db: Active database session.
        lead: The ``Lead`` ORM instance.

    Returns:
        Dict with ``action`` (what to do), ``reason`` (why), and
        ``priority`` (``"high"`` / ``"medium"`` / ``"low"``).
    """
    status = lead.status
    outcome = lead.call_outcome

    # --- Terminal states: no action needed ---
    if status == LeadStatus.COMPLETED:
        return {
            "action": "Send follow-up email with resources or referral request",
            "reason": "Call was completed successfully; capitalize on the positive interaction.",
            "priority": "medium",
        }

    if status == LeadStatus.DECLINED:
        return {
            "action": "Archive lead and add to re-engagement list for 90 days",
            "reason": "Prospect declined the appointment. Low probability of immediate re-engagement.",
            "priority": "low",
        }

    if status == LeadStatus.NOT_INTERESTED:
        return {
            "action": "Archive lead — no further outreach",
            "reason": "Prospect explicitly expressed no interest during form submission.",
            "priority": "low",
        }

    if status == LeadStatus.ERROR:
        return {
            "action": "Investigate pipeline error and manually reprocess the lead",
            "reason": "Lead processing failed and requires manual intervention.",
            "priority": "high",
        }

    # --- Active pipeline states ---
    now = datetime.now(timezone.utc)
    appt = lead.appt_datetime_utc
    if appt and appt.tzinfo is None:
        appt = appt.replace(tzinfo=timezone.utc)

    if status == LeadStatus.PENDING:
        return {
            "action": "Trigger pipeline processing to create calendar event and send confirmation email",
            "reason": "Lead is newly submitted and awaiting initial processing.",
            "priority": "high",
        }

    if status in (LeadStatus.SCHEDULED, LeadStatus.ACCEPTED, LeadStatus.TENTATIVE):
        if appt and appt > now:
            days_until = (appt - now).total_seconds() / 86400
            if days_until <= 1:
                return {
                    "action": "Send reminder email and prepare for the call",
                    "reason": f"Appointment is in {days_until * 24:.0f} hours. Time to send a reminder.",
                    "priority": "high",
                }
            elif days_until <= 3:
                return {
                    "action": "Confirm appointment with a brief check-in message",
                    "reason": f"Appointment is in {days_until:.1f} days. A confirmation builds confidence.",
                    "priority": "medium",
                }
            else:
                return {
                    "action": "Monitor — appointment is confirmed and upcoming",
                    "reason": f"Appointment is {days_until:.0f} days away. No immediate action required.",
                    "priority": "low",
                }
        elif appt and appt <= now:
            # Appointment time has passed but status hasn't moved to completed.
            return {
                "action": "Check call outcome and update lead status",
                "reason": "Appointment time has passed but the lead is still in a pre-call status.",
                "priority": "high",
            }
        else:
            return {
                "action": "Verify appointment datetime and follow up if missing",
                "reason": "Lead is scheduled but has no parsed UTC appointment time.",
                "priority": "high",
            }

    if status == LeadStatus.REMINDED:
        return {
            "action": "Follow up with a personal call if no response after reminder",
            "reason": "Reminder was sent but the lead hasn't progressed. Direct outreach may be needed.",
            "priority": "medium",
        }

    # --- Call-outcome-based recommendations ---
    if outcome == CallOutcome.NO_ANSWER:
        return {
            "action": "Retry call at a different time or send a voicemail follow-up email",
            "reason": "Prospect didn't answer. Try an alternative contact method.",
            "priority": "medium",
        }

    if outcome == CallOutcome.VOICEMAIL:
        return {
            "action": "Send a follow-up email referencing the voicemail and propose new times",
            "reason": "Left voicemail (or went to voicemail). Email is a reliable follow-up channel.",
            "priority": "medium",
        }

    if outcome == CallOutcome.BUSY:
        return {
            "action": "Schedule a callback for 2–3 hours later",
            "reason": "Line was busy. A short-delay retry often succeeds.",
            "priority": "medium",
        }

    if outcome == CallOutcome.RESCHEDULED:
        return {
            "action": "Confirm the new appointment time via email and update calendar event",
            "reason": "Call happened but needs rescheduling. Lock in the new time promptly.",
            "priority": "high",
        }

    if outcome == CallOutcome.CANCELLED:
        return {
            "action": "Archive lead or offer to reschedule if appropriate",
            "reason": "Call was cancelled. Determine if re-engagement is viable.",
            "priority": "low",
        }

    if outcome == CallOutcome.NO_SHOW:
        return {
            "action": "Send a polite no-show follow-up and offer to reschedule",
            "reason": "Prospect missed the call. A empathetic follow-up preserves the relationship.",
            "priority": "medium",
        }

    if outcome == CallOutcome.WRONG_NUMBER:
        return {
            "action": "Verify contact details and attempt to reach the correct number",
            "reason": "Reached wrong person. The phone number may need correction.",
            "priority": "medium",
        }

    if outcome == CallOutcome.NOT_INTERESTED:
        return {
            "action": "Archive lead and add to long-term nurture list",
            "reason": "Prospect expressed no interest on the call. Respect their decision.",
            "priority": "low",
        }

    # --- Default: no specific signals ---
    return {
        "action": "Review lead details and initiate outreach",
        "reason": "No specific action signals detected. Manual review recommended.",
        "priority": "medium",
    }
