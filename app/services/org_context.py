"""Organization context for multi-tenant service layer.

Provides a lightweight, immutable context object that carries the
organization identity through the service layer. Services receive
this context at instantiation time rather than reading from global state.

DESIGN PRINCIPLES:
  - Explicit: passed as a parameter, not a global variable
  - Immutable: frozen dataclass, cannot be mutated after creation
  - Testable: can be constructed with any org_id in tests
  - No request-global state, no singletons, no ContextVars

Usage:
    ctx = OrganizationContext.from_id(some_uuid)
    cal_service = CalendarService(org_context=ctx, db=db)
    ai_service = AIService(org_context=ctx, db=db)

Background tasks create the context from the lead's organization_id:
    ctx = OrganizationContext.from_id(lead.organization_id)
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class OrganizationContext:
    """Immutable organization context for service instantiation.

    This is the primary mechanism for passing organization identity
    through the service layer. Every service that needs to resolve
    org-specific credentials or configuration receives one of these.

    Attributes:
        organization_id: The UUID of the owning organization.

    Example (from a request with JWT auth):
        ctx = OrganizationContext.from_id(current_user.organization_id)

    Example (from a background task):
        lead = db.get(Lead, lead_id)
        ctx = OrganizationContext.from_id(lead.organization_id)

    Example (from tests):
        ctx = OrganizationContext.from_id(uuid.UUID("test-org-id"))
    """
    organization_id: uuid.UUID

    @classmethod
    def from_id(cls, org_id: uuid.UUID | str) -> OrganizationContext:
        """Create a context from an explicit organization ID.

        Accepts both UUID objects and string representations.
        """
        if isinstance(org_id, str):
            org_id = uuid.UUID(org_id)
        return cls(organization_id=org_id)
