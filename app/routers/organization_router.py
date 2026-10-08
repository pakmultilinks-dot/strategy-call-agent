"""Organization user management + settings router (Phase 6B.3 + 6F).

Endpoints:
  GET    /organization/users              - List users in current org
  POST   /organization/users              - Invite/create a user in current org
  PATCH  /organization/users/{user_id}    - Update user role/status
  DELETE /organization/users/{user_id}    - Remove a user from the org
  GET    /organization/settings           - Get org settings (all users)
  PATCH  /organization/settings           - Update org settings (owner/admin)

SECURITY:
  - All operations are scoped to current_user.organization_id
  - Only owner/admin can manage users and settings
  - Owner cannot delete themselves if they are the last owner
  - target_user.organization_id must match current_user.organization_id
  - Passwords are NEVER returned in responses
  - webhook_secret is NEVER returned in any response
"""
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth import (
    get_current_user,
    hash_password,
    require_role,
    validate_password_strength,
)
from app.database import get_db
from app.models_multi_tenant import (
    Organization,
    OrgScheduleConfig,
    User,
    UserRole,
    UserStatus,
)
from app.schemas_auth import (
    MessageResponse,
    OrganizationSettingsResponse,
    OrganizationSettingsUpdate,
    UserCreateRequest,
    UserInfo,
    UserListResponse,
    UserUpdateRequest,
    build_safe_user_info,
)
from app.services.audit_service import log_audit_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/organization", tags=["organization"])


@router.get("/users", response_model=UserListResponse)
def list_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserListResponse:
    """List all users in the current user's organization.

    Accessible by all authenticated users (owner, admin, member).
    """
    users = (
        db.query(User)
        .filter(User.organization_id == current_user.organization_id)
        .order_by(User.created_at.asc())
        .all()
    )

    org = db.query(Organization).filter(
        Organization.id == current_user.organization_id
    ).first()

    return UserListResponse(
        users=[build_safe_user_info(u, org) for u in users],
        total=len(users),
    )


@router.post("/users", response_model=UserInfo, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    current_user: User = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> UserInfo:
    """Create a new user in the current user's organization.

    Only owner and admin can create users.
    New users are created with the specified role.
    """
    validate_password_strength(payload.password)

    # Validate role
    try:
        role = UserRole(payload.role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role: {payload.role}. Must be one of: owner, admin, member",
        )

    # SECURITY (H5): only an owner may create another owner.  Admins
    # creating owners would be privilege escalation.
    if role == UserRole.OWNER and current_user.role != UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the owner can create owner accounts",
        )

    # Check for duplicate email within the organization
    existing = (
        db.query(User)
        .filter(
            User.organization_id == current_user.organization_id,
            User.email == payload.email.lower(),
        )
        .first()
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists in your organization",
        )

    password_hashed = hash_password(payload.password)

    user = User(
        organization_id=current_user.organization_id,
        email=payload.email.lower(),
        full_name=payload.name,
        password_hash=password_hashed,
        role=role,
        status=UserStatus.ACTIVE,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    org = db.query(Organization).filter(
        Organization.id == current_user.organization_id
    ).first()

    logger.info(
        "user created: org=%s user=%s email=%s role=%s by=%s",
        current_user.organization_id,
        user.id,
        user.email,
        role.value,
        current_user.id,
    )
    log_audit_event(db, event_type="audit.user_created",
                    user_id=current_user.id, organization_id=current_user.organization_id,
                    detail={"target_user_id": str(user.id), "email": user.email,
                            "role": role.value})
    db.commit()

    return build_safe_user_info(user, org)


@router.patch("/users/{user_id}", response_model=UserInfo)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdateRequest,
    current_user: User = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> UserInfo:
    """Update a user's role or status.

    Only owner and admin can update users.
    All changes are scoped to the current organization.
    """
    # Find the target user within the same organization
    target_user = (
        db.query(User)
        .filter(
            User.id == user_id,
            User.organization_id == current_user.organization_id,
        )
        .first()
    )
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in your organization",
        )

    # Non-owners cannot promote to owner
    if payload.role and current_user.role != UserRole.OWNER:
        if payload.role == "owner":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the owner can assign the owner role",
            )

    # SECURITY (H6): protect the last active owner.  Demoting or
    # disabling the final owner would lock everyone out of the org.
    _demoting_owner = (
        target_user.role == UserRole.OWNER
        and payload.role is not None
        and payload.role != UserRole.OWNER.value
    )
    _disabling_owner = (
        target_user.role == UserRole.OWNER
        and payload.status is not None
        and payload.status != UserStatus.ACTIVE.value
    )
    if _demoting_owner or _disabling_owner:
        other_active_owners = (
            db.query(User)
            .filter(
                User.organization_id == current_user.organization_id,
                User.id != target_user.id,
                User.role == UserRole.OWNER,
                User.status == UserStatus.ACTIVE,
            )
            .count()
        )
        if other_active_owners == 0:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot demote or disable the last active owner of the organization",
            )

    # SECURITY (H6): nobody can demote/disable themselves via this
    # endpoint (use the dedicated account flows instead).
    if target_user.id == current_user.id and (_demoting_owner or _disabling_owner):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot demote or disable your own account here",
        )

    # Apply updates
    if payload.name is not None:
        target_user.full_name = payload.name

    if payload.role is not None:
        try:
            new_role = UserRole(payload.role)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid role: {payload.role}. Must be one of: owner, admin, member",
            )
        target_user.role = new_role

    if payload.status is not None:
        try:
            new_status = UserStatus(payload.status)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid status: {payload.status}. Must be one of: active, disabled",
            )
        target_user.status = new_status

    db.commit()
    db.refresh(target_user)

    org = db.query(Organization).filter(
        Organization.id == current_user.organization_id
    ).first()

    logger.info(
        "user updated: org=%s user=%s by=%s",
        current_user.organization_id,
        target_user.id,
        current_user.id,
    )
    log_audit_event(db, event_type="audit.user_updated",
                    user_id=current_user.id, organization_id=current_user.organization_id,
                    detail={"target_user_id": str(target_user.id)})
    db.commit()

    return build_safe_user_info(target_user, org)


@router.delete("/users/{user_id}", response_model=MessageResponse)
def delete_user(
    user_id: uuid.UUID,
    current_user: User = Depends(require_role(UserRole.OWNER)),
    db: Session = Depends(get_db),
) -> MessageResponse:
    """Remove a user from the current user's organization.

    Only the owner can delete users.
    The last owner cannot be deleted (prevents orphaning the organization).
    """
    # Find the target user within the same organization
    target_user = (
        db.query(User)
        .filter(
            User.id == user_id,
            User.organization_id == current_user.organization_id,
        )
        .first()
    )
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in your organization",
        )

    # Prevent deleting yourself
    if target_user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    # Prevent deleting the last owner
    if target_user.role == UserRole.OWNER:
        owner_count = (
            db.query(User)
            .filter(
                User.organization_id == current_user.organization_id,
                User.role == UserRole.OWNER,
            )
            .count()
        )
        if owner_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete the last owner of the organization",
            )

    db.delete(target_user)
    db.commit()

    logger.info(
        "user deleted: org=%s user=%s email=%s by=%s",
        current_user.organization_id,
        target_user.id,
        target_user.email,
        current_user.id,
    )
    log_audit_event(db, event_type="audit.user_deleted",
                    user_id=current_user.id, organization_id=current_user.organization_id,
                    detail={"target_user_id": str(target_user.id),
                            "email": target_user.email})
    db.commit()

    return MessageResponse(message="User deleted successfully")


# ---------------------------------------------------------------------------
# Organization Settings (Phase 6F)
# ---------------------------------------------------------------------------


@router.get("/settings", response_model=OrganizationSettingsResponse)
def get_organization_settings(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> OrganizationSettingsResponse:
    """Get organization settings for the authenticated user's org.

    Accessible by all authenticated users (owner, admin, member).
    NEVER returns webhook_secret or credentials.
    """
    org = (
        db.query(Organization)
        .filter(Organization.id == current_user.organization_id)
        .first()
    )
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    # Get schedule config if it exists
    sched = (
        db.query(OrgScheduleConfig)
        .filter(OrgScheduleConfig.organization_id == org.id)
        .first()
    )

    return OrganizationSettingsResponse(
        id=org.id,
        name=org.name,
        slug=org.slug,
        display_name=org.display_name,
        status=org.status.value if org.status else "active",
        timezone=org.timezone or "America/Chicago",
        sender_name=org.sender_name,
        brand_color=org.brand_color,
        tagline=org.tagline,
        meeting_duration_minutes=sched.meeting_duration_minutes if sched else None,
        reminder_enabled=sched.reminder_enabled if sched else None,
        reminder_hour=sched.reminder_hour if sched else None,
        reminder_minute=sched.reminder_minute if sched else None,
        rsvp_poll_interval_minutes=sched.rsvp_poll_interval_minutes if sched else None,
    )


@router.patch("/settings", response_model=OrganizationSettingsResponse)
def update_organization_settings(
    payload: OrganizationSettingsUpdate,
    current_user: User = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> OrganizationSettingsResponse:
    """Update organization settings.

    Only Owner/Admin can modify settings. Member can view but not modify.
    All changes are scoped to the current organization.
    """
    org = (
        db.query(Organization)
        .filter(Organization.id == current_user.organization_id)
        .first()
    )
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    # Apply org-level field updates
    updated_fields = []
    if payload.name is not None:
        org.name = payload.name
        updated_fields.append("name")
    if payload.display_name is not None:
        org.display_name = payload.display_name
        updated_fields.append("display_name")
    if payload.timezone is not None:
        org.timezone = payload.timezone
        updated_fields.append("timezone")
    if payload.sender_name is not None:
        org.sender_name = payload.sender_name
        updated_fields.append("sender_name")
    if payload.brand_color is not None:
        org.brand_color = payload.brand_color
        updated_fields.append("brand_color")
    if payload.tagline is not None:
        org.tagline = payload.tagline
        updated_fields.append("tagline")

    # Apply schedule config updates (create if needed)
    sched = (
        db.query(OrgScheduleConfig)
        .filter(OrgScheduleConfig.organization_id == org.id)
        .first()
    )
    if sched is None:
        sched = OrgScheduleConfig(organization_id=org.id)
        db.add(sched)
        db.flush()

    if payload.meeting_duration_minutes is not None:
        sched.meeting_duration_minutes = payload.meeting_duration_minutes
        updated_fields.append("meeting_duration_minutes")
    if payload.reminder_enabled is not None:
        sched.reminder_enabled = payload.reminder_enabled
        updated_fields.append("reminder_enabled")
    if payload.reminder_hour is not None:
        sched.reminder_hour = payload.reminder_hour
        updated_fields.append("reminder_hour")
    if payload.reminder_minute is not None:
        sched.reminder_minute = payload.reminder_minute
        updated_fields.append("reminder_minute")
    if payload.rsvp_poll_interval_minutes is not None:
        sched.rsvp_poll_interval_minutes = payload.rsvp_poll_interval_minutes
        updated_fields.append("rsvp_poll_interval_minutes")

    db.commit()
    db.refresh(org)
    db.refresh(sched)

    logger.info(
        "organization settings updated: org=%s fields=%s by=%s",
        org.id,
        updated_fields,
        current_user.id,
    )
    log_audit_event(db, event_type="audit.org_settings_updated",
                    user_id=current_user.id, organization_id=org.id,
                    detail={"fields": updated_fields})
    db.commit()

    # ── Reschedule live APScheduler jobs for this org (Problem #5) ───
    try:
        from app.main import reschedule_org_scheduler_jobs
        reschedule_org_scheduler_jobs(org.id)
    except Exception:
        logger.exception("failed to reschedule org scheduler jobs after settings update for org %s", org.id)

    return OrganizationSettingsResponse(
        id=org.id,
        name=org.name,
        slug=org.slug,
        display_name=org.display_name,
        status=org.status.value if org.status else "active",
        timezone=org.timezone or "America/Chicago",
        sender_name=org.sender_name,
        brand_color=org.brand_color,
        tagline=org.tagline,
        meeting_duration_minutes=sched.meeting_duration_minutes,
        reminder_enabled=sched.reminder_enabled,
        reminder_hour=sched.reminder_hour,
        reminder_minute=sched.reminder_minute,
        rsvp_poll_interval_minutes=sched.rsvp_poll_interval_minutes,
    )
