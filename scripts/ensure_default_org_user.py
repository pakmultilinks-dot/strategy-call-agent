"""Ensure the default organization has at least one OWNER user.

The default org (Integrated IT Trainings) exists but has 0 users, which
means no one can authenticate via JWT to initiate Google OAuth.
This script creates an OWNER user so the dashboard login + OAuth flow works.

Usage (inside Docker):
    ADMIN_PASSWORD='...' python /app/scripts/ensure_default_org_user.py

SECURITY: the admin password MUST come from the ADMIN_PASSWORD
environment variable. It is never hardcoded, never printed, and never
baked into the image.

This is idempotent - safe to run multiple times.
"""
import os
import sys
sys.path.insert(0, "/app")

import uuid

import app.models  # noqa: F401 - register models
import app.models_multi_tenant  # noqa: F401 - register multi-tenant models

from app.database import SessionLocal
from app.models_multi_tenant import Organization, User, UserRole, UserStatus
from app.auth import hash_password

DEFAULT_ORG_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
ADMIN_EMAIL = "admin@integratedittrainings.com"


def _get_admin_password() -> str:
    password = os.environ.get("ADMIN_PASSWORD", "").strip()
    if not password:
        print(
            "FAIL: ADMIN_PASSWORD environment variable is not set. "
            "Refusing to create an admin user with a default password.",
            file=sys.stderr,
        )
        sys.exit(2)
    if len(password) < 12:
        print(
            "FAIL: ADMIN_PASSWORD must be at least 12 characters.",
            file=sys.stderr,
        )
        sys.exit(2)
    return password


def main():
    admin_password = _get_admin_password()
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == DEFAULT_ORG_ID).first()
        if not org:
            print(f"FAIL: Default org {DEFAULT_ORG_ID} does not exist!")
            return 1

        print(f"Default org: {org.name} (id={org.id})")

        # Check if user already exists
        existing = db.query(User).filter(
            User.organization_id == DEFAULT_ORG_ID,
            User.email == ADMIN_EMAIL,
        ).first()

        if existing:
            print(f"User already exists: {existing.email} (id={existing.id}, role={existing.role.value})")
            # Ensure password_hash is set
            if not existing.password_hash:
                existing.password_hash = hash_password(admin_password)
                db.commit()
                print("  -> Password hash was missing, now set")
            print(f"  -> Status: {existing.status.value}")
            return 0

        # Create the owner user
        password_hash = hash_password(admin_password)
        user = User(
            organization_id=DEFAULT_ORG_ID,
            email=ADMIN_EMAIL,
            full_name="Platform Admin",
            password_hash=password_hash,
            role=UserRole.OWNER,
            status=UserStatus.ACTIVE,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        print(f"Created user: {user.email} (id={user.id})")
        print(f"  Role: {user.role.value}")
        print(f"  Status: {user.status.value}")
        print(f"  Org: {org.name}")
        # The password is NEVER printed.
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main() or 0)
