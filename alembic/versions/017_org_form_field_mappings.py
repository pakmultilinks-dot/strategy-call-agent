"""Phase 29 — Add organization-scoped Google Form field mappings.

Creates ``org_form_field_mappings`` table that allows each organization
to map Google Form question labels to canonical Lead model fields.

Revision ID: 017_org_form_field_mappings
Create Date: 2026-08-29
"""
from alembic import op
import sqlalchemy as sa

revision = "017_org_form_field_mappings"
down_revision = "016_followup_execution_tracking"
branch_labels = None
depends_on = None

# The canonical Lead model fields that can be mapped from form labels.
_CANONICAL_FIELDS = [
    "name",
    "email",
    "company_address",
    "phone_number",
    "direct_number",
    "courses",
    "interested",
    "caller_name",
    "scheduled_date",
    "appt_datetime_raw",
    "scheduled_date_time",
    "form_date",
    "form_time",
]


def upgrade() -> None:
    op.create_table(
        "org_form_field_mappings",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "organization_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "form_label",
            sa.String(),
            nullable=False,
            comment="Question label from Google Form",
        ),
        sa.Column(
            "lead_field",
            sa.String(),
            nullable=False,
            comment="Target Lead model column name",
        ),
        sa.Column(
            "is_required",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column(
            "display_order",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        # Prevent duplicate form_label per org
        sa.UniqueConstraint(
            "organization_id", "form_label",
            name="uq_ffm_org_form_label",
        ),
        # Prevent duplicate lead_field per org (one source per target)
        sa.UniqueConstraint(
            "organization_id", "lead_field",
            name="uq_ffm_org_lead_field",
        ),
    )
    op.create_index(
        "ix_ffm_org_id",
        "org_form_field_mappings",
        ["organization_id"],
    )
    op.create_index(
        "ix_ffm_org_form_label",
        "org_form_field_mappings",
        ["organization_id", "form_label"],
    )


def downgrade() -> None:
    op.drop_index("ix_ffm_org_form_label", table_name="org_form_field_mappings")
    op.drop_index("ix_ffm_org_id", table_name="org_form_field_mappings")
    op.drop_table("org_form_field_mappings")
