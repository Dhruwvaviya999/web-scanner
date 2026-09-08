"""Add attack-surface tables (phase 4)

Endpoints, their parameters, forms and form fields, plus four crawl-summary
columns on `scans`.

All four tables are new and the scan columns are nullable, so users, scans,
findings and every phase 1-3 column remain valid. A scan recorded before this
migration simply has no endpoints and NULL crawl counters.

Revision ID: 0004_attack_surface
Revises: 0003_findings
Create Date: 2026-09-08

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_attack_surface"
down_revision: str | None = "0003_findings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PARAMETER_LOCATION = sa.Enum("QUERY", "PATH", "FORM", name="parameter_location")
FORM_FIELD_KIND = sa.Enum("INPUT", "TEXTAREA", "SELECT", "BUTTON", name="form_field_kind")


def upgrade() -> None:
    # --- crawl summary on the scan -------------------------------------- #
    op.add_column("scans", sa.Column("pages_crawled", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("pages_skipped", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("max_depth_reached", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("crawl_limit_reached", sa.Boolean(), nullable=True))

    # --- endpoints ------------------------------------------------------- #
    op.create_table(
        "endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        # Canonical URL: parameter names kept, values stripped before storage.
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column("page_title", sa.String(length=512), nullable=True),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_endpoints_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_endpoints"),
    )
    op.create_index("ix_endpoints_scan_id", "endpoints", ["scan_id"])
    op.create_index("ix_endpoints_scan_id_depth", "endpoints", ["scan_id", "depth"])

    # --- endpoint parameters (names only) -------------------------------- #
    op.create_table(
        "endpoint_parameters",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("endpoint_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("location", PARAMETER_LOCATION, nullable=False),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["endpoint_id"],
            ["endpoints.id"],
            name="fk_endpoint_parameters_endpoint_id_endpoints",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_endpoint_parameters"),
    )
    op.create_index(
        "ix_endpoint_parameters_endpoint_id", "endpoint_parameters", ["endpoint_id"]
    )

    # --- forms ------------------------------------------------------------ #
    op.create_table(
        "forms",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("page_url", sa.String(length=2048), nullable=False),
        sa.Column("action", sa.String(length=2048), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_forms_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_forms"),
    )
    op.create_index("ix_forms_scan_id", "forms", ["scan_id"])

    # --- form fields (names and types only, never values) ----------------- #
    op.create_table(
        "form_fields",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("form_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("kind", FORM_FIELD_KIND, nullable=False),
        sa.Column("input_type", sa.String(length=40), nullable=True),
        sa.ForeignKeyConstraint(
            ["form_id"], ["forms.id"], name="fk_form_fields_form_id_forms", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_form_fields"),
    )
    op.create_index("ix_form_fields_form_id", "form_fields", ["form_id"])


def downgrade() -> None:
    op.drop_index("ix_form_fields_form_id", table_name="form_fields")
    op.drop_table("form_fields")
    op.drop_index("ix_forms_scan_id", table_name="forms")
    op.drop_table("forms")
    op.drop_index("ix_endpoint_parameters_endpoint_id", table_name="endpoint_parameters")
    op.drop_table("endpoint_parameters")
    op.drop_index("ix_endpoints_scan_id_depth", table_name="endpoints")
    op.drop_index("ix_endpoints_scan_id", table_name="endpoints")
    op.drop_table("endpoints")

    op.drop_column("scans", "crawl_limit_reached")
    op.drop_column("scans", "max_depth_reached")
    op.drop_column("scans", "pages_skipped")
    op.drop_column("scans", "pages_crawled")

    # Dropping a table does not drop its enum type; without this a subsequent
    # upgrade fails with "type already exists".
    bind = op.get_bind()
    FORM_FIELD_KIND.drop(bind, checkfirst=True)
    PARAMETER_LOCATION.drop(bind, checkfirst=True)
