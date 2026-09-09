"""API attack surface: endpoints, parameters, documents and coverage counters

Phase 13 records what the scanner learned about a target's APIs.

Three new tables and a set of counters on scans. Nothing here holds a response
body, a parameter value, a credential or a header. api_endpoints.json_field_names
stores field *names* such as id or email, which describe the interface, while the
data that was in those fields is discarded at capture time and never reaches the
database.

api_endpoints.endpoint_id is nullable on purpose, and it carries the most
important distinction this phase makes: an operation the crawler actually
reached links back to its endpoints row, while one known only from an OpenAPI
document has no such row because nobody ever requested it. Writing documented
operations into endpoints instead would inflate the crawl counters, enter the
analysis-coverage totals, and make them eligible for authorization comparison
against resources that may not exist.

ON DELETE SET NULL rather than CASCADE for that link: if a crawl row goes, the
API record is still true — it was documented — it merely stops being observed.

Counters are nullable so that "the stage did not run" stays distinguishable from
"the stage ran and found nothing", matching every other counter on scans.

Revision ID: 0011_api_surface
Revises: 0010_scan_authorization
Create Date: 2026-09-09

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_api_surface"
down_revision: str | None = "0010_scan_authorization"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCAN_COUNTERS = (
    "api_endpoints_discovered",
    "api_endpoints_observed",
    "api_endpoints_documented_only",
    "api_parameters_discovered",
    "api_document_count",
    "api_authenticated_endpoints",
    "api_unknown_auth_endpoints",
)

_SCAN_FLAGS = ("api_detected", "api_truncated", "api_graphql_detected")


def upgrade() -> None:
    op.create_table(
        "api_endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("endpoint_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False, server_default="GET"),
        sa.Column("url", sa.String(length=2048), nullable=True),
        sa.Column("confidence", sa.String(length=16), nullable=False, server_default="LOW"),
        sa.Column("sources", sa.String(length=255), nullable=True),
        sa.Column(
            "auth_status", sa.String(length=32), nullable=False, server_default="UNKNOWN"
        ),
        sa.Column("observed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "documented", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("request_media_type", sa.String(length=120), nullable=True),
        sa.Column("response_media_type", sa.String(length=120), nullable=True),
        sa.Column("operation_id", sa.String(length=255), nullable=True),
        sa.Column("security", sa.String(length=512), nullable=True),
        sa.Column("json_top_level", sa.String(length=16), nullable=True),
        sa.Column("json_field_names", sa.Text(), nullable=True),
        sa.Column("json_depth", sa.Integer(), nullable=True),
        sa.Column("json_field_count", sa.Integer(), nullable=True),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_endpoints_scan_id", "api_endpoints", ["scan_id"])
    op.create_index("ix_api_endpoints_endpoint_id", "api_endpoints", ["endpoint_id"])
    op.create_index("ix_api_endpoints_scan_id_path", "api_endpoints", ["scan_id", "path"])

    op.create_table(
        "api_endpoint_parameters",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("api_endpoint_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("location", sa.String(length=16), nullable=False, server_default="QUERY"),
        sa.Column("required", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(
            ["api_endpoint_id"], ["api_endpoints.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_api_endpoint_parameters_api_endpoint_id",
        "api_endpoint_parameters",
        ["api_endpoint_id"],
    )

    op.create_table(
        "api_documents",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=True),
        sa.Column("document_version", sa.String(length=64), nullable=True),
        sa.Column("path_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("operation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("security_schemes", sa.String(length=1024), nullable=True),
        sa.Column(
            "truncated", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_documents_scan_id", "api_documents", ["scan_id"])

    # --- scan-level coverage ------------------------------------------------ #
    for flag in _SCAN_FLAGS:
        op.add_column(
            "scans",
            sa.Column(flag, sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )
    for counter in _SCAN_COUNTERS:
        op.add_column("scans", sa.Column(counter, sa.Integer(), nullable=True))
    op.add_column(
        "scans", sa.Column("api_graphql_path", sa.String(length=1024), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("scans", "api_graphql_path")
    for counter in reversed(_SCAN_COUNTERS):
        op.drop_column("scans", counter)
    for flag in reversed(_SCAN_FLAGS):
        op.drop_column("scans", flag)

    op.drop_index("ix_api_documents_scan_id", table_name="api_documents")
    op.drop_table("api_documents")

    op.drop_index(
        "ix_api_endpoint_parameters_api_endpoint_id", table_name="api_endpoint_parameters"
    )
    op.drop_table("api_endpoint_parameters")

    op.drop_index("ix_api_endpoints_scan_id_path", table_name="api_endpoints")
    op.drop_index("ix_api_endpoints_endpoint_id", table_name="api_endpoints")
    op.drop_index("ix_api_endpoints_scan_id", table_name="api_endpoints")
    op.drop_table("api_endpoints")
