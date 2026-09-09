"""Scan target-authentication metadata (phase 11)

Two columns, both metadata only.

Nothing secret is added here, and nothing secret is added anywhere else: the
bearer token or cookie values a user supplies so a scan can reach their own
authenticated pages are never written to the database. They exist in process
memory for the length of the scan and go with it. These columns record which
kind of credential a scan used and what one initial access check concluded —
enough for the scan list, the detail page and the report to be honest about
what the results cover, and useless to anybody who reads the table.

Validated strings rather than native enums, matching `current_stage` from
revision 0008: both vocabularies are expected to grow, and PostgreSQL enums
make growth expensive for no benefit here.

Existing rows are backfilled to NONE / NOT_CONFIGURED, which is exactly what
every scan created before this revision was.

Revision ID: 0009_scan_authentication
Revises: 0008_scan_lifecycle
Create Date: 2026-09-09

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_scan_authentication"
down_revision: str | None = "0008_scan_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # NOT NULL with a server default, so existing rows are filled in place and
    # a scan can never be ambiguous about whether it was authenticated.
    op.add_column(
        "scans",
        sa.Column(
            "auth_mode", sa.String(length=32), nullable=False, server_default="NONE"
        ),
    )
    op.add_column(
        "scans",
        sa.Column(
            "auth_status",
            sa.String(length=32),
            nullable=False,
            server_default="NOT_CONFIGURED",
        ),
    )


def downgrade() -> None:
    op.drop_column("scans", "auth_status")
    op.drop_column("scans", "auth_mode")
