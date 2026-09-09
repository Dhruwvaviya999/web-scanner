"""Authorization testing: the AUTHORIZATION finding category and coverage counters

Two unrelated changes that belong to the same phase.

1. `finding_category` gains AUTHORIZATION. The category is a native PostgreSQL
   enum, so a new member needs ALTER TYPE, and that has to run outside the
   migration's transaction. As in revisions 0006 and 0008, the value cannot be
   removed on downgrade: PostgreSQL has no ALTER TYPE DROP VALUE, and an unused
   label is inert.

2. Coverage counters for the authorization stage on `scans`.

Nothing secret is added. The identities used for authorization testing are
supplied per scan and their credentials live in memory for the length of the
run, exactly as in phase 11. `authz_context_labels` stores user-chosen display
names such as "alice" or "admin" — metadata about the test, never about the
credential.

Counters are nullable so that "the stage did not run" stays distinguishable
from "the stage ran and compared nothing", which is the same convention the
phase 4 and 5 counters use.

Revision ID: 0010_scan_authorization
Revises: 0009_scan_authentication
Create Date: 2026-09-09

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_scan_authorization"
down_revision: str | None = "0009_scan_authentication"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COUNTERS = (
    "authz_contexts",
    "authz_endpoints_eligible",
    "authz_endpoints_tested",
    "authz_comparisons",
    "authz_unknown",
    "authz_skipped",
    "authz_failed",
)


def upgrade() -> None:
    # ADD VALUE cannot be used later in the transaction that created it.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE finding_category ADD VALUE IF NOT EXISTS 'AUTHORIZATION'")

    op.add_column(
        "scans",
        sa.Column(
            "authz_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
    )
    op.add_column(
        "scans", sa.Column("authz_context_labels", sa.String(length=512), nullable=True)
    )
    for column in _COUNTERS:
        op.add_column("scans", sa.Column(column, sa.Integer(), nullable=True))


def downgrade() -> None:
    for column in reversed(_COUNTERS):
        op.drop_column("scans", column)
    op.drop_column("scans", "authz_context_labels")
    op.drop_column("scans", "authz_enabled")

    # Any finding written under the new category would become unreadable once
    # the application no longer knows the label, so those rows are moved to the
    # category this scanner used before authorization testing existed.
    op.execute("UPDATE findings SET category = 'OTHER' WHERE category = 'AUTHORIZATION'")

    # AUTHORIZATION itself stays: PostgreSQL cannot drop an enum value, and an
    # unused label costs nothing. Same trade-off as revisions 0006 and 0008.
