"""Scan lifecycle: queued/cancelled states, timing, progress (phase 10)

Three changes:

1. `scan_status` gains CANCELLED, and PENDING is renamed to QUEUED so the
   database and the state machine share one vocabulary. A rename keeps existing
   rows valid — nothing is rewritten, the label itself changes — which is why it
   is preferred here over adding QUEUED and migrating rows across.
2. Lifecycle timestamps and the cooperative-cancellation flag.
3. Coarse progress fields.

`queued_at` is backfilled from `created_at` for existing scans, which is exactly
what it meant before the column existed.

Revision ID: 0008_scan_lifecycle
Revises: 0007_sqli_category
Create Date: 2026-09-08

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_scan_lifecycle"
down_revision: str | None = "0007_sqli_category"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Enum surgery runs outside the migration's transaction: ADD VALUE cannot be
    # used later in the transaction that created it.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE scan_status RENAME VALUE 'PENDING' TO 'QUEUED'")
        op.execute("ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'CANCELLED'")

    # --- lifecycle timing --------------------------------------------------- #
    op.add_column("scans", sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "scans",
        sa.Column(
            "cancel_requested", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
    )

    # --- progress ----------------------------------------------------------- #
    op.add_column("scans", sa.Column("current_stage", sa.String(length=32), nullable=True))
    op.add_column("scans", sa.Column("progress_percent", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("progress_message", sa.String(length=255), nullable=True))
    op.add_column("scans", sa.Column("failure_stage", sa.String(length=32), nullable=True))

    # A scan was queued when it was created; that is what the column means.
    op.execute("UPDATE scans SET queued_at = created_at WHERE queued_at IS NULL")

    # The default label was renamed out from under the column default.
    op.alter_column("scans", "status", server_default="QUEUED")


def downgrade() -> None:
    for column in (
        "failure_stage",
        "progress_message",
        "progress_percent",
        "current_stage",
        "cancel_requested",
        "cancelled_at",
        "queued_at",
    ):
        op.drop_column("scans", column)

    # Nothing may reference a label this revision introduced. CANCELLED itself
    # stays: PostgreSQL has no ALTER TYPE DROP VALUE, and an unused label is
    # inert — the same trade-off taken for XSS and SQLI in phases 6 and 8.
    op.execute("UPDATE scans SET status = 'FAILED' WHERE status = 'CANCELLED'")

    # The rename must come last. Setting the column default to 'PENDING' before
    # the label exists again fails, and renaming a label updates every stored
    # default that referenced it, so no explicit alter_column is needed here.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE scan_status RENAME VALUE 'QUEUED' TO 'PENDING'")
