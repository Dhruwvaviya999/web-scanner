"""Add response-analysis columns to scans (phase 2)

Adds the two facts the phase-2 response analyzer produces that phase 1 did not
collect. Both are nullable, so scans recorded before this migration remain valid
and simply carry NULL for them.

Revision ID: 0002_response_analysis
Revises: 0001_initial
Create Date: 2026-09-08

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_response_analysis"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("page_title", sa.String(length=512), nullable=True))
    # BigInteger: a target's Content-Length can legitimately exceed 2 GiB.
    op.add_column("scans", sa.Column("content_length", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "content_length")
    op.drop_column("scans", "page_title")
