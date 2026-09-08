"""Add the XSS finding category (phase 6)

Reflected-XSS findings reuse the existing `findings` / `finding_occurrences` /
`endpoints` tables in full — the only schema change needed is one new label on
the `finding_category` enum. No new table, no new column.

On downgrade, any XSS findings are remapped to OTHER so that nothing references
the label. The label itself stays: PostgreSQL has no `ALTER TYPE ... DROP VALUE`,
and recreating the type would mean rewriting every findings row for no practical
gain. An unused enum label is inert, and a later upgrade re-adds it idempotently.

Revision ID: 0006_xss_category
Revises: 0005_scan_intelligence
Create Date: 2026-09-08

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_xss_category"
down_revision: str | None = "0005_scan_intelligence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ALTER TYPE ... ADD VALUE cannot be used later in the same transaction that
    # created it, so it runs outside the migration's transaction block.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE finding_category ADD VALUE IF NOT EXISTS 'XSS'")


def downgrade() -> None:
    # Leave no row pointing at a label this revision introduced.
    op.execute("UPDATE findings SET category = 'OTHER' WHERE category = 'XSS'")
