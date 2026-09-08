"""Add the SQLI finding category (phase 8)

SQL-injection findings reuse the existing findings / finding_occurrences /
endpoints tables in full — the only schema change is one new label on the
`finding_category` enum, exactly as phase 6 did for XSS. No new table, no new
column.

On downgrade, any SQLI findings are remapped to OTHER so nothing references the
label; the label itself stays, since PostgreSQL has no ALTER TYPE DROP VALUE and
an unused label is inert.

Revision ID: 0007_sqli_category
Revises: 0006_xss_category
Create Date: 2026-09-08

"""

from collections.abc import Sequence

from alembic import op

revision: str = "0007_sqli_category"
down_revision: str | None = "0006_xss_category"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ALTER TYPE ... ADD VALUE cannot run inside the migration's transaction.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE finding_category ADD VALUE IF NOT EXISTS 'SQLI'")


def downgrade() -> None:
    op.execute("UPDATE findings SET category = 'OTHER' WHERE category = 'SQLI'")
