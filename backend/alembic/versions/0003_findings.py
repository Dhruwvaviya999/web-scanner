"""Add the findings table (phase 3)

One row per security observation about a scan. Deleting a scan removes its
findings via ON DELETE CASCADE.

Existing users, scans and phase-2 columns are untouched: this migration only
adds a new table and its enum types, so scans recorded earlier remain valid and
simply have no findings attached.

Revision ID: 0003_findings
Revises: 0002_response_analysis
Create Date: 2026-09-08

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_findings"
down_revision: str | None = "0002_response_analysis"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Severity is declared most-severe-first so that PostgreSQL's native enum
# ordering makes `ORDER BY severity` return the worst findings first.
FINDING_SEVERITY = sa.Enum(
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="finding_severity"
)
FINDING_CONFIDENCE = sa.Enum("HIGH", "MEDIUM", "LOW", name="finding_confidence")
FINDING_CATEGORY = sa.Enum(
    "SECURITY_HEADER",
    "COOKIE",
    "TLS",
    "INFORMATION_DISCLOSURE",
    "OTHER",
    name="finding_category",
)


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("category", FINDING_CATEGORY, nullable=False),
        sa.Column("severity", FINDING_SEVERITY, nullable=False),
        sa.Column("confidence", FINDING_CONFIDENCE, nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("impact", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_findings_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_category", "findings", ["category"])
    # Backs the findings-for-one-scan query, ordered by severity.
    op.create_index("ix_findings_scan_id_severity", "findings", ["scan_id", "severity"])


def downgrade() -> None:
    op.drop_index("ix_findings_scan_id_severity", table_name="findings")
    op.drop_index("ix_findings_category", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")
    # Dropping the table does not drop its enum types; without this, a
    # subsequent upgrade fails with "type already exists".
    bind = op.get_bind()
    FINDING_CATEGORY.drop(bind, checkfirst=True)
    FINDING_CONFIDENCE.drop(bind, checkfirst=True)
    FINDING_SEVERITY.drop(bind, checkfirst=True)
