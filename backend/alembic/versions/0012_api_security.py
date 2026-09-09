"""API security: the API_SECURITY finding category and coverage counters

Two changes.

1. finding_category gains API_SECURITY. The category is a native PostgreSQL
   enum, so a new member needs ALTER TYPE, and that has to run outside the
   migration's transaction. As in revisions 0006, 0008 and 0010, the value
   cannot be removed on downgrade: PostgreSQL has no ALTER TYPE DROP VALUE, and
   an unused label is inert. Downgrade moves any affected rows to OTHER so they
   stay readable to an application that no longer knows the label.

2. Coverage counters for the API security stage on scans.

Nothing secret is added, and nothing about a response body is. The stage reads
field *names*, header values already vetted as safe, and error-signal category
names; the counters here are totals over those. There is deliberately no column
for a field value, a header credential or an error excerpt.

Counters are nullable so that "the stage did not run" stays distinguishable from
"the stage ran and found nothing", matching every other counter on scans.

Revision ID: 0012_api_security
Revises: 0011_api_surface
Create Date: 2026-09-09

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_api_security"
down_revision: str | None = "0011_api_surface"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COUNTERS = (
    "api_sec_endpoints_analyzed",
    "api_sec_endpoints_skipped",
    "api_sec_responses_analyzed",
    "api_sec_sensitive_fields",
    "api_sec_property_comparisons",
    "api_sec_verbose_errors",
    "api_sec_cors_checks",
    "api_sec_inventory_observations",
    "api_sec_contexts_analyzed",
    "api_sec_unknown_policy",
    "api_sec_findings",
)


def upgrade() -> None:
    # ADD VALUE cannot be used later in the transaction that created it.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE finding_category ADD VALUE IF NOT EXISTS 'API_SECURITY'")

    op.add_column(
        "scans",
        sa.Column(
            "api_sec_analyzed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    for counter in _COUNTERS:
        op.add_column("scans", sa.Column(counter, sa.Integer(), nullable=True))


def downgrade() -> None:
    for counter in reversed(_COUNTERS):
        op.drop_column("scans", counter)
    op.drop_column("scans", "api_sec_analyzed")

    # A finding written under the new category would be unreadable once the
    # application no longer knows the label, so those rows move to the category
    # this scanner used before API security analysis existed.
    op.execute("UPDATE findings SET category = 'OTHER' WHERE category = 'API_SECURITY'")

    # API_SECURITY itself stays: PostgreSQL cannot drop an enum value, and an
    # unused label costs nothing. Same trade-off as revisions 0006, 0008, 0010.
