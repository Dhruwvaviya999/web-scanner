"""Configuration security: the CONFIGURATION finding category and coverage counters

Two changes.

1. finding_category gains CONFIGURATION. The category is a native PostgreSQL
   enum, so a new member needs ALTER TYPE, and that has to run outside the
   migration's transaction. As in revisions 0006, 0008, 0010, 0012 and 0013, the
   value cannot be removed on downgrade: PostgreSQL has no ALTER TYPE DROP
   VALUE, and an unused label is inert. Downgrade moves any affected rows to
   OTHER so they stay readable to an application that no longer knows the label.

2. Coverage counters for the configuration security stage on scans.

Nothing secret is added, and nothing about a response body is. The stage that
fills these columns never holds a file's contents, an environment variable, a
credential, a repository object or a source line — they are discarded inside the
function that reads them — so there is deliberately no column here that could
store one. Every column below is an integer or a boolean.

`config_candidates_not_tested` and `config_budget_exhausted` deserve a note.
This stage works from bounded candidate lists and a hard request budget, and a
candidate the budget never reached has established nothing. Recording both means
a truncated scan reports reduced coverage rather than appearing to have looked
everywhere and found nothing.

Counters are nullable so that "the stage did not run" stays distinguishable from
"the stage ran and found nothing", matching every other counter on scans.

Revision ID: 0014_config_security
Revises: 0013_session_security
Create Date: 2026-09-12

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_config_security"
down_revision: str | None = "0013_session_security"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COUNTERS = (
    "config_method_observations",
    "config_debug_indicators",
    "config_files_checked",
    "config_files_exposed",
    "config_admin_endpoints",
    "config_management_endpoints",
    "config_directory_listings",
    "config_source_maps",
    "config_technology_disclosures",
    "config_path_observations",
    "config_candidates_not_tested",
    "config_requests_sent",
    "config_findings",
)

_FLAGS = (
    "config_https_used",
    "config_https_redirect",
    "config_hsts_observed",
    "config_budget_exhausted",
)


def upgrade() -> None:
    # ADD VALUE cannot be used later in the transaction that created it.
    with op.get_context().autocommit_block():
        op.execute(
            "ALTER TYPE finding_category ADD VALUE IF NOT EXISTS 'CONFIGURATION'"
        )

    op.add_column(
        "scans",
        sa.Column(
            "config_analyzed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    for flag in _FLAGS:
        op.add_column("scans", sa.Column(flag, sa.Boolean(), nullable=True))
    for counter in _COUNTERS:
        op.add_column("scans", sa.Column(counter, sa.Integer(), nullable=True))


def downgrade() -> None:
    for counter in reversed(_COUNTERS):
        op.drop_column("scans", counter)
    for flag in reversed(_FLAGS):
        op.drop_column("scans", flag)
    op.drop_column("scans", "config_analyzed")

    # A finding written under the new category would be unreadable once the
    # application no longer knows the label, so those rows move to the category
    # this scanner used before configuration analysis existed.
    op.execute("UPDATE findings SET category = 'OTHER' WHERE category = 'CONFIGURATION'")

    # CONFIGURATION itself stays: PostgreSQL cannot drop an enum value, and an
    # unused label costs nothing. Same trade-off as 0006, 0008, 0010, 0012, 0013.
