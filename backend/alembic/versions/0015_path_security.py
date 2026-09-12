"""Path security: the INPUT_VALIDATION finding category and coverage counters

Two changes.

1. finding_category gains INPUT_VALIDATION. The category is a native PostgreSQL
   enum, so a new member needs ALTER TYPE, and that has to run outside the
   migration's transaction. As in revisions 0006, 0008, 0010, 0012, 0013 and
   0014, the value cannot be removed on downgrade: PostgreSQL has no ALTER TYPE
   DROP VALUE, and an unused label is inert. Downgrade moves any affected rows
   to OTHER so they stay readable to an application that no longer knows it.

2. Coverage counters for the path-security stage on scans.

Nothing secret is added. The stage that fills these columns never holds a file's
contents, the canary's bytes, a probe value or a response body — the traversal
detector computes a boolean (marker present) while the body is in hand and
discards it — so there is deliberately no column here that could store one.
Every column below is an integer or a boolean.

`path_parameters_skipped` and `path_budget_exhausted` deserve a note: a
file-like parameter that was not tested (an unusable baseline, or a budget cut)
established nothing, and recording both keeps a partial run from reading as a
clean one.

Counters are nullable so that "the stage did not run" stays distinguishable from
"the stage ran and found nothing", matching every other counter on scans.

Revision ID: 0015_path_security
Revises: 0014_config_security
Create Date: 2026-09-12

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_path_security"
down_revision: str | None = "0014_config_security"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COUNTERS = (
    "path_parameters_considered",
    "path_file_parameters",
    "path_parameters_tested",
    "path_parameters_skipped",
    "path_endpoints_tested",
    "path_traversal_probes",
    "path_canary_matches",
    "path_lfi_candidates",
    "path_requests_sent",
    "path_findings",
)


def upgrade() -> None:
    # ADD VALUE cannot be used later in the transaction that created it.
    with op.get_context().autocommit_block():
        op.execute(
            "ALTER TYPE finding_category ADD VALUE IF NOT EXISTS 'INPUT_VALIDATION'"
        )

    op.add_column(
        "scans",
        sa.Column(
            "path_analyzed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    for counter in _COUNTERS:
        op.add_column("scans", sa.Column(counter, sa.Integer(), nullable=True))
    op.add_column(
        "scans", sa.Column("path_budget_exhausted", sa.Boolean(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("scans", "path_budget_exhausted")
    for counter in reversed(_COUNTERS):
        op.drop_column("scans", counter)
    op.drop_column("scans", "path_analyzed")

    # A finding written under the new category would be unreadable once the
    # application no longer knows the label, so those rows move to the category
    # this scanner used before path-security analysis existed.
    op.execute(
        "UPDATE findings SET category = 'OTHER' WHERE category = 'INPUT_VALIDATION'"
    )

    # INPUT_VALIDATION itself stays: PostgreSQL cannot drop an enum value, and an
    # unused label costs nothing. Same trade-off as 0006, 0008, 0010, 0012-0014.
