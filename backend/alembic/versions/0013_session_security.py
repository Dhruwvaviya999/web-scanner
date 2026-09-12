"""Session security: the SESSION_SECURITY finding category and coverage counters

Two changes.

1. finding_category gains SESSION_SECURITY. The category is a native PostgreSQL
   enum, so a new member needs ALTER TYPE, and that has to run outside the
   migration's transaction. As in revisions 0006, 0008, 0010 and 0012, the value
   cannot be removed on downgrade: PostgreSQL has no ALTER TYPE DROP VALUE, and
   an unused label is inert. Downgrade moves any affected rows to OTHER so they
   stay readable to an application that no longer knows the label.

2. Coverage counters for the session security stage on scans.

Nothing secret is added. The stage that fills these columns never holds a cookie
value, a session identifier, a bearer token, a JSON Web Token or any segment of
one, a CSRF token, or a form field value — they are discarded at the point they
are read — so there is deliberately no column here that could store one. Every
column below is an integer or a boolean.

`session_csrf_potential` deserves a note: it counts forms where several signals
line up but a server-side defence could still exist. It is shown in the report
and never becomes a finding, because the absence of a visible CSRF token is not
evidence that CSRF is exploitable.

Counters are nullable so that "the stage did not run" stays distinguishable from
"the stage ran and found nothing", matching every other counter on scans.

Revision ID: 0013_session_security
Revises: 0012_api_security
Create Date: 2026-09-12

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_session_security"
down_revision: str | None = "0012_api_security"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COUNTERS = (
    "session_cookies_identified",
    "session_identifiers_in_urls",
    "session_token_exposures",
    "session_csrf_forms_analyzed",
    "session_csrf_potential",
    "session_csrf_strong",
    "session_jwt_observed",
    "session_timeout_known",
    "session_logout_endpoints",
    "session_findings",
)


def upgrade() -> None:
    # ADD VALUE cannot be used later in the transaction that created it.
    with op.get_context().autocommit_block():
        op.execute(
            "ALTER TYPE finding_category ADD VALUE IF NOT EXISTS 'SESSION_SECURITY'"
        )

    op.add_column(
        "scans",
        sa.Column(
            "session_analyzed",
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
    op.drop_column("scans", "session_analyzed")

    # A finding written under the new category would be unreadable once the
    # application no longer knows the label, so those rows move to the category
    # this scanner used before session analysis existed.
    op.execute(
        "UPDATE findings SET category = 'OTHER' WHERE category = 'SESSION_SECURITY'"
    )

    # SESSION_SECURITY itself stays: PostgreSQL cannot drop an enum value, and
    # an unused label costs nothing. Same trade-off as 0006, 0008, 0010, 0012.
