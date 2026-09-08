"""Scan intelligence: rule identity, finding occurrences, coverage (phase 5)

Four changes:

1. `findings.code` becomes `findings.rule_id`, holding stable rule identifiers.
   Existing rows are rewritten in place by the mapping below, so phase 3 findings
   stay valid and keep their identity.
2. Findings gain an optional endpoint link, a subject and an occurrence count.
3. A `finding_occurrences` table records every endpoint a finding was seen on,
   so deduplication never loses that information.
4. Endpoints gain analysis state, and scans gain summary counters.

Revision ID: 0005_scan_intelligence
Revises: 0004_attack_surface
Create Date: 2026-09-08

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_scan_intelligence"
down_revision: str | None = "0004_attack_surface"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ENDPOINT_ANALYSIS_STATUS = sa.Enum(
    "NOT_ANALYZED", "ANALYZED", "SKIPPED", "FAILED", name="endpoint_analysis_status"
)
ANALYSIS_SKIP_REASON = sa.Enum(
    "NON_HTML",
    "EXTERNAL",
    "DUPLICATE",
    "CRAWL_LIMIT",
    "REQUEST_FAILED",
    "UNSUPPORTED_SCHEME",
    "EXCLUDED_RESOURCE",
    name="analysis_skip_reason",
)

#: Phase 3 shipped short lowercase codes. Mirrors LEGACY_CODE_TO_RULE in
#: app/scanner/security/types.py — kept literal here so the migration does not
#: depend on application code that may move.
LEGACY_CODE_TO_RULE = {
    "missing_hsts": "SECURITY_HEADER_HSTS_MISSING",
    "hsts_disabled": "SECURITY_HEADER_HSTS_DISABLED",
    "hsts_short_max_age": "SECURITY_HEADER_HSTS_SHORT_MAX_AGE",
    "missing_csp": "SECURITY_HEADER_CSP_MISSING",
    "permissive_csp": "SECURITY_HEADER_CSP_PERMISSIVE",
    "missing_content_type_options": "SECURITY_HEADER_X_CONTENT_TYPE_OPTIONS_MISSING",
    "missing_frame_options": "SECURITY_HEADER_X_FRAME_OPTIONS_MISSING",
    "missing_referrer_policy": "SECURITY_HEADER_REFERRER_POLICY_MISSING",
    "missing_permissions_policy": "SECURITY_HEADER_PERMISSIONS_POLICY_MISSING",
    "cookie_missing_secure": "COOKIE_SECURE_MISSING",
    "session_cookie_missing_httponly": "COOKIE_HTTPONLY_MISSING",
    "cookie_missing_samesite": "COOKIE_SAMESITE_MISSING",
    "cookie_samesite_none_without_secure": "COOKIE_SAMESITE_NONE_WITHOUT_SECURE",
}


def upgrade() -> None:
    bind = op.get_bind()

    # --- 1. findings.code -> findings.rule_id ---------------------------- #
    op.alter_column("findings", "code", new_column_name="rule_id")
    for legacy, rule_id in LEGACY_CODE_TO_RULE.items():
        bind.execute(
            sa.text("UPDATE findings SET rule_id = :rule_id WHERE rule_id = :legacy"),
            {"rule_id": rule_id, "legacy": legacy},
        )
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])

    # --- 2. finding identity and endpoint association -------------------- #
    op.add_column("findings", sa.Column("subject", sa.String(length=255), nullable=True))
    op.add_column(
        "findings",
        sa.Column("endpoint_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    # SET NULL, not CASCADE: removing an endpoint must not silently delete the
    # security finding that was reported against it.
    op.create_foreign_key(
        "fk_findings_endpoint_id_endpoints",
        "findings",
        "endpoints",
        ["endpoint_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_findings_endpoint_id", "findings", ["endpoint_id"])
    op.add_column(
        "findings",
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
    )

    # --- 3. finding occurrences ------------------------------------------ #
    op.create_table(
        "finding_occurrences",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("endpoint_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("endpoint_url", sa.String(length=2048), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_finding_occurrences_finding_id_findings",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["endpoint_id"],
            ["endpoints.id"],
            name="fk_finding_occurrences_endpoint_id_endpoints",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_finding_occurrences"),
    )
    op.create_index("ix_finding_occurrences_finding_id", "finding_occurrences", ["finding_id"])
    op.create_index(
        "ix_finding_occurrences_endpoint_id", "finding_occurrences", ["endpoint_id"]
    )

    # Give every pre-existing finding one occurrence, so the new shape is
    # consistent for rows recorded before this migration.
    bind.execute(
        sa.text(
            "INSERT INTO finding_occurrences (id, finding_id, endpoint_id, endpoint_url, evidence) "
            "SELECT gen_random_uuid(), id, NULL, NULL, evidence FROM findings"
        )
    )

    # --- 4. endpoint analysis state -------------------------------------- #
    ENDPOINT_ANALYSIS_STATUS.create(bind, checkfirst=True)
    ANALYSIS_SKIP_REASON.create(bind, checkfirst=True)
    op.add_column(
        "endpoints",
        sa.Column(
            "analysis_status",
            ENDPOINT_ANALYSIS_STATUS,
            nullable=False,
            server_default="NOT_ANALYZED",
        ),
    )
    op.add_column("endpoints", sa.Column("skip_reason", ANALYSIS_SKIP_REASON, nullable=True))
    op.add_column("endpoints", sa.Column("analysis_error", sa.Text(), nullable=True))
    op.create_index("ix_endpoints_analysis_status", "endpoints", ["analysis_status"])

    # --- 5. scan summary counters ---------------------------------------- #
    for column in (
        "endpoints_discovered",
        "endpoints_analyzed",
        "endpoints_skipped",
        "endpoints_failed",
        "forms_discovered",
        "parameters_discovered",
        "total_findings",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        "info_count",
    ):
        op.add_column("scans", sa.Column(column, sa.Integer(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()

    for column in (
        "info_count",
        "low_count",
        "medium_count",
        "high_count",
        "critical_count",
        "total_findings",
        "parameters_discovered",
        "forms_discovered",
        "endpoints_failed",
        "endpoints_skipped",
        "endpoints_analyzed",
        "endpoints_discovered",
    ):
        op.drop_column("scans", column)

    op.drop_index("ix_endpoints_analysis_status", table_name="endpoints")
    op.drop_column("endpoints", "analysis_error")
    op.drop_column("endpoints", "skip_reason")
    op.drop_column("endpoints", "analysis_status")
    ANALYSIS_SKIP_REASON.drop(bind, checkfirst=True)
    ENDPOINT_ANALYSIS_STATUS.drop(bind, checkfirst=True)

    op.drop_index("ix_finding_occurrences_endpoint_id", table_name="finding_occurrences")
    op.drop_index("ix_finding_occurrences_finding_id", table_name="finding_occurrences")
    op.drop_table("finding_occurrences")

    op.drop_column("findings", "occurrence_count")
    op.drop_index("ix_findings_endpoint_id", table_name="findings")
    op.drop_constraint("fk_findings_endpoint_id_endpoints", "findings", type_="foreignkey")
    op.drop_column("findings", "endpoint_id")
    op.drop_column("findings", "subject")

    # Reverse the rule rewrite so the column holds phase-3 codes again.
    op.drop_index("ix_findings_rule_id", table_name="findings")
    for legacy, rule_id in LEGACY_CODE_TO_RULE.items():
        bind.execute(
            sa.text("UPDATE findings SET rule_id = :legacy WHERE rule_id = :rule_id"),
            {"rule_id": rule_id, "legacy": legacy},
        )
    op.alter_column("findings", "rule_id", new_column_name="code")
