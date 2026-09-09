"""Scan ORM model.

Phase 1 stores the handful of facts a single HTTP probe produces directly on the
scan row. Later phases add a separate `findings` table rather than widening this
one further.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.api_surface import ApiDocument, ApiEndpointRow
    from app.models.attack_surface import Endpoint, Form
    from app.models.finding import Finding
    from app.models.user import User


class ScanStatus(str, enum.Enum):
    """The scan lifecycle. Legal transitions live in `services.scan_lifecycle`.

    COMPLETED, FAILED and CANCELLED are terminal: a scan that reaches one of
    them never runs again.
    """

    #: Created, not yet started.
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    #: Orchestration failed. Distinct from individual endpoints failing to
    #: analyse, which is recorded in coverage and leaves the scan COMPLETED.
    FAILED = "FAILED"
    #: Stopped on the owner's request. Partial results are kept.
    CANCELLED = "CANCELLED"


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", native_enum=True, validate_strings=True),
        nullable=False,
        default=ScanStatus.QUEUED,
        server_default=ScanStatus.QUEUED.value,
        index=True,
    )

    # --- Lifecycle timing (phase 10) ---
    # All timezone-aware UTC, consistent with the rest of the application.
    # `completed_at` is the terminal timestamp for every ending — COMPLETED,
    # FAILED and CANCELLED alike — so duration is always completed_at minus
    # started_at and never needs a per-outcome column. `cancelled_at` is kept
    # separately because "when the user asked to stop" is a distinct fact from
    # "when the run actually wound down".
    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: Set by the cancel endpoint; observed by the running scan at safe
    #: boundaries. Cancellation is cooperative — nothing is killed.
    cancel_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    # --- Progress (phase 10) ---
    # A validated string rather than a native enum: stages are presentation
    # detail and will change more often than the status set, and ALTER TYPE per
    # stage is friction for no gain. `services.scan_lifecycle.ScanStage`
    # enforces the allowed values.
    current_stage: Mapped[str | None] = mapped_column(String(32), nullable=True)
    #: Indicative only. NULL whenever a real figure cannot be justified — the
    #: crawler does not know its total work in advance.
    progress_percent: Mapped[int | None] = mapped_column(Integer, nullable=True)
    progress_message: Mapped[str | None] = mapped_column(String(255), nullable=True)

    #: Which stage was running when a scan failed. Safe to show: a stage name,
    #: never a stack trace, request or secret.
    failure_stage: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # --- Target authentication (phase 11) ---
    # Metadata only. The token or cookie values a user supplies for their own
    # application are NEVER written here, or anywhere else in the database:
    # they live in memory for the duration of the scan and are gone with the
    # request. These two columns record only which kind of credential was used
    # and what one initial access check concluded about it.
    #
    # Validated strings rather than native enums, for the same reason as
    # `current_stage`: the vocabularies are presentation-level and expected to
    # grow, and ALTER TYPE per value is friction for no gain.
    # `scanner.auth.AuthMode` and `AuthStatus` enforce the allowed values.
    auth_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, default="NONE", server_default="NONE"
    )
    auth_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="NOT_CONFIGURED", server_default="NOT_CONFIGURED"
    )

    # --- Authorization testing (phase 12) ---
    # Coverage counters and nothing else. The identities used are supplied per
    # scan and their credentials live only in memory, exactly as in phase 11 —
    # there is no column here, or anywhere, for one. `authz_context_labels`
    # holds user-chosen display names such as "alice" or "admin", which are
    # metadata about the test, not about the credential.
    authz_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    #: NULL when the stage did not run, which stays distinct from "ran and
    #: compared nothing" — the same convention as the phase 4/5 counters.
    authz_contexts: Mapped[int | None] = mapped_column(Integer, nullable=True)
    authz_context_labels: Mapped[str | None] = mapped_column(String(512), nullable=True)
    authz_endpoints_eligible: Mapped[int | None] = mapped_column(Integer, nullable=True)
    authz_endpoints_tested: Mapped[int | None] = mapped_column(Integer, nullable=True)
    authz_comparisons: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Comparisons with no declared policy to judge against. Not vulnerabilities.
    authz_unknown: Mapped[int | None] = mapped_column(Integer, nullable=True)
    authz_skipped: Mapped[int | None] = mapped_column(Integer, nullable=True)
    authz_failed: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # --- API discovery (phase 13) ---
    # Coverage counters for the API attack surface. The endpoints themselves
    # live in `api_endpoints`; these are the denormalised totals a scan list and
    # a report header need without a join, matching how the phase 4/5 crawl
    # counters work.
    #
    # NULL means the stage did not run, which stays distinct from "ran and found
    # nothing" — the same convention as every other counter on this row.
    api_detected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    api_endpoints_discovered: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Actually requested and answered, as opposed to merely described.
    api_endpoints_observed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Described by a specification and never reached. The distinction the API
    #: report leans on hardest: documented is not the same as working.
    api_endpoints_documented_only: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    api_parameters_discovered: Mapped[int | None] = mapped_column(Integer, nullable=True)
    api_document_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    api_authenticated_endpoints: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    api_unknown_auth_endpoints: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: True when a bound stopped the inventory growing, so a partial surface is
    #: never presented as complete.
    api_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    #: GraphQL presence only. Introspection is never run in this phase, and the
    #: report says so explicitly rather than leaving a reader to assume.
    api_graphql_detected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    api_graphql_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # --- API security analysis (phase 14) ---
    # Totals over what the stage read: field names, header values already vetted
    # as safe, and error-signal category names. There is deliberately no column
    # for a field value, a header credential or an excerpt of an error.
    #
    # NULL means the stage did not run, distinct from "ran and found nothing".
    api_sec_analyzed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    api_sec_endpoints_analyzed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    api_sec_endpoints_skipped: Mapped[int | None] = mapped_column(Integer, nullable=True)
    api_sec_responses_analyzed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    api_sec_sensitive_fields: Mapped[int | None] = mapped_column(Integer, nullable=True)
    api_sec_property_comparisons: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    api_sec_verbose_errors: Mapped[int | None] = mapped_column(Integer, nullable=True)
    api_sec_cors_checks: Mapped[int | None] = mapped_column(Integer, nullable=True)
    api_sec_inventory_observations: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    api_sec_contexts_analyzed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Sensitive-looking fields with no declared policy to judge them against.
    #: The common outcome on a real target, and never a finding.
    api_sec_unknown_policy: Mapped[int | None] = mapped_column(Integer, nullable=True)
    api_sec_findings: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # --- Basic HTTP probe result ---
    # All nullable: a scan that failed, or has not run yet, has none of them.
    http_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    final_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    server_header: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_https: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    redirect_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # --- Response analysis (phase 2) ---
    #: <title> of the target page, when it returned HTML carrying one.
    page_title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    #: Body size in bytes. BigInteger because Content-Length can exceed 2 GiB.
    content_length: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # --- Crawl summary (phase 4) ---
    # Null when the crawler did not run. `crawl_limit_reached` records normal
    # early termination on max_pages or the time budget, not a failure.
    pages_crawled: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pages_skipped: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_depth_reached: Mapped[int | None] = mapped_column(Integer, nullable=True)
    crawl_limit_reached: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    # --- Scan summary (phase 5) ---
    # Denormalised counters so a scan list does not need per-row aggregates.
    # Written once, at the end of the scan, from what the pipeline produced.
    endpoints_discovered: Mapped[int | None] = mapped_column(Integer, nullable=True)
    endpoints_analyzed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    endpoints_skipped: Mapped[int | None] = mapped_column(Integer, nullable=True)
    endpoints_failed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    forms_discovered: Mapped[int | None] = mapped_column(Integer, nullable=True)
    parameters_discovered: Mapped[int | None] = mapped_column(Integer, nullable=True)

    total_findings: Mapped[int | None] = mapped_column(Integer, nullable=True)
    critical_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    high_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    medium_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    low_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    info_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Populated only when `status == FAILED`; safe to show to the scan's owner.
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped["User"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    endpoints: Mapped[list["Endpoint"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    forms: Mapped[list["Form"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    api_endpoints: Mapped[list["ApiEndpointRow"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    api_documents: Mapped[list["ApiDocument"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        # Backs the scan-history query: filter by owner, newest first.
        Index("ix_scans_user_id_created_at", "user_id", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Scan id={self.id} status={self.status.value} target={self.target_url!r}>"
