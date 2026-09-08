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
    from app.models.attack_surface import Endpoint, Form
    from app.models.finding import Finding
    from app.models.user import User


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


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
        default=ScanStatus.PENDING,
        server_default=ScanStatus.PENDING.value,
        index=True,
    )

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

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

    __table_args__ = (
        # Backs the scan-history query: filter by owner, newest first.
        Index("ix_scans_user_id_created_at", "user_id", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Scan id={self.id} status={self.status.value} target={self.target_url!r}>"
