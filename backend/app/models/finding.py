"""Finding ORM model.

A finding is one security observation about one scan. Detectors produce
`FindingData` (a plain dataclass in the scanner package); the service layer turns
those into these rows. No detector touches the database.

The severity, confidence and category enums are imported from the scanner rather
than redeclared here, so the values the detectors emit and the values the
database accepts cannot drift apart.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin
from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
)

if TYPE_CHECKING:
    from app.models.attack_surface import Endpoint
    from app.models.scan import Scan


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    #: Stable identifier for the rule that fired, e.g.
    #: "SECURITY_HEADER_CSP_MISSING". This is the deduplication and correlation
    #: key; the title is display text and may be reworded freely.
    #:
    #: A validated string rather than a native enum: a scanner gains rules
    #: constantly, and ALTER TYPE on every one of them is friction for no gain.
    #: `FindingRule` enforces the allowed values in code and at the schema edge.
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)

    #: What the finding is about within its rule — a cookie name, for example.
    #: Part of the deduplication identity, so two cookies failing the same rule
    #: remain separate findings.
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True)

    #: The first endpoint this was observed on. Nullable: a finding may predate
    #: endpoint discovery, or come from a scan where crawling was disabled.
    #: SET NULL rather than CASCADE — losing an endpoint row must not silently
    #: delete the security finding that was reported against it.
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("endpoints.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    #: How many endpoints this finding was observed on. Denormalised from
    #: `occurrences` so a list view does not need to count rows.
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    category: Mapped[FindingCategory] = mapped_column(
        Enum(FindingCategory, name="finding_category", native_enum=True, validate_strings=True),
        nullable=False,
        index=True,
    )
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, name="finding_severity", native_enum=True, validate_strings=True),
        nullable=False,
        index=True,
    )
    confidence: Mapped[FindingConfidence] = mapped_column(
        Enum(
            FindingConfidence,
            name="finding_confidence",
            native_enum=True,
            validate_strings=True,
        ),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(Text, nullable=False)
    #: What was observed. Never contains a secret — cookie values in particular
    #: are discarded during parsing and cannot reach this column.
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    endpoint: Mapped["Endpoint | None"] = relationship(back_populates="findings")
    occurrences: Mapped[list["FindingOccurrence"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        # Backs the findings-for-a-scan query, ordered most severe first. The
        # native enum sorts in declaration order, which is CRITICAL -> INFO.
        Index("ix_findings_scan_id_severity", "scan_id", "severity"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Finding {self.severity.value} {self.rule_id!r} scan={self.scan_id}>"


class FindingOccurrence(Base):
    """One endpoint on which a finding was observed.

    Deduplication collapses repeats of a rule into a single `Finding`; this table
    is what stops that collapsing from losing information about *where* the rule
    failed. A missing CSP across twelve pages is one finding with twelve
    occurrences.
    """

    __tablename__ = "finding_occurrences"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    #: Null for a finding not tied to a discovered endpoint.
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("endpoints.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    #: The endpoint URL as observed, kept so an occurrence stays readable even if
    #: the endpoint row is later removed. Canonical, so it carries no query values.
    endpoint_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    #: What was observed at this endpoint. Never contains a secret.
    evidence: Mapped[str] = mapped_column(Text, nullable=False)

    finding: Mapped["Finding"] = relationship(back_populates="occurrences")
    endpoint: Mapped["Endpoint | None"] = relationship(back_populates="finding_occurrences")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<FindingOccurrence {self.endpoint_url!r}>"
