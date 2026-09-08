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

from sqlalchemy import Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin
from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
)

if TYPE_CHECKING:
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

    #: Stable identifier for the rule that fired, e.g. "missing_csp". Findings
    #: can be correlated across scans on this rather than on their wording.
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)

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

    __table_args__ = (
        # Backs the findings-for-a-scan query, ordered most severe first. The
        # native enum sorts in declaration order, which is CRITICAL -> INFO.
        Index("ix_findings_scan_id_severity", "scan_id", "severity"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Finding {self.severity.value} {self.code!r} scan={self.scan_id}>"
