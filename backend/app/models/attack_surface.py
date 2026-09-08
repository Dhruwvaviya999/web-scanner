"""Attack-surface ORM models: endpoints, their parameters, and forms.

These are write-once discovery records — a crawl either produced them or it did
not — so they carry a single `discovered_at` timestamp rather than the
created/updated pair used by mutable rows.

No column here holds a parameter value, a form field value, or a query string
with values in it. `Endpoint.url` is the canonical form produced by
`url_normalizer.canonical_url`, which strips query values before storage.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.scanner.analysis.types import AnalysisSkipReason, EndpointAnalysisStatus
from app.scanner.crawler.types import FormFieldKind, ParameterLocation

if TYPE_CHECKING:
    from app.models.finding import Finding, FindingOccurrence
    from app.models.scan import Scan


class Endpoint(Base):
    """One reachable URL discovered by the crawler."""

    __tablename__ = "endpoints"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    #: Canonical URL: query parameter names are kept, their values removed.
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False, default="GET")

    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    page_title: Mapped[str | None] = mapped_column(String(512), nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # --- Analysis state (phase 5) ---
    analysis_status: Mapped[EndpointAnalysisStatus] = mapped_column(
        Enum(
            EndpointAnalysisStatus,
            name="endpoint_analysis_status",
            native_enum=True,
            validate_strings=True,
        ),
        nullable=False,
        default=EndpointAnalysisStatus.NOT_ANALYZED,
        server_default=EndpointAnalysisStatus.NOT_ANALYZED.value,
        index=True,
    )
    #: Why the endpoint was not analysed. Set only for SKIPPED and FAILED.
    skip_reason: Mapped[AnalysisSkipReason | None] = mapped_column(
        Enum(
            AnalysisSkipReason,
            name="analysis_skip_reason",
            native_enum=True,
            validate_strings=True,
        ),
        nullable=True,
    )
    #: Readable detail for a FAILED endpoint. Never response content.
    analysis_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="endpoints")
    findings: Mapped[list["Finding"]] = relationship(back_populates="endpoint")
    finding_occurrences: Mapped[list["FindingOccurrence"]] = relationship(
        back_populates="endpoint",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    parameters: Mapped[list["EndpointParameter"]] = relationship(
        back_populates="endpoint",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        # Backs the endpoints-for-a-scan listing, shallowest first.
        Index("ix_endpoints_scan_id_depth", "scan_id", "depth"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Endpoint {self.method} {self.path!r} depth={self.depth}>"


class EndpointParameter(Base):
    """One input parameter name observed on an endpoint. Names only, no values."""

    __tablename__ = "endpoint_parameters"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("endpoints.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    location: Mapped[ParameterLocation] = mapped_column(
        Enum(
            ParameterLocation,
            name="parameter_location",
            native_enum=True,
            validate_strings=True,
        ),
        nullable=False,
        default=ParameterLocation.QUERY,
    )

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    endpoint: Mapped["Endpoint"] = relationship(back_populates="parameters")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<EndpointParameter {self.name!r} {self.location.value}>"


class Form(Base):
    """An HTML form found on a crawled page. Discovered only — never submitted."""

    __tablename__ = "forms"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    page_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    action: Mapped[str] = mapped_column(String(2048), nullable=False)
    #: GET or POST — the only methods an HTML form can issue.
    method: Mapped[str] = mapped_column(String(10), nullable=False, default="GET")

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan: Mapped["Scan"] = relationship(back_populates="forms")
    fields: Mapped[list["FormField"]] = relationship(
        back_populates="form",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Form {self.method} {self.action!r}>"


class FormField(Base):
    """One named control inside a form. The control's value is never stored."""

    __tablename__ = "form_fields"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    form_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("forms.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[FormFieldKind] = mapped_column(
        Enum(FormFieldKind, name="form_field_kind", native_enum=True, validate_strings=True),
        nullable=False,
        default=FormFieldKind.INPUT,
    )
    #: The `type` attribute for inputs (text, password, email...). Metadata only:
    #: knowing a field is a password field never implies storing what was in it.
    input_type: Mapped[str | None] = mapped_column(String(40), nullable=True)

    form: Mapped["Form"] = relationship(back_populates="fields")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<FormField {self.name!r} {self.kind.value}>"
