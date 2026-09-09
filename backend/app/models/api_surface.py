"""API attack-surface ORM models.

**Why these are not columns on `Endpoint`.** An `Endpoint` row means "the
crawler requested this URL and got a response". A specification can describe an
operation nobody has ever reached — that is the single most useful thing API
discovery produces, and writing it as an `Endpoint` would be a lie: it would
inflate `endpoints_discovered`, enter the analysis-coverage counters, and become
eligible for authorization comparison against a resource that may not exist.

So an observed API endpoint links back to its `Endpoint` row through
`endpoint_id`, and a documented-only one simply has none. One record per
`(method, path)` either way, which is what keeps the API inventory finite and
what lets phase 12's authorization matrix keep referring to paths rather than to
a second set of identities.

Nothing here holds a response body, a parameter value, a credential or a header.
`json_field_names` is a list of *names* — `id`, `email`, `role` — which describes
the interface; the data that was in those fields is discarded with the body at
capture time and never reaches this table.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.attack_surface import Endpoint
    from app.models.scan import Scan

#: Joins list-valued metadata into one column. A unit separator cannot occur in
#: a media type, a scheme name or a JSON field name, so a value containing a
#: comma cannot split into two on read-back.
LIST_SEPARATOR = "\x1f"


def join_list(values) -> str | None:
    """Pack a sequence for storage, or None when it is empty."""
    items = [str(value) for value in values if str(value)]
    return LIST_SEPARATOR.join(items) if items else None


def split_list(value: str | None) -> list[str]:
    """Unpack a stored list. An empty column reads back as an empty list."""
    if not value:
        return []
    return [item for item in value.split(LIST_SEPARATOR) if item]


class ApiEndpointRow(Base):
    """One API operation discovered during a scan.

    Identity within a scan is `(method, path)`. Query values never participate,
    so `/api/products?id=1` and `?id=2` are one row with a parameter named `id`.
    """

    __tablename__ = "api_endpoints"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    #: The crawl row this was observed on. NULL for a documented-only operation,
    #: which by definition was never requested.
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("endpoints.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False, default="GET")
    #: Canonical URL when observed; NULL when only documented.
    url: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    # --- Classification ---
    # Validated strings rather than native enums, following `current_stage` and
    # the phase-12 authorization columns: these vocabularies are presentation
    # detail and expected to grow, and ALTER TYPE per value buys nothing.
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="LOW")
    #: Every mechanism that found this operation, packed. More than one is the
    #: normal case and is stronger evidence than any single source.
    sources: Mapped[str | None] = mapped_column(String(255), nullable=True)
    auth_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNKNOWN"
    )
    observed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    documented: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # --- Observed / documented detail ---
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    request_media_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    response_media_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    operation_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Security scheme *names* a specification attached to this operation. The
    #: scanner never constructs a credential from one.
    security: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # --- JSON response structure. Names only, never values. ---
    json_top_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    json_field_names: Mapped[str | None] = mapped_column(Text, nullable=True)
    json_depth: Mapped[int | None] = mapped_column(Integer, nullable=True)
    json_field_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan: Mapped["Scan"] = relationship(back_populates="api_endpoints")
    endpoint: Mapped["Endpoint | None"] = relationship()
    parameters: Mapped[list["ApiEndpointParameter"]] = relationship(
        back_populates="api_endpoint",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        Index("ix_api_endpoints_scan_id_path", "scan_id", "path"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ApiEndpoint {self.method} {self.path!r} {self.confidence}>"


class ApiEndpointParameter(Base):
    """One API parameter name. Names and locations only — never a value."""

    __tablename__ = "api_endpoint_parameters"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    api_endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("api_endpoints.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    #: PATH, QUERY, HEADER, COOKIE or BODY. A validated string rather than an
    #: extension of the phase-4 `parameter_location` enum, which would need
    #: ALTER TYPE for three values only the API layer uses.
    location: Mapped[str] = mapped_column(String(16), nullable=False, default="QUERY")
    #: From a specification, when it said. NULL means nobody said.
    required: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    api_endpoint: Mapped["ApiEndpointRow"] = relationship(back_populates="parameters")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ApiEndpointParameter {self.name!r} {self.location}>"


class ApiDocument(Base):
    """A specification the scanner found and read. Never executed."""

    __tablename__ = "api_documents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    #: "3.0.1", "2.0" — as the document declared it.
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    document_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    path_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    operation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: Declared authentication scheme names. Metadata only; no credential is
    #: ever built from these.
    security_schemes: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    #: True when parsing stopped at the path budget, so a partial read is never
    #: mistaken for a complete inventory.
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan: Mapped["Scan"] = relationship(back_populates="api_documents")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ApiDocument {self.version} {self.url!r}>"
