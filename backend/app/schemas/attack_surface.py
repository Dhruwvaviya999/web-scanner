"""Attack-surface response schemas.

None of these carry a parameter value or a form field value — only names, types
and structure.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.scanner.analysis.types import AnalysisSkipReason, EndpointAnalysisStatus
from app.scanner.crawler.types import FormFieldKind, ParameterLocation


class EndpointParameterRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str = Field(description="Parameter name. Values are never recorded.")
    location: ParameterLocation


class EndpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    url: str = Field(
        description="Canonical URL: query parameter names are kept, their values removed."
    )
    path: str
    method: str
    status_code: int | None
    content_type: str | None
    depth: int
    page_title: str | None
    discovered_at: datetime
    analysis_status: EndpointAnalysisStatus
    skip_reason: AnalysisSkipReason | None = None
    analysis_error: str | None = None
    parameters: list[EndpointParameterRead] = []


class FormFieldRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: FormFieldKind
    input_type: str | None = Field(
        default=None, description="The input's `type` attribute. Metadata only."
    )


class FormRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    page_url: str
    action: str
    method: str
    discovered_at: datetime
    fields: list[FormFieldRead] = []


class AttackSurfaceSummary(BaseModel):
    """Counters for the attack-surface header."""

    endpoints: int
    forms: int
    parameters: int = Field(description="Distinct parameter names across all endpoints.")
    pages_crawled: int | None = None
    pages_skipped: int | None = None
    max_depth_reached: int | None = None
    crawl_limit_reached: bool | None = Field(
        default=None,
        description="True when max_pages or the time budget ended the crawl. Normal termination.",
    )

    # --- Coverage (phase 5) ---
    endpoints_analyzed: int | None = None
    endpoints_skipped: int | None = None
    endpoints_failed: int | None = Field(
        default=None,
        description="Endpoints that could not be assessed. These never produce findings.",
    )


class EndpointListResponse(BaseModel):
    items: list[EndpointRead]
    summary: AttackSurfaceSummary


class FormListResponse(BaseModel):
    items: list[FormRead]
    total: int
