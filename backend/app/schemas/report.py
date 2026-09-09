"""Report response schemas.

The wire shape of the canonical report. Field names and ordering are stable so
the JSON is suitable for saving to a file, diffing, or feeding a CI check.

Only fields already vetted as safe in earlier phases appear here. There is no
field for a cookie value, an authorization header, a probe value, a payload, a
request body or a query-parameter value — a secret has nowhere to go.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.scanner.auth import AuthMode, AuthStatus
from app.scanner.security.types import FindingCategory, FindingConfidence, FindingSeverity


class ReportAuthenticationRead(BaseModel):
    """How the scan authenticated. Structurally incapable of holding a secret."""

    model_config = ConfigDict(from_attributes=True)

    mode: AuthMode
    status: AuthStatus
    authenticated: bool = Field(
        description="Whether any credential was configured for this scan."
    )
    confirmed: bool = Field(
        description=(
            "Whether one initial access check accepted the credentials. Not a "
            "claim that they were valid for every path, or for the whole scan."
        )
    )


class ReportMetadataRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scan_id: str
    target_url: str
    final_url: str | None
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None
    generated_at: datetime
    error_message: str | None = None
    cancelled_at: datetime | None = None
    failure_stage: str | None = Field(
        default=None,
        description="Stage a failed scan was in. A stage name only, never a trace.",
    )
    authentication: ReportAuthenticationRead
    is_conclusive: bool = Field(
        description=(
            "True only when the scan ran to completion. A failed or cancelled scan "
            "covers only what it reached before stopping, so an empty findings list "
            "on an inconclusive report is not an all-clear."
        )
    )


class CoverageSummaryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    endpoints_discovered: int | None
    endpoints_analyzed: int | None
    endpoints_skipped: int | None
    endpoints_failed: int | None
    forms_discovered: int | None
    parameters_discovered: int | None
    pages_crawled: int | None
    pages_skipped: int | None
    max_depth_reached: int | None
    crawl_limit_reached: bool | None
    scan_completed: bool = Field(
        description="Whether the run itself finished, as opposed to failing or being cancelled."
    )
    authentication_usable: bool = Field(
        description=(
            "False when credentials were supplied and the target refused them, so "
            "only the anonymous surface was covered."
        )
    )
    is_complete: bool = Field(
        description=(
            "True only when every discovered endpoint was analysed or deliberately "
            "skipped, with no analysis failures. A clean result with is_complete=false "
            "means the scan did not cover everything it found."
        )
    )


class SeveritySummaryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class ReportEndpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    url: str = Field(description="Canonical URL: parameter names only, never values.")
    path: str | None = None
    method: str | None = None


class ReportFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rule_id: str
    category: FindingCategory
    severity: FindingSeverity
    confidence: FindingConfidence
    title: str
    description: str
    impact: str
    remediation: str
    evidence: str = Field(
        description="Normalised observation. Never contains secrets or probe values."
    )
    subject: str | None
    occurrence_count: int
    endpoints: list[ReportEndpointRead] = []


class CategoryGroupRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    category: FindingCategory
    total: int
    severity: SeveritySummaryRead


class AttackSurfaceSummaryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    endpoints: int
    forms: int
    parameters: int


class ScanReportRead(BaseModel):
    """The canonical report, as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    metadata: ReportMetadataRead
    coverage: CoverageSummaryRead
    severity: SeveritySummaryRead
    attack_surface: AttackSurfaceSummaryRead
    findings: list[ReportFindingRead] = []
    categories: list[CategoryGroupRead] = []
    parameter_names: list[str] = Field(
        default=[], description="Discovered parameter names. Names only, never values."
    )
