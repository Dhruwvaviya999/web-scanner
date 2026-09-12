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


class ReportApiParameterRead(BaseModel):
    """One API parameter. Structurally incapable of holding a value."""

    model_config = ConfigDict(from_attributes=True)

    name: str
    location: str
    required: bool | None = None


class ReportApiEndpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    path: str
    method: str
    confidence: str
    sources: list[str]
    auth_status: str
    observed: bool = Field(
        description="The scanner requested this and something answered."
    )
    documented: bool = Field(
        description="A specification says it exists. That is a claim, not a fact."
    )
    documented_only: bool = Field(
        description="Described by a specification and never actually reached."
    )
    status_code: int | None = None
    request_media_type: str | None = None
    response_media_type: str | None = None
    operation_id: str | None = None
    security: list[str] = Field(
        default_factory=list,
        description="Security scheme names a specification declared. Never a credential.",
    )
    parameters: list[ReportApiParameterRead] = Field(default_factory=list)
    json_field_names: list[str] = Field(
        default_factory=list,
        description="Field names from a JSON response. Never a value from one.",
    )
    json_top_level: str | None = None


class ReportApiDocumentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    url: str
    version: str
    title: str | None = None
    path_count: int
    operation_count: int
    security_schemes: list[str] = Field(default_factory=list)
    truncated: bool


class ReportApiSecurityRead(BaseModel):
    """API security coverage. Structurally incapable of holding a value."""

    model_config = ConfigDict(from_attributes=True)

    analyzed: bool
    endpoints_analyzed: int
    endpoints_skipped: int
    responses_analyzed: int
    sensitive_fields_detected: int
    property_comparisons: int
    verbose_errors: int
    cors_checks: int
    inventory_observations: int
    contexts_analyzed: int
    unknown_policy: int = Field(
        description=(
            "Sensitive-looking fields with no declared policy to judge them "
            "against. Observations, not findings — and not a clean result either."
        )
    )
    findings_count: int
    judged: bool = Field(
        description=(
            "True when at least something was measured against a declared policy "
            "rather than merely observed."
        )
    )


class ReportSessionSecurityRead(BaseModel):
    """Session coverage. Structurally incapable of holding a value.

    Every field is a boolean or a count. There is no field for a cookie value, a
    session identifier, a token, a JWT segment, a CSRF token or a form field
    value, because none of those reach this layer.
    """

    model_config = ConfigDict(from_attributes=True)

    analyzed: bool
    session_cookies_identified: int
    session_identifiers_in_urls: int
    token_exposures: int
    csrf_forms_analyzed: int
    csrf_potential: int = Field(
        description=(
            "Forms where several signals line up but a server-side defence could "
            "still exist. Shown, and deliberately never a finding: the absence of "
            "a visible CSRF token is not evidence that CSRF is exploitable."
        )
    )
    csrf_strong: int = Field(
        description=(
            "Forms where the browser's own SameSite defence does not apply either. "
            "The only verdict that produces a finding, and still unconfirmed: no "
            "request was forged to test it."
        )
    )
    jwt_tokens_observed: int
    timeout_known: bool = Field(
        description=(
            "Whether anything established a session lifetime. False is not a "
            "weakness — server-side expiry cannot be observed from outside."
        )
    )
    logout_endpoints_discovered: int = Field(
        description="Found and recorded. None of them was ever called."
    )
    findings_count: int
    requests_sent: int = Field(
        description="Requests this stage made. Zero by design."
    )
    csrf_conclusive: bool = Field(
        description=(
            "False whenever any form landed on POTENTIAL. Those are unresolved "
            "questions, not an all-clear."
        )
    )


class ReportConfigSecurityRead(BaseModel):
    """Configuration coverage. Structurally incapable of holding content.

    Every field is a boolean or a count. There is no field for a response body,
    a file's contents, an environment variable, a secret, a repository object
    or a source line, because none of those reach this layer.
    """

    model_config = ConfigDict(from_attributes=True)

    analyzed: bool
    https_used: bool
    https_redirect: bool
    hsts_observed: bool
    method_observations: int
    debug_indicators: int
    sensitive_files_checked: int
    sensitive_files_exposed: int
    admin_endpoints_discovered: int = Field(
        description=(
            "Administrative paths that answered. Not by itself a weakness — many "
            "applications correctly serve a login form at one."
        )
    )
    management_endpoints_discovered: int
    directory_listings: int
    source_maps: int
    technology_disclosures: int = Field(
        description="Headers naming the stack. Informational; this is normal."
    )
    path_normalization_observations: int
    candidates_not_tested: int = Field(
        description=(
            "Bounded candidate paths the request budget never reached. These "
            "established nothing and must not be read as clean."
        )
    )
    requests_sent: int
    findings_count: int
    budget_exhausted: bool
    coverage_complete: bool = Field(
        description=(
            "False when a budget cut the candidate checks short, so silence about "
            "the remainder is absence of evidence rather than evidence of absence."
        )
    )


class ReportApiSurfaceRead(BaseModel):
    """The API attack surface. No response body, no credential, no header."""

    model_config = ConfigDict(from_attributes=True)

    detected: bool
    endpoints_discovered: int
    endpoints_observed: int = Field(
        description="Actually requested and answered, as opposed to merely described."
    )
    endpoints_documented_only: int = Field(
        description="Described by a specification and never reached."
    )
    parameters_discovered: int
    authenticated_endpoints: int
    unknown_auth_endpoints: int
    openapi_documents: int
    graphql_detected: bool
    graphql_path: str | None = None
    graphql_introspection_tested: bool = Field(
        description="Always false: this phase detects GraphQL and never queries it."
    )
    truncated: bool
    complete_inventory: bool = Field(
        description=(
            "True when no limit stopped the inventory growing. Never a claim that "
            "every API the application has was found."
        )
    )
    endpoints: list[ReportApiEndpointRead] = Field(default_factory=list)
    documents: list[ReportApiDocumentRead] = Field(default_factory=list)


class ReportAuthorizationRead(BaseModel):
    """Authorization coverage. Structurally incapable of holding a secret."""

    model_config = ConfigDict(from_attributes=True)

    enabled: bool
    contexts: int
    context_labels: list[str] = Field(
        default_factory=list,
        description="User-chosen identity names. Never a credential.",
    )
    endpoints_eligible: int
    endpoints_tested: int
    comparisons: int
    unknown: int = Field(
        description=(
            "Comparisons with no declared policy to judge against. These are not "
            "findings, and a high count means the scan was not told what to expect."
        )
    )
    skipped: int
    failed: int
    has_policy: bool = Field(
        description=(
            "True only when at least one comparison was measured against a "
            "declared expectation."
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
    authorization: ReportAuthorizationRead
    api: ReportApiSurfaceRead
    api_security: ReportApiSecurityRead
    session_security: ReportSessionSecurityRead
    config_security: ReportConfigSecurityRead
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
