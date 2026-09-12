"""The canonical scan report.

One representation, built once from persisted scan data, consumed by every
output: the JSON API, the frontend, and whatever exporters come later. Nothing
downstream queries the database on its own, so every view of a scan agrees.

Read-only by construction. These are plain dataclasses with no session, no
models and no network — building one cannot trigger a scan, re-fetch an
endpoint, or re-run a detector.

Ordering is deterministic and defined here rather than left to the database:
severity descending, then category, then rule id, then subject. Two reports
built from the same stored rows are byte-identical.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from app.models.scan import ScanStatus
from app.scanner.auth import AuthMode, AuthStatus
from app.scanner.security.types import FindingCategory, FindingConfidence, FindingSeverity

#: Severity ordering used everywhere in a report. Most severe first.
SEVERITY_RANK: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}


@dataclass(frozen=True, slots=True)
class ReportAuthentication:
    """How the scan authenticated to the target.

    Two enum values and nothing else. There is no field here that could hold a
    token, a cookie value or a header, so the report's leakage guarantee is
    structural rather than a matter of remembering to redact.
    """

    mode: str
    status: str

    @property
    def authenticated(self) -> bool:
        """Whether credentials were configured — not whether they worked."""
        return self.mode != AuthMode.NONE.value

    @property
    def confirmed(self) -> bool:
        """Whether one initial access check accepted the credentials.

        Deliberately narrow. It says the origin answered a single request
        without refusing it, not that the credentials were valid for every path
        or for the whole scan.
        """
        return self.authenticated and self.status == AuthStatus.AVAILABLE.value


@dataclass(frozen=True, slots=True)
class ReportAuthorization:
    """What the authorization stage compared.

    Counters and user-chosen labels. There is no field here for a credential, a
    response body or a fingerprint, so a private record cannot travel into a
    report through this path.

    `unknown` is the number the report leans on hardest: comparisons where no
    policy was declared. A large number there does not mean the application is
    fine, it means the scanner was not told what "fine" would look like.
    """

    enabled: bool = False
    contexts: int = 0
    context_labels: tuple[str, ...] = ()
    endpoints_eligible: int = 0
    endpoints_tested: int = 0
    comparisons: int = 0
    unknown: int = 0
    skipped: int = 0
    failed: int = 0

    @property
    def conclusive_comparisons(self) -> int:
        """Comparisons that had a declared policy to judge against."""
        return max(0, self.comparisons - self.unknown)

    @property
    def has_policy(self) -> bool:
        """Whether any comparison was measured against a declared expectation.

        False means authorization was exercised but nothing was asserted — the
        scan observed access without being able to call any of it right or
        wrong.
        """
        return self.enabled and self.conclusive_comparisons > 0


@dataclass(frozen=True, slots=True)
class ReportApiParameter:
    """One API parameter in the report. A name and a place, never a value."""

    name: str
    location: str
    required: bool | None = None


@dataclass(frozen=True, slots=True)
class ReportApiEndpoint:
    """One API operation as it appears in a report.

    `observed` and `documented` are both carried because they answer different
    questions. Observed means the scanner requested it and something answered.
    Documented means a specification says it exists — which is a claim, not a
    fact, and a reviewer reading an inventory needs to know which they are
    looking at.
    """

    path: str
    method: str
    confidence: str
    sources: tuple[str, ...]
    auth_status: str
    observed: bool
    documented: bool
    status_code: int | None = None
    request_media_type: str | None = None
    response_media_type: str | None = None
    operation_id: str | None = None
    security: tuple[str, ...] = ()
    parameters: tuple[ReportApiParameter, ...] = ()
    #: Field *names* from a JSON response. Never a value from one.
    json_field_names: tuple[str, ...] = ()
    json_top_level: str | None = None

    @property
    def documented_only(self) -> bool:
        return self.documented and not self.observed

    @property
    def sort_key(self) -> tuple[str, str]:
        return (self.path, self.method)


@dataclass(frozen=True, slots=True)
class ReportApiDocument:
    """A specification the scanner read. Nothing in it was executed."""

    url: str
    version: str
    title: str | None = None
    path_count: int = 0
    operation_count: int = 0
    security_schemes: tuple[str, ...] = ()
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class ReportApiSurface:
    """What API discovery found, and how much of it is actually established.

    The counters are deliberately split three ways. `endpoints_observed` is what
    the scanner saw work; `endpoints_documented_only` is what a document claims
    exists and nobody checked; the difference between them is the part of an API
    inventory that most often gets overstated.
    """

    detected: bool = False
    endpoints_discovered: int = 0
    endpoints_observed: int = 0
    endpoints_documented_only: int = 0
    parameters_discovered: int = 0
    authenticated_endpoints: int = 0
    unknown_auth_endpoints: int = 0
    openapi_documents: int = 0
    graphql_detected: bool = False
    graphql_path: str | None = None
    #: Always False in this phase. Stated rather than omitted, so a reader is
    #: never left to assume introspection was attempted.
    graphql_introspection_tested: bool = False
    truncated: bool = False
    endpoints: tuple[ReportApiEndpoint, ...] = ()
    documents: tuple[ReportApiDocument, ...] = ()

    @property
    def complete_inventory(self) -> bool:
        """Whether the inventory is bounded by the target rather than by us.

        False when a limit stopped it growing. Never a claim that every API the
        application has was found — only a crawl and a published specification
        were consulted, and neither is guaranteed to be exhaustive.
        """
        return self.detected and not self.truncated


@dataclass(frozen=True, slots=True)
class ReportApiSecurity:
    """What the API security stage read, and how much of it it could judge.

    `unknown_policy` is the number to read first. A sensitive-looking field with
    no declared policy behind it is an observation, not a finding — the scanner
    saw something worth a human's attention and has no basis for calling it
    wrong. A large count there means the scan needs an authorization policy, not
    that the API is clean.
    """

    analyzed: bool = False
    endpoints_analyzed: int = 0
    endpoints_skipped: int = 0
    responses_analyzed: int = 0
    sensitive_fields_detected: int = 0
    property_comparisons: int = 0
    verbose_errors: int = 0
    cors_checks: int = 0
    inventory_observations: int = 0
    contexts_analyzed: int = 0
    unknown_policy: int = 0
    findings_count: int = 0

    @property
    def judged(self) -> bool:
        """Whether anything was measured against a declared policy.

        False means the stage ran and observed, but every sensitive field it saw
        was unjudgeable. Nothing about that supports "the API is fine".
        """
        return self.analyzed and (
            self.findings_count > 0
            or self.sensitive_fields_detected > self.unknown_policy
        )


@dataclass(frozen=True, slots=True)
class ReportSessionSecurity:
    """What session analysis observed, and what it deliberately did not claim.

    Two numbers need reading together. `csrf_strong` is the count that produced
    findings; `csrf_potential` is the count that did not, and it is shown
    because hiding it would misrepresent the result. A potential is a form where
    several signals line up and a server-side defence could still exist — origin
    validation, a required header, framework middleware, none of them visible
    without forging a request, which this scanner does not do.

    `timeout_known` being false is likewise not a weakness. Server-side session
    expiry cannot be observed from outside, so "unknown" is the honest answer
    and the report says unknown rather than implying "never expires".
    """

    analyzed: bool = False
    session_cookies_identified: int = 0
    session_identifiers_in_urls: int = 0
    token_exposures: int = 0
    csrf_forms_analyzed: int = 0
    csrf_potential: int = 0
    csrf_strong: int = 0
    jwt_tokens_observed: int = 0
    timeout_known: bool = False
    logout_endpoints_discovered: int = 0
    findings_count: int = 0
    #: Requests this stage made. Zero by design, and stated rather than assumed.
    requests_sent: int = 0

    @property
    def csrf_conclusive(self) -> bool:
        """Whether the CSRF result can be read as settled.

        False whenever any form landed on POTENTIAL: those are unresolved
        questions, and a report that showed only the findings count would let
        them read as an all-clear.
        """
        return self.analyzed and self.csrf_potential == 0


@dataclass(frozen=True, slots=True)
class ReportConfigSecurity:
    """What configuration and deployment analysis observed.

    Two fields decide how the rest should be read. `candidates_not_tested`
    counts bounded candidate paths the request budget never reached, and
    `budget_exhausted` says the budget is why. A scan that stopped early has
    established nothing about what it did not check, and `coverage_complete`
    exists so a partial result cannot be presented as a clean one.

    Nothing here can hold content. Every field is a boolean or a count, because
    the stage that fills them discards each response body inside the function
    that read it.
    """

    analyzed: bool = False
    https_used: bool = False
    https_redirect: bool = False
    hsts_observed: bool = False
    method_observations: int = 0
    debug_indicators: int = 0
    sensitive_files_checked: int = 0
    sensitive_files_exposed: int = 0
    admin_endpoints_discovered: int = 0
    management_endpoints_discovered: int = 0
    directory_listings: int = 0
    source_maps: int = 0
    technology_disclosures: int = 0
    path_normalization_observations: int = 0
    candidates_not_tested: int = 0
    requests_sent: int = 0
    findings_count: int = 0
    budget_exhausted: bool = False

    @property
    def coverage_complete(self) -> bool:
        """Whether every candidate the stage meant to check was checked.

        False means some were not, so silence about them is absence of
        evidence rather than evidence of absence.
        """
        return self.analyzed and not self.budget_exhausted and not self.candidates_not_tested


@dataclass(frozen=True, slots=True)
class ReportPathSecurity:
    """What path-traversal / LFI testing found.

    `canary_matches` is the load-bearing number: a match means the controlled
    marker was returned from outside the intended directory, which is the only
    evidence this stage treats as a finding. Everything else is coverage —
    how many file-like parameters were considered, tested, or skipped — and a
    skipped parameter established nothing, so it is never read as safe.

    Nothing here can hold content. Every field is a boolean or a count, because
    the detector reduces each response to a marker boolean and discards the body.
    """

    analyzed: bool = False
    parameters_considered: int = 0
    file_parameters: int = 0
    parameters_tested: int = 0
    parameters_skipped: int = 0
    endpoints_tested: int = 0
    traversal_probes: int = 0
    canary_matches: int = 0
    lfi_candidates: int = 0
    requests_sent: int = 0
    findings_count: int = 0
    budget_exhausted: bool = False

    @property
    def coverage_complete(self) -> bool:
        """Whether every file-like parameter considered was actually tested.

        False when a budget cut the run short or a baseline was unusable, so
        silence about the remainder is absence of evidence, not evidence of
        absence.
        """
        if not self.analyzed:
            return False
        if self.budget_exhausted:
            return False
        return self.parameters_skipped == 0


@dataclass(frozen=True, slots=True)
class ReportMetadata:
    """What was scanned, when, and how the scan ended."""

    scan_id: str
    target_url: str
    #: Scheme://host[:port] the scan actually settled on, when known.
    final_url: str | None
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    #: Wall-clock seconds from start to finish. None while a scan is running.
    duration_seconds: float | None
    #: When this report was rendered — not when the scan ran.
    generated_at: datetime
    #: Present only when the scan itself failed.
    error_message: str | None = None
    #: When cancellation was requested, for a scan that was stopped.
    cancelled_at: datetime | None = None
    #: Which stage a failed scan was in. A stage name only, never a trace.
    failure_stage: str | None = None
    #: Safe authentication metadata. Never the credential itself.
    authentication: ReportAuthentication = field(
        default_factory=lambda: ReportAuthentication(
            mode=AuthMode.NONE.value, status=AuthStatus.NOT_CONFIGURED.value
        )
    )

    @property
    def is_conclusive(self) -> bool:
        """Whether the scan ran to completion.

        False for a failed or cancelled scan. A report for one of those covers
        only what the run reached before it stopped, so a reader must never take
        its emptiness as an all-clear.
        """
        if self.status != ScanStatus.COMPLETED.value:
            return False
        # Credentials were supplied and the target refused them. The scan ran to
        # completion, but it ran as an anonymous visitor: everything behind the
        # login was never looked at. Calling that conclusive would let a rejected
        # credential read as a clean result, which is the exact failure mode
        # authenticated scanning must not have.
        return self.authentication.status != AuthStatus.REJECTED.value


@dataclass(frozen=True, slots=True)
class CoverageSummary:
    """How much of the discovered surface was actually assessed.

    Counters are `None` when the corresponding stage did not run, which is what
    keeps "not attempted" distinguishable from "attempted and found nothing".
    """

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
    #: Whether the run itself finished. A scan that failed or was cancelled
    #: stopped part-way by definition, however much it had analysed by then.
    scan_completed: bool = True
    #: False when credentials were supplied and the target refused them. The
    #: crawl then covered only the anonymous surface, whatever the counters say.
    authentication_usable: bool = True
    #: Authorization testing, which is separate from authentication coverage: a
    #: scan can authenticate perfectly and test no access control at all.
    authorization: ReportAuthorization = field(default_factory=lambda: ReportAuthorization())
    #: API reconnaissance. A classification of the surface, not a test of it:
    #: discovering an API says nothing about whether it is secure.
    api: ReportApiSurface = field(default_factory=lambda: ReportApiSurface())
    #: What the read-only API security review found in those same responses.
    api_security: ReportApiSecurity = field(
        default_factory=lambda: ReportApiSecurity()
    )
    #: Session handling: where identifiers travelled, what tokens declare, and
    #: how much can honestly be said about CSRF. Passive throughout.
    session_security: ReportSessionSecurity = field(
        default_factory=lambda: ReportSessionSecurity()
    )
    #: Deployment and transport configuration. The only late stage that sends
    #: requests, and the only one whose coverage can be cut short by a budget.
    config_security: ReportConfigSecurity = field(
        default_factory=lambda: ReportConfigSecurity()
    )
    #: File/path parameter testing: what looked file-like, what was probed, and
    #: whether a controlled traversal canary was retrieved. Active, canary-based.
    path_security: ReportPathSecurity = field(
        default_factory=lambda: ReportPathSecurity()
    )

    @property
    def is_complete(self) -> bool:
        """True when everything discovered was analysed without failures.

        A report must not present a clean result as reassuring when coverage was
        partial, so this is what the "no findings" wording keys on. A scan that
        did not run to completion is never complete here, no matter what its
        counters say: a cancelled run stopped before it knew what it had left,
        and a scan whose credentials were refused never saw the authenticated
        surface at all.
        """
        if not self.scan_completed:
            return False
        if not self.authentication_usable:
            return False
        if self.endpoints_discovered is None or self.endpoints_analyzed is None:
            return False
        if self.endpoints_failed:
            return False
        skipped = self.endpoints_skipped or 0
        return self.endpoints_analyzed + skipped >= self.endpoints_discovered


@dataclass(frozen=True, slots=True)
class SeveritySummary:
    """Finding counts by severity."""

    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


@dataclass(frozen=True, slots=True)
class ReportEndpointRef:
    """An endpoint a finding was observed on."""

    url: str
    path: str | None = None
    method: str | None = None


@dataclass(frozen=True, slots=True)
class ReportFinding:
    """One finding, flattened for presentation.

    Carries only fields already vetted as safe to surface. Evidence comes from
    the detectors' normalised wording — it names parameters, contexts and
    database families, never a probe value, payload, cookie or header.
    """

    rule_id: str
    category: FindingCategory
    severity: FindingSeverity
    confidence: FindingConfidence
    title: str
    description: str
    impact: str
    remediation: str
    evidence: str
    subject: str | None
    occurrence_count: int
    #: Every endpoint the rule was observed on, ordered by URL.
    endpoints: tuple[ReportEndpointRef, ...] = ()

    @property
    def sort_key(self) -> tuple[int, str, str, str]:
        """Deterministic order: severity, category, rule, subject."""
        return (
            SEVERITY_RANK[self.severity],
            self.category.value,
            self.rule_id,
            self.subject or "",
        )


@dataclass(frozen=True, slots=True)
class CategoryGroup:
    """Findings for one category, with its own severity counts."""

    category: FindingCategory
    total: int
    severity: SeveritySummary


@dataclass(frozen=True, slots=True)
class AttackSurfaceSummary:
    """What the crawler found, independent of whether anything was wrong."""

    endpoints: int
    forms: int
    parameters: int


@dataclass(frozen=True, slots=True)
class ScanReport:
    """The canonical report. Everything downstream reads this and only this."""

    metadata: ReportMetadata
    coverage: CoverageSummary
    severity: SeveritySummary
    attack_surface: AttackSurfaceSummary
    findings: tuple[ReportFinding, ...] = ()
    categories: tuple[CategoryGroup, ...] = ()
    #: Distinct parameter names discovered, sorted. Names only, never values.
    parameter_names: tuple[str, ...] = ()

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


@dataclass(slots=True)
class _SeverityTally:
    """Mutable counter used while building a report."""

    counts: dict[FindingSeverity, int] = field(
        default_factory=lambda: {severity: 0 for severity in FindingSeverity}
    )

    def add(self, severity: FindingSeverity) -> None:
        self.counts[severity] += 1

    def summary(self) -> SeveritySummary:
        return SeveritySummary(
            total=sum(self.counts.values()),
            critical=self.counts[FindingSeverity.CRITICAL],
            high=self.counts[FindingSeverity.HIGH],
            medium=self.counts[FindingSeverity.MEDIUM],
            low=self.counts[FindingSeverity.LOW],
            info=self.counts[FindingSeverity.INFO],
        )
