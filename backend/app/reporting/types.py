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

    @property
    def is_conclusive(self) -> bool:
        """Whether the scan ran to completion.

        False for a failed or cancelled scan. A report for one of those covers
        only what the run reached before it stopped, so a reader must never take
        its emptiness as an all-clear.
        """
        return self.status == ScanStatus.COMPLETED.value


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

    @property
    def is_complete(self) -> bool:
        """True when everything discovered was analysed without failures.

        A report must not present a clean result as reassuring when coverage was
        partial, so this is what the "no findings" wording keys on. A scan that
        did not run to completion is never complete here, no matter what its
        counters say: a cancelled run stopped before it knew what it had left.
        """
        if not self.scan_completed:
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
