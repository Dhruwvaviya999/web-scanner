"""Value objects for the endpoint-analysis stage.

Plain dataclasses. Nothing here touches the network or the database — the stage
consumes responses the crawler already captured and produces findings for the
service layer to persist.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from app.scanner.security.types import FindingData


class EndpointAnalysisStatus(str, enum.Enum):
    """Whether an endpoint's security configuration was assessed."""

    NOT_ANALYZED = "NOT_ANALYZED"
    ANALYZED = "ANALYZED"
    #: Deliberately not analysed — the detectors do not apply to this response.
    SKIPPED = "SKIPPED"
    #: Should have been analysed but could not be. Never yields findings.
    FAILED = "FAILED"


class AnalysisSkipReason(str, enum.Enum):
    """Why an endpoint was not analysed.

    Distinct from the crawler's `SkipReason`, which explains why a *link* was
    never fetched. This explains why a fetched endpoint was not assessed.
    """

    NON_HTML = "NON_HTML"
    EXTERNAL = "EXTERNAL"
    DUPLICATE = "DUPLICATE"
    CRAWL_LIMIT = "CRAWL_LIMIT"
    REQUEST_FAILED = "REQUEST_FAILED"
    UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"
    EXCLUDED_RESOURCE = "EXCLUDED_RESOURCE"


@dataclass(frozen=True, slots=True)
class EndpointAnalysis:
    """The outcome of assessing one endpoint."""

    url: str
    status: EndpointAnalysisStatus
    skip_reason: AnalysisSkipReason | None = None
    #: Human-readable detail when `status` is FAILED. Never response content.
    error: str | None = None
    findings: tuple[FindingData, ...] = ()


@dataclass(frozen=True, slots=True)
class FindingOccurrence:
    """One place a finding was observed.

    `endpoint_url` is None for a scan-level finding — one produced before any
    endpoint existed, such as when crawling is disabled.
    """

    endpoint_url: str | None
    evidence: str


@dataclass(slots=True)
class AggregatedFinding:
    """One finding identity, plus every endpoint it was observed on.

    Deduplication collapses repeats of the same rule into a single finding while
    keeping the full list of affected endpoints — a missing CSP across twelve
    pages is one finding with twelve occurrences, not twelve findings.
    """

    data: FindingData
    occurrences: list[FindingOccurrence] = field(default_factory=list)

    @property
    def occurrence_count(self) -> int:
        return len(self.occurrences)

    @property
    def primary_endpoint_url(self) -> str | None:
        """The first endpoint this was seen on, used as the finding's own link."""
        for occurrence in self.occurrences:
            if occurrence.endpoint_url is not None:
                return occurrence.endpoint_url
        return None


@dataclass(slots=True)
class AnalysisResult:
    """Everything the analysis stage produced for one scan."""

    endpoint_analyses: list[EndpointAnalysis] = field(default_factory=list)
    findings: list[AggregatedFinding] = field(default_factory=list)

    def count(self, status: EndpointAnalysisStatus) -> int:
        return sum(1 for analysis in self.endpoint_analyses if analysis.status is status)

    @property
    def analyzed(self) -> int:
        return self.count(EndpointAnalysisStatus.ANALYZED)

    @property
    def skipped(self) -> int:
        return self.count(EndpointAnalysisStatus.SKIPPED)

    @property
    def failed(self) -> int:
        return self.count(EndpointAnalysisStatus.FAILED)
