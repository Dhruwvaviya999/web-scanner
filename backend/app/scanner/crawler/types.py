"""Value objects for attack-surface discovery.

Plain dataclasses, like the rest of the scanner package: the crawler knows
nothing about SQLAlchemy. `scan_service` translates these into rows.

Nothing here holds a parameter *value* or a form field *value*. Only names,
types and structure are carried, so a session token sitting in a query string
cannot reach the database through this path.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class ParameterLocation(str, enum.Enum):
    """Where an input parameter is carried.

    Phase 4 only emits QUERY — form inputs are recorded as form fields instead.
    PATH and FORM are declared so later phases can use them without a migration.
    """

    QUERY = "QUERY"
    PATH = "PATH"
    FORM = "FORM"


class FormFieldKind(str, enum.Enum):
    """Which HTML element produced a form field."""

    INPUT = "INPUT"
    TEXTAREA = "TEXTAREA"
    SELECT = "SELECT"
    BUTTON = "BUTTON"


class SkipReason(str, enum.Enum):
    """Why a discovered URL was not crawled. Kept for the scan summary."""

    EXTERNAL_ORIGIN = "EXTERNAL_ORIGIN"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    PAGE_LIMIT = "PAGE_LIMIT"
    ALREADY_VISITED = "ALREADY_VISITED"
    UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"
    FETCH_FAILED = "FETCH_FAILED"
    TIME_BUDGET = "TIME_BUDGET"


@dataclass(frozen=True, slots=True)
class CrawlConfig:
    """Bounds on a crawl. Every limit is configurable; none is hardcoded below."""

    enabled: bool = True
    max_pages: int = 50
    max_depth: int = 3
    #: Wall-clock budget for the whole crawl, independent of per-request timeouts.
    #: Guarantees the crawl ends even against a slow site with many pages.
    time_budget_seconds: float = 90.0
    #: Redirects followed per crawled page. Lower than the probe's: a crawl
    #: following long chains on every page multiplies request count.
    max_redirects_per_page: int = 3


@dataclass(frozen=True, slots=True)
class DiscoveredFormField:
    name: str
    kind: FormFieldKind
    #: The `type` attribute for inputs (text, password, email...), else None.
    input_type: str | None = None


@dataclass(frozen=True, slots=True)
class DiscoveredForm:
    """An HTML form found on a page. Never submitted — discovery only."""

    page_url: str
    action: str
    method: str
    fields: tuple[DiscoveredFormField, ...] = ()


@dataclass(frozen=True, slots=True)
class DiscoveredEndpoint:
    """One reachable URL, recorded with the response it produced.

    `url` is the canonical form with query *values* removed — see
    `url_normalizer.canonical_url`.
    """

    url: str
    path: str
    method: str
    depth: int
    status_code: int | None = None
    content_type: str | None = None
    page_title: str | None = None
    #: Query parameter names observed on this endpoint. Names only.
    parameters: tuple[str, ...] = ()


@dataclass(slots=True)
class CrawlResult:
    """Everything one crawl discovered, plus how it terminated."""

    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    pages_crawled: int = 0
    pages_skipped: int = 0
    max_depth_reached: int = 0
    #: True when max_pages or the time budget stopped the crawl early. This is
    #: normal termination, not a failure — the scan still completes.
    limit_reached: bool = False
    skip_reasons: dict[str, int] = field(default_factory=dict)

    def record_skip(self, reason: SkipReason) -> None:
        self.pages_skipped += 1
        self.skip_reasons[reason.value] = self.skip_reasons.get(reason.value, 0) + 1

    @property
    def parameter_count(self) -> int:
        return sum(len(endpoint.parameters) for endpoint in self.endpoints)


@dataclass(frozen=True, slots=True)
class FetchedPage:
    """The transport result for one crawled URL.

    `body` is empty for non-HTML responses: only documents are worth parsing.
    """

    url: str
    status_code: int
    content_type: str | None
    body: bytes
    is_html: bool
