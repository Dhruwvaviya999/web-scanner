"""Value objects for API discovery.

Phase 13 is **reconnaissance**. Everything here describes an attack surface;
nothing here attacks one. An endpoint appearing in this model means the scanner
believes it behaves like an API — not that it is vulnerable, and not that it is
safe. Classification is an input to the existing detectors, never a verdict of
its own.

Three ideas are kept strictly apart, because conflating them is how an API
inventory becomes a work of fiction:

* **Observed** — the crawler actually requested it and saw a response.
* **Documented** — a specification says it exists. Nobody checked.
* **Inferred** — a weak signal, such as a path that merely looks like an API.

`ApiEndpoint.sources` records which of these applied, and more than one can.

No value from an API response is represented anywhere in this module. Field
*names* and structure are carried; the data that was in them is not, which is
what keeps a record, a token or a customer's email out of the database.
"""

from __future__ import annotations

import enum
from collections.abc import Sequence
from dataclasses import dataclass, field


class ApiConfidence(str, enum.Enum):
    """How strongly the evidence supports "this is an API".

    HIGH   — the response itself said so: a JSON or XML media type.
    MEDIUM — corroborated indirect evidence, such as a specification entry.
    LOW    — a weak signal on its own, such as a path containing `/api/`.

    LOW deliberately does **not** make something an API. A page at `/api/about`
    that returns HTML is a web page with an unfortunate URL, and treating it as
    an API would put noise into every downstream count.
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


#: Ordering for "keep the strongest evidence", lowest value strongest.
CONFIDENCE_ORDER: dict[ApiConfidence, int] = {
    ApiConfidence.HIGH: 0,
    ApiConfidence.MEDIUM: 1,
    ApiConfidence.LOW: 2,
}


class ApiSource(str, enum.Enum):
    """Where knowledge of an endpoint came from.

    An endpoint can have several. A path both documented in OpenAPI and reached
    by the crawler is stronger evidence than either alone, so a second discovery
    adds a source rather than replacing the first.
    """

    #: The crawler requested it and saw a response.
    CRAWLER = "CRAWLER"
    #: Listed in an OpenAPI 3.x document. Not necessarily reachable.
    OPENAPI = "OPENAPI"
    #: Listed in a Swagger 2.0 document. Not necessarily reachable.
    SWAGGER = "SWAGGER"
    #: The action of an HTML form.
    FORM = "FORM"
    #: Concluded from the response the crawler already had — chiefly its media type.
    RESPONSE_ANALYSIS = "RESPONSE_ANALYSIS"
    #: Recognised as a GraphQL endpoint.
    GRAPHQL = "GRAPHQL"


class ApiAuthStatus(str, enum.Enum):
    """What is known about needing credentials to reach an endpoint.

    Conservative by construction. A single 401 is not enough to call something
    AUTH_REQUIRED when the scan never presented a credential in the first place
    — content negotiation, a wrong method or a missing header explain that
    result just as well.
    """

    #: Reached without any credential.
    ANONYMOUS_ACCESSIBLE = "ANONYMOUS_ACCESSIBLE"
    #: Reached while the scan was authenticated. Says nothing about anonymous
    #: access, which was not separately attempted.
    AUTHENTICATED_ACCESSIBLE = "AUTHENTICATED_ACCESSIBLE"
    #: Refused for an authenticated scan, or refused anonymously while another
    #: identity in the same scan was served it.
    AUTH_REQUIRED = "AUTH_REQUIRED"
    UNKNOWN = "UNKNOWN"


class ApiParameterLocation(str, enum.Enum):
    """Where an API parameter is carried. Mirrors OpenAPI's `in` values."""

    PATH = "PATH"
    QUERY = "QUERY"
    HEADER = "HEADER"
    COOKIE = "COOKIE"
    #: A named field of a request body described by a specification. Recorded as
    #: a name only, and never submitted by this phase.
    BODY = "BODY"


class ApiMediaKind(str, enum.Enum):
    """What family a media type belongs to, for classification."""

    JSON = "JSON"
    XML = "XML"
    FORM = "FORM"
    MULTIPART = "MULTIPART"
    HTML = "HTML"
    GRAPHQL = "GRAPHQL"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class ApiParameter:
    """One API parameter. A name and a place — never a value."""

    name: str
    location: ApiParameterLocation = ApiParameterLocation.QUERY
    #: From a specification, when it said. `None` means nobody said.
    required: bool | None = None

    @property
    def identity(self) -> tuple[str, str]:
        return (self.name, self.location.value)


@dataclass(frozen=True, slots=True)
class JsonShape:
    """The structure of a JSON response, with none of its content.

    Field *names* are kept because they describe the interface — `id`, `email`,
    `role` tell a reviewer what an endpoint deals in. The values behind them are
    not kept, ever: that is where the customer data, the session identifier and
    the API key live.
    """

    #: "object", "array", or "scalar".
    top_level: str
    field_names: tuple[str, ...] = ()
    depth: int = 0
    field_count: int = 0
    #: True when the summary stopped at a configured bound rather than the end
    #: of the document, so a partial field list is never mistaken for complete.
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class ApiEndpoint:
    """One API operation: a method and a path within the scanned origin.

    Identity is `(method, path)`. Query *values* never participate, so
    `/api/products?id=1` and `/api/products?id=2` are the same endpoint with a
    parameter called `id` — which is the only representation that stays finite
    on a real site.
    """

    path: str
    method: str = "GET"
    #: Canonical URL when the endpoint was actually observed. `None` for one
    #: known only from a specification, which has no observed URL by definition.
    url: str | None = None
    confidence: ApiConfidence = ApiConfidence.LOW
    sources: frozenset[ApiSource] = frozenset()
    auth_status: ApiAuthStatus = ApiAuthStatus.UNKNOWN
    #: Media type the endpoint *accepts*, where a specification said so.
    request_media_type: str | None = None
    #: Media type it returned, where it was observed.
    response_media_type: str | None = None
    status_code: int | None = None
    operation_id: str | None = None
    parameters: tuple[ApiParameter, ...] = ()
    #: Security scheme names a specification attached to this operation. Names
    #: only: the scanner never constructs a credential from them.
    security: tuple[str, ...] = ()
    json_shape: JsonShape | None = None

    @property
    def identity(self) -> tuple[str, str]:
        return (self.method.upper(), self.path)

    @property
    def observed(self) -> bool:
        """Whether anything actually requested this and got a response."""
        return ApiSource.CRAWLER in self.sources or ApiSource.RESPONSE_ANALYSIS in self.sources

    @property
    def documented(self) -> bool:
        """Whether a specification described it."""
        return bool(self.sources & {ApiSource.OPENAPI, ApiSource.SWAGGER})

    @property
    def documented_only(self) -> bool:
        """Described by a specification and never actually seen.

        The distinction the report leans on hardest: a documented endpoint has
        not been shown to exist, let alone to work.
        """
        return self.documented and not self.observed


@dataclass(frozen=True, slots=True)
class SecurityScheme:
    """An authentication scheme a specification declares. Metadata only.

    Recorded so a reviewer can see what the API expects. The scanner never
    builds a credential from this, never prompts for one, and never tries one.
    """

    name: str
    kind: str
    #: `header`, `query` or `cookie` for an API key. None otherwise.
    location: str | None = None
    scheme: str | None = None


@dataclass(frozen=True, slots=True)
class OpenApiDocument:
    """A specification the scanner found and parsed. Never executed."""

    url: str
    #: "3.x" or "2.0".
    version: str
    title: str | None = None
    document_version: str | None = None
    path_count: int = 0
    operation_count: int = 0
    security_schemes: tuple[SecurityScheme, ...] = ()
    #: True when parsing stopped at the path budget.
    truncated: bool = False

    @property
    def source(self) -> ApiSource:
        return ApiSource.SWAGGER if self.version.startswith("2") else ApiSource.OPENAPI


@dataclass(frozen=True, slots=True)
class GraphQlDetection:
    """Presence detection only.

    Phase 13 does not run introspection, does not send a query, and does not
    send a mutation. `introspection_tested` is therefore always False — it
    exists so a report can say so explicitly rather than leaving a reader to
    assume the scanner looked.
    """

    detected: bool = False
    url: str | None = None
    path: str | None = None
    indicators: tuple[str, ...] = ()
    introspection_tested: bool = False


@dataclass(frozen=True, slots=True)
class ApiDiscoveryLimits:
    """Bounds on API discovery.

    Documentation discovery is the only part of this phase that sends requests
    of its own, and it is capped hard: a handful of well-known paths on one
    origin. There is no path brute-forcer here and there is not meant to be one.
    """

    #: Documentation paths tried. Small and fixed, not an enumeration.
    max_document_candidates: int = 8
    #: Paths read out of one specification.
    max_parsed_paths: int = 500
    #: API endpoints retained for a scan, across every source.
    max_endpoints: int = 500
    max_parameters_per_endpoint: int = 50
    #: Field names kept from one JSON response summary.
    max_json_fields: int = 50
    #: How deep a JSON summary descends before it stops counting.
    max_json_depth: int = 6


#: Well-known specification paths. Deliberately short: these are conventional
#: locations published by frameworks, not guesses, and the list is not a
#: substitute for the target telling us where its documentation lives.
DEFAULT_DOCUMENT_CANDIDATES: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v1/openapi.json",
    "/swagger/v1/swagger.json",
    "/.well-known/openapi.json",
)

#: Paths checked for GraphQL. One conventional location plus its common alias.
DEFAULT_GRAPHQL_CANDIDATES: tuple[str, ...] = ("/graphql", "/api/graphql")


@dataclass(frozen=True, slots=True)
class ApiDiscoveryConfig:
    """Configuration for the API discovery stage."""

    enabled: bool = True
    #: Whether to request well-known documentation paths. The only part of this
    #: stage that generates traffic the crawl did not already generate.
    fetch_documents: bool = True
    limits: ApiDiscoveryLimits = field(default_factory=ApiDiscoveryLimits)
    document_candidates: tuple[str, ...] = DEFAULT_DOCUMENT_CANDIDATES
    graphql_candidates: tuple[str, ...] = DEFAULT_GRAPHQL_CANDIDATES


@dataclass(slots=True)
class ApiStats:
    """Counters for the report. Safe to persist and display."""

    endpoints_discovered: int = 0
    endpoints_observed: int = 0
    endpoints_documented_only: int = 0
    parameters_discovered: int = 0
    documents_found: int = 0
    document_candidates_tried: int = 0
    requests_sent: int = 0
    authenticated_endpoints: int = 0
    unknown_auth_endpoints: int = 0
    graphql_endpoints: int = 0
    #: Endpoints dropped because a bound was reached.
    truncated: bool = False
    notes: dict[str, int] = field(default_factory=dict)

    def note(self, reason: str) -> None:
        self.notes[reason] = self.notes.get(reason, 0) + 1


@dataclass(frozen=True, slots=True)
class ApiOutcome:
    """Safe summary of the stage, for the scan row and the report."""

    detected: bool = False
    endpoints_discovered: int = 0
    endpoints_observed: int = 0
    endpoints_documented_only: int = 0
    parameters_discovered: int = 0
    openapi_documents: int = 0
    graphql_endpoints: int = 0
    authenticated_endpoints: int = 0
    unknown_auth_endpoints: int = 0
    truncated: bool = False

    @classmethod
    def from_stats(cls, stats: ApiStats) -> "ApiOutcome":
        return cls(
            detected=stats.endpoints_discovered > 0
            or stats.documents_found > 0
            or stats.graphql_endpoints > 0,
            endpoints_discovered=stats.endpoints_discovered,
            endpoints_observed=stats.endpoints_observed,
            endpoints_documented_only=stats.endpoints_documented_only,
            parameters_discovered=stats.parameters_discovered,
            openapi_documents=stats.documents_found,
            graphql_endpoints=stats.graphql_endpoints,
            authenticated_endpoints=stats.authenticated_endpoints,
            unknown_auth_endpoints=stats.unknown_auth_endpoints,
            truncated=stats.truncated,
        )


@dataclass(frozen=True, slots=True)
class ApiSurface:
    """Everything API discovery concluded for one scan."""

    endpoints: tuple[ApiEndpoint, ...] = ()
    documents: tuple[OpenApiDocument, ...] = ()
    graphql: GraphQlDetection = field(default_factory=GraphQlDetection)
    stats: ApiStats = field(default_factory=ApiStats)

    def outcome(self) -> ApiOutcome:
        return ApiOutcome.from_stats(self.stats)


def strongest(a: ApiConfidence, b: ApiConfidence) -> ApiConfidence:
    """The better-supported of two confidences."""
    return a if CONFIDENCE_ORDER[a] <= CONFIDENCE_ORDER[b] else b


def merge_parameters(
    existing: Sequence[ApiParameter], incoming: Sequence[ApiParameter], limit: int
) -> tuple[ApiParameter, ...]:
    """Union two parameter sets by `(name, location)`, keeping the richer entry.

    A specification's parameter carries a `required` flag the crawler cannot
    know, so a documented parameter supersedes an observed one of the same name;
    everything else is left alone.
    """
    merged: dict[tuple[str, str], ApiParameter] = {p.identity: p for p in existing}
    for parameter in incoming:
        current = merged.get(parameter.identity)
        if current is None or (current.required is None and parameter.required is not None):
            merged[parameter.identity] = parameter
    return tuple(list(merged.values())[:limit])
