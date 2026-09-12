"""Value objects for configuration, deployment and transport analysis.

Phase 16 asks how a deployment is *set up*, which is a different question from
whether its code has a flaw. A missing HTTPS redirect, a `.env` served from the
web root, a debug page left switched on — none of these is a bug in the
application, and all of them are how applications get broken into.

Three disciplines run through the whole package.

**Absence of a best practice is not a vulnerability.** A site with no
`Permissions-Policy` is not thereby insecure, and a path containing the word
"admin" is not thereby exposed. Where the evidence supports only an observation,
the result is an observation with an `UNKNOWN` verdict and no finding.

**A candidate that was not checked is not a candidate that passed.** Every
bounded list here can run out of budget, and the outcome vocabulary keeps
`NOT_TESTED` distinct from `NOT_FOUND` so a truncated scan can never read as a
clean one.

**No content is ever represented.** There is no field anywhere in this module
for a response body, a file's contents, an environment variable, a secret, a
credential, a repository object or a source line. A sensitive file that is found
is described by its path, its media type and its size — nothing that was *in* it
survives the request that fetched it.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class TransportScheme(str, enum.Enum):
    """What the scan actually spoke to the target."""

    HTTPS = "HTTPS"
    HTTP = "HTTP"
    UNKNOWN = "UNKNOWN"


class RedirectBehaviour(str, enum.Enum):
    """What a plain-HTTP request to the target did.

    `NOT_APPLICABLE` is for a target that was already HTTPS: there was no
    plaintext request to redirect, and reporting "no redirect" would be false.
    """

    #: HTTP answered with a redirect that landed on HTTPS. The correct setup.
    REDIRECTS_TO_HTTPS = "REDIRECTS_TO_HTTPS"
    #: HTTP served the application directly, with no upgrade.
    SERVES_OVER_HTTP = "SERVES_OVER_HTTP"
    #: HTTP redirected, but somewhere still insecure.
    REDIRECTS_TO_HTTP = "REDIRECTS_TO_HTTP"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class TlsObservation(str, enum.Enum):
    """What the transport layer established, and nothing more.

    Deliberately coarse. This phase does not run a TLS scanner: it does not
    enumerate ciphers, negotiate down a protocol version, or inspect a
    certificate chain. It reports whether the HTTP client completed a verified
    TLS handshake, because that is the one fact the existing client already
    establishes as a side effect of doing its job.
    """

    #: A verified HTTPS connection succeeded.
    VERIFIED = "VERIFIED"
    #: The client refused the certificate. Which specific defect it had is not
    #: determined here, and the finding says so.
    CERTIFICATE_REJECTED = "CERTIFICATE_REJECTED"
    #: HTTPS could not be reached at all — refused, timed out, no listener.
    UNREACHABLE = "UNREACHABLE"
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    UNKNOWN = "UNKNOWN"


class HstsQuality(str, enum.Enum):
    """How much an HSTS policy is actually worth.

    Phase 3 already reports HSTS *missing*, *disabled* and *short*. This grades
    what Phase 3 does not look at, so the two can never describe the same defect
    twice — see `config_security.transport`.
    """

    #: A long max-age with includeSubDomains. Nothing to say.
    STRONG = "STRONG"
    #: Present and non-trivial, but scoped to the bare host only.
    HOST_ONLY = "HOST_ONLY"
    #: Sent over plain HTTP, where every browser ignores it.
    INEFFECTIVE_OVER_HTTP = "INEFFECTIVE_OVER_HTTP"
    #: Header absent. Whether that matters is decided elsewhere.
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"


class CandidateOutcome(str, enum.Enum):
    """What happened to one bounded candidate path.

    `NOT_TESTED` is the member that earns this enum its place. A candidate the
    budget never reached has told us nothing, and collapsing it into
    `NOT_FOUND` would turn a truncated scan into a clean bill of health.
    """

    #: Fetched, and the response indicates the resource is really there.
    EXPOSED = "EXPOSED"
    #: Fetched, and the target does not serve it.
    NOT_FOUND = "NOT_FOUND"
    #: Fetched, and the target refused it — which is the correct answer.
    PROTECTED = "PROTECTED"
    #: Fetched, and the response was not interpretable either way.
    UNKNOWN = "UNKNOWN"
    #: Never requested: budget, cancellation, or a disabled check.
    NOT_TESTED = "NOT_TESTED"
    #: The request itself failed. Not evidence of anything about the target.
    ERROR = "ERROR"


class AccessVisibility(str, enum.Enum):
    """Who could reach an administrative or management endpoint.

    Derived from what was observed across the identities available, and from the
    Phase 12 policy when one was declared. With neither, the answer is `UNKNOWN`
    — an admin panel behind a login this scan was not given is indistinguishable
    from one that is properly protected.
    """

    #: An anonymous request received it.
    PUBLICLY_REACHABLE = "PUBLICLY_REACHABLE"
    #: Anonymous was refused; a credentialed identity got in.
    AUTHENTICATED_ONLY = "AUTHENTICATED_ONLY"
    #: Nothing there.
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN = "UNKNOWN"


class CandidateKind(str, enum.Enum):
    """Which bounded list a candidate came from. Drives budgets and reporting."""

    ADMIN = "ADMIN"
    MANAGEMENT = "MANAGEMENT"
    DEBUG = "DEBUG"
    HEALTH = "HEALTH"
    SENSITIVE_FILE = "SENSITIVE_FILE"
    REPOSITORY = "REPOSITORY"
    BACKUP = "BACKUP"
    SAMPLE = "SAMPLE"
    SOURCE_MAP = "SOURCE_MAP"


class DebugSignal(str, enum.Enum):
    """A recognisable marker of development configuration.

    Category names only. The text that produced the match is never carried:
    a framework debug page contains exactly the internals this phase exists to
    report as exposed, so quoting one into a finding would make the report the
    leak.
    """

    FRAMEWORK_DEBUG_PAGE = "FRAMEWORK_DEBUG_PAGE"
    DEBUG_TOOLBAR = "DEBUG_TOOLBAR"
    DEVELOPMENT_SERVER_BANNER = "DEVELOPMENT_SERVER_BANNER"
    DEBUG_HEADER = "DEBUG_HEADER"
    ENVIRONMENT_INDICATOR = "ENVIRONMENT_INDICATOR"
    INTERACTIVE_CONSOLE = "INTERACTIVE_CONSOLE"
    CONFIGURATION_DUMP = "CONFIGURATION_DUMP"


class CspGrade(str, enum.Enum):
    """How much a Content-Security-Policy restricts script execution.

    Phase 3 reports a *missing* policy and flags `'unsafe-inline'` and
    `'unsafe-eval'` at INFO. This grades the axis Phase 3 does not: whether the
    policy names a source broad enough that script can come from anywhere. Only
    `UNRESTRICTED` produces a finding, and only because that is a different
    defect from the markers Phase 3 already names.
    """

    #: A nonce or hash source. Modern, and makes 'unsafe-inline' inert.
    NONCE_OR_HASH = "NONCE_OR_HASH"
    #: Script sources are named and bounded.
    RESTRICTED = "RESTRICTED"
    #: 'unsafe-inline'/'unsafe-eval' without a wildcard. Phase 3's territory.
    WEAKENED = "WEAKENED"
    #: A wildcard or scheme source means script may load from anywhere.
    UNRESTRICTED = "UNRESTRICTED"
    #: No policy at all. Phase 3 reports this; recorded here for correlation.
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"


class HeaderDefect(str, enum.Enum):
    """A structural problem with a security header, as opposed to its absence.

    Phase 3 asks whether each header is present and broadly sane. These are the
    defects that survive that check: two headers disagreeing, a header with no
    value, a header a browser stopped honouring years ago.
    """

    DUPLICATE_CONFLICTING = "DUPLICATE_CONFLICTING"
    EMPTY_VALUE = "EMPTY_VALUE"
    DEPRECATED = "DEPRECATED"
    INVALID_VALUE = "INVALID_VALUE"


class NormalizationSignal(str, enum.Enum):
    """A disagreement about what a path means.

    Observed from responses already gathered. No traversal payload is sent and
    no encoded path is fuzzed: the purpose is to notice that two layers disagree
    about a URL, which is a configuration smell, not to exploit the gap.
    """

    #: `/path` and `/path/` both served content, with no redirect between them.
    TRAILING_SLASH_DIVERGENCE = "TRAILING_SLASH_DIVERGENCE"
    #: The same resource answered under two different spellings.
    DUPLICATE_REPRESENTATION = "DUPLICATE_REPRESENTATION"
    #: A redirect rewrote the path in a way that changes what it addresses.
    REDIRECT_REWRITES_PATH = "REDIRECT_REWRITES_PATH"


# --------------------------------------------------------------------------- #
# Observations
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class TransportObservation:
    """How the target is reached, and what it says about staying that way."""

    scheme: TransportScheme = TransportScheme.UNKNOWN
    redirect: RedirectBehaviour = RedirectBehaviour.UNKNOWN
    tls: TlsObservation = TlsObservation.NOT_ATTEMPTED
    hsts_present: bool = False
    hsts_quality: HstsQuality = HstsQuality.UNKNOWN
    hsts_max_age: int | None = None
    hsts_include_subdomains: bool = False
    #: Preload is recorded, never required: it is a public commitment with a
    #: removal process measured in months, and plenty of correct deployments
    #: decline it.
    hsts_preload: bool = False
    #: A loopback or private-network target, where demanding HTTPS would be
    #: wrong far more often than right.
    local_target: bool = False
    final_url: str | None = None
    detail: str = ""

    @property
    def secure_transport(self) -> bool:
        return self.scheme is TransportScheme.HTTPS


@dataclass(frozen=True, slots=True)
class MethodObservation:
    """What one endpoint says, and shows, about the methods it supports.

    `advertised` is what an `Allow` or `Access-Control-Allow-Methods` header
    claims. `observed` is what actually answered. Keeping them apart is the
    whole point: a header is documentation, and this phase does not send a
    `PUT` to find out whether the documentation is true.
    """

    url: str
    #: Methods the target advertised. A claim.
    advertised: tuple[str, ...] = ()
    #: Methods the scan actually saw answer. GET, HEAD and OPTIONS only.
    observed: tuple[str, ...] = ()
    #: Advertised, never sent, and unsafe to send unasked.
    untested: tuple[str, ...] = ()
    #: Whether TRACE was advertised. Never invoked against a live target.
    trace_advertised: bool = False
    #: Whether TRACE was confirmed enabled. Only ever set from a fixture.
    trace_confirmed: bool = False
    allow_header: str | None = None
    status_code: int | None = None
    detail: str = ""

    @property
    def unsafe_advertised(self) -> tuple[str, ...]:
        return tuple(m for m in self.advertised if m in _UNSAFE_METHODS)


#: Methods that change state or echo a request. Advertising one is not a
#: finding — a REST API legitimately uses every one of PUT, PATCH and DELETE —
#: so this set exists to decide what is worth *saying*, never what to send.
_UNSAFE_METHODS = frozenset({"PUT", "PATCH", "DELETE", "TRACE", "CONNECT", "TRACK"})

#: The only methods this phase will ever put on the wire. Enforced at the
#: transport call site as well as here, so a future edit to a candidate list
#: cannot turn into a state-changing request.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True, slots=True)
class CandidateObservation:
    """One bounded candidate path and what came back.

    There is no body field, and that is structural rather than a convention:
    the module fetches these paths precisely because they may hold secrets, so
    there must be no route by which one reaches a report.
    """

    path: str
    kind: CandidateKind
    outcome: CandidateOutcome = CandidateOutcome.NOT_TESTED
    status_code: int | None = None
    media_type: str | None = None
    #: Bytes the response declared or delivered. A size, never a sample.
    size: int | None = None
    visibility: AccessVisibility = AccessVisibility.UNKNOWN
    #: Whether the request carried the configured credentials.
    authenticated: bool = False
    #: Why the outcome is what it is, in the module's own words.
    signals: tuple[str, ...] = ()
    detail: str = ""

    @property
    def exposed(self) -> bool:
        return self.outcome is CandidateOutcome.EXPOSED


@dataclass(frozen=True, slots=True)
class DebugObservation:
    """Evidence that a target is running in development configuration."""

    url: str
    signals: tuple[DebugSignal, ...] = ()
    status_code: int | None = None
    #: Set when Phase 14 already recorded a diagnostic leak on this response, so
    #: the two phases can correlate instead of both reporting it.
    corroborated_by_error_analysis: bool = False
    detail: str = ""

    @property
    def conclusive(self) -> bool:
        """Whether the evidence is strong enough to call this debug mode.

        One marker can be a coincidence — the word "debug" appears in plenty of
        production pages. Two independent markers, or one marker plus a
        diagnostic leak Phase 14 already found, is a configuration.
        """
        return len(self.signals) >= 2 or (
            bool(self.signals) and self.corroborated_by_error_analysis
        )


@dataclass(frozen=True, slots=True)
class ListingObservation:
    """A directory index served in place of a page."""

    url: str
    #: How many entries the listing appeared to contain. A count, not names.
    entry_count: int | None = None
    server_style: str | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class SourceMapObservation:
    """A JavaScript source map reachable from the origin.

    Recorded because a map republishes the original sources, which may include
    comments and internal paths never meant to ship. It is *not* automatically
    serious: plenty of teams publish maps deliberately so production errors are
    debuggable. Nothing from inside the map is retained beyond a count.
    """

    asset_url: str
    map_url: str
    #: Whether the map itself answered, as opposed to merely being referenced.
    reachable: bool = False
    #: How many original files the map lists. A count. No path, no source.
    source_count: int | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class TechnologyObservation:
    """A header naming the software behind the target.

    Informational by default and by design. Version disclosure is the normal
    behaviour of most web servers, and a scanner that grades every `Server:`
    header as a weakness is one whose findings get filtered out unread.
    """

    url: str
    header: str
    #: The header's value. Safe by construction — `Server` and `X-Powered-By`
    #: carry product names, and the vetted list in `deployment` excludes every
    #: header that could carry a credential.
    value: str
    #: Whether the value pins an exact version.
    versioned: bool = False
    detail: str = ""


@dataclass(frozen=True, slots=True)
class HeaderDefectObservation:
    """A security header that is present but structurally wrong."""

    url: str
    header: str
    defect: HeaderDefect
    #: Bounded, and only for headers on the vetted list.
    value: str | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class CspObservation:
    """A Content-Security-Policy graded on the axis Phase 3 does not check."""

    url: str
    grade: CspGrade = CspGrade.UNKNOWN
    #: Sources broad enough that script could come from anywhere.
    wildcard_sources: tuple[str, ...] = ()
    has_nonce: bool = False
    has_hash: bool = False
    has_unsafe_inline: bool = False
    has_unsafe_eval: bool = False
    #: True when more than one policy header was sent. Browsers intersect them,
    #: which is usually not what whoever added the second one intended.
    duplicated: bool = False
    detail: str = ""

    @property
    def reportable(self) -> bool:
        """Only the unrestricted case. The rest is Phase 3's to report."""
        return self.grade is CspGrade.UNRESTRICTED


@dataclass(frozen=True, slots=True)
class NormalizationObservation:
    """Two layers disagreeing about what a path addresses."""

    signal: NormalizationSignal
    #: The two spellings involved. Paths only.
    paths: tuple[str, ...] = ()
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ConfigSignals:
    """Deployment metadata computed while a body was still in hand.

    Attached to a captured response alongside the Phase 13 JSON shape, the
    Phase 14 error signals and the Phase 15 session signals. Every field is a
    boolean, a count, a category name or a URL — no page text survives, which
    is the same bargain the three phases before this one struck.

    Computing it at capture is what makes directory-listing and source-map
    detection possible at all: the crawler drops bodies, and re-fetching every
    page to look at them again would double the scan's traffic for nothing.
    """

    #: The response was a server-generated directory index.
    directory_listing: bool = False
    listing_entry_count: int | None = None
    listing_style: str | None = None
    #: Development-mode markers found in the body. Category names only; the
    #: text that matched is discarded with the body.
    debug_signals: tuple[DebugSignal, ...] = ()
    #: The body was a server or framework default page.
    default_content: bool = False
    #: The source map URL a JavaScript asset published, resolved absolute.
    #: A reference the asset itself printed — never a guessed filename.
    source_map_reference: str | None = None

    @property
    def notable(self) -> bool:
        return bool(
            self.directory_listing
            or self.debug_signals
            or self.default_content
            or self.source_map_reference
        )


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ConfigSecurityLimits:
    """Ceilings on the traffic this phase may generate.

    Every number is a hard stop, not a target. A candidate not reached inside
    these bounds is recorded as `NOT_TESTED`, so exhausting a budget degrades
    coverage rather than quietly producing a clean result.
    """

    #: Total candidate requests across every list below.
    max_requests: int = 100
    max_admin_candidates: int = 50
    max_sensitive_file_candidates: int = 50
    max_backup_candidates: int = 50
    #: Backup variants derived per discovered file. Three, not a wordlist.
    max_backup_variants_per_file: int = 3
    max_source_maps: int = 10
    #: Endpoints whose methods are examined via OPTIONS.
    max_method_checks: int = 20
    #: Crawled responses read for debug, listing and technology signals.
    max_responses_analyzed: int = 200
    #: Bytes read from a candidate before the body is discarded. Enough to
    #: classify a response; nowhere near enough to be a download.
    max_candidate_bytes: int = 8192


@dataclass(frozen=True, slots=True)
class ConfigSecurityConfig:
    """Configuration for the configuration-security stage."""

    enabled: bool = True
    limits: ConfigSecurityLimits = field(default_factory=ConfigSecurityLimits)
    #: Whether a target served over plain HTTP is a finding. Off by default:
    #: localhost and every development deployment is HTTP, and grading each one
    #: as a production transport failure would be wrong more often than right.
    #: Loopback and private-network targets stay exempt even when this is on.
    require_https: bool = False
    #: Whether bounded candidate paths are requested at all. With this off the
    #: stage is fully passive and reads only what earlier phases captured.
    probe_candidates: bool = True
    #: Whether TRACE may be confirmed by sending one. Off, and only ever turned
    #: on by a local fixture test: a TRACE against somebody's production server
    #: is a request nobody asked for.
    confirm_trace: bool = False


@dataclass(slots=True)
class ConfigSecurityStats:
    """Counters for the report. Safe to persist and display."""

    responses_analyzed: int = 0
    requests_sent: int = 0
    candidates_checked: int = 0
    candidates_not_tested: int = 0
    admin_candidates_checked: int = 0
    sensitive_file_candidates_checked: int = 0
    backup_candidates_checked: int = 0
    method_checks: int = 0
    source_maps_checked: int = 0
    admin_endpoints_discovered: int = 0
    management_endpoints_discovered: int = 0
    sensitive_files_exposed: int = 0
    debug_indicators: int = 0
    directory_listings: int = 0
    source_maps_exposed: int = 0
    technology_disclosures: int = 0
    path_normalization_observations: int = 0
    findings_count: int = 0
    #: True when a budget stopped the stage before its candidate lists ran out.
    budget_exhausted: bool = False
    notes: dict[str, int] = field(default_factory=dict)

    def note(self, reason: str) -> None:
        self.notes[reason] = self.notes.get(reason, 0) + 1


@dataclass(frozen=True, slots=True)
class ConfigSecurityOutcome:
    """Safe summary of the stage, for the scan row and the report."""

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

    @classmethod
    def from_result(cls, result: "ConfigSecurityResult") -> "ConfigSecurityOutcome":
        stats = result.stats
        transport = result.transport
        return cls(
            analyzed=bool(
                stats.responses_analyzed
                or stats.candidates_checked
                or transport.scheme is not TransportScheme.UNKNOWN
            ),
            https_used=transport.secure_transport,
            https_redirect=transport.redirect is RedirectBehaviour.REDIRECTS_TO_HTTPS,
            hsts_observed=transport.hsts_present,
            method_observations=len(result.methods),
            debug_indicators=stats.debug_indicators,
            sensitive_files_checked=stats.sensitive_file_candidates_checked,
            sensitive_files_exposed=stats.sensitive_files_exposed,
            admin_endpoints_discovered=stats.admin_endpoints_discovered,
            management_endpoints_discovered=stats.management_endpoints_discovered,
            directory_listings=stats.directory_listings,
            source_maps=stats.source_maps_exposed,
            technology_disclosures=stats.technology_disclosures,
            path_normalization_observations=stats.path_normalization_observations,
            candidates_not_tested=stats.candidates_not_tested,
            requests_sent=stats.requests_sent,
            findings_count=stats.findings_count,
            budget_exhausted=stats.budget_exhausted,
        )


@dataclass(frozen=True, slots=True)
class ConfigSecurityResult:
    """Everything the configuration-security stage concluded for one scan."""

    transport: TransportObservation = field(default_factory=TransportObservation)
    methods: tuple[MethodObservation, ...] = ()
    candidates: tuple[CandidateObservation, ...] = ()
    debug: tuple[DebugObservation, ...] = ()
    listings: tuple[ListingObservation, ...] = ()
    source_maps: tuple[SourceMapObservation, ...] = ()
    technologies: tuple[TechnologyObservation, ...] = ()
    header_defects: tuple[HeaderDefectObservation, ...] = ()
    csp: tuple[CspObservation, ...] = ()
    normalization: tuple[NormalizationObservation, ...] = ()
    stats: ConfigSecurityStats = field(default_factory=ConfigSecurityStats)

    def outcome(self) -> ConfigSecurityOutcome:
        return ConfigSecurityOutcome.from_result(self)

    @property
    def exposed_candidates(self) -> tuple[CandidateObservation, ...]:
        return tuple(c for c in self.candidates if c.exposed)
