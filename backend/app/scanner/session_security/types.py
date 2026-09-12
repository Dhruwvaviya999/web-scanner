"""Value objects for session-security analysis.

Phase 15 is **passive**. It reads cookies, URLs, forms and headers that earlier
phases already captured, and sends nothing. It does not hijack a session, replay
a token, force a fixation, submit a form, call a logout endpoint, or modify a
JWT — every one of those is an attack on a session rather than an observation
about one.

The discipline that runs through the whole module: **a token-shaped string is
not a vulnerability.** A cookie named `token` might be a CSRF token, a
pagination cursor or a feature flag. A form without a hidden `csrf_token` might
be protected by origin validation, a custom header requirement, framework
middleware or SameSite. Passive analysis cannot see any of those, so where the
evidence stops the verdict is `UNKNOWN` or `POTENTIAL` — never "confirmed".

No value is represented anywhere here. Cookie values, JWTs, CSRF tokens and
query-string values are all discarded at the point they are read; what survives
is names, attributes, claim *names* and algorithm labels.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class CookieRole(str, enum.Enum):
    """What a cookie appears to be for.

    Naming is the main signal available without reading values, so the roles are
    deliberately coarse. `ANALYTICS` and `PREFERENCE` exist to be *excluded*:
    a tracking cookie that persists for two years is not a session cookie, and
    treating it as one would put a security finding on every site with an
    analytics tag.
    """

    SESSION = "SESSION"
    AUTHENTICATION = "AUTHENTICATION"
    PREFERENCE = "PREFERENCE"
    ANALYTICS = "ANALYTICS"
    UNKNOWN = "UNKNOWN"


class SessionConfidence(str, enum.Enum):
    """How sure the classifier is that a cookie carries session state."""

    #: A framework name, or an unambiguous session word. `JSESSIONID`.
    HIGH_CONFIDENCE_SESSION = "HIGH_CONFIDENCE_SESSION"
    #: Suggestive naming plus corroborating attributes.
    LIKELY_SESSION = "LIKELY_SESSION"
    #: Not enough to say. The default, and not a finding.
    UNKNOWN = "UNKNOWN"


class ExposureLocation(str, enum.Enum):
    """Where a session-like identifier was seen."""

    QUERY_PARAMETER = "QUERY_PARAMETER"
    PATH_PARAMETER = "PATH_PARAMETER"
    LOCATION_HEADER = "LOCATION_HEADER"
    HIDDEN_FIELD = "HIDDEN_FIELD"
    JSON_FIELD = "JSON_FIELD"
    COOKIE = "COOKIE"


class ParameterClass(str, enum.Enum):
    """What a parameter name suggests it carries."""

    #: A session identifier by name: `sessionid`, `jsessionid`, `phpsessid`.
    SESSION_LIKE = "SESSION_LIKE"
    #: Credential-adjacent but not necessarily a session: `token`, `auth`, `key`.
    SECURITY_SENSITIVE = "SECURITY_SENSITIVE"
    #: Nothing notable.
    ORDINARY = "ORDINARY"
    UNKNOWN = "UNKNOWN"


class CsrfVerdict(str, enum.Enum):
    """What passive analysis can say about a form's CSRF posture.

    `STRONG` is deliberately hard to reach. Passive analysis cannot see origin
    validation, a custom header requirement or framework middleware, so the
    absence of a visible token is an absence of *evidence*, not evidence of
    absence. Only `STRONG` produces a vulnerability finding.
    """

    #: An anti-CSRF token field is present, or the form cannot change state.
    NONE = "NONE"
    #: Several signals line up, but a server-side defence could still exist.
    POTENTIAL = "POTENTIAL"
    #: Multiple independent signals, including one that rules out the most
    #: common invisible defence.
    STRONG = "STRONG"
    #: Not enough information to place it.
    UNKNOWN = "UNKNOWN"


class TimeoutEvidence(str, enum.Enum):
    """What is known about when a session expires.

    `UNKNOWN` is the honest answer for most targets, and the module says so
    rather than concluding "the session never expires" from a missing
    `Max-Age` — server-side expiry is invisible from outside.
    """

    #: `Max-Age` or `Expires` was present on a session cookie.
    COOKIE_LIFETIME = "COOKIE_LIFETIME"
    #: A JWT carried an `exp` claim.
    TOKEN_EXPIRY = "TOKEN_EXPIRY"
    #: A session cookie with no lifetime, which usually means it lasts as long
    #: as the browser stays open. It says nothing about server-side expiry.
    BROWSER_SESSION = "BROWSER_SESSION"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class SessionCookie:
    """A cookie the scanner believes carries session state.

    Built from the Phase 3 `CookieInfo`, which never held a value. This adds the
    role and the confidence; it does not re-derive the attributes, and it does
    not produce cookie-attribute findings — Phase 3 already owns those.
    """

    name: str
    role: CookieRole
    confidence: SessionConfidence
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    #: Seconds, when the cookie declared a lifetime.
    max_age: int | None = None
    #: Whether an `Expires` attribute was present. The date itself is not needed.
    has_expires: bool = False
    #: Whether the response carrying it was served over TLS.
    over_https: bool = True
    #: The endpoint whose response set it. A URL, never a value.
    set_on: str | None = None
    #: Which signals produced the classification, for explaining it.
    signals: tuple[str, ...] = ()

    @property
    def session_like(self) -> bool:
        return self.confidence is not SessionConfidence.UNKNOWN

    @property
    def transport_exposed(self) -> bool:
        """Carried over plaintext, or without Secure on TLS.

        Used to rank two sightings of the same cookie so the worse one is kept.
        It is deliberately *not* what produces a finding — see `plaintext`.
        """
        return self.session_like and (not self.over_https or not self.secure)

    @property
    def plaintext(self) -> bool:
        """Set by a response that was served over plain HTTP.

        The one transport case Phase 15 reports. Phase 3 already reports a
        session cookie set over HTTPS without `Secure`, and it deliberately does
        not assess `Secure` on a plain-HTTP response, because a browser ignores
        the attribute there anyway. That leaves this gap, and it is a real one:
        the cookie crossed the network in the clear.
        """
        return self.session_like and not self.over_https


@dataclass(frozen=True, slots=True)
class UrlExposure:
    """A session-like identifier seen in a URL or a redirect target."""

    url: str
    #: The parameter or field name. Never the value it carried.
    name: str
    location: ExposureLocation
    classification: ParameterClass
    #: Whether the endpoint was reached with credentials configured.
    authenticated: bool = False
    over_https: bool = True
    detail: str = ""


@dataclass(frozen=True, slots=True)
class JwtMetadata:
    """Structural metadata from a JWT. The token itself is discarded.

    Only the header and the *names* of the payload claims are read. No claim
    value, no signature and no segment of the token survives — the scanner
    reports that a token declares `alg: HS256` and carries an `exp` claim, and
    nothing about who it is for or what it grants.
    """

    #: The `alg` header, when the header decoded. A label, not a key.
    algorithm: str | None = None
    #: The `typ` header.
    token_type: str | None = None
    #: Payload claim *names* only.
    claim_names: tuple[str, ...] = ()
    has_expiry: bool = False
    has_issuer: bool = False
    has_audience: bool = False
    has_issued_at: bool = False
    #: Whether the header decoded at all. A three-segment string that does not
    #: decode is token-shaped but not a JWT.
    decoded: bool = False

    @property
    def unsigned(self) -> bool:
        """`alg: none` — a token that asserts it needs no signature."""
        return (self.algorithm or "").lower() == "none"


@dataclass(frozen=True, slots=True)
class JwtObservation:
    """Where a JWT was seen, and what its metadata says."""

    location: ExposureLocation
    #: Cookie name, field name or header name. Never the token.
    name: str
    url: str
    metadata: JwtMetadata
    over_https: bool = True
    detail: str = ""


@dataclass(frozen=True, slots=True)
class CsrfObservation:
    """A discovered form and what can be said about its CSRF posture."""

    page_url: str
    action: str
    method: str
    verdict: CsrfVerdict
    #: Names of hidden fields that look like anti-CSRF tokens. Names only.
    token_fields: tuple[str, ...] = ()
    #: Whether the scan had credentials configured when the form was found.
    authenticated: bool = False
    #: Whether a session cookie was observed at all.
    session_cookie_present: bool = False
    #: The weakest SameSite seen on a session cookie, which is what decides
    #: whether the browser's own defence applies.
    session_same_site: str | None = None
    #: Signals that produced the verdict, for explaining rather than asserting.
    signals: tuple[str, ...] = ()
    detail: str = ""

    @property
    def state_changing(self) -> bool:
        return self.method.upper() in _STATE_CHANGING_METHODS


#: Methods that change state by convention. GET is excluded deliberately: a GET
#: that changes state exists, but assuming every GET does would make every
#: search box a CSRF finding.
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True, slots=True)
class TimeoutObservation:
    """What could be established about session expiry."""

    evidence: TimeoutEvidence
    #: Cookie or token name the evidence came from. Never a value.
    source: str | None = None
    #: Seconds, when a cookie declared one.
    max_age: int | None = None
    detail: str = ""

    @property
    def known(self) -> bool:
        """Whether an expiry was actually established.

        `BROWSER_SESSION` is deliberately excluded. A cookie with no declared
        lifetime tells you when the *browser* discards it and nothing about when
        the server does, which is the question. Counting it as known would make
        the report say expiry was established while the same stage raises
        SESSION_TIMEOUT_UNKNOWN about it.
        """
        return self.evidence in (
            TimeoutEvidence.COOKIE_LIFETIME,
            TimeoutEvidence.TOKEN_EXPIRY,
        )


@dataclass(frozen=True, slots=True)
class LogoutObservation:
    """A logout endpoint the crawler found. It is never called.

    Recorded so a later phase can verify server-side session termination. This
    phase does not request it: invoking logout during a scan would end the
    session every other stage depends on, and proves nothing on its own.
    """

    url: str
    method: str = "GET"
    #: Whether it was a form action rather than a link.
    from_form: bool = False


@dataclass(frozen=True, slots=True)
class SessionSignals:
    """Session-relevant metadata computed while a body was still in hand.

    Attached to a captured response next to the Phase 13 JSON shape and the
    Phase 14 error signals. Holds no body, no token and no value — a JWT that
    appears here has already been reduced to its algorithm and claim names.
    """

    #: JWTs found in the body. Metadata only.
    body_jwts: tuple[JwtMetadata, ...] = ()
    #: JWTs found in Set-Cookie values, paired with the cookie name.
    cookie_jwts: tuple[tuple[str, JwtMetadata], ...] = ()


@dataclass(frozen=True, slots=True)
class SessionSecurityLimits:
    """Bounds on session analysis.

    The defaults describe a stage that sends nothing. `max_requests` is a
    ceiling for a future confirmation request rather than an allowance; this
    phase makes none.
    """

    max_cookies: int = 100
    max_urls: int = 500
    max_forms: int = 200
    max_jwts: int = 50
    #: Hard ceiling on any request this stage might make. It makes none today.
    max_requests: int = 0


@dataclass(frozen=True, slots=True)
class SessionSecurityConfig:
    """Configuration for the session-security stage."""

    enabled: bool = True
    limits: SessionSecurityLimits = field(default_factory=SessionSecurityLimits)
    #: Whether a session cookie set over plain HTTP is reported as a finding.
    #: Off by default, for the reason Phase 14 turns off its equivalent: every
    #: local fixture and development target is HTTP, and calling that a
    #: production transport failure would be wrong far more often than right.
    #: When off the observation is still counted and shown — just not raised.
    flag_plaintext_http: bool = False


@dataclass(slots=True)
class SessionSecurityStats:
    """Counters for the report. Safe to persist and display."""

    cookies_analyzed: int = 0
    session_cookies_identified: int = 0
    urls_analyzed: int = 0
    session_identifiers_in_urls: int = 0
    token_exposures: int = 0
    forms_analyzed: int = 0
    state_changing_forms: int = 0
    csrf_protected_forms: int = 0
    csrf_potential: int = 0
    csrf_strong: int = 0
    csrf_unknown: int = 0
    jwt_tokens_observed: int = 0
    jwt_metadata_observations: int = 0
    timeout_metadata_available: int = 0
    logout_endpoints_discovered: int = 0
    findings_count: int = 0
    requests_sent: int = 0
    notes: dict[str, int] = field(default_factory=dict)

    def note(self, reason: str) -> None:
        self.notes[reason] = self.notes.get(reason, 0) + 1


@dataclass(frozen=True, slots=True)
class SessionSecurityOutcome:
    """Safe summary of the stage, for the scan row and the report."""

    analyzed: bool = False
    session_cookies_identified: int = 0
    session_identifiers_in_urls: int = 0
    token_exposures: int = 0
    csrf_forms_analyzed: int = 0
    csrf_potential: int = 0
    csrf_strong: int = 0
    jwt_tokens_observed: int = 0
    timeout_metadata_available: int = 0
    logout_endpoints_discovered: int = 0
    findings_count: int = 0

    @classmethod
    def from_stats(cls, stats: SessionSecurityStats) -> "SessionSecurityOutcome":
        return cls(
            analyzed=bool(
                stats.cookies_analyzed or stats.urls_analyzed or stats.forms_analyzed
            ),
            session_cookies_identified=stats.session_cookies_identified,
            session_identifiers_in_urls=stats.session_identifiers_in_urls,
            token_exposures=stats.token_exposures,
            csrf_forms_analyzed=stats.forms_analyzed,
            csrf_potential=stats.csrf_potential,
            csrf_strong=stats.csrf_strong,
            jwt_tokens_observed=stats.jwt_tokens_observed,
            timeout_metadata_available=stats.timeout_metadata_available,
            logout_endpoints_discovered=stats.logout_endpoints_discovered,
            findings_count=stats.findings_count,
        )


@dataclass(frozen=True, slots=True)
class SessionSecurityResult:
    """Everything the session-security stage concluded for one scan."""

    cookies: tuple[SessionCookie, ...] = ()
    url_exposures: tuple[UrlExposure, ...] = ()
    csrf: tuple[CsrfObservation, ...] = ()
    jwts: tuple[JwtObservation, ...] = ()
    timeout: TimeoutObservation = field(
        default_factory=lambda: TimeoutObservation(evidence=TimeoutEvidence.UNKNOWN)
    )
    logout: tuple[LogoutObservation, ...] = ()
    stats: SessionSecurityStats = field(default_factory=SessionSecurityStats)

    def outcome(self) -> SessionSecurityOutcome:
        return SessionSecurityOutcome.from_stats(self.stats)
