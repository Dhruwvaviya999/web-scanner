"""The vocabulary of a security finding.

These enums are the single source of truth for severity, confidence and
category. `app.models.finding` imports them for its columns rather than
redeclaring them, which keeps the scanner free of any dependency on the ORM
while still giving the database one definition to store.

Member order matters: the native PostgreSQL enum is created in this order, so
`ORDER BY severity` sorts most-severe-first without a CASE expression.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class FindingSeverity(str, enum.Enum):
    """How much a finding matters, if confirmed.

    Configuration observations belong at LOW or INFO. Reserve HIGH and above for
    something with demonstrated impact — this scanner does not confirm
    exploitability, so it should rarely reach them.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingConfidence(str, enum.Enum):
    """How certain the detector is that the observation is real.

    HIGH   — directly observed in the response (a header is absent or present).
    MEDIUM — relies on a heuristic, such as inferring a cookie's purpose.
    LOW    — indicative only; needs a human to confirm.
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingCategory(str, enum.Enum):
    """What kind of check produced the finding.

    Phase 3 emits only SECURITY_HEADER and COOKIE. The rest are declared so that
    later detectors do not require a migration to start using them.
    """

    SECURITY_HEADER = "SECURITY_HEADER"
    COOKIE = "COOKIE"
    #: Cross-site scripting. Phase 6 emits only reflected XSS.
    XSS = "XSS"
    #: SQL injection. Phase 8 emits error-based and boolean-differential.
    SQLI = "SQLI"
    TLS = "TLS"
    #: Broken access control. Phase 12 emits anonymous, horizontal, vertical and
    #: object-level findings, all from comparisons across supplied identities.
    AUTHORIZATION = "AUTHORIZATION"
    #: API-specific weaknesses read from responses earlier phases already
    #: fetched: exposed fields, verbose errors, unsafe CORS, inventory drift.
    API_SECURITY = "API_SECURITY"
    #: Session handling: where identifiers travel, what tokens declare about
    #: themselves, and whether a state-changing form shows any CSRF defence.
    #: Passive throughout — Phase 15 never forges, replays or fixes a session.
    SESSION_SECURITY = "SESSION_SECURITY"
    #: How a deployment is set up rather than how it is coded: transport,
    #: exposed deployment files, debug mode left on, administrative surface.
    #: Phase 16 emits these; it never grades the absence of an optional
    #: hardening measure as a weakness.
    CONFIGURATION = "CONFIGURATION"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    OTHER = "OTHER"


class FindingRule(str, enum.Enum):
    """Stable programmatic identity for a detector rule.

    This is what deduplication and cross-scan correlation key on, so it must
    never change once shipped. Display titles are free to be reworded.

    Stored as a plain string column rather than a native database enum: a
    security scanner gains rules constantly, and `ALTER TYPE ... ADD VALUE` on
    every one of them is friction for no benefit. Validity is enforced here and
    at the schema boundary instead.
    """

    # --- Security headers ---
    SECURITY_HEADER_HSTS_MISSING = "SECURITY_HEADER_HSTS_MISSING"
    SECURITY_HEADER_HSTS_DISABLED = "SECURITY_HEADER_HSTS_DISABLED"
    SECURITY_HEADER_HSTS_SHORT_MAX_AGE = "SECURITY_HEADER_HSTS_SHORT_MAX_AGE"
    SECURITY_HEADER_CSP_MISSING = "SECURITY_HEADER_CSP_MISSING"
    SECURITY_HEADER_CSP_PERMISSIVE = "SECURITY_HEADER_CSP_PERMISSIVE"
    SECURITY_HEADER_X_CONTENT_TYPE_OPTIONS_MISSING = (
        "SECURITY_HEADER_X_CONTENT_TYPE_OPTIONS_MISSING"
    )
    SECURITY_HEADER_X_FRAME_OPTIONS_MISSING = "SECURITY_HEADER_X_FRAME_OPTIONS_MISSING"
    SECURITY_HEADER_REFERRER_POLICY_MISSING = "SECURITY_HEADER_REFERRER_POLICY_MISSING"
    SECURITY_HEADER_PERMISSIONS_POLICY_MISSING = "SECURITY_HEADER_PERMISSIONS_POLICY_MISSING"

    # --- Injection ---
    #: Reflected cross-site scripting. Active detection, inert marker only.
    XSS_REFLECTED = "XSS_REFLECTED"
    #: SQL injection surfaced by a database error under a syntax probe.
    SQLI_ERROR_BASED = "SQLI_ERROR_BASED"
    #: SQL injection surfaced by a reproducible true/false response difference.
    SQLI_BOOLEAN_DIFFERENTIAL = "SQLI_BOOLEAN_DIFFERENTIAL"

    # --- API security (phase 14) ---
    #: A sensitive field name appeared in an API response where no client
    #: should have received it.
    API_SENSITIVE_DATA_EXPOSURE = "API_SENSITIVE_DATA_EXPOSURE"
    #: One identity received properties another did not, and the policy says it
    #: should not have. Property-level authorization, not resource-level.
    API_PROPERTY_AUTHORIZATION = "API_PROPERTY_AUTHORIZATION"
    #: An error response carried diagnostics meant for a developer.
    API_VERBOSE_ERROR = "API_VERBOSE_ERROR"
    #: A cross-origin policy that grants more than it can have intended.
    API_CORS_MISCONFIGURATION = "API_CORS_MISCONFIGURATION"
    #: A response header naming internal software, versions or diagnostics.
    API_INFORMATION_DISCLOSURE = "API_INFORMATION_DISCLOSURE"
    #: Several API versions live at once, or documentation and service
    #: disagreeing about what exists. Informational: normal during a migration.
    API_LEGACY_VERSION = "API_LEGACY_VERSION"

    # --- Authorization / access control ---
    #: A resource the policy reserves for authenticated users was served to an
    #: anonymous request.
    AUTHZ_ANONYMOUS_ACCESS = "AUTHZ_ANONYMOUS_ACCESS"
    #: One identity reached a resource belonging to another at the same level.
    AUTHZ_HORIZONTAL_ACCESS = "AUTHZ_HORIZONTAL_ACCESS"
    #: A lower-privilege identity reached a higher-privilege resource.
    AUTHZ_VERTICAL_ACCESS = "AUTHZ_VERTICAL_ACCESS"
    #: An object whose declared owner is a different identity was served.
    AUTHZ_OBJECT_LEVEL_ACCESS = "AUTHZ_OBJECT_LEVEL_ACCESS"

    # --- Session security (phase 15) ---
    #: A session identifier appeared in a URL, where it reaches browser history,
    #: the Referer header and every log between here and the server.
    SESSION_TOKEN_IN_URL = "SESSION_TOKEN_IN_URL"
    #: A credential-like token surfaced somewhere it can be read — a redirect
    #: target, a hidden field, an API response field. Names only, never values.
    SESSION_TOKEN_EXPOSURE = "SESSION_TOKEN_EXPOSURE"
    #: A session cookie can reach the network without TLS protection. Distinct
    #: from the Phase 3 cookie-attribute rules: this correlates across the scan.
    SESSION_COOKIE_TRANSPORT = "SESSION_COOKIE_TRANSPORT"
    #: A state-changing form shows no CSRF defence this scanner can see, and the
    #: browser's own SameSite defence does not apply. Never a confirmed exploit:
    #: no request is forged, so a server-side defence may still exist.
    SESSION_CSRF_POTENTIAL = "SESSION_CSRF_POTENTIAL"
    #: A JWT declares something worth review — alg none, no expiry, or claim
    #: names suggesting it carries more than an identity.
    SESSION_JWT_WEAKNESS = "SESSION_JWT_WEAKNESS"
    #: Nothing observable establishes when the session expires. Informational,
    #: and explicitly not a claim that it never does.
    SESSION_TIMEOUT_UNKNOWN = "SESSION_TIMEOUT_UNKNOWN"
    #: Session handling revealed something about the stack or its state that a
    #: client did not need to know.
    SESSION_INFORMATION_DISCLOSURE = "SESSION_INFORMATION_DISCLOSURE"

    # --- Configuration and deployment (phase 16) ---
    #: The application is served over plain HTTP with no upgrade offered.
    #: Off by default and never raised for a loopback or private target.
    CONFIG_INSECURE_HTTP = "CONFIG_INSECURE_HTTP"
    #: An HSTS policy that does not cover what it should. Scoped to the axes
    #: Phase 3 does not check — subdomain coverage, and HSTS sent over HTTP.
    CONFIG_WEAK_HSTS = "CONFIG_WEAK_HSTS"
    #: A method advertised where it does not belong, or a diagnostic method
    #: such as TRACE. Advertisement only: no unsafe method is ever invoked.
    CONFIG_UNSAFE_HTTP_METHODS = "CONFIG_UNSAFE_HTTP_METHODS"
    #: The target is running in development configuration.
    CONFIG_DEBUG_EXPOSURE = "CONFIG_DEBUG_EXPOSURE"
    #: A deployment file that should not be under a web root was served.
    CONFIG_SENSITIVE_FILE_EXPOSURE = "CONFIG_SENSITIVE_FILE_EXPOSURE"
    #: Version-control metadata is reachable. Detected from one file; the
    #: repository is never enumerated or reconstructed.
    CONFIG_REPOSITORY_METADATA_EXPOSURE = "CONFIG_REPOSITORY_METADATA_EXPOSURE"
    #: A server-generated directory index was served in place of a page.
    CONFIG_DIRECTORY_LISTING = "CONFIG_DIRECTORY_LISTING"
    #: A default or sample page shipped by the server or framework is live.
    CONFIG_DEFAULT_SAMPLE_EXPOSURE = "CONFIG_DEFAULT_SAMPLE_EXPOSURE"
    #: An administrative interface answered an anonymous request.
    CONFIG_ADMIN_INTERFACE_EXPOSURE = "CONFIG_ADMIN_INTERFACE_EXPOSURE"
    #: A management or operations endpoint exposed internal detail.
    CONFIG_MANAGEMENT_INTERFACE_EXPOSURE = "CONFIG_MANAGEMENT_INTERFACE_EXPOSURE"
    #: The stack names itself in a response header. Informational: this is the
    #: default behaviour of most web servers, not a weakness.
    CONFIG_TECHNOLOGY_DISCLOSURE = "CONFIG_TECHNOLOGY_DISCLOSURE"
    #: A CSP that places no restriction on where script may come from. Scoped
    #: off Phase 3's permissive-directive rule, which covers unsafe-inline.
    CONFIG_WEAK_CSP = "CONFIG_WEAK_CSP"
    #: A security header present but structurally broken — duplicated and
    #: conflicting, empty, or one browsers no longer honour.
    CONFIG_HEADER_MISCONFIGURATION = "CONFIG_HEADER_MISCONFIGURATION"
    #: Two layers disagree about what a path addresses.
    CONFIG_PATH_NORMALIZATION = "CONFIG_PATH_NORMALIZATION"
    #: A JavaScript source map is reachable. Often deliberate; graded low.
    CONFIG_SOURCE_MAP_EXPOSURE = "CONFIG_SOURCE_MAP_EXPOSURE"
    #: A TLS handshake the client refused to complete.
    CONFIG_TLS_CONNECTION_FAILURE = "CONFIG_TLS_CONNECTION_FAILURE"

    # --- Cookies ---
    COOKIE_SECURE_MISSING = "COOKIE_SECURE_MISSING"
    COOKIE_HTTPONLY_MISSING = "COOKIE_HTTPONLY_MISSING"
    COOKIE_SAMESITE_MISSING = "COOKIE_SAMESITE_MISSING"
    COOKIE_SAMESITE_NONE_WITHOUT_SECURE = "COOKIE_SAMESITE_NONE_WITHOUT_SECURE"


#: Phase 3 stored short lowercase codes. Kept so the 0005 migration can rewrite
#: existing rows, and so old exports remain interpretable.
LEGACY_CODE_TO_RULE: dict[str, FindingRule] = {
    "missing_hsts": FindingRule.SECURITY_HEADER_HSTS_MISSING,
    "hsts_disabled": FindingRule.SECURITY_HEADER_HSTS_DISABLED,
    "hsts_short_max_age": FindingRule.SECURITY_HEADER_HSTS_SHORT_MAX_AGE,
    "missing_csp": FindingRule.SECURITY_HEADER_CSP_MISSING,
    "permissive_csp": FindingRule.SECURITY_HEADER_CSP_PERMISSIVE,
    "missing_content_type_options": FindingRule.SECURITY_HEADER_X_CONTENT_TYPE_OPTIONS_MISSING,
    "missing_frame_options": FindingRule.SECURITY_HEADER_X_FRAME_OPTIONS_MISSING,
    "missing_referrer_policy": FindingRule.SECURITY_HEADER_REFERRER_POLICY_MISSING,
    "missing_permissions_policy": FindingRule.SECURITY_HEADER_PERMISSIONS_POLICY_MISSING,
    "cookie_missing_secure": FindingRule.COOKIE_SECURE_MISSING,
    "session_cookie_missing_httponly": FindingRule.COOKIE_HTTPONLY_MISSING,
    "cookie_missing_samesite": FindingRule.COOKIE_SAMESITE_MISSING,
    "cookie_samesite_none_without_secure": FindingRule.COOKIE_SAMESITE_NONE_WITHOUT_SECURE,
}


@dataclass(frozen=True, slots=True)
class FindingData:
    """A finding as produced by a detector, before it reaches the database.

    Detectors return these; the service layer turns them into `Finding` rows.
    Nothing here knows about SQLAlchemy, so every rule stays a pure function of
    the HTTP response.
    """

    #: Which rule fired. The deduplication identity, never a display string.
    rule: FindingRule
    title: str
    category: FindingCategory
    severity: FindingSeverity
    confidence: FindingConfidence
    description: str
    #: What was actually observed. Must never contain a secret — in particular,
    #: never a cookie value.
    evidence: str
    impact: str
    remediation: str
    #: What the finding is *about* within its rule — a cookie name, for example.
    #: Two findings of the same rule but different subjects stay separate, so
    #: "cookie `session` missing Secure" never merges with "cookie `theme`
    #: missing Secure". None for rules that apply to the response as a whole.
    subject: str | None = None

    @property
    def identity(self) -> tuple[str, str | None]:
        """The deduplication key: which rule, about what."""
        return (self.rule.value, self.subject)


#: Sort key for presenting findings most-severe-first.
SEVERITY_ORDER: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}


def sort_findings(findings: list[FindingData]) -> list[FindingData]:
    """Most severe first, then alphabetically for a stable order."""
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.title))
