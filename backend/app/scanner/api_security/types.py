"""Value objects for API security analysis.

Phase 14 is **read-only**. It reasons about responses earlier phases already
fetched: their field names, their headers, their status codes. It sends no
payload, invokes no operation, and generates no error to look at.

The governing idea is stated once here and enforced everywhere below: **a field
being present is not proof of a vulnerability.** Whether an API should return
`phone` depends on what the application is for, and a scanner cannot know that.
So the model separates three things that are easy to blur:

* **What was observed** — this field name appeared in this response.
* **How sensitive the field is** — a property of the name, not of the context.
* **Whether the context should have received it** — which only a declared
  authorization policy can answer, and usually nobody declared one.

Only when all three line up does a finding follow. Otherwise the observation is
recorded as informational, which is the honest result.

Nothing here holds a field *value*. The whole module works from names, counts
and header values that were already vetted as safe to keep.
"""

from __future__ import annotations

import enum
from collections.abc import Sequence
from dataclasses import dataclass, field


class FieldSensitivity(str, enum.Enum):
    """How sensitive a field name is, independent of who received it.

    A property of the name alone. `password_hash` is highly sensitive wherever
    it appears; whether its appearance is a *problem* is a separate question the
    context answers.
    """

    #: Nothing about the name suggests sensitivity.
    UNKNOWN = "UNKNOWN"
    #: Sensitive in some contexts and perfectly ordinary in others — a phone
    #: number in a staff directory, an address on an order the customer placed.
    POTENTIALLY_SENSITIVE = "POTENTIALLY_SENSITIVE"
    #: A secret by construction. There is no ordinary reason for a client to
    #: receive a password hash, a private key or an access token belonging to
    #: someone else.
    HIGHLY_SENSITIVE = "HIGHLY_SENSITIVE"


class FieldCategory(str, enum.Enum):
    """What kind of sensitive thing a field name refers to."""

    AUTHENTICATION = "AUTHENTICATION"
    TOKEN = "TOKEN"
    SESSION = "SESSION"
    CRYPTOGRAPHIC = "CRYPTOGRAPHIC"
    PERSONAL = "PERSONAL"
    FINANCIAL = "FINANCIAL"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    NONE = "NONE"


class ErrorSignal(str, enum.Enum):
    """A category of verbose-error evidence found in a response.

    Category names only. Nothing from the response text is ever carried with
    one — the whole point is to be able to say "a stack trace was present"
    without keeping the stack trace.
    """

    STACK_TRACE = "STACK_TRACE"
    FILESYSTEM_PATH = "FILESYSTEM_PATH"
    DATABASE_ERROR = "DATABASE_ERROR"
    SQL_STATEMENT = "SQL_STATEMENT"
    FRAMEWORK_DEBUG = "FRAMEWORK_DEBUG"
    EXCEPTION_CLASS = "EXCEPTION_CLASS"
    INTERNAL_HOST = "INTERNAL_HOST"
    ENVIRONMENT_DUMP = "ENVIRONMENT_DUMP"


#: Signals strong enough on their own to call a response verbose. A stack trace
#: or a SQL statement in a client-facing body is a debugging aid that escaped;
#: a lone filesystem path might be a legitimate resource name.
STRONG_ERROR_SIGNALS: frozenset[ErrorSignal] = frozenset(
    {
        ErrorSignal.STACK_TRACE,
        ErrorSignal.DATABASE_ERROR,
        ErrorSignal.SQL_STATEMENT,
        ErrorSignal.FRAMEWORK_DEBUG,
        ErrorSignal.ENVIRONMENT_DUMP,
    }
)


class ExposureVerdict(str, enum.Enum):
    """What an observed sensitive field amounts to.

    `UNKNOWN_POLICY` is the common case on a real target and is deliberately not
    a finding: the scanner saw a sensitive-looking field and has no basis for
    saying it should not be there.
    """

    #: A declared policy says this context should not have the resource at all,
    #: or the field is a secret no client should receive.
    UNAUTHORIZED = "UNAUTHORIZED"
    #: The context is entitled to it, or the difference is expected.
    EXPECTED = "EXPECTED"
    #: Sensitive-looking, with nothing to judge it against.
    UNKNOWN_POLICY = "UNKNOWN_POLICY"


@dataclass(frozen=True, slots=True)
class FieldClassification:
    """One field name, classified. Never a value."""

    name: str
    category: FieldCategory = FieldCategory.NONE
    sensitivity: FieldSensitivity = FieldSensitivity.UNKNOWN
    #: Which rule matched, for explaining the verdict rather than asserting it.
    rule: str | None = None

    @property
    def sensitive(self) -> bool:
        return self.sensitivity is not FieldSensitivity.UNKNOWN


@dataclass(frozen=True, slots=True)
class SensitiveFieldObservation:
    """A sensitive-looking field seen in one response, for one context."""

    url: str
    method: str
    context_id: str
    context_label: str
    field: FieldClassification
    verdict: ExposureVerdict
    #: True when the request carried no credential at all.
    anonymous: bool
    status_code: int | None = None
    #: Safe reason text. Never response content.
    detail: str = ""


@dataclass(frozen=True, slots=True)
class PropertyComparison:
    """Field sets two contexts received for the same resource.

    The comparison Phase 12 could not make: it established who could reach a
    resource, this establishes what each of them was handed once inside.
    """

    url: str
    reference_context_id: str
    subject_context_id: str
    subject_context_label: str
    #: Field names the subject received that the reference did not. Names only.
    extra_fields: tuple[FieldClassification, ...] = ()
    verdict: ExposureVerdict = ExposureVerdict.UNKNOWN_POLICY
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ErrorObservation:
    """A response that leaked diagnostic detail. No body, ever."""

    url: str
    method: str
    status_code: int
    content_type: str | None
    signals: tuple[ErrorSignal, ...]
    #: Byte length of the body that produced the signals. A number, not content.
    body_length: int = 0

    @property
    def strong(self) -> bool:
        return bool(set(self.signals) & STRONG_ERROR_SIGNALS)


class CorsVerdict(str, enum.Enum):
    """What a CORS configuration amounts to.

    `ABSENT` is explicitly not a problem. CORS is not required for every API,
    and reporting its absence as a weakness would be noise on every server-to-
    server API in existence.
    """

    #: Wildcard origin together with credentials. Browsers refuse this
    #: combination, which is itself the point: shipping it means the policy was
    #: never thought through.
    WILDCARD_WITH_CREDENTIALS = "WILDCARD_WITH_CREDENTIALS"
    #: A specific origin reflected back with credentials and no `Vary: Origin`.
    REFLECTED_WITH_CREDENTIALS = "REFLECTED_WITH_CREDENTIALS"
    #: `null` origin allowed, which sandboxed documents can forge.
    NULL_ORIGIN_ALLOWED = "NULL_ORIGIN_ALLOWED"
    #: A specific origin with credentials but no `Vary: Origin`. A shared cache
    #: can then hand one origin's credentialed response to another. Real, and
    #: milder than the two above.
    CREDENTIALED_WITHOUT_VARY = "CREDENTIALED_WITHOUT_VARY"
    #: Present and unremarkable.
    SAFE = "SAFE"
    #: No CORS headers. Not a weakness.
    ABSENT = "ABSENT"


@dataclass(frozen=True, slots=True)
class CorsObservation:
    """One endpoint's CORS posture, from headers already received."""

    url: str
    verdict: CorsVerdict
    allow_origin: str | None = None
    allow_credentials: bool = False
    vary_origin: bool = False
    detail: str = ""

    @property
    def unsafe(self) -> bool:
        return self.verdict in (
            CorsVerdict.WILDCARD_WITH_CREDENTIALS,
            CorsVerdict.REFLECTED_WITH_CREDENTIALS,
            CorsVerdict.NULL_ORIGIN_ALLOWED,
            CorsVerdict.CREDENTIALED_WITHOUT_VARY,
        )


@dataclass(frozen=True, slots=True)
class DisclosureObservation:
    """A response header that named internal software or infrastructure."""

    url: str
    header: str
    #: The header's value, kept only when it is a software banner — a version
    #: string is the finding. Never a credential: the analyser refuses to record
    #: any header that could carry one.
    value: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class InventoryObservation:
    """Something notable about the API inventory itself.

    Deliberately informational. Two versions of an API coexisting is normal
    during a migration; it becomes a finding only with explicit evidence, and
    the scanner rarely has any.
    """

    kind: str
    detail: str
    paths: tuple[str, ...] = ()
    #: Version labels involved, when the observation is about versioning.
    versions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ApiSecurityLimits:
    """Bounds on API security analysis.

    The defaults describe a stage that sends nothing: it reads what earlier
    phases captured. `max_requests` exists as a ceiling for a future
    confirmation request rather than as an allowance to be spent.
    """

    #: API endpoints examined.
    max_endpoints: int = 500
    #: Sensitive-field observations retained per endpoint.
    max_fields_per_endpoint: int = 50
    #: Property comparisons drawn across contexts.
    max_property_comparisons: int = 200
    #: Hard ceiling on any request this stage might make. It makes none today.
    max_requests: int = 100


@dataclass(frozen=True, slots=True)
class ApiSecurityConfig:
    """Configuration for the API security stage."""

    enabled: bool = True
    limits: ApiSecurityLimits = field(default_factory=ApiSecurityLimits)
    #: Whether to treat plaintext HTTP as a finding. Off by default: every
    #: local fixture and every development target is HTTP, and reporting that
    #: as a production TLS weakness would be wrong far more often than right.
    flag_plaintext_http: bool = False


@dataclass(slots=True)
class ApiSecurityStats:
    """Counters for the report. Safe to persist and display."""

    endpoints_analyzed: int = 0
    endpoints_skipped: int = 0
    responses_analyzed: int = 0
    sensitive_fields_detected: int = 0
    property_comparisons: int = 0
    verbose_errors: int = 0
    cors_checks: int = 0
    cors_unsafe: int = 0
    disclosures: int = 0
    inventory_observations: int = 0
    contexts_analyzed: int = 0
    #: Sensitive-looking fields with no policy to judge them against. The most
    #: common outcome, and never a finding.
    unknown_policy: int = 0
    findings_count: int = 0
    requests_sent: int = 0
    truncated: bool = False
    notes: dict[str, int] = field(default_factory=dict)

    def note(self, reason: str) -> None:
        self.notes[reason] = self.notes.get(reason, 0) + 1


@dataclass(frozen=True, slots=True)
class ApiSecurityOutcome:
    """Safe summary of the stage, for the scan row and the report."""

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

    @classmethod
    def from_stats(cls, stats: ApiSecurityStats) -> "ApiSecurityOutcome":
        return cls(
            analyzed=stats.endpoints_analyzed > 0 or stats.responses_analyzed > 0,
            endpoints_analyzed=stats.endpoints_analyzed,
            endpoints_skipped=stats.endpoints_skipped,
            responses_analyzed=stats.responses_analyzed,
            sensitive_fields_detected=stats.sensitive_fields_detected,
            property_comparisons=stats.property_comparisons,
            verbose_errors=stats.verbose_errors,
            cors_checks=stats.cors_checks,
            inventory_observations=stats.inventory_observations,
            contexts_analyzed=stats.contexts_analyzed,
            unknown_policy=stats.unknown_policy,
            findings_count=stats.findings_count,
        )


@dataclass(frozen=True, slots=True)
class ApiSecurityResult:
    """Everything the API security stage concluded for one scan."""

    sensitive_fields: tuple[SensitiveFieldObservation, ...] = ()
    property_comparisons: tuple[PropertyComparison, ...] = ()
    errors: tuple[ErrorObservation, ...] = ()
    cors: tuple[CorsObservation, ...] = ()
    disclosures: tuple[DisclosureObservation, ...] = ()
    inventory: tuple[InventoryObservation, ...] = ()
    stats: ApiSecurityStats = field(default_factory=ApiSecurityStats)

    def outcome(self) -> ApiSecurityOutcome:
        return ApiSecurityOutcome.from_stats(self.stats)


def unique_fields(
    classifications: Sequence[FieldClassification],
) -> tuple[FieldClassification, ...]:
    """Deduplicate by field name, keeping the first classification seen."""
    seen: dict[str, FieldClassification] = {}
    for classification in classifications:
        seen.setdefault(classification.name, classification)
    return tuple(seen.values())
