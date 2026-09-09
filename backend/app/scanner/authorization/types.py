"""Value objects for authorization testing.

**Authorization testing is comparative.** A single response says almost nothing:
a 403 might be a working access control or a broken route, and a 200 might be a
private record or a generic "nothing here" page. Meaning comes from putting two
contexts side by side against the same resource and asking whether they were
treated differently.

Two ideas are kept strictly apart throughout this package:

* **Observed access** — what the target actually did.
* **Expected access** — what the authorized user told us *should* happen.

The scanner does not invent the second one. It cannot read an application's
business rules out of its HTTP traffic, and pretending otherwise is how
authorization scanners produce noise. Where no expectation was supplied, the
result is `UNKNOWN` and no finding is raised. See `matrix.py`.
"""

from __future__ import annotations

import enum
from collections.abc import Sequence
from dataclasses import dataclass, field

from app.scanner.auth.types import AuthenticationContext, AuthMode


class AccessExpectation(str, enum.Enum):
    """What the authorized user says should happen. Never inferred."""

    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    #: No policy was supplied for this pair. The default, and not a vulnerability.
    UNKNOWN = "UNKNOWN"


class ObservedAccess(str, enum.Enum):
    """What the target actually did, as far as one response can say."""

    #: The context received the resource.
    ALLOWED = "ALLOWED"
    #: The target refused: 401, 403, a redirect to sign in, or 404.
    DENIED = "DENIED"
    #: A server error, a transport failure, or a response that says neither.
    INCONCLUSIVE = "INCONCLUSIVE"


class ComparisonVerdict(str, enum.Enum):
    """How the observation lines up with the expectation."""

    #: Observed matches expected. The boundary held.
    MATCHES_POLICY = "MATCHES_POLICY"
    #: Expected denied, observed allowed, and the content confirms it. A finding.
    VIOLATION = "VIOLATION"
    #: Expected allowed, observed denied. Fail-safe, so never a finding — but
    #: worth surfacing, because the declared policy and the application disagree.
    CONFLICT = "CONFLICT"
    #: No expectation, or the evidence does not support a conclusion.
    UNKNOWN = "UNKNOWN"


class AuthorizationTestKind(str, enum.Enum):
    """Which comparison produced an observation."""

    #: Anonymous versus an authenticated context.
    ANONYMOUS = "ANONYMOUS"
    #: One identity against another identity's resource, same privilege level.
    HORIZONTAL = "HORIZONTAL"
    #: A lower-privilege identity against a higher-privilege resource.
    VERTICAL = "VERTICAL"
    #: A specific object whose owner the user declared.
    OBJECT_LEVEL = "OBJECT_LEVEL"


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationContext:
    """One explicitly supplied testing identity.

    Wraps a phase-11 `AuthenticationContext` rather than re-implementing
    credential handling: the secret stays inside the object that already knows
    how to refuse to render itself, and every request still goes through the one
    transport that applies credentials.

    `role_label` is metadata the user chose. The scanner attaches no meaning to
    the word "admin" — privilege ordering comes from `privilege_rank`, which the
    user also supplies, because role names are not universal.
    """

    #: Stable identifier used by the matrix and in findings. Not a secret.
    id: str
    #: Human-readable name for the report. Chosen by the user.
    display_name: str
    #: Free-text label such as USER or ADMIN. Metadata only.
    role_label: str | None = None
    #: Higher means more privileged. Only used to decide which comparisons are
    #: "vertical" and which are "horizontal"; never to infer policy.
    privilege_rank: int = 0
    authentication: AuthenticationContext = field(
        default_factory=AuthenticationContext.none
    )

    @property
    def anonymous(self) -> bool:
        return self.authentication.mode is AuthMode.NONE

    def __repr__(self) -> str:
        # The authentication context redacts itself, but spelling it out here
        # keeps a nested repr from ever being the thing that leaks.
        return (
            f"AuthorizationContext(id={self.id!r}, role={self.role_label!r}, "
            f"rank={self.privilege_rank}, anonymous={self.anonymous})"
        )

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class ResponseFingerprint:
    """A bounded, non-sensitive summary of one response.

    This is what makes "did these two contexts receive the same thing?"
    answerable without ever keeping the thing itself. The body is reduced to a
    length and a truncated digest; no substring of it survives, so a private
    record cannot travel into a finding, a report or a log through this path.

    The digest is *not* a security primitive. It exists to compare two responses
    the scanner already holds in memory, which is why a short prefix is enough.
    """

    status_code: int
    content_type: str | None
    #: Byte length of the body the scanner read, subject to the response cap.
    body_length: int
    #: Truncated digest of the normalised body. Never the body itself.
    body_digest: str
    #: Path of the URL the response settled on. No query values.
    final_path: str | None
    redirected: bool

    def summary(self) -> str:
        """One safe line for evidence. Contains no response content."""
        parts = [f"status {self.status_code}"]
        if self.content_type:
            parts.append(self.content_type)
        parts.append(f"{self.body_length} bytes")
        if self.redirected and self.final_path:
            parts.append(f"redirected to {self.final_path}")
        return ", ".join(parts)


@dataclass(frozen=True, slots=True)
class AuthorizationObservation:
    """One (context, resource) test and what it concluded.

    Deliberately records the expectation alongside the observation, so a reader
    can always see whether a verdict rests on a declared policy or on nothing.
    """

    kind: AuthorizationTestKind
    #: The identity that made the request.
    context_id: str
    context_label: str
    #: The identity the resource is understood to belong to, when known.
    reference_context_id: str | None
    #: Canonical URL tested. Parameter names only, as everywhere else.
    url: str
    expected: AccessExpectation
    observed: ObservedAccess
    verdict: ComparisonVerdict
    #: Whether the subject received materially the same content as the
    #: reference. `None` when there was nothing to compare against.
    equivalent_to_reference: bool | None
    fingerprint: ResponseFingerprint | None
    #: Field *names* this context received, when the body was JSON. Names only,
    #: exactly as everywhere else — they are what lets phase 14 ask the
    #: property-level question without repeating a single request.
    json_fields: tuple[str, ...] = ()
    #: Safe, human-readable reason. Never response content.
    detail: str = ""


@dataclass(frozen=True, slots=True)
class AuthorizationBudgetLimits:
    """Bounds on authorization traffic.

    Authorization testing multiplies requests: every extra context re-tests
    every eligible endpoint. Without a ceiling, a four-context scan of a large
    site is a denial-of-service against the target the user asked us to help.
    """

    #: Identities considered, including anonymous.
    max_contexts: int = 4
    #: Endpoints put through the matrix.
    max_endpoints: int = 100
    #: Context-versus-context comparisons drawn per endpoint.
    max_comparisons_per_endpoint: int = 8
    #: Hard ceiling on requests this stage may send, across all contexts.
    max_requests: int = 400


@dataclass(slots=True)
class AuthorizationStats:
    """Counters for the report. Safe to persist and display."""

    contexts: int = 0
    endpoints_eligible: int = 0
    endpoints_tested: int = 0
    requests_sent: int = 0
    comparisons: int = 0
    #: Comparisons with no declared policy and no ownership to reason from.
    unknown: int = 0
    #: Endpoints skipped: budget, an unsupported method, or an unusable reference.
    skipped: int = 0
    #: Requests that failed at the transport.
    failed: int = 0
    budget_exhausted: bool = False
    notes: dict[str, int] = field(default_factory=dict)

    def note(self, reason: str) -> None:
        self.notes[reason] = self.notes.get(reason, 0) + 1


@dataclass(frozen=True, slots=True)
class AuthorizationConfig:
    """Configuration for the authorization stage as a whole."""

    enabled: bool = False
    limits: AuthorizationBudgetLimits = field(default_factory=AuthorizationBudgetLimits)
    #: Similarity at or above which two bodies count as materially the same.
    #: High on purpose: "roughly alike" is how a scanner mistakes a shared page
    #: template for a leaked record.
    equivalence_threshold: float = 0.95
    #: Bodies shorter than this are too small for similarity to mean anything —
    #: two short error pages are always "similar". Such a pair never yields a
    #: finding on similarity alone.
    min_comparable_body_bytes: int = 64


@dataclass(frozen=True, slots=True)
class AuthorizationOutcome:
    """Safe summary of the stage, for the scan row and the report."""

    enabled: bool = False
    contexts: int = 0
    endpoints_eligible: int = 0
    endpoints_tested: int = 0
    comparisons: int = 0
    unknown: int = 0
    skipped: int = 0
    failed: int = 0
    #: Labels of the identities used. User-chosen names, never credentials.
    context_labels: tuple[str, ...] = ()

    @classmethod
    def from_stats(
        cls, stats: AuthorizationStats, labels: Sequence[str]
    ) -> "AuthorizationOutcome":
        return cls(
            enabled=True,
            contexts=stats.contexts,
            endpoints_eligible=stats.endpoints_eligible,
            endpoints_tested=stats.endpoints_tested,
            comparisons=stats.comparisons,
            unknown=stats.unknown,
            skipped=stats.skipped,
            failed=stats.failed,
            context_labels=tuple(labels),
        )
