"""Value objects for path-traversal and local-file-inclusion analysis.

Phase 17 asks one narrow question: can a parameter that names a file or a path
be pushed to name a *different* file, outside the boundary the application
intended? That is directory traversal, and where the mechanism is the
application resolving a local file from user input it is local file inclusion.

Three disciplines run through the package.

**Evidence, not a filename.** The scanner never targets a real system file. It
carries one logical canary — a harmless marker file the *local test fixture*
places outside the intended directory — and a finding requires that the
application actually returned that canary, reproducibly. Reflection of the
payload is not retrieval, an error page is not retrieval, and a status change on
its own is not retrieval.

**No content is ever represented.** There is no field anywhere here for a
response body, a file's contents, the canary's bytes, a probe value, a
credential or a cookie. What survives a probe is booleans, counts, status codes
and media types — the *fact* of retrieval, never the substance of it.

**Unknown stays unknown.** A parameter that cannot be classified with
confidence is not probed, and a probe whose evidence is weak yields no finding.
A parameter never tested is recorded as skipped, never as safe.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class ParameterClass(str, enum.Enum):
    """How likely a parameter is to control a file or path.

    Naming is the strongest signal available before any request, but it is not
    the only one, and it is never sufficient on its own to *conclude* anything —
    only to decide what is worth a careful probe. `NOT_FILE_PARAMETER` and
    `UNKNOWN` are both left un-probed.
    """

    #: A name that exists to carry a file or path: `file`, `filepath`, `template`.
    LIKELY_FILE_PARAMETER = "LIKELY_FILE_PARAMETER"
    #: Plausibly a file, but the name is shared with non-file uses: `page`, `src`.
    POSSIBLE_FILE_PARAMETER = "POSSIBLE_FILE_PARAMETER"
    #: A name that clearly is not a file: `id`, `q`, `page_size`.
    NOT_FILE_PARAMETER = "NOT_FILE_PARAMETER"
    #: Not enough to say. The default, and not probed.
    UNKNOWN = "UNKNOWN"

    @property
    def eligible(self) -> bool:
        """Whether a parameter of this class is worth an active probe."""
        return self in (
            ParameterClass.LIKELY_FILE_PARAMETER,
            ParameterClass.POSSIBLE_FILE_PARAMETER,
        )


class TraversalVerdict(str, enum.Enum):
    """What the differential and canary evidence supports.

    Only `STRONG` produces a finding, and only because it means the controlled
    canary was retrieved from outside the intended directory and the behaviour
    reproduced. Everything softer is recorded and left as an observation.
    """

    #: The canary was retrieved outside its boundary, reproducibly.
    STRONG = "STRONG"
    #: A material differential that falls short of canary retrieval.
    POSSIBLE = "POSSIBLE"
    #: The endpoint behaved normally under every probe.
    NONE = "NONE"
    #: The baseline was unusable, or the evidence was inconclusive.
    UNKNOWN = "UNKNOWN"


class InclusionMechanism(str, enum.Enum):
    """Which weakness the evidence points at.

    The two overlap, and the scanner reports the one the evidence supports
    rather than claiming a server-side implementation it cannot see.
    """

    #: Input escaped an intended directory to name a file elsewhere.
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    #: The application resolved or included a local file from the input — a
    #: template/include-style parameter is the signal that separates this from
    #: plain traversal.
    LOCAL_FILE_INCLUSION = "LOCAL_FILE_INCLUSION"


class TargetPlatform(str, enum.Enum):
    """What the response evidence says about the target's OS.

    Almost always `UNKNOWN`, and deliberately so: this phase does not probe
    system-specific paths to fingerprint an operating system, and a
    platform-neutral canary tells it nothing about the host.
    """

    UNKNOWN = "UNKNOWN"
    UNIX = "UNIX"
    WINDOWS = "WINDOWS"


class SkipReason(str, enum.Enum):
    """Why an eligible-looking parameter was not tested. Never means "safe"."""

    NOT_A_FILE_PARAMETER = "NOT_A_FILE_PARAMETER"
    BASELINE_UNUSABLE = "BASELINE_UNUSABLE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    CANCELLED = "CANCELLED"
    PROBE_FAILED = "PROBE_FAILED"


# --------------------------------------------------------------------------- #
# Observations
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ParameterAssessment:
    """A parameter and how it was classified. Names only, never a value."""

    endpoint: str
    parameter: str
    classification: ParameterClass
    #: Which signals produced the classification, so a reader sees the why.
    signals: tuple[str, ...] = ()

    @property
    def eligible(self) -> bool:
        return self.classification.eligible


@dataclass(frozen=True, slots=True)
class TraversalObservation:
    """One parameter's traversal result on one endpoint.

    Carries only safe metadata. `canary_matched` is the load-bearing field: it
    is true only when the controlled marker file was actually returned, which
    reflection of a payload can never produce.
    """

    endpoint: str
    method: str
    parameter: str
    verdict: TraversalVerdict
    mechanism: InclusionMechanism
    #: Whether the controlled canary marker appeared in a probe response.
    canary_matched: bool = False
    #: Whether the canary retrieval reproduced on a second identical probe.
    reproduced: bool = False
    baseline_status: int | None = None
    probe_status: int | None = None
    baseline_media_type: str | None = None
    probe_media_type: str | None = None
    platform: TargetPlatform = TargetPlatform.UNKNOWN
    #: Whether the probe carried the configured authentication.
    authenticated: bool = False
    #: A user-chosen identity label, when the scan ran authenticated. Never a
    #: credential.
    context_label: str | None = None
    #: Signals behind the verdict, for explaining rather than asserting.
    signals: tuple[str, ...] = ()

    @property
    def reportable(self) -> bool:
        return self.verdict is TraversalVerdict.STRONG


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class PathSecurityLimits:
    """Ceilings on the traffic this phase may generate. Every one fails closed."""

    #: File-like parameters probed on a single endpoint.
    max_parameters_per_endpoint: int = 3
    #: Traversal variants sent per parameter. A small fixed set, never a wordlist.
    max_variants_per_parameter: int = 8
    #: Endpoints considered per scan.
    max_targets: int = 25
    #: Hard scan-wide probe ceiling, enforced by the shared ProbeBudget.
    max_probes_per_scan: int = 200
    #: Per-parameter and per-endpoint budget ceilings for the ProbeBudget.
    #: A parameter needs 1 baseline + up to 8 variants + 1 reproduction.
    per_parameter_budget: int = 12
    per_endpoint_budget: int = 48
    #: Bytes of a probe response scanned for the canary before it is discarded.
    max_response_bytes: int = 32_768


@dataclass(frozen=True, slots=True)
class PathSecurityConfig:
    """Configuration for the path-security stage."""

    enabled: bool = True
    limits: PathSecurityLimits = field(default_factory=PathSecurityLimits)


@dataclass(slots=True)
class PathSecurityStats:
    """Coverage counters for the report. Safe to persist and display."""

    parameters_considered: int = 0
    file_parameters: int = 0
    parameters_tested: int = 0
    parameters_skipped: int = 0
    endpoints_tested: int = 0
    traversal_probes: int = 0
    canary_matches: int = 0
    lfi_candidates: int = 0
    uncertain_classifications: int = 0
    failed_probes: int = 0
    requests_sent: int = 0
    findings_count: int = 0
    budget_exhausted: bool = False
    notes: dict[str, int] = field(default_factory=dict)

    def note(self, reason: str) -> None:
        self.notes[reason] = self.notes.get(reason, 0) + 1


@dataclass(frozen=True, slots=True)
class PathSecurityOutcome:
    """Safe summary of the stage, for the scan row and the report."""

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

    @classmethod
    def from_result(cls, result: "PathSecurityResult") -> "PathSecurityOutcome":
        stats = result.stats
        return cls(
            analyzed=bool(stats.parameters_considered or stats.parameters_tested),
            parameters_considered=stats.parameters_considered,
            file_parameters=stats.file_parameters,
            parameters_tested=stats.parameters_tested,
            parameters_skipped=stats.parameters_skipped,
            endpoints_tested=stats.endpoints_tested,
            traversal_probes=stats.traversal_probes,
            canary_matches=stats.canary_matches,
            lfi_candidates=stats.lfi_candidates,
            requests_sent=stats.requests_sent,
            findings_count=stats.findings_count,
            budget_exhausted=stats.budget_exhausted,
        )


@dataclass(frozen=True, slots=True)
class PathSecurityResult:
    """Everything the path-security stage concluded for one scan."""

    assessments: tuple[ParameterAssessment, ...] = ()
    observations: tuple[TraversalObservation, ...] = ()
    stats: PathSecurityStats = field(default_factory=PathSecurityStats)

    def outcome(self) -> PathSecurityOutcome:
        return PathSecurityOutcome.from_result(self)

    @property
    def confirmed(self) -> tuple[TraversalObservation, ...]:
        return tuple(o for o in self.observations if o.reportable)
