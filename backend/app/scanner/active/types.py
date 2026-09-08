"""Value objects and the detector contract for active probing.

"Active" means the scanner sends requests it constructed, rather than only
reading what the crawler already fetched. Everything generic about doing that
safely lives in this package; what a probe *means* stays with the detector.

Response types are deliberately not redefined here. A probe response is the
transport's own `RawHttpResponse` — the same type the probe and crawler
produce — so there is one response shape in the codebase rather than three.
"""

from __future__ import annotations

import enum
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from app.scanner.security.types import FindingData
from app.scanner.types import RawHttpResponse

if TYPE_CHECKING:
    from app.scanner.active.engine import ProbeEngine


class ProbePurpose(str, enum.Enum):
    """Why a request was sent. Used for logging and probe accounting."""

    #: Establishes normal behaviour before anything is varied.
    BASELINE = "BASELINE"
    #: Carries a detector-controlled value.
    PROBE = "PROBE"


class ProbeFailure(str, enum.Enum):
    """Why a probe produced no response. Never yields a finding."""

    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    INVALID_URL = "INVALID_URL"
    REQUEST_FAILED = "REQUEST_FAILED"
    DETECTOR_ERROR = "DETECTOR_ERROR"


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    """One endpoint a detector may test.

    Carries parameter *names* only. The framework never sees, and never needs,
    the values a real user submitted.
    """

    url: str
    parameters: tuple[str, ...] = ()
    content_type: str | None = None
    method: str = "GET"


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    """A single request a detector wants sent.

    The detector supplies the input to vary and the value to put there; the
    engine builds the URL, so a detector cannot choose a host, scheme or path of
    its own and thereby escape the scan's scope.
    """

    target: ProbeTarget
    #: Which input is being varied. None sends the target URL unmodified.
    parameter: str | None
    #: The value to place in that input. Exists only in memory, never stored.
    value: str
    purpose: ProbePurpose = ProbePurpose.PROBE


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """The result of one probe. Either a response or a reason there is none."""

    request: ProbeRequest
    response: RawHttpResponse | None = None
    failure: ProbeFailure | None = None

    @property
    def ok(self) -> bool:
        return self.response is not None

    @property
    def status_code(self) -> int | None:
        return self.response.status_code if self.response else None

    @property
    def content_type(self) -> str | None:
        return self.response.headers.get("content-type") if self.response else None


@dataclass(frozen=True, slots=True)
class Eligibility:
    """Whether a detector will test a target, and why not when it will not."""

    eligible: bool
    reason: str | None = None

    @classmethod
    def yes(cls) -> "Eligibility":
        return cls(eligible=True)

    @classmethod
    def no(cls, reason: str) -> "Eligibility":
        return cls(eligible=False, reason=reason)

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.eligible


#: What a detector hands back: the endpoint it applies to, and the finding.
DetectorObservation = tuple[str, FindingData]


@dataclass(slots=True)
class ActiveScanStats:
    """Probe accounting for one scan, so volume stays observable."""

    requests_sent: int = 0
    targets_considered: int = 0
    targets_probed: int = 0
    targets_skipped: int = 0
    failures: int = 0
    budget_exhausted: bool = False
    notes: dict[str, int] = field(default_factory=dict)

    def note(self, key: str) -> None:
        self.notes[key] = self.notes.get(key, 0) + 1


class ActiveDetector(Protocol):
    """Contract every active detector implements.

    The split is deliberate:

    * `eligible` is pure and cheap, so the framework can filter targets before
      any request is sent.
    * `probe` receives the engine rather than a transport, so a detector can
      only reach the network through the layer that enforces scope, budget and
      timeouts. There is no way for a detector to open its own connection.

    Response interpretation and finding construction are *not* on this protocol
    on purpose — they are pure and belong in separate modules the detector
    calls (for XSS: `analyzer.py` and `findings.py`). Keeping them off the
    interface is what stops network code and judgement code from merging.
    """

    name: str

    def eligible(self, target: ProbeTarget) -> Eligibility:
        """Cheap, pure filter. Must not perform I/O."""
        ...

    async def probe(
        self, target: ProbeTarget, engine: "ProbeEngine"
    ) -> Sequence[DetectorObservation]:
        """Test one target and return whatever findings the evidence supports."""
        ...
