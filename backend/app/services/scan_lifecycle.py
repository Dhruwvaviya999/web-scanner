"""The scan state machine.

One place defines which scan states exist, which stages a run passes through,
and which transitions are legal. Every status change goes through `transition`,
so an illegal move — a finished scan going back to RUNNING, a failed scan being
marked complete — is impossible rather than merely unlikely.

Terminal states (COMPLETED, FAILED, CANCELLED) have no outgoing edges at all.
Once a scan stops, it stays stopped.
"""

from __future__ import annotations

import enum

from app.core.errors import ConflictError
from app.models.scan import ScanStatus


class ScanStage(str, enum.Enum):
    """Where a run currently is. Coarser than a percentage, and honest.

    The scanner cannot know its total work in advance — the crawler discovers
    pages as it goes — so the stage is the primary progress signal and any
    percentage attached to it is an approximation.
    """

    QUEUED = "QUEUED"
    INITIALIZING = "INITIALIZING"
    PROBING = "PROBING"
    CRAWLING = "CRAWLING"
    ANALYZING = "ANALYZING"
    API_DISCOVERY = "API_DISCOVERY"
    AUTHORIZATION = "AUTHORIZATION"
    API_SECURITY = "API_SECURITY"
    SESSION_SECURITY_ANALYSIS = "SESSION_SECURITY_ANALYSIS"
    CONFIGURATION_SECURITY = "CONFIGURATION_SECURITY"
    PATH_SECURITY = "PATH_SECURITY"
    AGGREGATING = "AGGREGATING"
    FINALIZING = "FINALIZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


#: Indicative progress per stage. Deliberately coarse: these are milestones, not
#: measurements. QUEUED is 0 and the terminal stages are 100; the middle values
#: say "roughly this far through" and nothing more precise than that.
STAGE_PROGRESS: dict[ScanStage, int | None] = {
    ScanStage.QUEUED: 0,
    ScanStage.INITIALIZING: 5,
    ScanStage.PROBING: 15,
    ScanStage.CRAWLING: 40,
    ScanStage.ANALYZING: 70,
    ScanStage.API_DISCOVERY: 75,
    ScanStage.AUTHORIZATION: 80,
    ScanStage.API_SECURITY: 83,
    ScanStage.SESSION_SECURITY_ANALYSIS: 84,
    ScanStage.CONFIGURATION_SECURITY: 86,
    ScanStage.PATH_SECURITY: 88,
    ScanStage.AGGREGATING: 85,
    ScanStage.FINALIZING: 95,
    ScanStage.COMPLETED: 100,
    ScanStage.FAILED: 100,
    ScanStage.CANCELLED: 100,
}

#: Default human-readable message per stage.
STAGE_MESSAGE: dict[ScanStage, str] = {
    ScanStage.QUEUED: "Waiting to start.",
    ScanStage.INITIALIZING: "Preparing the scan.",
    ScanStage.PROBING: "Fetching the target.",
    ScanStage.CRAWLING: "Discovering pages and inputs.",
    ScanStage.ANALYZING: "Analysing discovered endpoints.",
    ScanStage.API_DISCOVERY: "Mapping the API attack surface.",
    ScanStage.AUTHORIZATION: "Comparing access across the supplied identities.",
    ScanStage.API_SECURITY: "Reviewing API responses for exposure.",
    ScanStage.SESSION_SECURITY_ANALYSIS: "Reviewing session handling and CSRF posture.",
    ScanStage.CONFIGURATION_SECURITY: "Checking deployment and transport configuration.",
    ScanStage.PATH_SECURITY: "Testing file and path parameters for traversal.",
    ScanStage.AGGREGATING: "Grouping findings.",
    ScanStage.FINALIZING: "Saving results.",
    ScanStage.COMPLETED: "Scan complete.",
    ScanStage.FAILED: "The scan did not complete.",
    ScanStage.CANCELLED: "The scan was cancelled.",
}

#: The only legal status moves. Everything else is rejected.
ALLOWED_TRANSITIONS: dict[ScanStatus, frozenset[ScanStatus]] = {
    ScanStatus.QUEUED: frozenset(
        {ScanStatus.RUNNING, ScanStatus.FAILED, ScanStatus.CANCELLED}
    ),
    ScanStatus.RUNNING: frozenset(
        {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}
    ),
    # Terminal: no outgoing edges.
    ScanStatus.COMPLETED: frozenset(),
    ScanStatus.FAILED: frozenset(),
    ScanStatus.CANCELLED: frozenset(),
}

TERMINAL_STATUSES: frozenset[ScanStatus] = frozenset(
    {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}
)


def is_terminal(status: ScanStatus) -> bool:
    return status in TERMINAL_STATUSES


def can_transition(current: ScanStatus, target: ScanStatus) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


def transition(current: ScanStatus, target: ScanStatus) -> ScanStatus:
    """Validate a status change, or raise.

    Raises `ConflictError` (HTTP 409) rather than a generic error, because an
    illegal transition is a caller problem — cancelling a scan that already
    finished, or starting one twice — not a server fault.
    """
    if current is target:
        return target
    if not can_transition(current, target):
        raise ConflictError(
            f"A {current.value.lower()} scan cannot become {target.value.lower()}.",
            code="invalid_scan_transition",
        )
    return target


#: Which stage a terminal status corresponds to.
TERMINAL_STAGE: dict[ScanStatus, ScanStage] = {
    ScanStatus.COMPLETED: ScanStage.COMPLETED,
    ScanStatus.FAILED: ScanStage.FAILED,
    ScanStatus.CANCELLED: ScanStage.CANCELLED,
}
