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
    TLS = "TLS"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    OTHER = "OTHER"


@dataclass(frozen=True, slots=True)
class FindingData:
    """A finding as produced by a detector, before it reaches the database.

    Detectors return these; the service layer turns them into `Finding` rows.
    Nothing here knows about SQLAlchemy, so every rule stays a pure function of
    the HTTP response.
    """

    #: Stable identifier for the rule that fired, e.g. "missing_csp".
    #: Lets findings be correlated across scans without matching on prose.
    code: str
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
