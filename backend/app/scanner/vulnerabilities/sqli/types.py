"""Typed intermediate results for SQL-injection analysis.

Plain dataclasses and enums. Nothing here performs I/O or touches the database.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class DatabaseFamily(str, enum.Enum):
    """Which engine an error signature points at.

    GENERIC covers driver- and SQLSTATE-level wording that does not name one
    engine — still strong evidence of a database error, just not attributable.
    """

    MYSQL = "MySQL/MariaDB"
    POSTGRESQL = "PostgreSQL"
    MSSQL = "Microsoft SQL Server"
    ORACLE = "Oracle"
    SQLITE = "SQLite"
    GENERIC = "Generic SQL"


class ErrorSignalStrength(str, enum.Enum):
    """How strongly a response looks like a database error.

    Deliberately separate from any vulnerability conclusion. STRONG means the
    text matches a specific engine's error wording; POSSIBLE means it matches a
    weaker generic pattern; NONE means nothing matched.
    """

    NONE = "NONE"
    POSSIBLE = "POSSIBLE"
    STRONG = "STRONG"


@dataclass(frozen=True, slots=True)
class ErrorSignal:
    """One database-error signature that matched a response."""

    family: DatabaseFamily
    strength: ErrorSignalStrength
    #: A short, fixed label for the signature that fired — never the matched
    #: text itself, which could contain fragments of a query or of user data.
    signature: str


@dataclass(frozen=True, slots=True)
class ErrorAnalysis:
    """The database-error assessment of a single response body."""

    strength: ErrorSignalStrength
    signals: tuple[ErrorSignal, ...] = ()

    @property
    def primary(self) -> ErrorSignal | None:
        return self.signals[0] if self.signals else None

    @property
    def has_error(self) -> bool:
        return self.strength is not ErrorSignalStrength.NONE


class SqliOutcome(str, enum.Enum):
    """The conclusion for one parameter."""

    NO_SIGNAL = "NO_SIGNAL"
    #: A database error appeared under a probe but not in the baseline.
    ERROR_BASED = "ERROR_BASED"
    #: True-like and false-like probes drove a stable, material difference.
    BOOLEAN_DIFFERENTIAL = "BOOLEAN_DIFFERENTIAL"


@dataclass(frozen=True, slots=True)
class DifferentialSignal:
    """The evidence behind a boolean-differential conclusion.

    Records the shape of the difference, never response bodies. Two independent
    repetitions must agree before this is trusted, which is what `reproduced`
    records.
    """

    #: Similarity of the true-like probe to the baseline (higher is more alike).
    true_similarity: float
    #: Similarity of the false-like probe to the baseline (lower means it moved).
    false_similarity: float
    #: The true/false pair behaved the same way on a second, independent attempt.
    reproduced: bool
    status_differs: bool = False
