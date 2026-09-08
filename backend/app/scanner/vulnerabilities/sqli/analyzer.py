"""Pure SQL-injection response analysis.

Two independent pieces, both network-free:

* `analyze_error_signals` — does a response body look like a database error?
* `assess_differential` — do true/false probe similarities form a stable pattern?

Neither draws the final conclusion. The detector combines these with the
baseline (an error absent from the baseline but present under a probe; a
differential that reproduces) — that combination is what a finding requires, and
it lives in `detector.py`, not here.
"""

from __future__ import annotations

import re

from app.scanner.vulnerabilities.sqli.types import (
    DatabaseFamily,
    DifferentialSignal,
    ErrorAnalysis,
    ErrorSignal,
    ErrorSignalStrength,
)


class DatabaseErrorSignature:
    """One compiled database-error pattern.

    Patterns are multi-token on purpose. A page containing the bare word "SQL"
    is not a database error, so every signature requires wording that ordinary
    application text does not produce — an engine name beside an error verb, a
    driver identifier, a SQLSTATE marker.
    """

    __slots__ = ("family", "strength", "signature", "_regex")

    def __init__(
        self,
        family: DatabaseFamily,
        strength: ErrorSignalStrength,
        signature: str,
        pattern: str,
    ) -> None:
        self.family = family
        self.strength = strength
        self.signature = signature
        self._regex = re.compile(pattern, re.IGNORECASE)

    def search(self, text: str) -> ErrorSignal | None:
        if self._regex.search(text):
            return ErrorSignal(family=self.family, strength=self.strength, signature=self.signature)
        return None


# Signatures ordered engine-specific first. Each requires enough context that
# normal prose will not match it.
_SIGNATURES: tuple[DatabaseErrorSignature, ...] = (
    # --- MySQL / MariaDB ---
    DatabaseErrorSignature(
        DatabaseFamily.MYSQL, ErrorSignalStrength.STRONG, "mysql_syntax",
        r"you have an error in your sql syntax",
    ),
    DatabaseErrorSignature(
        DatabaseFamily.MYSQL, ErrorSignalStrength.STRONG, "mysql_driver",
        r"\b(?:warning:\s*mysqli?|mysqli?_(?:query|fetch|num_rows|error)|mysql_fetch_array)\b",
    ),
    DatabaseErrorSignature(
        DatabaseFamily.MYSQL, ErrorSignalStrength.STRONG, "mariadb_syntax",
        r"check the manual that corresponds to your (?:mysql|mariadb) server version",
    ),
    # --- PostgreSQL ---
    DatabaseErrorSignature(
        DatabaseFamily.POSTGRESQL, ErrorSignalStrength.STRONG, "pg_error",
        r"\bpg_(?:query|exec|prepare|connect)\b|\bpostgresql\b.{0,40}\berror\b",
    ),
    DatabaseErrorSignature(
        DatabaseFamily.POSTGRESQL, ErrorSignalStrength.STRONG, "pg_unterminated",
        r"unterminated quoted string at or near",
    ),
    DatabaseErrorSignature(
        DatabaseFamily.POSTGRESQL, ErrorSignalStrength.STRONG, "pg_syntax",
        r"syntax error at or near",
    ),
    # --- Microsoft SQL Server ---
    DatabaseErrorSignature(
        DatabaseFamily.MSSQL, ErrorSignalStrength.STRONG, "mssql_driver",
        r"microsoft (?:ole db|sql server)|\bodbc sql server driver\b|\bsystem\.data\.sqlclient\b",
    ),
    DatabaseErrorSignature(
        DatabaseFamily.MSSQL, ErrorSignalStrength.STRONG, "mssql_unclosed",
        r"unclosed quotation mark after the character string",
    ),
    DatabaseErrorSignature(
        DatabaseFamily.MSSQL, ErrorSignalStrength.STRONG, "mssql_incorrect_syntax",
        r"incorrect syntax near",
    ),
    # --- Oracle ---
    DatabaseErrorSignature(
        DatabaseFamily.ORACLE, ErrorSignalStrength.STRONG, "oracle_ora",
        r"\bora-\d{5}\b",
    ),
    DatabaseErrorSignature(
        DatabaseFamily.ORACLE, ErrorSignalStrength.STRONG, "oracle_driver",
        r"\b(?:oracle|oci)[-_ ]?(?:error|driver|call failed)\b|quoted string not properly terminated",
    ),
    # --- SQLite ---
    DatabaseErrorSignature(
        DatabaseFamily.SQLITE, ErrorSignalStrength.STRONG, "sqlite_error",
        r"\bsqlite3?\.(?:operational|programming|database)?error\b|\bsqlite_error\b",
    ),
    DatabaseErrorSignature(
        DatabaseFamily.SQLITE, ErrorSignalStrength.STRONG, "sqlite_syntax",
        r"sql(?:ite)? error:.{0,40}\bnear\b|unrecognized token:",
    ),
    # --- Generic driver / SQLSTATE wording (weaker, unattributed) ---
    DatabaseErrorSignature(
        DatabaseFamily.GENERIC, ErrorSignalStrength.STRONG, "sqlstate",
        r"\bsqlstate\[[0-9a-z]{5}\]|\bsqlstate\b.{0,20}\b\d{5}\b",
    ),
    DatabaseErrorSignature(
        DatabaseFamily.GENERIC, ErrorSignalStrength.POSSIBLE, "pdo_exception",
        r"\bpdoexception\b|\bpdo::\w+\b",
    ),
    DatabaseErrorSignature(
        DatabaseFamily.GENERIC, ErrorSignalStrength.POSSIBLE, "jdbc_exception",
        r"\bjava\.sql\.sql(?:syntax(?:error)?)?exception\b|\bhibernate\b.{0,30}\bsqlgrammar\b",
    ),
    DatabaseErrorSignature(
        DatabaseFamily.GENERIC, ErrorSignalStrength.POSSIBLE, "generic_query_error",
        r"\b(?:unclosed|unterminated) (?:quotation|quoted string)\b"
        r"|\bsql\b.{0,20}\bsyntax\b.{0,20}\berror\b",
    ),
)


def analyze_error_signals(text: str) -> ErrorAnalysis:
    """Every database-error signature that matches `text`, strongest first.

    Pure. The presence of a signature is not itself a finding — the detector
    only treats it as evidence when it is absent from the baseline.
    """
    if not text:
        return ErrorAnalysis(strength=ErrorSignalStrength.NONE)

    signals: list[ErrorSignal] = []
    for signature in _SIGNATURES:
        signal = signature.search(text)
        if signal is not None:
            signals.append(signal)

    if not signals:
        return ErrorAnalysis(strength=ErrorSignalStrength.NONE)

    signals.sort(key=lambda s: 0 if s.strength is ErrorSignalStrength.STRONG else 1)
    strongest = signals[0].strength
    return ErrorAnalysis(strength=strongest, signals=tuple(signals))


# --------------------------------------------------------------------------- #
# Boolean-differential assessment
# --------------------------------------------------------------------------- #

#: A true-like probe must stay at least this similar to the baseline for the
#: pattern to count — the injection is expected to preserve normal behaviour.
TRUE_SIMILARITY_FLOOR = 0.95

#: A false-like probe must fall at least this far below the true-like probe
#: before the difference counts as material rather than noise.
FALSE_SIMILARITY_MARGIN = 0.10

#: And the false-like probe must be no more similar than this outright, so a
#: pair of near-identical pages can never satisfy the rule.
FALSE_SIMILARITY_CEILING = 0.92


def is_material_difference(true_similarity: float, false_similarity: float) -> bool:
    """Whether one true/false pair shows a materially boolean-shaped difference.

    Requires all three: the true-like probe tracks the baseline, the false-like
    probe drops a clear margin below it, and the false-like probe is not itself
    near-identical to the baseline. One condition alone is treated as noise.
    """
    if true_similarity < TRUE_SIMILARITY_FLOOR:
        return False
    if false_similarity > FALSE_SIMILARITY_CEILING:
        return False
    return (true_similarity - false_similarity) >= FALSE_SIMILARITY_MARGIN


def assess_differential(
    first: DifferentialSignal, second: DifferentialSignal | None
) -> bool:
    """Whether a differential is strong enough to support a finding.

    Both attempts must individually show a material difference. A single
    observation — however clean — is treated as noise, because a page can differ
    between two requests for reasons that have nothing to do with the parameter.
    """
    if not is_material_difference(first.true_similarity, first.false_similarity):
        return False
    if second is None:
        return False
    return is_material_difference(second.true_similarity, second.false_similarity)
