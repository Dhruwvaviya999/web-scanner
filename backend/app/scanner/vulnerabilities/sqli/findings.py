"""Turning an SQLi conclusion into a finding.

Pure. Evidence names the parameter, the database family and the shape of the
signal — never a query, a probe value, or any response content that could carry
data. Nothing here is CRITICAL, and the wording never claims data extraction or
confirmed arbitrary SQL execution: this detector observes signals consistent
with injection, it does not exploit.
"""

from __future__ import annotations

from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingData,
    FindingRule,
    FindingSeverity,
)
from app.scanner.vulnerabilities.sqli.types import DatabaseFamily, ErrorSignalStrength


def subject_for(parameter: str) -> str:
    """Deterministic subject: the parameter name only, never its value."""
    return f"parameter:{parameter}"


_REMEDIATION = (
    "Use parameterized queries or prepared statements, and never build SQL by concatenating "
    "untrusted input. An allow-list on the parameter's expected shape (for example, an integer "
    "id) adds defence in depth."
)


def build_error_based_finding(
    parameter: str,
    family: DatabaseFamily,
    strength: ErrorSignalStrength,
    probe_label: str,
) -> FindingData:
    """A finding for a database error that a probe induced but the baseline lacked.

    Confidence follows signature strength: a specific engine's error wording is
    HIGH; a weaker generic driver pattern is MEDIUM. Severity is HIGH either way
    — an injectable query is serious — but never CRITICAL, because execution was
    not confirmed.
    """
    confidence = (
        FindingConfidence.HIGH
        if strength is ErrorSignalStrength.STRONG
        else FindingConfidence.MEDIUM
    )

    evidence = (
        f'Changing the "{parameter}" query parameter produced a {family.value} error signature '
        "that was absent from the baseline response. The probe altered SQL syntax only; no data "
        "was requested or returned."
    )
    description = (
        f'A controlled change to the "{parameter}" query parameter caused a database-related '
        "error that the unmodified request did not. That pattern is consistent with the value "
        "reaching an SQL query without safe parameterization. Detection used harmless syntax "
        "probes; no data extraction was attempted."
    )
    impact = (
        "If attacker-controlled input reaches a database query unparameterized, an attacker may "
        "be able to alter the query's logic — potentially reading or changing data the query can "
        "reach. This scanner observed an error signal consistent with that; it did not confirm "
        "execution or extract any data."
    )

    return FindingData(
        rule=FindingRule.SQLI_ERROR_BASED,
        title="Potential SQL injection (error-based)",
        category=FindingCategory.SQLI,
        severity=FindingSeverity.HIGH,
        confidence=confidence,
        description=description,
        evidence=evidence,
        impact=impact,
        remediation=_REMEDIATION,
        subject=subject_for(parameter),
    )


def build_boolean_finding(parameter: str, probe_label: str) -> FindingData:
    """A finding for a reproduced true/false differential.

    Only reached when both attempts agreed, so confidence is HIGH. Still not
    CRITICAL, and the wording stays at "consistent with", not "confirmed".
    """
    evidence = (
        f'Two independent true/false condition pairs on the "{parameter}" query parameter drove '
        "a stable, material difference in the response: the true-like probe matched the baseline "
        "while the false-like probe did not. The probes changed boolean logic only."
    )
    description = (
        f'The "{parameter}" query parameter changed the response in a way that tracks the truth '
        "value of an injected boolean condition, reproducibly. That behaviour is consistent with "
        "the value being interpreted as part of an SQL query rather than as data."
    )
    impact = (
        "A boolean-controllable query lets an attacker infer or influence query results by "
        "crafting conditions. This scanner observed a reproducible differential consistent with "
        "that; it did not extract data or confirm arbitrary SQL execution."
    )

    return FindingData(
        rule=FindingRule.SQLI_BOOLEAN_DIFFERENTIAL,
        title="Potential SQL injection (boolean-differential)",
        category=FindingCategory.SQLI,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        description=description,
        evidence=evidence,
        impact=impact,
        remediation=_REMEDIATION,
        subject=subject_for(parameter),
    )
