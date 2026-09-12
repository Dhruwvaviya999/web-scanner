"""Turning a traversal conclusion into a finding.

Pure. Evidence names the endpoint, the method, the parameter and the shape of
the proof — a controlled canary was reproducibly retrieved — and nothing else.
It never carries the probe value, the canary's contents, a response body, a
credential or a cookie. Nothing here is CRITICAL, and the wording says what was
observed (a harmless marker returned from outside the intended directory), not
that arbitrary files were read: the detector confirms a *class* of weakness
against a cooperative canary, it does not exfiltrate.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from app.scanner.path_security.types import (
    InclusionMechanism,
    TraversalObservation,
)
from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingData,
    FindingRule,
    FindingSeverity,
)

_CATEGORY = FindingCategory.INPUT_VALIDATION


def subject_for(parameter: str) -> str:
    """Deterministic subject: the parameter name only, never its value."""
    return f"parameter:{parameter}"


def _path_of(url: str) -> str:
    try:
        return urlsplit(url).path or url
    except ValueError:  # pragma: no cover - urlsplit is lenient
        return url


_TRAVERSAL_REMEDIATION = (
    "Resolve file paths against a fixed trusted base directory and canonicalize the "
    "result before use, rejecting any path that escapes the base. Prefer an allow-list "
    "of permitted files or opaque identifiers over passing user input to the filesystem, "
    "and enforce server-side authorization on the resource regardless."
)

_LFI_REMEDIATION = (
    "Never concatenate untrusted input into an include or template path. Map user input "
    "to an allow-list of permitted templates or resources by key, isolate the "
    "template/resource directory, and remove dynamic include behaviour where it is not "
    "genuinely needed."
)


def build_traversal_finding(observation: TraversalObservation) -> FindingData | None:
    """A finding for a reproduced canary retrieval outside the boundary.

    Only a `STRONG` observation reaches a finding, so confidence is HIGH: the
    controlled marker was returned and the behaviour reproduced. Severity is
    HIGH — unauthorized local file access is serious — but never CRITICAL,
    because this is a controlled canary, not demonstrated extraction of real
    data.
    """
    if not observation.reportable:
        return None

    lfi = observation.mechanism is InclusionMechanism.LOCAL_FILE_INCLUSION
    rule = (
        FindingRule.LOCAL_FILE_INCLUSION if lfi else FindingRule.PATH_TRAVERSAL
    )
    title = (
        "Local file inclusion" if lfi else "Path traversal"
    )
    mechanism_sentence = (
        "The application resolved a local file from the parameter's value, including "
        "content from outside the intended resource directory."
        if lfi
        else "The parameter's value escaped the intended directory and the application "
        "returned a file from outside it."
    )

    auth_note = ""
    if observation.authenticated:
        label = observation.context_label or "the configured identity"
        auth_note = (
            f" The endpoint was tested as {label}; the credential itself is not recorded."
        )

    description = (
        f'The "{observation.parameter}" parameter on {observation.method} '
        f"{_path_of(observation.endpoint)} accepted a directory-traversal value that "
        "reproducibly returned a controlled canary file placed outside the intended "
        f"resource directory. {mechanism_sentence} Detection used a harmless marker "
        "file; no real system file was requested, and the file's contents are not "
        f"recorded.{auth_note}"
    )
    evidence = (
        f"{observation.method} {_path_of(observation.endpoint)} — parameter "
        f'"{observation.parameter}". Baseline status '
        f"{observation.baseline_status}, probe status {observation.probe_status}; "
        f"baseline media type {observation.baseline_media_type or 'unknown'}, probe "
        f"media type {observation.probe_media_type or 'unknown'}. The controlled "
        "traversal canary marker was returned and the result reproduced on a repeat "
        "probe. No file contents, probe values or credentials are stored."
    )
    impact = (
        "Attacker-controlled input can select files outside the location the "
        "application intended, exposing files that should not be reachable. This scan "
        "demonstrated the escape with a harmless canary; against a real deployment the "
        "same weakness could reach genuinely sensitive files the process can read."
    )

    return FindingData(
        rule=rule,
        title=title,
        category=_CATEGORY,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        description=description,
        evidence=evidence,
        impact=impact,
        remediation=_LFI_REMEDIATION if lfi else _TRAVERSAL_REMEDIATION,
        subject=subject_for(observation.parameter),
    )
