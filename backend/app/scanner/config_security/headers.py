"""Security headers that are present but wrong, and CSP quality.

Phase 3 asks whether each security header is *there*. This asks whether the one
that is there actually works. Those are different questions, and keeping them
apart is what stops the two phases reporting one defect twice.

**The CSP boundary, precisely.** Phase 3 emits `SECURITY_HEADER_CSP_MISSING`
when there is no policy, and `SECURITY_HEADER_CSP_PERMISSIVE` at INFO when the
policy contains `'unsafe-inline'`, `'unsafe-eval'` or a wildcard `default-src`.
This module grades a different axis — whether script may be loaded *from
anywhere* — and emits a finding only for `UNRESTRICTED`:

* a wildcard or scheme source (`*`, `https:`, `data:`, `blob:`) in the
  effective script source, which Phase 3 does not check for on `script-src`;
* no script restriction at all because `default-src` is itself wildcarded.

`'unsafe-inline'` on its own returns `WEAKENED` and produces **nothing here**,
because Phase 3 has already said it. The grade is still recorded, so the report
can show the correlation without duplicating the finding.

There is one more thing worth grading that neither phase reports today: a nonce
or hash source makes `'unsafe-inline'` inert in every modern browser. A policy
Phase 3 flags as permissive may in fact be strong, and `CspGrade.NONCE_OR_HASH`
is how a reader finds that out.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence

from app.scanner.config_security.types import (
    CspGrade,
    CspObservation,
    HeaderDefect,
    HeaderDefectObservation,
)

#: Sources that place no meaningful restriction on where script comes from.
#: `https:` is included deliberately: it permits every host on the internet
#: that speaks TLS, which is not a restriction.
_WILDCARD_SOURCES = frozenset({"*", "https:", "http:", "data:", "blob:", "filesystem:"})

_NONCE = re.compile(r"'nonce-[^']+'", re.IGNORECASE)
_HASH = re.compile(r"'sha(?:256|384|512)-[^']+'", re.IGNORECASE)

#: Headers this module will read a value from. Vetted, as in `deployment`: none
#: of these can carry a credential.
_INSPECTABLE = frozenset(
    {
        "content-security-policy",
        "content-security-policy-report-only",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "strict-transport-security",
        "x-xss-protection",
        "permissions-policy",
        "feature-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
    }
)

#: Headers browsers no longer honour, or that were replaced. Reporting one is
#: low-value on its own; `X-XSS-Protection` is the exception, because a stale
#: `1; mode=block` was itself exploitable and Chrome removed the feature.
_DEPRECATED = {
    "x-xss-protection": "browsers removed the XSS auditor this header controlled",
    "feature-policy": "replaced by Permissions-Policy",
    "public-key-pins": "HPKP was removed from browsers after causing outages",
    "expect-ct": "obsolete since Certificate Transparency became mandatory",
}

#: Values that are structurally invalid for the header carrying them.
_VALID_VALUES: dict[str, frozenset[str]] = {
    "x-frame-options": frozenset({"deny", "sameorigin"}),
    "x-content-type-options": frozenset({"nosniff"}),
}

_MAX_VALUE = 300


def _values(headers: Mapping[str, str], name: str) -> list[str]:
    """Every value for a header name.

    A plain mapping collapses repeats, so this also splits a comma-joined value
    for the headers where a comma cannot legally appear inside one policy —
    which is how a duplicated header usually reaches us.
    """
    found: list[str] = []
    for key, value in headers.items():
        if key.lower() != name:
            continue
        if name in ("x-frame-options", "x-content-type-options") and "," in value:
            found.extend(part.strip() for part in value.split(",") if part.strip())
        else:
            found.append(value.strip())
    return [v for v in found if v]


def parse_directives(policy: str) -> dict[str, tuple[str, ...]]:
    """A CSP into `{directive: sources}`. Lowercased names, original sources."""
    directives: dict[str, tuple[str, ...]] = {}
    for segment in policy.split(";"):
        parts = segment.strip().split()
        if not parts:
            continue
        directives.setdefault(parts[0].lower(), tuple(parts[1:]))
    return directives


def effective_script_sources(directives: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    """What actually governs script: `script-src`, else `default-src`.

    CSP's fallback chain matters here. A policy with `default-src *` and no
    `script-src` permits script from anywhere, and reading only `script-src`
    would miss it entirely.
    """
    for directive in ("script-src-elem", "script-src", "default-src"):
        if directive in directives:
            return directives[directive]
    return ()


def analyze_csp(url: str, headers: Mapping[str, str]) -> CspObservation:
    """Grade a policy on the axis Phase 3 does not examine."""
    policies = _values(headers, "content-security-policy")

    if not policies:
        return CspObservation(
            url=url,
            grade=CspGrade.ABSENT,
            detail="no Content-Security-Policy was sent; Phase 3 reports this",
        )

    policy = policies[0]
    directives = parse_directives(policy)
    sources = effective_script_sources(directives)
    lowered = [source.lower() for source in sources]

    has_nonce = bool(_NONCE.search(policy))
    has_hash = bool(_HASH.search(policy))
    unsafe_inline = "'unsafe-inline'" in lowered
    unsafe_eval = "'unsafe-eval'" in lowered
    wildcards = tuple(source for source in lowered if source in _WILDCARD_SOURCES)

    if wildcards or not sources:
        grade = CspGrade.UNRESTRICTED
    elif has_nonce or has_hash:
        # A nonce or hash makes 'unsafe-inline' inert in every modern browser,
        # so this policy is stronger than Phase 3's marker check suggests.
        grade = CspGrade.NONCE_OR_HASH
    elif unsafe_inline or unsafe_eval:
        grade = CspGrade.WEAKENED
    else:
        grade = CspGrade.RESTRICTED

    return CspObservation(
        url=url,
        grade=grade,
        wildcard_sources=tuple(dict.fromkeys(wildcards)),
        has_nonce=has_nonce,
        has_hash=has_hash,
        has_unsafe_inline=unsafe_inline,
        has_unsafe_eval=unsafe_eval,
        duplicated=len(policies) > 1,
        detail=_csp_detail(grade, wildcards, has_nonce or has_hash),
    )


def _csp_detail(grade: CspGrade, wildcards: Sequence[str], keyed: bool) -> str:
    if grade is CspGrade.UNRESTRICTED:
        if wildcards:
            return (
                f"script may load from {', '.join(sorted(set(wildcards)))}, which places "
                "no meaningful restriction on its origin"
            )
        return "the policy names no source that governs script execution"
    if grade is CspGrade.NONCE_OR_HASH:
        return (
            "script sources are keyed by nonce or hash, which is the strong form and "
            "makes any 'unsafe-inline' in the same policy inert"
        )
    if grade is CspGrade.WEAKENED:
        return "the policy allows inline or evaluated script; Phase 3 reports this"
    if grade is CspGrade.RESTRICTED:
        return "script sources are named and bounded"
    return "no policy was sent"


def analyze_header_defects(
    url: str, headers: Mapping[str, str]
) -> tuple[HeaderDefectObservation, ...]:
    """Security headers that are present but structurally broken.

    Absence is Phase 3's subject and is never reported here. What this finds is
    a header that exists and does not do its job: two of them disagreeing, one
    with an empty value, one a browser stopped honouring.
    """
    found: list[HeaderDefectObservation] = []

    for name in _INSPECTABLE:
        values = _values(headers, name)

        if len(values) > 1 and len(set(v.lower() for v in values)) > 1:
            found.append(
                HeaderDefectObservation(
                    url=url,
                    header=name,
                    defect=HeaderDefect.DUPLICATE_CONFLICTING,
                    value=", ".join(values)[:_MAX_VALUE],
                    detail=(
                        "the response carries this header more than once with different "
                        "values; browsers resolve the conflict in ways that differ by "
                        "header and are rarely what was intended"
                    ),
                )
            )

        if name in _VALID_VALUES and values:
            allowed = _VALID_VALUES[name]
            invalid = [v for v in values if v.split(";")[0].strip().lower() not in allowed]
            if invalid:
                found.append(
                    HeaderDefectObservation(
                        url=url,
                        header=name,
                        defect=HeaderDefect.INVALID_VALUE,
                        value=invalid[0][:_MAX_VALUE],
                        detail=(
                            "the value is not one this header accepts, so browsers "
                            "ignore the header entirely"
                        ),
                    )
                )

    # Empty values are checked against the raw mapping, since `_values` drops
    # them — the whole point is that the header is there and says nothing.
    for key, raw in headers.items():
        name = key.lower()
        if name in _INSPECTABLE and not (raw or "").strip():
            found.append(
                HeaderDefectObservation(
                    url=url,
                    header=name,
                    defect=HeaderDefect.EMPTY_VALUE,
                    detail=(
                        "the header is present with no value, which protects nothing "
                        "while looking as though something was configured"
                    ),
                )
            )

    for name, reason in _DEPRECATED.items():
        if _values(headers, name):
            found.append(
                HeaderDefectObservation(
                    url=url,
                    header=name,
                    defect=HeaderDefect.DEPRECATED,
                    value=_values(headers, name)[0][:_MAX_VALUE],
                    detail=reason,
                )
            )

    return tuple(found)


def merge_defects(
    observations: Iterable[HeaderDefectObservation],
) -> tuple[HeaderDefectObservation, ...]:
    """One row per header-and-defect pair, whichever URL it was first seen on."""
    best: dict[tuple[str, str], HeaderDefectObservation] = {}
    for observation in observations:
        best.setdefault((observation.header, observation.defect.value), observation)
    return tuple(best.values())
