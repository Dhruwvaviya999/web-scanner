"""Turning API security observations into findings.

Every builder takes an observation and nothing else, which is what keeps a
response value out of a finding by construction: the observations already
carry only names, counts, categories and header values that were vetted as safe.

Severity is set from the evidence rather than from the rule. The same rule spans
"an anonymous request was handed a password hash" and "an authenticated client
received a field a policy says it should not" — the first is worse, and the
finding says so. Confidence carries what is left of the uncertainty.

No finding in this phase is CRITICAL. The scanner observes structure; it does
not confirm exploitability, and reserving the top grade for something it never
establishes would be dishonest.
"""

from __future__ import annotations

from app.scanner.api_security.types import (
    CorsObservation,
    CorsVerdict,
    DisclosureObservation,
    ErrorObservation,
    FieldCategory,
    FieldSensitivity,
    InventoryObservation,
    PropertyComparison,
    SensitiveFieldObservation,
)
from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingData,
    FindingRule,
    FindingSeverity,
)

_CATEGORY = FindingCategory.API_SECURITY


def _path_of(url: str) -> str:
    from urllib.parse import urlsplit

    try:
        return urlsplit(url).path or url
    except ValueError:  # pragma: no cover - urlsplit is lenient
        return url


# --------------------------------------------------------------------------- #
# Sensitive data exposure
# --------------------------------------------------------------------------- #


def sensitive_data_finding(observation: SensitiveFieldObservation) -> FindingData:
    """A sensitive field returned where it should not have been.

    The evidence names the field and says nothing about what was in it. That is
    the whole discipline of this phase: reporting `password_hash` was present is
    useful, and reporting its value would make the report the leak.
    """
    field = observation.field
    highly = field.sensitivity is FieldSensitivity.HIGHLY_SENSITIVE
    never_legitimate = field.category in (
        FieldCategory.AUTHENTICATION,
        FieldCategory.CRYPTOGRAPHIC,
    )

    if never_legitimate or (highly and observation.anonymous):
        severity = FindingSeverity.HIGH
        confidence = FindingConfidence.HIGH
    elif highly:
        severity = FindingSeverity.HIGH
        confidence = FindingConfidence.MEDIUM
    else:
        severity = FindingSeverity.MEDIUM
        confidence = FindingConfidence.MEDIUM

    who = (
        "an unauthenticated request"
        if observation.anonymous
        else f"the identity {observation.context_label!r}"
    )

    return FindingData(
        rule=FindingRule.API_SENSITIVE_DATA_EXPOSURE,
        title="Sensitive field exposed in an API response",
        category=_CATEGORY,
        severity=severity,
        confidence=confidence,
        description=(
            f"The JSON response from {observation.method} {_path_of(observation.url)} "
            f"contained a field named {field.name!r}, which is "
            f"{field.sensitivity.value.replace('_', ' ').lower()} material of the "
            f"{field.category.value.lower()} kind, and it was returned to {who}. "
            "The scanner read the response structure only; the value in that field "
            "was never recorded."
        ),
        evidence=(
            f"field {field.name!r}; category {field.category.value}; "
            f"sensitivity {field.sensitivity.value}; context "
            f"{observation.context_label!r}; status {observation.status_code}; "
            f"{observation.detail}"
        ),
        impact=(
            "Secret material returned to a client is disclosed to anyone who can "
            "make that request, and to anything that logs, caches or proxies the "
            "response. Where the field is authentication or key material, the "
            "disclosure is equivalent to handing over the credential itself."
            if never_legitimate or highly
            else "Personal or business-sensitive data is reaching a client that may "
            "not need it, widening the blast radius of any account compromise or "
            "logging mistake."
        ),
        remediation=(
            "Return only the fields the client actually needs, using an explicit "
            "response schema or serializer rather than serialising the backend "
            "object. Remove authentication and key material from responses "
            "entirely — no client requires it. Where a field is needed by some "
            "callers and not others, enforce that at the property level on the "
            "server, not by filtering in the client."
        ),
        # Endpoint, context and field together: two sensitive fields on one
        # endpoint stay separate findings, because they are separate defects.
        subject=f"{observation.context_id}:{_path_of(observation.url)}:{field.name}",
    )


def property_authorization_finding(comparison: PropertyComparison) -> FindingData:
    """A context received properties another identity did not, and should not have."""
    names = ", ".join(sorted(f.name for f in comparison.extra_fields))
    worst = max(
        comparison.extra_fields,
        key=lambda f: f.sensitivity is FieldSensitivity.HIGHLY_SENSITIVE,
    )
    highly = worst.sensitivity is FieldSensitivity.HIGHLY_SENSITIVE

    return FindingData(
        rule=FindingRule.API_PROPERTY_AUTHORIZATION,
        title="Sensitive properties returned to an identity that should not receive them",
        category=_CATEGORY,
        severity=FindingSeverity.HIGH if highly else FindingSeverity.MEDIUM,
        confidence=FindingConfidence.HIGH if highly else FindingConfidence.MEDIUM,
        description=(
            f"For {_path_of(comparison.url)}, the identity "
            f"{comparison.subject_context_label!r} received fields that "
            f"{comparison.reference_context_id!r} did not: {names}. "
            f"{comparison.detail}. Only field names were compared; no value from "
            "either response was read into this finding."
        ),
        evidence=(
            f"extra fields {names}; subject {comparison.subject_context_label!r}; "
            f"reference {comparison.reference_context_id!r}; {comparison.detail}"
        ),
        impact=(
            "Access control was applied to the resource but not to its properties, "
            "so an identity that is allowed to read an object is also reading parts "
            "of it that belong to someone else or to the system."
        ),
        remediation=(
            "Apply authorization at the property level as well as the resource "
            "level: decide per field, on the server, which caller may see it. An "
            "explicit response schema per role is more reliable than removing "
            "fields conditionally from one shared serializer."
        ),
        subject=f"{comparison.subject_context_id}:{_path_of(comparison.url)}",
    )


# --------------------------------------------------------------------------- #
# Verbose errors
# --------------------------------------------------------------------------- #


def verbose_error_finding(observation: ErrorObservation) -> FindingData:
    """An error response that carried developer diagnostics.

    The evidence lists which *categories* of diagnostic were present. It does
    not quote the stack trace, the query or the path, because a finding that
    reproduced them would republish the disclosure it is reporting.
    """
    signals = ", ".join(signal.value for signal in observation.signals)

    return FindingData(
        rule=FindingRule.API_VERBOSE_ERROR,
        title="API error response exposed internal diagnostics",
        category=_CATEGORY,
        severity=FindingSeverity.MEDIUM if observation.strong else FindingSeverity.LOW,
        confidence=(
            FindingConfidence.HIGH if observation.strong else FindingConfidence.MEDIUM
        ),
        description=(
            f"The {observation.status_code} response from {observation.method} "
            f"{_path_of(observation.url)} contained diagnostic material intended for "
            f"a developer rather than a client: {signals}. The scanner recorded which "
            "kinds of detail were present and deliberately kept none of the text."
        ),
        evidence=(
            f"status {observation.status_code}; "
            f"{observation.content_type or 'no content type'}; "
            f"{observation.body_length} bytes; signals {signals}"
        ),
        impact=(
            "Diagnostic output tells an attacker which framework, database and "
            "file layout the service uses, and often names internal hosts or "
            "queries. That converts guesswork into targeted work, and occasionally "
            "discloses secrets outright."
        ),
        remediation=(
            "Turn debug mode off in anything reachable by a client, and return a "
            "generic error body with a correlation id. Keep the stack trace, the "
            "query and the paths in server-side logs where they are useful and not "
            "public."
        ),
        subject=f"{observation.method}:{_path_of(observation.url)}",
    )


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

_CORS_SEVERITY = {
    CorsVerdict.WILDCARD_WITH_CREDENTIALS: FindingSeverity.MEDIUM,
    CorsVerdict.NULL_ORIGIN_ALLOWED: FindingSeverity.MEDIUM,
    CorsVerdict.REFLECTED_WITH_CREDENTIALS: FindingSeverity.MEDIUM,
    CorsVerdict.CREDENTIALED_WITHOUT_VARY: FindingSeverity.LOW,
}


def cors_finding(observation: CorsObservation) -> FindingData:
    """An unsafe cross-origin policy, read from headers already received."""
    return FindingData(
        rule=FindingRule.API_CORS_MISCONFIGURATION,
        title="Unsafe cross-origin resource sharing configuration",
        category=_CATEGORY,
        severity=_CORS_SEVERITY.get(observation.verdict, FindingSeverity.LOW),
        confidence=FindingConfidence.HIGH,
        description=(
            f"{_path_of(observation.url)} returned "
            f"Access-Control-Allow-Origin: {observation.allow_origin} with "
            f"Access-Control-Allow-Credentials: "
            f"{'true' if observation.allow_credentials else 'false'}. "
            f"{observation.detail}. This was read from headers the scan already "
            "received; no cross-origin request was made to test it."
        ),
        evidence=(
            f"Access-Control-Allow-Origin: {observation.allow_origin}; "
            f"credentials {observation.allow_credentials}; "
            f"Vary on Origin: {observation.vary_origin}; {observation.verdict.value}"
        ),
        impact=(
            "A permissive cross-origin policy combined with credentials lets a page "
            "on another site read authenticated responses using a visitor's own "
            "session, turning any cross-site link into a data-read primitive."
        ),
        remediation=(
            "Name the origins you trust explicitly rather than reflecting or "
            "wildcarding them, and only send Access-Control-Allow-Credentials where "
            "a credentialed cross-origin call is genuinely required. Add "
            "Vary: Origin so a shared cache cannot serve one origin's response to "
            "another."
        ),
        subject=_path_of(observation.url),
    )


def disclosure_finding(observation: DisclosureObservation) -> FindingData:
    """A header naming internal software, a version, or live diagnostics."""
    return FindingData(
        rule=FindingRule.API_INFORMATION_DISCLOSURE,
        title="API response header disclosed internal detail",
        category=_CATEGORY,
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.HIGH,
        description=(
            f"The response from {_path_of(observation.url)} carried the header "
            f"{observation.header}: {observation.value}. {observation.detail}."
        ),
        evidence=f"{observation.header}: {observation.value}",
        impact=(
            "Naming the software and its version tells an attacker which known "
            "vulnerabilities to try first. It is not a weakness on its own; it "
            "removes the reconnaissance step from someone else's work."
        ),
        remediation=(
            "Suppress version detail in server and framework banners, and remove "
            "diagnostic headers from anything a client can reach."
        ),
        subject=f"{_path_of(observation.url)}:{observation.header.lower()}",
    )


def inventory_finding(observation: InventoryObservation) -> FindingData:
    """An inventory observation. Informational by design.

    Several API versions being live is what a migration looks like from outside,
    and a specification that has drifted from the service is a process problem
    rather than a demonstrated weakness. It is reported because knowing which
    surfaces are live is genuinely useful — and at INFO, because the scanner has
    no evidence that any of it is exploitable.
    """
    return FindingData(
        rule=FindingRule.API_LEGACY_VERSION,
        title="API inventory observation",
        category=_CATEGORY,
        severity=FindingSeverity.INFO,
        confidence=FindingConfidence.MEDIUM,
        description=(
            f"{observation.detail} Affected paths: "
            f"{', '.join(observation.paths) if observation.paths else 'n/a'}."
        ),
        evidence=(
            f"{observation.kind}; "
            f"versions {', '.join(observation.versions) if observation.versions else 'n/a'}; "
            f"{len(observation.paths)} paths"
        ),
        impact=(
            "Surfaces nobody is tracking do not get the review, the rate limiting "
            "or the patching the current one does. An older version left reachable "
            "is a common way for a fixed vulnerability to remain exploitable."
        ),
        remediation=(
            "Keep an inventory of which API versions are live and intended, retire "
            "the ones that are neither, and keep the published specification in "
            "step with what the service actually serves."
        ),
        subject=observation.kind,
    )
