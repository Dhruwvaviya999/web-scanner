"""Turning session observations into findings.

Two rules govern everything below.

**No values.** Not a session cookie value, not a bearer token, not a JWT or any
segment of one, not a CSRF token, not a hidden field's contents, not an
`Authorization` header. The observations reaching these builders never carried
one, so a finding cannot leak one even by accident. Evidence names a parameter,
a cookie, a claim or a form action, and stops.

**No overclaiming.** Nothing here is CRITICAL. Nothing here says a session was
hijacked, forged, fixed or replayed, because nothing in this phase attempted any
of those. The CSRF finding in particular is written as *this defence was not
observed* rather than *this site is vulnerable*: passive analysis cannot see
origin validation, a header requirement or framework middleware, and a finding
that pretended otherwise would be wrong on most well-built sites.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingData,
    FindingRule,
    FindingSeverity,
)
from app.scanner.session_security.token_analyzer import sensitive_claims, weaknesses
from app.scanner.session_security.types import (
    CsrfObservation,
    CsrfVerdict,
    ExposureLocation,
    JwtObservation,
    ParameterClass,
    SessionCookie,
    TimeoutEvidence,
    TimeoutObservation,
    UrlExposure,
)

_CATEGORY = FindingCategory.SESSION_SECURITY


def _path_of(url: str) -> str:
    try:
        return urlsplit(url).path or url
    except ValueError:  # pragma: no cover - urlsplit is lenient
        return url


# --------------------------------------------------------------------------- #
# Session identifiers in URLs
# --------------------------------------------------------------------------- #


def url_exposure_finding(exposure: UrlExposure) -> FindingData:
    """A session-like identifier travelling in a URL.

    Severity follows what the name says it carries. A parameter called
    `sessionid` is a session handle; one called `token` might be a password
    reset, a pagination cursor under an unfortunate name, or a session — the
    finding grades it lower and says which uncertainty applies.
    """
    session_like = exposure.classification is ParameterClass.SESSION_LIKE
    in_url = exposure.location in (
        ExposureLocation.QUERY_PARAMETER,
        ExposureLocation.PATH_PARAMETER,
        ExposureLocation.LOCATION_HEADER,
    )

    if session_like and in_url:
        rule = FindingRule.SESSION_TOKEN_IN_URL
        severity = FindingSeverity.HIGH
        confidence = FindingConfidence.HIGH
        title = "Session identifier carried in the URL"
    elif session_like:
        rule = FindingRule.SESSION_TOKEN_EXPOSURE
        severity = FindingSeverity.MEDIUM
        confidence = FindingConfidence.MEDIUM
        title = "Session identifier exposed in a response"
    else:
        rule = FindingRule.SESSION_TOKEN_EXPOSURE
        severity = FindingSeverity.MEDIUM
        confidence = FindingConfidence.MEDIUM
        title = "Credential-like parameter carried in the URL"

    where = {
        ExposureLocation.QUERY_PARAMETER: "as a query parameter",
        ExposureLocation.PATH_PARAMETER: "as a path parameter",
        ExposureLocation.LOCATION_HEADER: "in a Location redirect header",
        ExposureLocation.HIDDEN_FIELD: "in a hidden form field",
        ExposureLocation.JSON_FIELD: "as a field in a JSON response",
        ExposureLocation.COOKIE: "in a cookie",
    }[exposure.location]

    description = (
        f'The parameter "{exposure.name}" was observed {where} on '
        f"{_path_of(exposure.url)}. {exposure.detail.capitalize()}. "
        "Only the parameter name was recorded; its value was never read or stored."
    )

    if exposure.classification is ParameterClass.SECURITY_SENSITIVE:
        description += (
            " The name suggests a credential, but this scanner cannot tell a session "
            "handle from a single-use link token without reading the value, which it "
            "does not do."
        )

    return FindingData(
        rule=rule,
        title=title,
        category=_CATEGORY,
        severity=severity,
        confidence=confidence,
        description=description,
        evidence=(
            f'Parameter name "{exposure.name}" seen {where} on {_path_of(exposure.url)}'
            f"{'' if exposure.over_https else ' over plain HTTP'}."
        ),
        impact=(
            "Identifiers in a URL are written to browser history, sent in the Referer "
            "header to any third-party resource the page loads, and recorded in server, "
            "proxy and CDN access logs. Anyone reading those logs, or receiving that "
            "Referer, holds whatever the identifier grants."
        ),
        remediation=(
            "Carry session identifiers in cookies with HttpOnly, Secure and SameSite "
            "set, or in an Authorization header. If a token must appear in a link, make "
            "it single-use and short-lived, and redirect to a clean URL as soon as it "
            "has been consumed."
        ),
        subject=f"{_path_of(exposure.url)}#{exposure.name}",
    )


# --------------------------------------------------------------------------- #
# Session cookie transport
# --------------------------------------------------------------------------- #


def cookie_transport_finding(cookie: SessionCookie) -> FindingData:
    """A session cookie issued by a plain-HTTP response.

    Scoped narrowly on purpose. Phase 3 already reports a session cookie set
    over HTTPS without `Secure`, and it deliberately skips that check on a
    plain-HTTP response because a browser ignores the attribute there. This
    covers exactly the gap that leaves — the cookie crossed the network in the
    clear — and emits nothing for the case Phase 3 already owns.
    """
    return FindingData(
        rule=FindingRule.SESSION_COOKIE_TRANSPORT,
        title="Session cookie issued over an unencrypted connection",
        category=_CATEGORY,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        description=(
            f'The cookie "{cookie.name}" was classified as session state '
            f"({cookie.role.value.lower()}, {cookie.confidence.value.lower()}) and the "
            "response that set it was served over plain HTTP, so the cookie crossed "
            "the network in the clear. The cookie's value was never read."
        ),
        evidence=(
            f'Cookie "{cookie.name}" set on {_path_of(cookie.set_on or "")} — '
            f"secure={cookie.secure}, over_https={cookie.over_https}, "
            f"role={cookie.role.value}."
        ),
        impact=(
            "A session cookie observable on the network is a session anyone on the "
            "path can assume, without needing a password. Public wireless networks and "
            "compromised intermediate hops are the usual place this is collected."
        ),
        remediation=(
            "Serve the whole application over HTTPS, set Secure on every session "
            "cookie, and redirect plain HTTP to HTTPS before any session cookie is "
            "issued. HSTS stops the first request from going out in the clear at all."
        ),
        subject=cookie.name,
    )


# --------------------------------------------------------------------------- #
# CSRF
# --------------------------------------------------------------------------- #


def csrf_finding(observation: CsrfObservation) -> FindingData | None:
    """A CSRF finding, and **only** for a STRONG verdict.

    `POTENTIAL` deliberately produces nothing. The most common reason a form has
    no visible token is that the framework does not need one there, and turning
    every tokenless POST into a finding is how a scanner becomes something people
    stop reading. `STRONG` requires the session cookie to declare
    `SameSite=None`, which is the one signal that rules out the browser's own
    defence — and even then the finding says the defence was *not observed*.
    """
    if observation.verdict is not CsrfVerdict.STRONG:
        return None

    action = observation.action or observation.page_url

    return FindingData(
        rule=FindingRule.SESSION_CSRF_POTENTIAL,
        title="State-changing form with no observable CSRF defence",
        category=_CATEGORY,
        severity=FindingSeverity.MEDIUM,
        # Never HIGH confidence: no forged request was sent, so a server-side
        # defence this scanner cannot see may well be in place.
        confidence=FindingConfidence.MEDIUM,
        description=(
            f"A {observation.method} form on {_path_of(observation.page_url)} submitting "
            f"to {action} carries no hidden anti-CSRF token field, and the session "
            "cookie observed on this target declares SameSite=None — so a browser will "
            "attach it to a request originating from another site. "
            "This is an absence of observable protection, not a demonstrated "
            "vulnerability: no forged request was sent. Origin or Referer validation, a "
            "required custom header, or framework middleware reading a token from a "
            "header would all defeat an attack and are invisible to a passive scan. "
            "Verify by hand before acting on this."
        ),
        evidence=(
            f"{observation.method} {action} — no hidden anti-CSRF token field among "
            f"the form's inputs; session cookie SameSite="
            f"{observation.session_same_site or 'unstated'}. "
            f"Signals: {', '.join(observation.signals)}. "
            "No form was submitted and no field value was recorded."
        ),
        impact=(
            "If no server-side check exists, another site can cause a logged-in user's "
            "browser to perform this action without their knowledge, using their "
            "session. What that is worth depends entirely on what the form does."
        ),
        remediation=(
            "Require a per-session anti-CSRF token on every state-changing request and "
            "reject any request without a valid one. Set SameSite=Lax or Strict on the "
            "session cookie unless a cross-site flow genuinely requires None. Validating "
            "the Origin header on state-changing requests is a cheap second layer."
        ),
        subject=f"{observation.method} {action}",
    )


# --------------------------------------------------------------------------- #
# JWT metadata
# --------------------------------------------------------------------------- #


def jwt_finding(observation: JwtObservation) -> FindingData | None:
    """A weakness a token declares about itself.

    Reads what the token publishes and nothing more. No signature is verified,
    forged or stripped; no token is replayed. `alg: none` is a real problem and
    is graded as one; a missing `exp` is worth saying and is graded as
    informational; a mainstream algorithm is not a finding at all.
    """
    observations = weaknesses(observation.metadata)
    if not observations:
        return None

    unsigned = observation.metadata.unsigned
    sensitive = sensitive_claims(observation.metadata)

    if unsigned:
        severity = FindingSeverity.HIGH
        confidence = FindingConfidence.HIGH
        title = "Token declares no signature algorithm"
    elif sensitive:
        severity = FindingSeverity.MEDIUM
        confidence = FindingConfidence.MEDIUM
        title = "Token carries claim names suggesting sensitive content"
    else:
        severity = FindingSeverity.LOW
        confidence = FindingConfidence.MEDIUM
        title = "Token declares no expiry"

    where = {
        ExposureLocation.COOKIE: f'the cookie "{observation.name}"',
        ExposureLocation.JSON_FIELD: f'the response field "{observation.name}"',
        ExposureLocation.HIDDEN_FIELD: f'the hidden field "{observation.name}"',
        ExposureLocation.QUERY_PARAMETER: f'the query parameter "{observation.name}"',
        ExposureLocation.PATH_PARAMETER: f'the path parameter "{observation.name}"',
        ExposureLocation.LOCATION_HEADER: "a redirect target",
    }.get(observation.location, observation.name)

    return FindingData(
        rule=FindingRule.SESSION_JWT_WEAKNESS,
        title=title,
        category=_CATEGORY,
        severity=severity,
        confidence=confidence,
        description=(
            f"A JSON Web Token observed in {where} on {_path_of(observation.url)} "
            f"{'; '.join(observations)}. Only the token's header and the names of its "
            "claims were read — no claim value, no signature and no part of the token "
            "was stored, and nothing was sent anywhere."
        ),
        evidence=(
            f"Token in {where} — alg={observation.metadata.algorithm or 'unstated'}, "
            f"exp claim present={observation.metadata.has_expiry}, "
            f"claim names: {', '.join(observation.metadata.claim_names) or 'none read'}."
        ),
        impact=(
            "A token declaring alg none asserts that it needs no signature, and any "
            "verifier honouring that will accept a token an attacker wrote. A token "
            "with no expiry remains valid until something else revokes it, so a copy "
            "taken from a log or a browser stays usable indefinitely."
            if unsigned or not observation.metadata.has_expiry
            else "Claims travel in a form anyone holding the token can read; a JWT is "
            "signed, not encrypted."
        ),
        remediation=(
            "Reject alg none and pin the accepted algorithm server-side rather than "
            "trusting the token's own header. Issue short-lived tokens with an exp "
            "claim and refresh them. Keep anything sensitive out of the payload — a JWT "
            "is readable by anyone who holds it."
        ),
        subject=f"{_path_of(observation.url)}#{observation.name}",
    )


# --------------------------------------------------------------------------- #
# Timeout
# --------------------------------------------------------------------------- #


def timeout_finding(observation: TimeoutObservation) -> FindingData | None:
    """That session expiry could not be established.

    Informational, and worded as a gap in what the scan could see. Server-side
    expiry is not observable from outside, so this must never be read as "the
    session never expires" — a claim this phase has no way to support.
    """
    if observation.evidence not in (
        TimeoutEvidence.UNKNOWN,
        TimeoutEvidence.BROWSER_SESSION,
    ):
        return None

    if observation.evidence is TimeoutEvidence.BROWSER_SESSION:
        description = (
            f'The session cookie "{observation.source}" declares no Max-Age and no '
            "Expires, so a browser keeps it until it closes. Whether the server expires "
            "the session independently cannot be observed from outside, so this scan "
            "cannot say how long a session actually lasts."
        )
    else:
        description = (
            "Nothing observed during this scan established when a session expires. No "
            "session cookie declared a lifetime and no token carried an expiry claim. "
            "This is a gap in what a passive scan can see, not evidence that sessions "
            "do not expire."
        )

    return FindingData(
        rule=FindingRule.SESSION_TIMEOUT_UNKNOWN,
        title="Session expiry could not be determined",
        category=_CATEGORY,
        severity=FindingSeverity.INFO,
        confidence=FindingConfidence.LOW,
        description=description,
        evidence=(
            f"Timeout evidence: {observation.evidence.value}"
            + (f' from "{observation.source}"' if observation.source else "")
            + ". No session was held open, expired or re-tested to determine this."
        ),
        impact=(
            "A session that outlives its usefulness widens the window in which a stolen "
            "identifier still works. Whether that applies here is unknown."
        ),
        remediation=(
            "Confirm by hand that the server invalidates sessions after a bounded idle "
            "period and an absolute maximum lifetime, and that logout destroys "
            "server-side state rather than only clearing the cookie."
        ),
        subject=observation.source or "session",
    )


# --------------------------------------------------------------------------- #
# Disclosure
# --------------------------------------------------------------------------- #


def information_disclosure_finding(
    *, url: str, detail: str, subject: str
) -> FindingData:
    """Something session handling revealed that a client did not need."""
    return FindingData(
        rule=FindingRule.SESSION_INFORMATION_DISCLOSURE,
        title="Session handling revealed implementation detail",
        category=_CATEGORY,
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.MEDIUM,
        description=(
            f"{detail} This was observed on {_path_of(url)}. It is not a vulnerability "
            "on its own; it narrows the guesswork for someone looking for one."
        ),
        evidence=f"{subject} observed on {_path_of(url)}. No value was recorded.",
        impact=(
            "Knowing the session technology tells an attacker which default "
            "configurations, known weaknesses and identifier formats to try first."
        ),
        remediation=(
            "Rename framework-default session cookies and suppress headers that name "
            "the session implementation. This is defence in depth, not a fix on its own."
        ),
        subject=subject,
    )
