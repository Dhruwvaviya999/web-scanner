"""Security-header analysis.

Pure functions over headers the scanner already collected — no network access,
no database. Every rule here is a *configuration observation*, not a confirmed
vulnerability, and the wording of each finding is deliberately measured: a
missing header means a defence-in-depth control is absent, not that the site is
exploitable.

Two rules keep the output honest rather than merely long:

* HSTS is only meaningful over HTTPS, so it is not reported for an HTTP target.
* Headers that govern how a *document* is rendered (CSP, X-Frame-Options,
  Referrer-Policy, Permissions-Policy) are only checked when the response is
  actually a document. Reporting a missing CSP on a JSON API endpoint is noise.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingData,
    FindingRule,
    FindingSeverity,
)

#: Below this, an HSTS policy is too short-lived to protect a returning visitor.
#: 180 days is the floor commonly required for preload eligibility.
MIN_HSTS_MAX_AGE_SECONDS = 15_552_000

_MAX_AGE_RE = re.compile(r"max-age\s*=\s*\"?(\d+)\"?", re.IGNORECASE)

#: Directives that neutralise much of a policy's value if used broadly.
_PERMISSIVE_CSP_MARKERS = ("'unsafe-inline'", "'unsafe-eval'")

_VALID_FRAME_OPTIONS = frozenset({"deny", "sameorigin"})

_HTML_MEDIA_TYPES = frozenset({"text/html", "application/xhtml+xml"})


def _header(headers: Mapping[str, str], name: str) -> str | None:
    """Case-insensitive lookup that treats a blank header as absent."""
    for key, value in headers.items():
        if key.lower() == name:
            stripped = value.strip()
            return stripped or None
    return None


def _is_document_response(content_type: str | None) -> bool:
    """True when document-scoped headers are worth checking.

    A response with no `Content-Type` at all is treated as a document, so that a
    misconfigured server is not silently exempted from these checks.
    """
    if not content_type:
        return True
    return content_type.split(";", 1)[0].strip().lower() in _HTML_MEDIA_TYPES


def analyze_security_headers(
    headers: Mapping[str, str],
    *,
    is_https: bool,
    content_type: str | None = None,
) -> list[FindingData]:
    """Return every header observation for one response.

    `is_https` refers to the *final* URL, so a target that redirects to HTTPS is
    judged on where it ended up.
    """
    findings: list[FindingData] = []
    document = _is_document_response(content_type)

    findings.extend(_check_hsts(headers, is_https=is_https))
    findings.extend(_check_content_type_options(headers))

    if document:
        csp = _header(headers, "content-security-policy")
        findings.extend(_check_csp(csp))
        findings.extend(_check_frame_options(headers, csp=csp))
        findings.extend(_check_referrer_policy(headers))
        findings.extend(_check_permissions_policy(headers))

    return findings


# --------------------------------------------------------------------------- #
# Individual rules
# --------------------------------------------------------------------------- #


def _check_hsts(headers: Mapping[str, str], *, is_https: bool) -> list[FindingData]:
    """HTTP Strict-Transport-Security.

    Only assessed for HTTPS responses. Browsers ignore the header when it
    arrives over plain HTTP, so reporting it as missing on an HTTP target would
    be a false positive.
    """
    if not is_https:
        return []

    value = _header(headers, "strict-transport-security")

    if value is None:
        return [
            FindingData(
                rule=FindingRule.SECURITY_HEADER_HSTS_MISSING,
                title="Strict-Transport-Security header not set",
                category=FindingCategory.SECURITY_HEADER,
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.HIGH,
                description=(
                    "This site is served over HTTPS but does not send a "
                    "Strict-Transport-Security (HSTS) header. HSTS instructs browsers to "
                    "use HTTPS for future visits automatically, without first trying an "
                    "insecure connection."
                ),
                evidence="No Strict-Transport-Security header was present in the response.",
                impact=(
                    "A visitor who reaches the site over HTTP — by typing the domain, or "
                    "by following an http:// link — can have that first request "
                    "intercepted before the redirect to HTTPS takes effect. This requires "
                    "an attacker positioned on the network path."
                ),
                remediation=(
                    "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
                    "on HTTPS responses. Roll the max-age out gradually, and confirm every "
                    "subdomain supports HTTPS before adding includeSubDomains."
                ),
            )
        ]

    match = _MAX_AGE_RE.search(value)
    max_age = int(match.group(1)) if match else None

    if max_age == 0:
        return [
            FindingData(
                rule=FindingRule.SECURITY_HEADER_HSTS_DISABLED,
                title="Strict-Transport-Security is disabled by max-age=0",
                category=FindingCategory.SECURITY_HEADER,
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.HIGH,
                description=(
                    "The HSTS header is present but sets max-age=0, which tells browsers "
                    "to forget any existing HSTS policy for this host."
                ),
                evidence=f"Strict-Transport-Security: {value}",
                impact=(
                    "The protection HSTS would provide is switched off. This is sometimes "
                    "intentional while rolling the policy back."
                ),
                remediation=(
                    "Set a non-zero max-age once the site is committed to HTTPS, for "
                    "example max-age=31536000."
                ),
            )
        ]

    if max_age is not None and max_age < MIN_HSTS_MAX_AGE_SECONDS:
        return [
            FindingData(
                rule=FindingRule.SECURITY_HEADER_HSTS_SHORT_MAX_AGE,
                title="Strict-Transport-Security max-age is short",
                category=FindingCategory.SECURITY_HEADER,
                severity=FindingSeverity.INFO,
                confidence=FindingConfidence.HIGH,
                description=(
                    f"HSTS is enabled with max-age={max_age} seconds, which is below the "
                    f"{MIN_HSTS_MAX_AGE_SECONDS}-second (180-day) value generally "
                    "recommended once a deployment is stable."
                ),
                evidence=f"Strict-Transport-Security: {value}",
                impact=(
                    "The policy expires sooner, so a returning visitor is protected for a "
                    "shorter window. A short max-age is normal during initial rollout."
                ),
                remediation=(
                    "Once HTTPS is known to be stable across the site, raise max-age to "
                    "31536000 (one year)."
                ),
            )
        ]

    return []


def _check_csp(csp: str | None) -> list[FindingData]:
    """Content-Security-Policy presence, plus a deliberately shallow value check.

    No CSP parser is attempted here. The only value-level judgement is whether
    the policy contains directives that are widely understood to weaken it, and
    that is reported at INFO because a policy using them is still better than no
    policy at all.
    """
    if csp is None:
        return [
            FindingData(
                rule=FindingRule.SECURITY_HEADER_CSP_MISSING,
                title="Content-Security-Policy header not set",
                category=FindingCategory.SECURITY_HEADER,
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.HIGH,
                description=(
                    "The response does not define a Content-Security-Policy. CSP tells the "
                    "browser which sources of script, style and other content are allowed "
                    "to load, and is the main defence-in-depth control against cross-site "
                    "scripting."
                ),
                evidence="No Content-Security-Policy header was present in the response.",
                impact=(
                    "If a cross-site scripting flaw exists elsewhere in the application, "
                    "there is no policy to limit what injected script can do. This finding "
                    "does not itself mean such a flaw is present — no injection testing was "
                    "performed."
                ),
                remediation=(
                    "Define a policy starting from a restrictive base such as "
                    "\"default-src 'self'\", then widen it only for the origins the site "
                    "genuinely needs. Deploy with Content-Security-Policy-Report-Only "
                    "first to find breakage."
                ),
            )
        ]

    lowered = csp.lower()
    markers = [m for m in _PERMISSIVE_CSP_MARKERS if m in lowered]
    if re.search(r"default-src\s+[^;]*\*", lowered):
        markers.append("wildcard default-src")

    if markers:
        return [
            FindingData(
                rule=FindingRule.SECURITY_HEADER_CSP_PERMISSIVE,
                title="Content-Security-Policy contains permissive directives",
                category=FindingCategory.SECURITY_HEADER,
                severity=FindingSeverity.INFO,
                confidence=FindingConfidence.MEDIUM,
                description=(
                    "A Content-Security-Policy is set, which is good, but it includes "
                    f"directives that reduce its effectiveness: {', '.join(markers)}. "
                    "This scan does not evaluate the policy in full — only these specific "
                    "markers were looked for."
                ),
                evidence=f"Content-Security-Policy: {csp[:400]}",
                impact=(
                    "Permissive directives such as 'unsafe-inline' allow inline script to "
                    "execute, which is the main behaviour CSP is intended to block. The "
                    "policy still constrains other content sources."
                ),
                remediation=(
                    "Replace 'unsafe-inline' with per-request nonces or hashes for the "
                    "scripts and styles that need them, and narrow any wildcard sources."
                ),
            )
        ]

    return []


def _check_content_type_options(headers: Mapping[str, str]) -> list[FindingData]:
    """X-Content-Type-Options: nosniff."""
    value = _header(headers, "x-content-type-options")

    if value is not None and value.strip().lower() == "nosniff":
        return []

    if value is None:
        evidence = "No X-Content-Type-Options header was present in the response."
        description = (
            "The response does not send 'X-Content-Type-Options: nosniff'. Without it, "
            "browsers may ignore the declared Content-Type and guess at the type of a "
            "response based on its bytes."
        )
    else:
        evidence = f"X-Content-Type-Options: {value}"
        description = (
            "The X-Content-Type-Options header is present but its value is not "
            "'nosniff', which is the only value browsers act on."
        )

    return [
        FindingData(
            rule=FindingRule.SECURITY_HEADER_X_CONTENT_TYPE_OPTIONS_MISSING,
            title="X-Content-Type-Options is not set to nosniff",
            category=FindingCategory.SECURITY_HEADER,
            severity=FindingSeverity.LOW,
            confidence=FindingConfidence.HIGH,
            description=description,
            evidence=evidence,
            impact=(
                "A response that a user can influence — an uploaded file, for example — "
                "could be interpreted as a different content type than intended, such as "
                "HTML or script."
            ),
            remediation="Send 'X-Content-Type-Options: nosniff' on all responses.",
        )
    ]


def _check_frame_options(headers: Mapping[str, str], *, csp: str | None) -> list[FindingData]:
    """X-Frame-Options, unless CSP frame-ancestors already covers framing.

    `frame-ancestors` supersedes X-Frame-Options in every browser that supports
    CSP, so a site using it is not missing a control and is not reported.
    """
    if csp and "frame-ancestors" in csp.lower():
        return []

    value = _header(headers, "x-frame-options")

    if value is not None and value.strip().lower() in _VALID_FRAME_OPTIONS:
        return []

    if value is None:
        evidence = "No X-Frame-Options header and no CSP frame-ancestors directive was present."
        description = (
            "Nothing in the response restricts which sites may embed this page in a "
            "frame — neither an X-Frame-Options header nor a CSP frame-ancestors "
            "directive."
        )
    else:
        evidence = f"X-Frame-Options: {value}"
        description = (
            "X-Frame-Options is present but its value is not one browsers honour. "
            "Only DENY and SAMEORIGIN are supported; ALLOW-FROM was removed."
        )

    return [
        FindingData(
            rule=FindingRule.SECURITY_HEADER_X_FRAME_OPTIONS_MISSING,
            title="Framing is not restricted",
            category=FindingCategory.SECURITY_HEADER,
            severity=FindingSeverity.LOW,
            confidence=FindingConfidence.HIGH,
            description=description,
            evidence=evidence,
            impact=(
                "The page can be embedded by another site and overlaid with content the "
                "user cannot see, so a click can be redirected to an action they did not "
                "intend (clickjacking). Pages with no state-changing actions are at "
                "little practical risk."
            ),
            remediation=(
                "Send 'X-Frame-Options: DENY' — or SAMEORIGIN if the page is framed by "
                "your own site — and add a CSP 'frame-ancestors' directive, which "
                "supersedes it in modern browsers."
            ),
        )
    ]


def _check_referrer_policy(headers: Mapping[str, str]) -> list[FindingData]:
    if _header(headers, "referrer-policy") is not None:
        return []

    return [
        FindingData(
            rule=FindingRule.SECURITY_HEADER_REFERRER_POLICY_MISSING,
            title="Referrer-Policy header not set",
            category=FindingCategory.SECURITY_HEADER,
            severity=FindingSeverity.LOW,
            confidence=FindingConfidence.HIGH,
            description=(
                "No Referrer-Policy is declared, so the browser falls back to its default. "
                "Modern browsers default to strict-origin-when-cross-origin, but that is "
                "not guaranteed across all clients."
            ),
            evidence="No Referrer-Policy header was present in the response.",
            impact=(
                "Full URLs may be sent to third-party sites in the Referer header. Where "
                "URLs contain identifiers, tokens or search terms, that information leaves "
                "the origin."
            ),
            remediation=(
                "Send 'Referrer-Policy: strict-origin-when-cross-origin', or "
                "'no-referrer' for pages whose URLs are sensitive."
            ),
        )
    ]


def _check_permissions_policy(headers: Mapping[str, str]) -> list[FindingData]:
    if _header(headers, "permissions-policy") is not None:
        return []

    return [
        FindingData(
            rule=FindingRule.SECURITY_HEADER_PERMISSIONS_POLICY_MISSING,
            title="Permissions-Policy header not set",
            category=FindingCategory.SECURITY_HEADER,
            severity=FindingSeverity.INFO,
            confidence=FindingConfidence.HIGH,
            description=(
                "No Permissions-Policy is declared. This header lets a site switch off "
                "browser features it does not use — camera, microphone, geolocation and "
                "similar — for itself and for any content it embeds."
            ),
            evidence="No Permissions-Policy header was present in the response.",
            impact=(
                "Embedded third-party content may request powerful browser features that "
                "the site itself never needs. This is a hardening opportunity rather than "
                "a weakness."
            ),
            remediation=(
                "Send a policy disabling unused features, for example "
                "'Permissions-Policy: camera=(), microphone=(), geolocation=()'."
            ),
        )
    ]
