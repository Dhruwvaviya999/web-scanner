"""Conservative CSRF analysis.

The central problem: **a missing CSRF token is not a missing CSRF defence.** A
form with no hidden token may be protected by `Origin`/`Referer` validation,
a required custom header, framework middleware that reads a token from a header
rather than a field, double-submit cookies, or — most often — the browser's own
`SameSite=Lax` default, which stops a cross-site POST from carrying the session
cookie at all.

None of those are visible from the outside without submitting a forged request,
which this scanner does not do. So this module correlates the signals it *can*
see and reports one of four verdicts:

* ``NONE``      — a token field is present, or the form cannot change state.
* ``UNKNOWN``   — the evidence runs out. The honest default.
* ``POTENTIAL`` — state-changing, no visible token, a session cookie exists.
                  Worth a look; not a vulnerability claim.
* ``STRONG``    — all of the above *and* the session cookie declares
                  ``SameSite=None``, which rules out the browser's own defence.

Only ``STRONG`` becomes a vulnerability finding, and even that is reported as a
weakness to verify rather than a confirmed exploit. Nothing here submits a form.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from urllib.parse import urljoin, urlsplit

from app.scanner.crawler.types import DiscoveredForm, DiscoveredFormField
from app.scanner.session_security.types import (
    CsrfObservation,
    CsrfVerdict,
    LogoutObservation,
)

#: Names that mean an anti-CSRF token and nothing else. Credited **whatever the
#: input type says**, on purpose: `<input name="csrf_token">` with no `type`
#: attribute is a hidden token in every framework that emits it, and refusing to
#: count it because the attribute was absent would manufacture a CSRF finding
#: against a form that is protected. A false negative here costs a warning; a
#: false positive costs the report's credibility.
_UNAMBIGUOUS_TOKEN_NAMES = frozenset(
    {
        "csrf_token",
        "csrftoken",
        "csrfmiddlewaretoken",
        "_csrf",
        "_csrf_token",
        "xsrf_token",
        "xsrftoken",
        "_xsrf",
        "authenticity_token",
        "requestverificationtoken",
        "anti_forgery_token",
        "antiforgerytoken",
        "csrfmagictoken",
    }
)

#: Names that are *sometimes* an anti-CSRF token and sometimes something the
#: user types — an invite code, a 2FA code, a workflow state. Credited only when
#: the field is hidden, because a visible one is an input, not a defence.
_AMBIGUOUS_TOKEN_NAMES = frozenset(
    {
        "_token",
        "token",
        "nonce",
        "form_key",
        "form_token",
        "security_token",
        "request_token",
        "verification_token",
        "state",
    }
)

#: Fragments that mark a token field under a name neither table carries.
#: Whole-word-ish rather than substring: `tokenizer_config` must not match.
_TOKEN_FRAGMENTS = ("csrf", "xsrf", "forgery", "authenticity")

#: Field names whose presence marks a credential-entry form. A login form is
#: still worth noting, but "login CSRF" is a materially smaller problem than
#: forging an authenticated state change, so it never reaches `STRONG`.
_CREDENTIAL_INPUT_TYPES = frozenset({"password"})

_SPLIT = re.compile(r"[^a-z0-9]+")

_LOGOUT_FRAGMENTS = ("logout", "log-out", "log_out", "signout", "sign-out", "sign_out")


def _normalize(name: str) -> str:
    return _SPLIT.sub("_", (name or "").strip().lower()).strip("_")


def is_token_field(field: DiscoveredFormField) -> bool:
    """Whether a form field looks like an anti-CSRF token.

    An unambiguous name counts on its own. An ambiguous one — `token`, `state`,
    `nonce` — counts only when the field is hidden, because a visible field by
    that name is something the user types rather than a defence.
    """
    normalized = _normalize(field.name)
    if not normalized:
        return False

    if normalized in _UNAMBIGUOUS_TOKEN_NAMES or any(
        fragment in normalized for fragment in _TOKEN_FRAGMENTS
    ):
        return True

    hidden = (field.input_type or "").strip().lower() == "hidden"
    return hidden and normalized in _AMBIGUOUS_TOKEN_NAMES


def token_fields(form: DiscoveredForm) -> tuple[str, ...]:
    """Names of the fields that look like anti-CSRF tokens.

    Names only. The value of a CSRF token is a live credential for the session
    that issued it and is never read, stored or reported.
    """
    return tuple(field.name for field in form.fields if is_token_field(field))


def _has_credential_input(form: DiscoveredForm) -> bool:
    return any(
        (field.input_type or "").strip().lower() in _CREDENTIAL_INPUT_TYPES
        for field in form.fields
    )


def _same_origin(page_url: str, action: str) -> bool | None:
    """Whether the form posts back to the origin it was served from.

    `None` when it cannot be determined. A form posting to a third party is not
    this target's CSRF problem, and claiming otherwise would report a finding
    against a site the scan never looked at.
    """
    if not action:
        return True  # An empty action posts to the current URL.
    try:
        resolved = urlsplit(urljoin(page_url, action))
        page = urlsplit(page_url)
    except ValueError:  # pragma: no cover - urlsplit is lenient
        return None
    if not resolved.netloc or not page.netloc:
        return None
    return resolved.netloc.lower() == page.netloc.lower()


def analyze_form(
    form: DiscoveredForm,
    *,
    session_cookie_present: bool = False,
    session_same_site: str | None = None,
    authenticated: bool = False,
) -> CsrfObservation:
    """Place one form on the NONE / UNKNOWN / POTENTIAL / STRONG scale.

    Every branch below records the signal that produced it, so a reader can
    disagree with the verdict on the evidence rather than on trust.
    """
    method = (form.method or "GET").strip().upper() or "GET"
    found_tokens = token_fields(form)
    signals: list[str] = []

    def observe(verdict: CsrfVerdict, detail: str) -> CsrfObservation:
        return CsrfObservation(
            page_url=form.page_url,
            action=form.action,
            method=method,
            verdict=verdict,
            token_fields=found_tokens,
            authenticated=authenticated,
            session_cookie_present=session_cookie_present,
            session_same_site=session_same_site,
            signals=tuple(signals),
            detail=detail,
        )

    # A GET form is not assumed to change state. Some do, but treating every
    # search box as a CSRF candidate would bury the forms that matter.
    if method not in {"POST", "PUT", "PATCH", "DELETE"}:
        signals.append(f"method:{method.lower()}-not-state-changing")
        return observe(
            CsrfVerdict.NONE,
            f"{method} form; not treated as state-changing without evidence that it is",
        )

    if found_tokens:
        signals.append("field:anti-csrf-token-present")
        return observe(
            CsrfVerdict.NONE,
            "a hidden anti-CSRF token field is present",
        )

    signals.append("field:no-anti-csrf-token")

    same_origin = _same_origin(form.page_url, form.action)
    if same_origin is False:
        signals.append("action:cross-origin")
        return observe(
            CsrfVerdict.UNKNOWN,
            "the form posts to another origin, whose CSRF defences this scan cannot assess",
        )

    # Without ambient authority there is nothing for a forged request to ride
    # on. No session cookie observed means CSRF cannot be established here —
    # not that the form is safe.
    if not session_cookie_present:
        signals.append("session:no-session-cookie-observed")
        return observe(
            CsrfVerdict.UNKNOWN,
            "no session cookie was observed, so whether a forged request would "
            "carry authority could not be determined",
        )

    signals.append("session:session-cookie-observed")
    if authenticated:
        signals.append("context:authenticated-scan")

    normalized_same_site = (session_same_site or "").strip().lower()
    credential_form = _has_credential_input(form)
    if credential_form:
        signals.append("form:credential-entry")

    if normalized_same_site == "none":
        signals.append("samesite:none-browser-defence-does-not-apply")
        if credential_form:
            # Login CSRF: real, but it forges a session into a victim's browser
            # rather than forging an action out of one. Not the same weight.
            return observe(
                CsrfVerdict.POTENTIAL,
                "a credential-entry form with no anti-CSRF token, where the session "
                "cookie declares SameSite=None; login CSRF is possible, though the "
                "impact differs from forging an authenticated action",
            )
        return observe(
            CsrfVerdict.STRONG,
            "a state-changing form with no anti-CSRF token, where the session cookie "
            "declares SameSite=None, so the browser will attach it to a cross-site "
            "request; a server-side defence may still exist and was not tested",
        )

    if normalized_same_site in {"lax", "strict"}:
        signals.append(f"samesite:{normalized_same_site}")
        return observe(
            CsrfVerdict.POTENTIAL,
            f"a state-changing form with no anti-CSRF token; the session cookie's "
            f"SameSite={normalized_same_site} would block a cross-site form post in a "
            "current browser, so this is worth reviewing rather than a confirmed weakness",
        )

    signals.append("samesite:unstated")
    return observe(
        CsrfVerdict.POTENTIAL,
        "a state-changing form with no anti-CSRF token and no SameSite stated on the "
        "session cookie; current browsers default to Lax, which would block a "
        "cross-site form post, but older clients do not",
    )


def analyze_forms(
    forms: Iterable[DiscoveredForm],
    *,
    session_cookie_present: bool = False,
    session_same_site: str | None = None,
    authenticated: bool = False,
    limit: int = 200,
) -> tuple[CsrfObservation, ...]:
    """Analyze a bounded set of forms, one page-and-action pair at a time."""
    observations: list[CsrfObservation] = []
    seen: set[tuple[str, str, str]] = set()
    for form in forms:
        key = (form.page_url, form.action, (form.method or "GET").upper())
        if key in seen:
            continue
        seen.add(key)
        observations.append(
            analyze_form(
                form,
                session_cookie_present=session_cookie_present,
                session_same_site=session_same_site,
                authenticated=authenticated,
            )
        )
        if len(observations) >= limit:
            break
    return tuple(observations)


def find_logout_endpoints(
    urls: Sequence[str] = (),
    forms: Iterable[DiscoveredForm] = (),
    *,
    limit: int = 20,
) -> tuple[LogoutObservation, ...]:
    """Find logout endpoints. **They are recorded and never called.**

    Requesting a logout during a scan would destroy the session every later
    stage depends on, and would prove nothing: a logout that returns 200 tells
    you nothing about whether the server actually invalidated the session. The
    endpoints are recorded so a reviewer knows where to check by hand.
    """
    found: dict[str, LogoutObservation] = {}

    for url in urls:
        path = urlsplit(url).path.lower() if url else ""
        if any(fragment in path for fragment in _LOGOUT_FRAGMENTS):
            found.setdefault(url, LogoutObservation(url=url, method="GET"))
            if len(found) >= limit:
                return tuple(found.values())

    for form in forms:
        action = form.action or form.page_url
        resolved = urljoin(form.page_url, action) if action else form.page_url
        if any(fragment in resolved.lower() for fragment in _LOGOUT_FRAGMENTS):
            found[resolved] = LogoutObservation(
                url=resolved,
                method=(form.method or "POST").upper(),
                from_form=True,
            )
            if len(found) >= limit:
                break

    return tuple(found.values())
