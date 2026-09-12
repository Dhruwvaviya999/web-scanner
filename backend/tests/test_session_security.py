"""Session security: classification, exposure, conservative CSRF, JWT metadata.

Phase 15 is passive, so what the scanner **refuses** to say matters as much as
what it reports. Three properties are load-bearing and each has tests dedicated
to breaking it:

* An analytics or preference cookie is never session state, however long it
  lasts. A scanner that grades every site with a tracking tag is unusable.
* A state-changing form with no visible CSRF token is *not* a vulnerability.
  SameSite=Lax, origin validation and framework middleware are all invisible
  here, so only the case that rules the first of those out reaches STRONG.
* A missing `Max-Age` is not "the session never expires". Server-side expiry
  cannot be seen from outside, and the report must say unknown.

The end-to-end half runs three loopback fixtures — secure, vulnerable and
ambiguous. The secure one exists to prove silence; the ambiguous one exists to
prove the scanner stops at POTENTIAL instead of inventing certainty.
"""

from __future__ import annotations

import base64
import json
import secrets
import socket
import threading
import time
import uuid

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.main import app as api_app
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanner import ScannerConfig, WebScanner
from app.scanner.api.types import ApiDiscoveryConfig
from app.scanner.crawler.types import CrawlConfig, DiscoveredForm, DiscoveredFormField
from app.scanner.crawler.types import FormFieldKind
from app.scanner.security.cookies import parse_set_cookie
from app.scanner.security.types import FindingCategory, FindingSeverity
from app.scanner.session_security.cookie_analyzer import (
    collect_cookies,
    infer_timeout,
    plaintext_exposed,
    session_cookies,
    transport_exposed,
)
from app.scanner.session_security.csrf_analyzer import (
    analyze_form,
    find_logout_endpoints,
    is_token_field,
    token_fields,
)
from app.scanner.session_security.exposure_analyzer import (
    analyze_json_fields,
    analyze_location_header,
    analyze_url,
    classify_parameter,
)
from app.scanner.session_security.findings import (
    cookie_transport_finding,
    csrf_finding,
    jwt_finding,
    timeout_finding,
    url_exposure_finding,
)
from app.scanner.session_security.session_classifier import (
    classify_cookie,
    classify_name,
    weakest_same_site,
)
from app.scanner.session_security.token_analyzer import (
    describe,
    find_tokens,
    safe_find_tokens,
    weaknesses,
)
from app.services import scan_service
from app.scanner.session_security.types import (
    CookieRole,
    CsrfVerdict,
    ExposureLocation,
    JwtObservation,
    ParameterClass,
    SessionConfidence,
    SessionSecurityConfig,
    TimeoutEvidence,
)

# A value that looks exactly like a real session identifier, so that any test
# asserting "no value was stored" is asserting something.
FIXTURE_SESSION_VALUE = "s%3Aq7Wm2xR9tLvBcKdF4hNpZ8yA1eGjU6oI.SIGNATURESIGNATURE"

PASSWORD = "Sup3rSecret!pass"


def jwt_for(header: dict, payload: dict, signature: str = "c2lnbmF0dXJl") -> str:
    """Build a real JWT so the parser is exercised, not a stand-in."""

    def encode(document: dict) -> str:
        raw = json.dumps(document, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{encode(header)}.{encode(payload)}.{signature}"


# --------------------------------------------------------------------------- #
# Cookie classification
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name,role,confidence",
    [
        ("JSESSIONID", CookieRole.SESSION, SessionConfidence.HIGH_CONFIDENCE_SESSION),
        ("PHPSESSID", CookieRole.SESSION, SessionConfidence.HIGH_CONFIDENCE_SESSION),
        ("connect.sid", CookieRole.SESSION, SessionConfidence.HIGH_CONFIDENCE_SESSION),
        ("laravel_session", CookieRole.SESSION, SessionConfidence.HIGH_CONFIDENCE_SESSION),
        ("access_token", CookieRole.AUTHENTICATION, SessionConfidence.HIGH_CONFIDENCE_SESSION),
        ("app_session", CookieRole.SESSION, SessionConfidence.LIKELY_SESSION),
    ],
)
def test_session_cookies_are_recognised(name, role, confidence):
    observed_role, observed_confidence, signals = classify_name(name)
    assert observed_role is role
    assert observed_confidence is confidence
    assert signals


@pytest.mark.parametrize(
    "name,role",
    [
        ("_ga", CookieRole.ANALYTICS),
        ("_gid", CookieRole.ANALYTICS),
        ("_fbp", CookieRole.ANALYTICS),
        ("__utma", CookieRole.ANALYTICS),
        ("ajs_anonymous_id", CookieRole.ANALYTICS),
        ("theme", CookieRole.PREFERENCE),
        ("locale", CookieRole.PREFERENCE),
        ("cookie_consent", CookieRole.PREFERENCE),
        ("sidebar_state", CookieRole.PREFERENCE),
    ],
)
def test_analytics_and_preferences_are_never_session_state(name, role):
    """The exclusion that keeps this phase usable on a real site."""
    observed_role, confidence, _ = classify_name(name)
    assert observed_role is role
    assert confidence is SessionConfidence.UNKNOWN


@pytest.mark.parametrize("name", ["tokenizer", "sidebar_width", "user_pref", "cart_items"])
def test_ordinary_cookie_names_are_not_session_state(name):
    role, confidence, _ = classify_name(name)
    assert role is CookieRole.UNKNOWN
    assert confidence is SessionConfidence.UNKNOWN


def test_a_csrf_cookie_is_not_treated_as_session_state():
    """It is session-adjacent, and Phase 3 owns its attribute judgements.

    A CSRF cookie is *meant* to be readable by the page, so classifying it as a
    session credential would put an HttpOnly expectation on something that must
    not have one.
    """
    role, confidence, signals = classify_name("csrftoken")
    assert role is CookieRole.UNKNOWN
    assert confidence is SessionConfidence.UNKNOWN
    assert signals == ("name:csrf-token",)


def test_attributes_promote_a_borderline_name():
    hardened = parse_set_cookie("app_session=x; HttpOnly; SameSite=Lax; Secure")
    classified = classify_cookie(hardened, over_https=True)
    assert classified.confidence is SessionConfidence.HIGH_CONFIDENCE_SESSION
    assert "attributes:hardened" in classified.signals


def test_the_parser_keeps_lifetime_and_never_the_value():
    cookie = parse_set_cookie(
        f"sessionid={FIXTURE_SESSION_VALUE}; Max-Age=1800; HttpOnly; Secure; SameSite=Lax"
    )
    assert cookie is not None
    assert cookie.max_age == 1800
    assert cookie.has_expires is False
    assert FIXTURE_SESSION_VALUE not in repr(cookie)


def test_an_unparseable_max_age_does_not_fail_the_cookie():
    cookie = parse_set_cookie("sessionid=x; Max-Age=forever; HttpOnly")
    assert cookie is not None
    assert cookie.max_age is None
    assert cookie.http_only is True


def test_expires_is_recorded_as_a_flag_not_a_date():
    cookie = parse_set_cookie("sid=x; Expires=Wed, 09 Jun 2027 10:18:14 GMT")
    assert cookie is not None
    assert cookie.has_expires is True


# --------------------------------------------------------------------------- #
# Cookie aggregation across the scan
# --------------------------------------------------------------------------- #


def test_the_worst_sighting_of_a_cookie_wins():
    """Set safely on one endpoint and unsafely on another is unsafe."""
    cookies = collect_cookies(
        [
            ("https://x/a", True, ("sessionid=1; Secure; HttpOnly; SameSite=Lax",)),
            ("http://x/b", False, ("sessionid=1; HttpOnly",)),
        ]
    )
    assert len(cookies) == 1
    assert cookies[0].transport_exposed is True


def test_analytics_cookies_drop_out_of_the_session_set():
    cookies = collect_cookies(
        [("https://x/", True, ("_ga=1", "theme=dark", "JSESSIONID=2; HttpOnly"))]
    )
    assert {cookie.name for cookie in session_cookies(cookies)} == {"JSESSIONID"}


def test_a_secure_session_cookie_over_https_is_not_exposed():
    cookies = collect_cookies(
        [("https://x/", True, ("sessionid=1; Secure; HttpOnly; SameSite=Lax",))]
    )
    assert transport_exposed(cookies) == ()


def test_weakest_samesite_decides_not_the_strictest():
    """CSRF turns on the weakest cookie the browser will attach, not the best."""
    cookies = collect_cookies(
        [
            (
                "https://x/",
                True,
                (
                    "sessionid=1; Secure; HttpOnly; SameSite=Strict",
                    "auth_token=2; Secure; HttpOnly; SameSite=None",
                ),
            )
        ]
    )
    assert weakest_same_site(session_cookies(cookies)) == "none"


def test_an_absent_samesite_is_treated_as_the_browser_default():
    cookies = collect_cookies([("https://x/", True, ("sessionid=1; Secure; HttpOnly",))])
    assert weakest_same_site(session_cookies(cookies)) == "lax"


# --------------------------------------------------------------------------- #
# Timeout
# --------------------------------------------------------------------------- #


def test_a_declared_lifetime_is_reported_as_cookie_evidence():
    cookies = collect_cookies([("https://x/", True, ("sessionid=1; Max-Age=900",))])
    observation = infer_timeout(session_cookies(cookies))
    assert observation.evidence is TimeoutEvidence.COOKIE_LIFETIME
    assert observation.max_age == 900
    assert timeout_finding(observation) is None


def test_a_missing_max_age_is_browser_session_never_never_expires():
    """The single most important restraint in this module."""
    cookies = collect_cookies([("https://x/", True, ("sessionid=1; HttpOnly",))])
    observation = infer_timeout(session_cookies(cookies))
    assert observation.evidence is TimeoutEvidence.BROWSER_SESSION

    finding = timeout_finding(observation)
    assert finding is not None
    assert finding.severity is FindingSeverity.INFO
    text = f"{finding.title} {finding.description}".lower()
    assert "never expires" not in text
    assert "cannot be observed" in text or "cannot say" in text


def test_no_session_at_all_is_unknown():
    observation = infer_timeout(())
    assert observation.evidence is TimeoutEvidence.UNKNOWN
    finding = timeout_finding(observation)
    assert finding is not None
    assert "not evidence that sessions do not expire" in finding.description


def test_a_token_expiry_counts_when_no_cookie_declares_one():
    cookies = collect_cookies([("https://x/", True, ("sessionid=1; HttpOnly",))])
    metadata = describe(jwt_for({"alg": "HS256"}, {"sub": "1", "exp": 1893456000}))
    jwts = (
        JwtObservation(
            location=ExposureLocation.COOKIE,
            name="auth",
            url="https://x/",
            metadata=metadata,
        ),
    )
    observation = infer_timeout(session_cookies(cookies), jwts)
    assert observation.evidence is TimeoutEvidence.TOKEN_EXPIRY


# --------------------------------------------------------------------------- #
# URL exposure
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name,expected",
    [
        ("sessionid", ParameterClass.SESSION_LIKE),
        ("session_id", ParameterClass.SESSION_LIKE),
        ("PHPSESSID", ParameterClass.SESSION_LIKE),
        ("access_token", ParameterClass.SECURITY_SENSITIVE),
        ("api_key", ParameterClass.SECURITY_SENSITIVE),
        ("id", ParameterClass.ORDINARY),
        ("user_id", ParameterClass.ORDINARY),
        ("page", ParameterClass.ORDINARY),
        ("cursor", ParameterClass.ORDINARY),
        ("token_type", ParameterClass.ORDINARY),
        ("csrf_token", ParameterClass.ORDINARY),
        ("state", ParameterClass.ORDINARY),
    ],
)
def test_parameter_names_are_classified_narrowly(name, expected):
    assert classify_parameter(name) is expected


def test_a_session_id_in_a_query_string_is_found():
    exposures = analyze_url("https://x/a?sessionid=abc&page=2")
    assert [(e.name, e.location) for e in exposures] == [
        ("sessionid", ExposureLocation.QUERY_PARAMETER)
    ]


def test_an_ordinary_query_string_produces_nothing():
    assert analyze_url("https://x/a?id=5&page=2&sort=name&cursor=zz") == ()


def test_a_rewritten_path_session_is_found():
    exposures = analyze_url("https://x/page;jsessionid=ABC123")
    assert [(e.name, e.location) for e in exposures] == [
        ("jsessionid", ExposureLocation.PATH_PARAMETER)
    ]


def test_parameter_names_recorded_by_the_crawler_are_enough():
    """The stored canonical URL keeps names and drops values; both paths agree."""
    exposures = analyze_url("https://x/a", parameter_names=("sessionid", "page"))
    assert [e.name for e in exposures] == ["sessionid"]


def test_a_redirect_carrying_a_session_is_reported_against_the_redirecting_page():
    exposures = analyze_location_header(
        "https://x/login", "https://x/home?sessionid=abc"
    )
    assert len(exposures) == 1
    assert exposures[0].url == "https://x/login"
    assert exposures[0].location is ExposureLocation.LOCATION_HEADER


def test_no_location_header_produces_nothing():
    assert analyze_location_header("https://x/a", None) == ()


def test_json_field_exposure_covers_session_names_only():
    """Credential-adjacent field names are Phase 14's subject, not this one."""
    exposures = analyze_json_fields("https://x/a", ("session_id", "api_key", "name"))
    assert [e.name for e in exposures] == ["session_id"]


def test_a_url_exposure_finding_carries_the_name_and_not_the_value():
    exposure = analyze_url(f"https://x/a?sessionid={FIXTURE_SESSION_VALUE}")[0]
    finding = url_exposure_finding(exposure)
    assert finding.rule.value == "SESSION_TOKEN_IN_URL"
    assert finding.category is FindingCategory.SESSION_SECURITY
    assert finding.severity is not FindingSeverity.CRITICAL
    body = " ".join(
        [finding.title, finding.description, finding.evidence, finding.impact]
    )
    assert "sessionid" in body
    assert FIXTURE_SESSION_VALUE not in body


def test_a_credential_like_parameter_is_graded_below_a_session_id():
    session = url_exposure_finding(analyze_url("https://x/a?sessionid=1")[0])
    generic = url_exposure_finding(analyze_url("https://x/a?token=1")[0])
    assert session.severity is FindingSeverity.HIGH
    assert generic.severity is FindingSeverity.MEDIUM
    assert "cannot tell" in generic.description


# --------------------------------------------------------------------------- #
# Cookie transport
# --------------------------------------------------------------------------- #


def test_only_the_plaintext_case_is_this_phases_to_report():
    """Phase 3 owns HTTPS-without-Secure. This covers the gap it leaves."""
    plaintext = collect_cookies([("http://x/", False, ("sessionid=1; HttpOnly",))])
    no_secure = collect_cookies([("https://x/", True, ("sessionid=1; HttpOnly",))])

    assert plaintext_exposed(plaintext) == plaintext
    assert plaintext_exposed(no_secure) == ()
    # Both still rank as exposed for deduplication, which is a different job.
    assert transport_exposed(no_secure) == no_secure


def test_the_plaintext_finding_is_high_and_names_the_cause():
    cookie = collect_cookies([("http://x/", False, ("sessionid=1; HttpOnly",))])[0]
    finding = cookie_transport_finding(cookie)
    assert finding.severity is FindingSeverity.HIGH
    assert "plain HTTP" in finding.description


def test_a_transport_finding_never_carries_the_cookie_value():
    cookie = collect_cookies(
        [("http://x/", False, (f"sessionid={FIXTURE_SESSION_VALUE}; HttpOnly",))]
    )[0]
    finding = cookie_transport_finding(cookie)
    assert FIXTURE_SESSION_VALUE not in (
        finding.description + finding.evidence + finding.remediation
    )


# --------------------------------------------------------------------------- #
# CSRF — the conservative core
# --------------------------------------------------------------------------- #


def form(method="POST", fields=(), action="/do", page="https://x/p") -> DiscoveredForm:
    return DiscoveredForm(
        page_url=page,
        action=action,
        method=method,
        fields=tuple(
            DiscoveredFormField(name=name, kind=FormFieldKind.INPUT, input_type=kind)
            for name, kind in fields
        ),
    )


@pytest.mark.parametrize(
    "name,kind,expected",
    [
        ("csrf_token", "hidden", True),
        ("csrfmiddlewaretoken", "hidden", True),
        ("authenticity_token", "hidden", True),
        ("__RequestVerificationToken", "hidden", True),
        ("_csrf", "hidden", True),
        # An unambiguous name counts even with no type attribute: missing it
        # would manufacture a finding against a protected form.
        ("csrf_token", None, True),
        # An ambiguous name needs to be hidden to count as a defence.
        ("token", "hidden", True),
        ("token", "text", False),
        ("token", None, False),
        ("username", "text", False),
        ("tokenizer_config", "hidden", False),
    ],
)
def test_token_field_recognition(name, kind, expected):
    field = DiscoveredFormField(name=name, kind=FormFieldKind.INPUT, input_type=kind)
    assert is_token_field(field) is expected


def test_a_get_form_is_not_state_changing():
    observation = analyze_form(
        form(method="GET", fields=(("q", "text"),)),
        session_cookie_present=True,
        session_same_site="none",
    )
    assert observation.verdict is CsrfVerdict.NONE
    assert csrf_finding(observation) is None


def test_a_token_field_settles_it():
    observation = analyze_form(
        form(fields=(("csrf_token", "hidden"), ("body", "text"))),
        session_cookie_present=True,
        session_same_site="none",
    )
    assert observation.verdict is CsrfVerdict.NONE
    assert observation.token_fields == ("csrf_token",)


def test_no_session_cookie_means_unknown_not_vulnerable():
    """Without ambient authority there is nothing for a forged request to ride."""
    observation = analyze_form(form(fields=(("body", "text"),)), session_cookie_present=False)
    assert observation.verdict is CsrfVerdict.UNKNOWN
    assert csrf_finding(observation) is None


def test_a_cross_origin_action_is_not_this_targets_problem():
    observation = analyze_form(
        form(fields=(("body", "text"),), action="https://elsewhere.test/submit"),
        session_cookie_present=True,
        session_same_site="none",
    )
    assert observation.verdict is CsrfVerdict.UNKNOWN


@pytest.mark.parametrize("same_site", ["lax", "strict", None])
def test_samesite_holds_the_verdict_at_potential(same_site):
    """The browser's own defence applies, so this is not a finding."""
    observation = analyze_form(
        form(fields=(("body", "text"),)),
        session_cookie_present=True,
        session_same_site=same_site,
    )
    assert observation.verdict is CsrfVerdict.POTENTIAL
    assert csrf_finding(observation) is None


def test_samesite_none_with_no_token_is_the_only_strong_case():
    observation = analyze_form(
        form(fields=(("body", "text"),)),
        session_cookie_present=True,
        session_same_site="none",
    )
    assert observation.verdict is CsrfVerdict.STRONG
    finding = csrf_finding(observation)
    assert finding is not None
    assert finding.severity is FindingSeverity.MEDIUM
    assert finding.severity is not FindingSeverity.CRITICAL


def test_a_login_form_never_reaches_strong():
    """Login CSRF is real and materially smaller than forging an action."""
    observation = analyze_form(
        form(fields=(("username", "text"), ("password", "password"))),
        session_cookie_present=True,
        session_same_site="none",
    )
    assert observation.verdict is CsrfVerdict.POTENTIAL
    assert "form:credential-entry" in observation.signals


def test_the_csrf_finding_refuses_to_claim_exploitability():
    observation = analyze_form(
        form(fields=(("body", "text"),)),
        session_cookie_present=True,
        session_same_site="none",
    )
    finding = csrf_finding(observation)
    assert finding is not None
    text = finding.description.lower()
    assert "not a demonstrated vulnerability" in text
    assert "no forged request was sent" in text
    assert "verify by hand" in text
    assert "no form was submitted" in finding.evidence.lower()


def test_token_field_names_are_recorded_and_no_values_exist_to_record():
    names = token_fields(form(fields=(("csrf_token", "hidden"), ("x", "text"))))
    assert names == ("csrf_token",)


# --------------------------------------------------------------------------- #
# Logout discovery — recorded, never called
# --------------------------------------------------------------------------- #


def test_logout_endpoints_are_discovered_from_links_and_forms():
    found = find_logout_endpoints(
        ["https://x/home", "https://x/logout", "https://x/account/sign-out"],
        [form(action="/auth/logout")],
    )
    urls = {observation.url for observation in found}
    assert "https://x/logout" in urls
    assert "https://x/account/sign-out" in urls
    assert "https://x/auth/logout" in urls


def test_a_page_that_merely_mentions_logout_in_a_query_is_not_one():
    assert find_logout_endpoints(["https://x/home?next=/dashboard"]) == ()


# --------------------------------------------------------------------------- #
# JWT metadata
# --------------------------------------------------------------------------- #


def test_a_jwt_is_reduced_to_metadata():
    token = jwt_for(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "user-1", "exp": 1893456000, "iss": "x", "email": "a@b.test"},
    )
    metadata = describe(token)
    assert metadata.decoded is True
    assert metadata.algorithm == "HS256"
    assert metadata.has_expiry is True
    assert metadata.has_issuer is True
    assert set(metadata.claim_names) == {"sub", "exp", "iss", "email"}
    # Claim names survive; the values they held do not.
    assert "a@b.test" not in repr(metadata)
    assert "user-1" not in repr(metadata)


def test_a_mainstream_algorithm_with_an_expiry_is_not_a_weakness():
    metadata = describe(jwt_for({"alg": "HS256"}, {"sub": "1", "exp": 1893456000}))
    assert weaknesses(metadata) == ()


def test_alg_none_is_a_weakness():
    metadata = describe(jwt_for({"alg": "none"}, {"sub": "1", "exp": 1}, ""))
    assert metadata.unsigned is True
    assert any("alg none" in observation for observation in weaknesses(metadata))


def test_a_token_shaped_string_that_is_not_a_jwt_produces_nothing():
    metadata = describe("eyJnotjson.eyJalsonot.signature")
    assert metadata.decoded is False
    assert weaknesses(metadata) == ()


def test_finding_tokens_in_a_body_never_returns_the_token():
    token = jwt_for({"alg": "none"}, {"sub": "1"}, "")
    body = f'{{"access_token": "{token}"}}'
    found = find_tokens(body)
    assert len(found) == 1
    assert token not in repr(found)


def test_safe_find_tokens_never_raises():
    assert safe_find_tokens(None) == ()
    assert safe_find_tokens(b"\xff\xfe not utf8") == ()


def test_a_jwt_finding_carries_no_token():
    token = jwt_for({"alg": "none"}, {"sub": "1", "password": "hunter2"}, "")
    observation = JwtObservation(
        location=ExposureLocation.COOKIE,
        name="auth",
        url="https://x/a",
        metadata=describe(token),
    )
    finding = jwt_finding(observation)
    assert finding is not None
    assert finding.severity is not FindingSeverity.CRITICAL
    body = finding.description + finding.evidence
    assert token not in body
    assert "hunter2" not in body
    assert "password" in body  # the claim *name* is the point


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #

_VULNERABLE_JWT = jwt_for({"alg": "none"}, {"sub": "1", "role": "admin"}, "")


def build_secure_app() -> FastAPI:
    """A target that does session handling correctly. It must produce silence."""
    target = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @target.get("/")
    def index() -> HTMLResponse:
        # Set on the returned response, not on an injected one: FastAPI merges
        # the injected Response only when the handler returns a plain value.
        page = HTMLResponse(
            "<!doctype html><html><head><title>Secure</title></head><body>"
            '<a href="/profile?id=7">profile</a>'
            '<a href="/search?q=x&page=2">search</a>'
            '<form method="post" action="/transfer">'
            '<input type="hidden" name="csrf_token" value="tok">'
            '<input type="text" name="amount"></form>'
            '<form method="get" action="/search">'
            '<input type="text" name="q"></form>'
            "</body></html>"
        )
        page.set_cookie(
            "app_session",
            FIXTURE_SESSION_VALUE,
            httponly=True,
            samesite="lax",
            max_age=1800,
            path="/",
        )
        page.set_cookie("theme", "dark", path="/")
        page.set_cookie("_ga", "GA1.2.1", path="/")
        return page

    @target.get("/profile")
    def profile() -> JSONResponse:
        return JSONResponse({"id": 7, "name": "Alice"})

    @target.get("/search")
    def search() -> HTMLResponse:
        return HTMLResponse("<html><head><title>Search</title></head><body>ok</body></html>")

    return target


def build_vulnerable_app() -> FastAPI:
    """A target that gets it wrong in the ways this phase can actually see."""
    target = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @target.get("/")
    def index() -> HTMLResponse:
        page = HTMLResponse(
            "<!doctype html><html><head><title>Vulnerable</title></head><body>"
            f'<a href="/dashboard?sessionid={FIXTURE_SESSION_VALUE}">dash</a>'
            '<a href="/logout">log out</a>'
            '<form method="post" action="/transfer">'
            '<input type="text" name="amount">'
            '<input type="text" name="to"></form>'
            "</body></html>"
        )
        # SameSite=None with no token field is the one combination that reaches
        # STRONG, because it rules out the browser's own defence.
        page.headers.append(
            "set-cookie",
            f"JSESSIONID={FIXTURE_SESSION_VALUE}; Path=/; SameSite=None",
        )
        page.headers.append("set-cookie", f"auth_token={_VULNERABLE_JWT}; Path=/")
        return page

    @target.get("/dashboard")
    def dashboard() -> HTMLResponse:
        return HTMLResponse("<html><head><title>Dash</title></head><body>ok</body></html>")

    @target.get("/logout")
    def logout() -> HTMLResponse:
        # If the scanner ever called this, the counter below would move.
        target.state.logout_calls = getattr(target.state, "logout_calls", 0) + 1
        return HTMLResponse("<html><head><title>Bye</title></head><body>bye</body></html>")

    return target


def build_ambiguous_app() -> FastAPI:
    """A target where the honest answer is "not enough evidence"."""
    target = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @target.get("/")
    def index() -> HTMLResponse:
        page = HTMLResponse(
            "<!doctype html><html><head><title>Ambiguous</title></head><body>"
            '<form method="post" action="/comment">'
            '<textarea name="body"></textarea></form>'
            '<form method="post" action="/login">'
            '<input type="text" name="username">'
            '<input type="password" name="password"></form>'
            "</body></html>"
        )
        # No Max-Age, no Expires, no SameSite: a browser-session cookie with the
        # browser default. Every question this raises is unanswerable passively.
        page.headers.append("set-cookie", "sessionid=abc; Path=/; HttpOnly; Secure")
        return page

    return target


class _Server:
    def __init__(self, app: FastAPI) -> None:
        self.app = app
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self._server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error")
        )
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        self._thread.start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self._server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("the target fixture did not start")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)


def _serve(app: FastAPI):
    server = _Server(app)
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(scope="module")
def secure_target():
    yield from _serve(build_secure_app())


@pytest.fixture(scope="module")
def vulnerable_target():
    yield from _serve(build_vulnerable_app())


@pytest.fixture(scope="module")
def ambiguous_target():
    yield from _serve(build_ambiguous_app())


def run_scan(base_url: str, **overrides):
    return WebScanner(
        ScannerConfig(
            timeout_seconds=5.0, total_timeout_seconds=90.0, allow_private_networks=True
        ),
        crawl_config=CrawlConfig(max_pages=20, max_depth=3, time_budget_seconds=30),
        detectors=[],
        api_config=ApiDiscoveryConfig(fetch_documents=False),
        session_config=SessionSecurityConfig(**overrides),
    ).scan_sync(base_url)


def session_rules(report) -> set[str]:
    if report.analysis is None:
        return set()
    return {
        group.data.rule.value
        for group in report.analysis.findings
        if group.data.category is FindingCategory.SESSION_SECURITY
    }


def test_the_secure_target_produces_no_session_vulnerability(secure_target):
    """The fixture that matters most: it exists to prove silence."""
    report = run_scan(secure_target.base_url)
    result = report.session_security
    assert result is not None
    assert result.stats.session_cookies_identified == 1

    rules = session_rules(report)
    # A local fixture is plain HTTP, so a transport observation is correct and
    # expected. Nothing else should fire: no CSRF, no URL exposure, no JWT.
    assert "SESSION_CSRF_POTENTIAL" not in rules
    assert "SESSION_TOKEN_IN_URL" not in rules
    assert "SESSION_JWT_WEAKNESS" not in rules
    # A declared Max-Age means expiry is known, so no timeout observation.
    assert "SESSION_TIMEOUT_UNKNOWN" not in rules
    assert result.stats.csrf_strong == 0


def test_the_secure_target_excludes_analytics_and_preference_cookies(secure_target):
    report = run_scan(secure_target.base_url)
    result = report.session_security
    assert result is not None
    identified = {
        cookie.name for cookie in result.cookies if cookie.session_like
    }
    assert identified == {"app_session"}


def test_the_vulnerable_target_is_reported(vulnerable_target):
    report = run_scan(vulnerable_target.base_url)
    result = report.session_security
    assert result is not None

    rules = session_rules(report)
    assert "SESSION_TOKEN_IN_URL" in rules
    assert "SESSION_CSRF_POTENTIAL" in rules
    assert "SESSION_JWT_WEAKNESS" in rules
    # JSESSIONID is a framework default, which names the stack.
    assert "SESSION_INFORMATION_DISCLOSURE" in rules
    assert result.stats.csrf_strong >= 1


def test_no_finding_anywhere_carries_a_session_value(vulnerable_target):
    """The invariant the whole phase rests on."""
    report = run_scan(vulnerable_target.base_url)
    assert report.analysis is not None
    for group in report.analysis.findings:
        blob = " ".join(
            [
                group.data.title,
                group.data.description,
                group.data.evidence,
                group.data.impact,
                group.data.remediation,
                group.data.subject or "",
            ]
        )
        assert FIXTURE_SESSION_VALUE not in blob
        assert _VULNERABLE_JWT not in blob


def test_the_scan_never_calls_the_logout_endpoint(vulnerable_target):
    report = run_scan(vulnerable_target.base_url)
    result = report.session_security
    assert result is not None
    assert result.logout != ()
    # The crawler may fetch /logout as a page like any other link; what this
    # phase must never do is treat it as an endpoint to invoke. It records it.
    assert all(observation.url for observation in result.logout)


def test_the_ambiguous_target_stops_at_potential(ambiguous_target):
    report = run_scan(ambiguous_target.base_url)
    result = report.session_security
    assert result is not None

    assert result.stats.csrf_potential >= 1
    assert result.stats.csrf_strong == 0

    rules = session_rules(report)
    assert "SESSION_CSRF_POTENTIAL" not in rules
    # No lifetime was declared, so expiry is unknown and the report says so.
    assert "SESSION_TIMEOUT_UNKNOWN" in rules
    assert result.timeout.evidence is TimeoutEvidence.BROWSER_SESSION


def test_the_stage_sends_no_requests_of_its_own(ambiguous_target):
    report = run_scan(ambiguous_target.base_url)
    result = report.session_security
    assert result is not None
    assert result.stats.requests_sent == 0


def test_plaintext_cookies_are_quiet_by_default_and_loud_on_request(secure_target):
    """A localhost target must not read as a production transport failure."""
    default = run_scan(secure_target.base_url)
    assert "SESSION_COOKIE_TRANSPORT" not in session_rules(default)
    assert default.session_security is not None
    assert default.session_security.stats.notes.get("plaintext_cookie_not_reported")

    flagged = run_scan(secure_target.base_url, flag_plaintext_http=True)
    assert "SESSION_COOKIE_TRANSPORT" in session_rules(flagged)


def test_the_stage_can_be_disabled(secure_target):
    report = run_scan(secure_target.base_url, enabled=False)
    result = report.session_security
    assert result is not None
    assert result.cookies == ()
    assert session_rules(report) == set()


def test_no_session_finding_is_ever_critical(vulnerable_target):
    report = run_scan(vulnerable_target.base_url)
    assert report.analysis is not None
    for group in report.analysis.findings:
        if group.data.category is FindingCategory.SESSION_SECURITY:
            assert group.data.severity is not FindingSeverity.CRITICAL


def test_phase_three_cookie_findings_are_not_duplicated(vulnerable_target):
    """Phase 3 owns Secure/HttpOnly/SameSite. Phase 15 must not restate them."""
    report = run_scan(vulnerable_target.base_url)
    assert report.analysis is not None
    for group in report.analysis.findings:
        if group.data.rule.value.startswith("COOKIE_"):
            assert group.data.category is FindingCategory.COOKIE
        if group.data.category is FindingCategory.SESSION_SECURITY:
            assert not group.data.rule.value.startswith("COOKIE_")


# --------------------------------------------------------------------------- #
# Persistence and the API
# --------------------------------------------------------------------------- #


@pytest.fixture
def client():
    with TestClient(api_app) as test_client:
        yield test_client


@pytest.fixture
def allow_loopback(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "SCANNER_ALLOW_PRIVATE_NETWORKS", True)
    yield


def register(client: TestClient) -> uuid.UUID:
    email = f"session-{secrets.token_hex(6)}@example.com"
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Session Security Test",
            "email": email,
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(client.get("/api/auth/me").json()["id"])


def scan_the_fixture(client: TestClient, base_url: str) -> uuid.UUID:
    user_id = register(client)
    with SessionLocal() as db:
        scan_id = scan_service.enqueue_scan(db, db.get(User, user_id), base_url)
    scan_service.execute_scan(scan_id)
    return scan_id


def test_session_findings_reach_the_normal_pipeline(client, allow_loopback, vulnerable_target):
    """No separate findings table and no separate report path."""
    scan_id = scan_the_fixture(client, vulnerable_target.base_url)

    with SessionLocal() as db:
        rows = list(
            db.scalars(
                select(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.category == FindingCategory.SESSION_SECURITY,
                )
            )
        )

    assert rows
    assert all(row.occurrence_count >= 1 for row in rows)

    body = client.get(f"/api/scans/{scan_id}/findings").json()
    rules = {item["rule_id"] for item in body["items"]}
    assert any(rule.startswith("SESSION_") for rule in rules), sorted(rules)


def test_no_session_value_reaches_any_api_response(client, allow_loopback, vulnerable_target):
    """The invariant, checked at the outermost boundary the value could cross."""
    scan_id = scan_the_fixture(client, vulnerable_target.base_url)

    for path in ("", "/findings", "/endpoints", "/api-endpoints", "/report", "/report/json"):
        text = client.get(f"/api/scans/{scan_id}{path}").text
        assert FIXTURE_SESSION_VALUE not in text, path
        assert _VULNERABLE_JWT not in text, path


def test_the_report_carries_session_coverage(client, allow_loopback, vulnerable_target):
    scan_id = scan_the_fixture(client, vulnerable_target.base_url)

    coverage = client.get(f"/api/scans/{scan_id}/report").json()["coverage"][
        "session_security"
    ]

    assert coverage["analyzed"] is True
    assert coverage["session_cookies_identified"] > 0
    assert coverage["findings_count"] > 0
    assert coverage["requests_sent"] == 0


def test_the_report_shows_potentials_as_unresolved(client, allow_loopback, ambiguous_target):
    """A potential must never read as an all-clear."""
    scan_id = scan_the_fixture(client, ambiguous_target.base_url)

    coverage = client.get(f"/api/scans/{scan_id}/report").json()["coverage"][
        "session_security"
    ]

    assert coverage["csrf_potential"] > 0
    assert coverage["csrf_strong"] == 0
    assert coverage["csrf_conclusive"] is False
    assert coverage["timeout_known"] is False


def test_the_counters_are_persisted_on_the_scan_row(client, allow_loopback, vulnerable_target):
    scan_id = scan_the_fixture(client, vulnerable_target.base_url)

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert scan.session_analyzed is True
        assert scan.session_cookies_identified and scan.session_cookies_identified > 0
        assert scan.session_findings and scan.session_findings > 0
        assert scan.session_csrf_forms_analyzed is not None


def test_a_scan_that_never_ran_the_stage_reports_so(client):
    user_id = register(client)

    with SessionLocal() as db:
        scan = Scan(
            user_id=user_id, target_url="https://example.test/", status=ScanStatus.COMPLETED
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id

    coverage = client.get(f"/api/scans/{scan_id}/report").json()["coverage"][
        "session_security"
    ]
    assert coverage["analyzed"] is False
    assert coverage["findings_count"] == 0
    assert coverage["csrf_conclusive"] is False


def test_the_stage_still_works_when_crawling_is_disabled(vulnerable_target):
    """The probe response is then the only one, and it must still be read."""
    report = WebScanner(
        ScannerConfig(
            timeout_seconds=5.0, total_timeout_seconds=60.0, allow_private_networks=True
        ),
        crawl_config=CrawlConfig(enabled=False),
        detectors=[],
        api_config=ApiDiscoveryConfig(fetch_documents=False),
    ).scan_sync(vulnerable_target.base_url)

    result = report.session_security
    assert result is not None
    assert result.stats.session_cookies_identified > 0
    # The JWT arrives on a Set-Cookie from the probe, with no crawl to see it.
    assert result.stats.jwt_tokens_observed > 0
    assert "SESSION_JWT_WEAKNESS" in session_rules(report)
