"""Authorization testing: policy, comparison, discovery, budget, leakage.

The pure tests — the matrix, the comparator, the detector — need nothing but
canned responses, which is what makes every judgement in this feature testable
without a network.

The rest run against two loopback applications started inside this process: one
that enforces access control correctly and one that deliberately does not. The
secure variant is the more important of the two. A scanner that finds the bug in
the broken app but also "finds" three in the correct one is not useful, so the
secure fixture exists to prove silence.

The fixture's identities are constants this repository owns, handed to the
scanner the way an authorized user hands over their own. Nothing here guesses,
registers or attacks a credential.
"""

from __future__ import annotations

import secrets
import socket
import threading
import time
import uuid

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app as api_app
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanner import ScannerConfig, WebScanner
from app.scanner.auth import AuthenticationContext, AuthMode
from app.scanner.auth.context import build_context
from app.scanner.authorization import (
    AccessExpectation,
    AuthorizationBudget,
    AuthorizationBudgetLimits,
    AuthorizationConfig,
    AuthorizationContext,
    AuthorizationMatrix,
    AuthorizationPlan,
    ComparisonVerdict,
    MatrixError,
    ObservedAccess,
    analyze_resource,
    build_finding,
    build_matrix,
    matches,
    normalize_pattern,
)
from app.scanner.authorization.comparator import classify_access, equivalent, fingerprint
from app.scanner.authorization.types import AuthorizationTestKind
from app.scanner.cancellation import CancellationToken
from app.scanner.crawler.types import CrawlConfig
from app.scanner.security.types import FindingCategory, FindingConfidence, FindingRule
from app.scanner.types import RawHttpResponse
from app.services import scan_service

PASSWORD = "Sup3rSecret!pass"

ALICE_TOKEN = "authz-alice-token"
BOB_TOKEN = "authz-bob-token"
ADMIN_TOKEN = "authz-admin-token"

#: Long enough that similarity means something. Two 20-byte pages are always
#: "similar", which is exactly the trap `min_comparable_body_bytes` closes.
_FILLER = "The quick brown fox jumps over the lazy dog. " * 4


# --------------------------------------------------------------------------- #
# A target with a public half, two customers and an administrator
# --------------------------------------------------------------------------- #


def build_target_app(*, vulnerable: bool) -> FastAPI:
    """The fixture, in a correct and a deliberately broken variant.

    The only difference between them is who the ownership checks accept. Routes,
    bodies and denial behaviour are otherwise identical, so a finding that
    appears in one and not the other is attributable to the access control and
    to nothing else.
    """
    target = FastAPI(docs_url=None, redoc_url=None)

    #: Every request the target received, for the transport-isolation tests.
    received: list[dict[str, str | None]] = []
    target.state.received = received

    def identity(request: Request) -> str | None:
        header = request.headers.get("authorization", "")
        for name, token in (
            ("alice", ALICE_TOKEN),
            ("bob", BOB_TOKEN),
            ("admin", ADMIN_TOKEN),
        ):
            if header == f"Bearer {token}":
                return name
        cookie = request.cookies.get("session")
        return {"sess-alice": "alice", "sess-bob": "bob", "sess-admin": "admin"}.get(
            cookie or ""
        )

    def page(title: str, body: str) -> str:
        return (
            f"<!doctype html><html><head><title>{title}</title></head>"
            f"<body><h1>{title}</h1><p>{body}</p><p>{_FILLER}</p></body></html>"
        )

    @target.middleware("http")
    async def record(request: Request, call_next):
        received.append(
            {
                "method": request.method,
                "path": request.url.path,
                "authorization": request.headers.get("authorization"),
                "cookie": request.headers.get("cookie"),
            }
        )
        return await call_next(request)

    def guard(request: Request, allowed: set[str]) -> Response | None:
        """Refuse the way real applications do: redirect anonymous, 403 others."""
        who = identity(request)
        if who is None:
            return RedirectResponse("/login", status_code=302)
        if vulnerable:
            # The bug: being signed in as anybody is treated as authorisation.
            return None
        if who not in allowed:
            return Response(status_code=403)
        return None

    @target.get("/")
    def index() -> HTMLResponse:
        return HTMLResponse(
            page(
                "Home",
                '<a href="/public">public</a> <a href="/private/a">a</a> '
                '<a href="/private/b">b</a> <a href="/admin">admin</a>',
            )
        )

    @target.get("/public")
    def public() -> HTMLResponse:
        return HTMLResponse(page("Public", "Anyone may read this page."))

    @target.get("/login")
    def login() -> HTMLResponse:
        return HTMLResponse(page("Sign in", "Authentication required."))

    @target.get("/private/a")
    def private_a(request: Request):
        return guard(request, {"alice", "admin"}) or HTMLResponse(
            page("Alice's area", "Private notes belonging to alice.")
        )

    @target.get("/private/b")
    def private_b(request: Request):
        return guard(request, {"bob", "admin"}) or HTMLResponse(
            page("Bob's area", "Private notes belonging to bob.")
        )

    @target.get("/admin")
    def admin(request: Request):
        return guard(request, {"admin"}) or HTMLResponse(
            page("Administration", "Administrative controls for the whole site.")
        )

    @target.get("/api/orders/101")
    def order_101(request: Request):
        return guard(request, {"alice", "admin"}) or HTMLResponse(
            page("Order 101", "Order 101 belongs to alice.")
        )

    @target.get("/api/orders/102")
    def order_102(request: Request):
        return guard(request, {"bob", "admin"}) or HTMLResponse(
            page("Order 102", "Order 102 belongs to bob.")
        )

    return target


class _Server:
    """Runs a fixture application on a free loopback port."""

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

    @property
    def received(self) -> list[dict[str, str | None]]:
        return self.app.state.received

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


@pytest.fixture(scope="module")
def secure_target():
    server = _Server(build_target_app(vulnerable=False))
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(scope="module")
def broken_target():
    server = _Server(build_target_app(vulnerable=True))
    server.start()
    try:
        yield server
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def scanner_config() -> ScannerConfig:
    return ScannerConfig(
        timeout_seconds=5.0, total_timeout_seconds=90.0, allow_private_networks=True
    )


def bearer(base_url: str, token: str) -> AuthenticationContext:
    return build_context(AuthMode.BEARER_TOKEN, base_url, token=token)


def context(
    base_url: str,
    context_id: str,
    token: str | None,
    *,
    role: str | None = None,
    rank: int = 0,
) -> AuthorizationContext:
    return AuthorizationContext(
        id=context_id,
        display_name=context_id,
        role_label=role,
        privilege_rank=rank,
        authentication=(
            AuthenticationContext.none() if token is None else bearer(base_url, token)
        ),
    )


def standard_contexts(base_url: str) -> tuple[AuthorizationContext, ...]:
    return (
        context(base_url, "anonymous", None),
        context(base_url, "alice", ALICE_TOKEN, role="USER", rank=0),
        context(base_url, "bob", BOB_TOKEN, role="USER", rank=0),
        context(base_url, "admin", ADMIN_TOKEN, role="ADMIN", rank=10),
    )


def standard_matrix() -> AuthorizationMatrix:
    """The policy the fixture actually implements, as a user would declare it."""
    return build_matrix(
        rules=[
            ("anonymous", "/private/*", AccessExpectation.DENIED),
            ("anonymous", "/admin", AccessExpectation.DENIED),
            ("alice", "/private/a", AccessExpectation.ALLOWED),
            ("alice", "/private/b", AccessExpectation.DENIED),
            ("alice", "/admin", AccessExpectation.DENIED),
            ("bob", "/private/b", AccessExpectation.ALLOWED),
            ("bob", "/private/a", AccessExpectation.DENIED),
            ("bob", "/admin", AccessExpectation.DENIED),
            ("admin", "/admin", AccessExpectation.ALLOWED),
        ],
        ownership=[("/api/orders/101", "alice"), ("/api/orders/102", "bob")],
        known_context_ids=["anonymous", "alice", "bob", "admin"],
    )


def run_scan(base_url: str, plan: AuthorizationPlan, **overrides):
    return WebScanner(
        scanner_config(),
        crawl_config=CrawlConfig(max_pages=15, max_depth=3, time_budget_seconds=30),
        detectors=[],
        authz_config=AuthorizationConfig(enabled=True, **overrides),
        authorization=plan,
    ).scan_sync(base_url)


def authz_findings(report) -> list:
    if report.analysis is None:
        return []
    return [
        group
        for group in report.analysis.findings
        if group.data.category is FindingCategory.AUTHORIZATION
    ]


def response(
    status: int = 200,
    body: str = "",
    *,
    content_type: str = "text/html",
    final_url: str = "https://example.test/resource",
    redirects: int = 0,
) -> RawHttpResponse:
    return RawHttpResponse(
        status_code=status,
        headers=httpx.Headers({"content-type": content_type}),
        final_url=final_url,
        is_https=True,
        redirect_count=redirects,
        elapsed_ms=5,
        body=body.encode("utf-8"),
    )


PRIVATE = f"<html><body>Alice's private order details. {_FILLER}</body></html>"
OTHER = f"<html><body>Bob's completely different order. {'x' * 300}</body></html>"
DENIAL = "<html><body>Forbidden</body></html>"

CONFIG = AuthorizationConfig(enabled=True)


# --------------------------------------------------------------------------- #
# 1. The matrix
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/admin", "/admin"),
        ("admin", "/admin"),
        ("/admin/", "/admin"),
        ("/admin/*", "/admin/*"),
        ("https://example.test/admin?x=1", "/admin"),
    ],
)
def test_patterns_normalise_to_a_path(raw, expected):
    assert normalize_pattern(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "/a\r\nb", "/" + "a" * 600])
def test_an_unusable_pattern_is_refused(raw):
    with pytest.raises(MatrixError):
        normalize_pattern(raw)


def test_matching_is_exact_or_prefix_only():
    assert matches("/admin", "https://x.test/admin") is True
    assert matches("/admin", "https://x.test/admin/users") is False
    assert matches("/admin/*", "https://x.test/admin/users") is True
    assert matches("/admin", "https://x.test/administration") is False


def test_the_query_string_is_not_part_of_matching():
    """Endpoints are stored with parameter names and no values, so it cannot be."""
    assert matches("/search", "https://x.test/search?q") is True


def test_an_undeclared_pair_is_unknown():
    """The default, and the whole point: silence is not permission or prohibition."""
    matrix = AuthorizationMatrix()
    assert (
        matrix.expectation_for("alice", "https://x.test/anything")
        is AccessExpectation.UNKNOWN
    )


def test_the_most_specific_rule_wins():
    matrix = build_matrix(
        rules=[
            ("alice", "/admin/*", AccessExpectation.DENIED),
            ("alice", "/admin/health", AccessExpectation.ALLOWED),
        ],
        known_context_ids=["alice"],
    )
    assert (
        matrix.expectation_for("alice", "https://x.test/admin/users")
        is AccessExpectation.DENIED
    )
    assert (
        matrix.expectation_for("alice", "https://x.test/admin/health")
        is AccessExpectation.ALLOWED
    )


def test_ownership_implies_both_halves_of_the_expectation():
    matrix = build_matrix(
        ownership=[("/api/orders/101", "alice")], known_context_ids=["alice", "bob"]
    )
    url = "https://x.test/api/orders/101"
    assert matrix.expectation_for("alice", url) is AccessExpectation.ALLOWED
    assert matrix.expectation_for("bob", url) is AccessExpectation.DENIED
    assert matrix.owner_of(url) == "alice"


def test_a_rule_for_an_unknown_context_is_refused():
    """Dropping it would leave a boundary the user believes is under test."""
    with pytest.raises(MatrixError):
        build_matrix(
            rules=[("nobody", "/x", AccessExpectation.DENIED)],
            known_context_ids=["alice"],
        )


def test_one_resource_cannot_have_two_owners():
    with pytest.raises(MatrixError):
        build_matrix(
            ownership=[("/api/orders/1", "alice"), ("/api/orders/1", "bob")],
            known_context_ids=["alice", "bob"],
        )


def test_declared_resources_exclude_wildcards():
    """A wildcard names no resource, so there is nothing specific to request."""
    matrix = build_matrix(
        rules=[
            ("alice", "/admin/*", AccessExpectation.DENIED),
            ("alice", "/reports/7", AccessExpectation.DENIED),
        ],
        known_context_ids=["alice"],
    )
    assert matrix.declared_resources() == ("/reports/7",)


# --------------------------------------------------------------------------- #
# 2. Classifying one response
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("status", [401, 403, 404, 405])
def test_a_refusal_is_denied(status):
    assert (
        classify_access(response(status), requested_url="https://x.test/r")
        is ObservedAccess.DENIED
    )


def test_a_redirect_to_sign_in_is_denied():
    redirected = response(200, PRIVATE, final_url="https://x.test/login", redirects=1)
    assert (
        classify_access(redirected, requested_url="https://x.test/private")
        is ObservedAccess.DENIED
    )


def test_asking_for_the_sign_in_page_is_not_a_refusal():
    landed = response(200, PRIVATE, final_url="https://x.test/login", redirects=1)
    assert (
        classify_access(landed, requested_url="https://x.test/login")
        is ObservedAccess.ALLOWED
    )


def test_a_success_is_allowed():
    assert (
        classify_access(response(200, PRIVATE), requested_url="https://x.test/r")
        is ObservedAccess.ALLOWED
    )


@pytest.mark.parametrize("status", [500, 502, 503])
def test_a_server_error_says_nothing(status):
    assert (
        classify_access(response(status), requested_url="https://x.test/r")
        is ObservedAccess.INCONCLUSIVE
    )


# --------------------------------------------------------------------------- #
# 3. Equivalence
# --------------------------------------------------------------------------- #


def test_identical_bodies_are_equivalent():
    assert equivalent(response(200, PRIVATE), response(200, PRIVATE), CONFIG) is True


def test_a_different_status_is_never_equivalent():
    assert equivalent(response(200, PRIVATE), response(403, PRIVATE), CONFIG) is False


def test_a_different_media_type_is_never_equivalent():
    assert (
        equivalent(
            response(200, PRIVATE),
            response(200, PRIVATE, content_type="application/json"),
            CONFIG,
        )
        is False
    )


def test_materially_different_bodies_are_not_equivalent():
    assert equivalent(response(200, PRIVATE), response(200, OTHER), CONFIG) is False


def test_two_short_denial_pages_are_not_called_equivalent():
    """Short pages are always similar; concluding from that flags every site."""
    assert equivalent(response(200, DENIAL), response(200, "<p>Nope</p>"), CONFIG) is False


def test_a_volatile_fragment_does_not_break_equivalence():
    """A timestamp or request id rendered into an otherwise identical page."""
    left = f"<html><body>Order details 2026-09-09T10:00:00 {_FILLER}</body></html>"
    right = f"<html><body>Order details 2026-09-09T11:22:33 {_FILLER}</body></html>"
    assert equivalent(response(200, left), response(200, right), CONFIG) is True


def test_a_fingerprint_keeps_no_content():
    secret_body = f"<html><body>SECRET-MARKER-9x7 {_FILLER}</body></html>"
    print_ = fingerprint(response(200, secret_body))

    rendered = f"{print_} {print_.summary()}"
    assert "SECRET-MARKER-9x7" not in rendered
    assert print_.status_code == 200
    assert print_.body_length == len(secret_body.encode())


# --------------------------------------------------------------------------- #
# 4. The comparison, on canned responses
# --------------------------------------------------------------------------- #


def _identity(context_id: str, rank: int) -> AuthorizationContext:
    """A named identity for the pure tests.

    Given real credentials on purpose: `anonymous` is derived from carrying no
    credential, so an identity built without one would be classified as the
    anonymous context and every comparison would be mislabelled.
    """
    return AuthorizationContext(
        id=context_id,
        display_name=context_id,
        privilege_rank=rank,
        authentication=build_context(
            AuthMode.BEARER_TOKEN, "https://x.test", token=f"token-{context_id}"
        ),
    )


ALICE = _identity("alice", 0)
BOB = _identity("bob", 0)
ADMIN = _identity("admin", 10)
ANON = AuthorizationContext(id="anonymous", display_name="Anonymous")

URL = "https://x.test/private/a"


def verdicts(observations) -> dict[str, ComparisonVerdict]:
    return {o.context_id: o.verdict for o in observations}


def test_an_enforced_boundary_produces_no_violation():
    matrix = build_matrix(
        rules=[
            ("alice", "/private/a", AccessExpectation.ALLOWED),
            ("bob", "/private/a", AccessExpectation.DENIED),
        ],
        known_context_ids=["alice", "bob"],
    )
    observations = analyze_resource(
        URL,
        [ALICE, BOB],
        {"alice": response(200, PRIVATE), "bob": response(403, DENIAL)},
        matrix,
        CONFIG,
    )

    assert verdicts(observations) == {
        "alice": ComparisonVerdict.MATCHES_POLICY,
        "bob": ComparisonVerdict.MATCHES_POLICY,
    }


def test_horizontal_access_to_the_same_content_is_a_violation():
    matrix = build_matrix(
        rules=[
            ("alice", "/private/a", AccessExpectation.ALLOWED),
            ("bob", "/private/a", AccessExpectation.DENIED),
        ],
        known_context_ids=["alice", "bob"],
    )
    observations = analyze_resource(
        URL,
        [ALICE, BOB],
        {"alice": response(200, PRIVATE), "bob": response(200, PRIVATE)},
        matrix,
        CONFIG,
    )

    violation = [o for o in observations if o.verdict is ComparisonVerdict.VIOLATION]
    assert len(violation) == 1
    assert violation[0].context_id == "bob"
    assert violation[0].kind is AuthorizationTestKind.HORIZONTAL
    assert violation[0].equivalent_to_reference is True


def test_a_200_with_different_content_is_not_a_violation():
    """The single biggest false positive in authorization scanning."""
    matrix = build_matrix(
        rules=[
            ("alice", "/private/a", AccessExpectation.ALLOWED),
            ("bob", "/private/a", AccessExpectation.DENIED),
        ],
        known_context_ids=["alice", "bob"],
    )
    observations = analyze_resource(
        URL,
        [ALICE, BOB],
        {"alice": response(200, PRIVATE), "bob": response(200, OTHER)},
        matrix,
        CONFIG,
    )

    bob = next(o for o in observations if o.context_id == "bob")
    assert bob.verdict is ComparisonVerdict.UNKNOWN
    assert bob.equivalent_to_reference is False


def test_vertical_access_is_classified_by_privilege_rank():
    matrix = build_matrix(
        rules=[
            ("admin", "/admin", AccessExpectation.ALLOWED),
            ("alice", "/admin", AccessExpectation.DENIED),
        ],
        known_context_ids=["alice", "admin"],
    )
    observations = analyze_resource(
        "https://x.test/admin",
        [ALICE, ADMIN],
        {"alice": response(200, PRIVATE), "admin": response(200, PRIVATE)},
        matrix,
        CONFIG,
    )

    violation = next(o for o in observations if o.verdict is ComparisonVerdict.VIOLATION)
    assert violation.context_id == "alice"
    assert violation.kind is AuthorizationTestKind.VERTICAL


def test_anonymous_access_is_classified_as_anonymous():
    matrix = build_matrix(
        rules=[
            ("alice", "/private/a", AccessExpectation.ALLOWED),
            ("anonymous", "/private/a", AccessExpectation.DENIED),
        ],
        known_context_ids=["alice", "anonymous"],
    )
    observations = analyze_resource(
        URL,
        [ANON, ALICE],
        {"anonymous": response(200, PRIVATE), "alice": response(200, PRIVATE)},
        matrix,
        CONFIG,
    )

    violation = next(o for o in observations if o.verdict is ComparisonVerdict.VIOLATION)
    assert violation.context_id == "anonymous"
    assert violation.kind is AuthorizationTestKind.ANONYMOUS


def test_object_level_access_uses_declared_ownership():
    matrix = build_matrix(
        ownership=[("/api/orders/101", "alice")], known_context_ids=["alice", "bob"]
    )
    url = "https://x.test/api/orders/101"
    observations = analyze_resource(
        url,
        [ALICE, BOB],
        {"alice": response(200, PRIVATE), "bob": response(200, PRIVATE)},
        matrix,
        CONFIG,
    )

    violation = next(o for o in observations if o.verdict is ComparisonVerdict.VIOLATION)
    assert violation.context_id == "bob"
    assert violation.kind is AuthorizationTestKind.OBJECT_LEVEL
    assert violation.reference_context_id == "alice"


def test_without_ownership_the_same_access_is_only_unknown():
    """No declared owner, no declared rule: the scanner has nothing to claim."""
    url = "https://x.test/api/orders/101"
    observations = analyze_resource(
        url,
        [ALICE, BOB],
        {"alice": response(200, PRIVATE), "bob": response(200, PRIVATE)},
        AuthorizationMatrix(),
        CONFIG,
    )

    assert {o.verdict for o in observations} == {ComparisonVerdict.UNKNOWN}
    assert all(o.expected is AccessExpectation.UNKNOWN for o in observations)


def test_a_denial_where_access_was_expected_is_a_conflict_not_a_finding():
    matrix = build_matrix(
        rules=[("alice", "/private/a", AccessExpectation.ALLOWED)],
        known_context_ids=["alice"],
    )
    observations = analyze_resource(
        URL, [ALICE], {"alice": response(403, DENIAL)}, matrix, CONFIG
    )

    assert observations[0].verdict is ComparisonVerdict.CONFLICT


def test_without_a_reference_nothing_is_claimed():
    """Access was expected to be denied and was not — but nobody legitimate got it."""
    matrix = build_matrix(
        rules=[("bob", "/private/a", AccessExpectation.DENIED)],
        known_context_ids=["bob"],
    )
    observations = analyze_resource(
        URL, [BOB], {"bob": response(200, PRIVATE)}, matrix, CONFIG
    )

    assert observations[0].verdict is ComparisonVerdict.UNKNOWN


def test_a_missing_response_is_unknown():
    matrix = build_matrix(
        rules=[("bob", "/private/a", AccessExpectation.DENIED)],
        known_context_ids=["bob"],
    )
    observations = analyze_resource(URL, [BOB], {"bob": None}, matrix, CONFIG)

    assert observations[0].verdict is ComparisonVerdict.UNKNOWN
    assert observations[0].observed is ObservedAccess.INCONCLUSIVE


# --------------------------------------------------------------------------- #
# 5. Findings built from observations
# --------------------------------------------------------------------------- #


def violation_observation(kind_url: str, contexts, responses, matrix):
    observations = analyze_resource(kind_url, contexts, responses, matrix, CONFIG)
    return next(o for o in observations if o.verdict is ComparisonVerdict.VIOLATION)


def test_a_finding_carries_no_response_content():
    matrix = build_matrix(
        ownership=[("/api/orders/101", "alice")], known_context_ids=["alice", "bob"]
    )
    secret_body = f"<html><body>PRIVATE-RECORD-42 {_FILLER}</body></html>"
    observation = violation_observation(
        "https://x.test/api/orders/101",
        [ALICE, BOB],
        {"alice": response(200, secret_body), "bob": response(200, secret_body)},
        matrix,
    )

    finding = build_finding(observation)
    rendered = " ".join(
        [finding.title, finding.description, finding.evidence, finding.impact,
         finding.remediation, finding.subject or ""]
    )
    assert "PRIVATE-RECORD-42" not in rendered
    assert _FILLER.strip() not in rendered
    assert finding.category is FindingCategory.AUTHORIZATION
    assert finding.rule is FindingRule.AUTHZ_OBJECT_LEVEL_ACCESS
    assert finding.confidence is FindingConfidence.HIGH


def test_two_identities_on_one_resource_stay_separate_findings():
    """Merging them would erase which boundary failed."""
    matrix = build_matrix(
        rules=[
            ("admin", "/admin", AccessExpectation.ALLOWED),
            ("alice", "/admin", AccessExpectation.DENIED),
            ("bob", "/admin", AccessExpectation.DENIED),
        ],
        known_context_ids=["alice", "bob", "admin"],
    )
    observations = analyze_resource(
        "https://x.test/admin",
        [ALICE, BOB, ADMIN],
        {
            "alice": response(200, PRIVATE),
            "bob": response(200, PRIVATE),
            "admin": response(200, PRIVATE),
        },
        matrix,
        CONFIG,
    )
    findings = [
        build_finding(o) for o in observations if o.verdict is ComparisonVerdict.VIOLATION
    ]

    assert len(findings) == 2
    assert len({f.identity for f in findings}) == 2


# --------------------------------------------------------------------------- #
# 6. The budget
# --------------------------------------------------------------------------- #


def test_the_request_budget_fails_closed():
    budget = AuthorizationBudget(limits=AuthorizationBudgetLimits(max_requests=2))

    assert budget.reserve_request() is True
    assert budget.reserve_request() is True
    assert budget.reserve_request() is False
    assert budget.exhausted() is True


def test_the_endpoint_budget_fails_closed():
    budget = AuthorizationBudget(limits=AuthorizationBudgetLimits(max_endpoints=1))

    assert budget.start_endpoint() is True
    assert budget.start_endpoint() is False


def test_comparisons_are_capped_per_endpoint():
    budget = AuthorizationBudget(
        limits=AuthorizationBudgetLimits(max_comparisons_per_endpoint=2)
    )

    assert budget.reserve_comparison("/a") is True
    assert budget.reserve_comparison("/a") is True
    assert budget.reserve_comparison("/a") is False
    # A different endpoint has its own allowance.
    assert budget.reserve_comparison("/b") is True


# --------------------------------------------------------------------------- #
# 7. End to end: the secure fixture must stay silent
# --------------------------------------------------------------------------- #


def test_a_correctly_protected_application_produces_no_findings(secure_target):
    """The most important test here: no false positives on a correct app."""
    plan = AuthorizationPlan(
        contexts=standard_contexts(secure_target.base_url), matrix=standard_matrix()
    )
    report = run_scan(secure_target.base_url, plan)

    assert authz_findings(report) == []
    assert report.authorization is not None
    assert report.authorization.enabled is True
    assert report.authorization.endpoints_tested > 0
    assert report.authorization.comparisons > 0


def test_only_get_requests_are_sent(secure_target):
    """Read-only by design: nothing here can change the target's state."""
    before = len(secure_target.received)
    plan = AuthorizationPlan(
        contexts=standard_contexts(secure_target.base_url), matrix=standard_matrix()
    )
    run_scan(secure_target.base_url, plan)

    methods = {entry["method"] for entry in secure_target.received[before:]}
    assert methods == {"GET"}


def test_each_identity_receives_only_its_own_credential(secure_target):
    """A shared cookie jar or a shared client would break this."""
    before = len(secure_target.received)
    plan = AuthorizationPlan(
        contexts=standard_contexts(secure_target.base_url), matrix=standard_matrix()
    )
    run_scan(secure_target.base_url, plan)

    seen = secure_target.received[before:]
    headers = {entry["authorization"] for entry in seen}
    assert headers <= {
        None,
        f"Bearer {ALICE_TOKEN}",
        f"Bearer {BOB_TOKEN}",
        f"Bearer {ADMIN_TOKEN}",
    }
    # No request ever carried two credentials, and none carried a cookie the
    # target set during an earlier identity's request.
    assert all(entry["cookie"] is None for entry in seen)


# --------------------------------------------------------------------------- #
# 8. End to end: the broken fixture must be caught
# --------------------------------------------------------------------------- #


def test_a_broken_application_produces_the_expected_findings(broken_target):
    plan = AuthorizationPlan(
        contexts=standard_contexts(broken_target.base_url), matrix=standard_matrix()
    )
    report = run_scan(broken_target.base_url, plan)

    rules = {group.data.rule for group in authz_findings(report)}
    assert FindingRule.AUTHZ_HORIZONTAL_ACCESS in rules, rules
    assert FindingRule.AUTHZ_VERTICAL_ACCESS in rules, rules
    assert FindingRule.AUTHZ_OBJECT_LEVEL_ACCESS in rules, rules
    # Anonymous is still refused by the broken fixture, so nothing claims it is.
    assert FindingRule.AUTHZ_ANONYMOUS_ACCESS not in rules


def test_the_findings_name_the_identity_and_the_resource(broken_target):
    plan = AuthorizationPlan(
        contexts=standard_contexts(broken_target.base_url), matrix=standard_matrix()
    )
    report = run_scan(broken_target.base_url, plan)

    subjects = {group.data.subject for group in authz_findings(report)}
    assert any(s and s.startswith("bob:") and "/private/a" in s for s in subjects), subjects
    assert any(s and s.startswith("alice:") and "/admin" in s for s in subjects), subjects


def test_no_credential_or_body_reaches_a_finding(broken_target):
    plan = AuthorizationPlan(
        contexts=standard_contexts(broken_target.base_url), matrix=standard_matrix()
    )
    report = run_scan(broken_target.base_url, plan)

    rendered = " ".join(
        f"{g.data.title} {g.data.description} {g.data.evidence} {g.data.impact} "
        f"{g.data.remediation} {g.data.subject}"
        for g in authz_findings(report)
    )
    for secret in (ALICE_TOKEN, BOB_TOKEN, ADMIN_TOKEN):
        assert secret not in rendered
    assert "Bearer" not in rendered
    assert "Private notes belonging to" not in rendered
    assert _FILLER.strip() not in rendered


# --------------------------------------------------------------------------- #
# 9. Not configured, cancellation, and scope
# --------------------------------------------------------------------------- #


def test_without_a_policy_nothing_is_claimed(secure_target):
    """Identities but no expectations: access is observed, never judged."""
    plan = AuthorizationPlan(contexts=standard_contexts(secure_target.base_url))
    report = run_scan(secure_target.base_url, plan)

    assert authz_findings(report) == []
    assert report.authorization is not None
    assert report.authorization.unknown == report.authorization.comparisons
    assert report.authorization.comparisons > 0


def test_one_identity_is_not_enough_to_compare(secure_target):
    plan = AuthorizationPlan(
        contexts=(context(secure_target.base_url, "alice", ALICE_TOKEN),)
    )
    report = run_scan(secure_target.base_url, plan)

    assert report.authorization is not None
    assert report.authorization.enabled is False


def test_a_disabled_stage_sends_nothing(secure_target):
    before = len(secure_target.received)
    plan = AuthorizationPlan(
        contexts=standard_contexts(secure_target.base_url), matrix=standard_matrix()
    )
    WebScanner(
        scanner_config(),
        crawl_config=CrawlConfig(enabled=False),
        detectors=[],
        authz_config=AuthorizationConfig(enabled=False),
        authorization=plan,
    ).scan_sync(secure_target.base_url)

    paths = {entry["path"] for entry in secure_target.received[before:]}
    assert "/private/a" not in paths


def test_cancellation_stops_authorization_requests(secure_target):
    before = len(secure_target.received)
    plan = AuthorizationPlan(
        contexts=standard_contexts(secure_target.base_url), matrix=standard_matrix()
    )
    report = WebScanner(
        scanner_config(),
        crawl_config=CrawlConfig(),
        detectors=[],
        authz_config=AuthorizationConfig(enabled=True),
        authorization=plan,
        cancellation=CancellationToken(lambda: True),
    ).scan_sync(secure_target.base_url)

    assert report.cancelled is True
    # Cancellation is observed at the first boundary, before any identity is
    # switched to, so the stage sends nothing at all.
    assert secure_target.received[before:] == []


def test_the_request_budget_bounds_the_stage(secure_target):
    before = len(secure_target.received)
    plan = AuthorizationPlan(
        contexts=standard_contexts(secure_target.base_url), matrix=standard_matrix()
    )
    run_scan(
        secure_target.base_url,
        plan,
        limits=AuthorizationBudgetLimits(max_requests=3, max_endpoints=50),
    )

    # Crawl traffic is in the same list, so the assertion is on the ceiling
    # holding rather than on an exact count.
    authz_like = [
        entry
        for entry in secure_target.received[before:]
        if entry["authorization"] is not None
    ]
    assert len(authz_like) <= 3


def test_credentials_are_not_offered_off_origin(secure_target, broken_target):
    """Each identity is bound to the origin its scan named, as in phase 11."""
    ctx = context(secure_target.base_url, "alice", ALICE_TOKEN)

    assert ctx.authentication.applies_to(f"{secure_target.base_url}/private/a") is True
    assert ctx.authentication.applies_to(f"{broken_target.base_url}/private/a") is False
    assert dict(ctx.authentication.headers_for(f"{broken_target.base_url}/x")) == {}


def test_a_context_never_renders_its_credential(secure_target):
    ctx = context(secure_target.base_url, "alice", ALICE_TOKEN)
    for rendered in (repr(ctx), str(ctx), f"{ctx}", "%s" % (ctx,)):
        assert ALICE_TOKEN not in rendered


# --------------------------------------------------------------------------- #
# 10. The API
# --------------------------------------------------------------------------- #


@pytest.fixture
def client():
    with TestClient(api_app) as test_client:
        yield test_client


def register(client: TestClient) -> uuid.UUID:
    email = f"authz-{secrets.token_hex(6)}@example.com"
    response_ = client.post(
        "/api/auth/register",
        json={
            "name": "Authz Test",
            "email": email,
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert response_.status_code == 201, response_.text
    return uuid.UUID(client.get("/api/auth/me").json()["id"])


def bearer_payload(context_id: str, token: str, **extra) -> dict:
    return {
        "id": context_id,
        "label": context_id,
        "authentication": {"mode": "BEARER_TOKEN", "token": token},
        **extra,
    }


@pytest.mark.parametrize(
    "authorization",
    [
        # Only one identity, and anonymous turned off: nothing to compare.
        {"enabled": True, "include_anonymous": False,
         "contexts": [{"id": "a", "label": "a",
                       "authentication": {"mode": "BEARER_TOKEN", "token": "t"}}]},
        # Duplicate ids.
        {"enabled": True, "contexts": [
            {"id": "a", "label": "a", "authentication": {"mode": "BEARER_TOKEN", "token": "t"}},
            {"id": "a", "label": "a2", "authentication": {"mode": "BEARER_TOKEN", "token": "u"}}]},
        # The reserved id.
        {"enabled": True, "contexts": [
            {"id": "anonymous", "label": "x",
             "authentication": {"mode": "BEARER_TOKEN", "token": "t"}}]},
        # A named identity with no credential.
        {"enabled": True, "contexts": [{"id": "a", "label": "a",
                                        "authentication": {"mode": "NONE"}}]},
        # A rule naming an identity that was not supplied.
        {"enabled": True, "contexts": [
            {"id": "a", "label": "a", "authentication": {"mode": "BEARER_TOKEN", "token": "t"}}],
         "rules": [{"context_id": "ghost", "resource": "/x", "expected": "DENIED"}]},
        # Ownership naming an identity that was not supplied.
        {"enabled": True, "contexts": [
            {"id": "a", "label": "a", "authentication": {"mode": "BEARER_TOKEN", "token": "t"}}],
         "ownership": [{"resource": "/x", "owner": "ghost"}]},
        # An injection attempt in a credential still fails phase-11 validation.
        {"enabled": True, "contexts": [
            {"id": "a", "label": "a",
             "authentication": {"mode": "BEARER_TOKEN", "token": "t\r\nX-Injected: 1"}}]},
    ],
)
def test_malformed_authorization_is_refused_before_a_scan_runs(client, authorization):
    register(client)
    response_ = client.post(
        "/api/scans",
        json={"target_url": "https://example.test/", "authorization": authorization},
    )

    assert response_.status_code == 422, response_.text
    assert client.get("/api/scans").json()["total"] == 0


def test_a_policy_error_never_echoes_a_credential(client):
    register(client)
    secret = "sup3r-secret-authz-token"
    response_ = client.post(
        "/api/scans",
        json={
            "target_url": "https://example.test/",
            "authorization": {
                "enabled": True,
                "contexts": [bearer_payload("a", secret)],
                "rules": [{"context_id": "ghost", "resource": "/x", "expected": "DENIED"}],
            },
        },
    )

    assert response_.status_code == 422
    assert secret not in response_.text


def insert_scan(user_id: uuid.UUID, **overrides) -> uuid.UUID:
    with SessionLocal() as db:
        scan = Scan(user_id=user_id, target_url="https://example.test/", **overrides)
        db.add(scan)
        db.commit()
        return scan.id


def test_a_scan_response_exposes_coverage_but_no_credential(client):
    user_id = register(client)
    scan_id = insert_scan(
        user_id,
        status=ScanStatus.COMPLETED,
        authz_enabled=True,
        authz_contexts=3,
        authz_context_labels="Anonymous\x1falice\x1fadmin",
        authz_endpoints_eligible=10,
        authz_endpoints_tested=9,
        authz_comparisons=27,
        authz_unknown=4,
        authz_skipped=1,
        authz_failed=0,
    )

    body = client.get(f"/api/scans/{scan_id}").json()

    assert body["authorization"]["enabled"] is True
    assert body["authorization"]["contexts"] == 3
    assert body["authorization"]["context_labels"] == ["Anonymous", "alice", "admin"]
    assert body["authorization"]["comparisons"] == 27
    assert body["authorization"]["unknown"] == 4
    lowered = client.get(f"/api/scans/{scan_id}").text.lower()
    for banned in ("bearer ", "set-cookie", "token\":\"", "password"):
        assert banned not in lowered, banned


def test_the_report_carries_authorization_coverage(client):
    user_id = register(client)
    scan_id = insert_scan(
        user_id,
        status=ScanStatus.COMPLETED,
        authz_enabled=True,
        authz_contexts=2,
        authz_context_labels="Anonymous\x1falice",
        authz_comparisons=10,
        authz_unknown=10,
    )

    body = client.get(f"/api/scans/{scan_id}/report").json()

    authorization = body["coverage"]["authorization"]
    assert authorization["enabled"] is True
    assert authorization["contexts"] == 2
    assert authorization["context_labels"] == ["Anonymous", "alice"]
    # Every comparison was unknown, so nothing was actually asserted.
    assert authorization["has_policy"] is False


def test_a_scan_without_authorization_says_so(client):
    user_id = register(client)
    scan_id = insert_scan(user_id, status=ScanStatus.COMPLETED)

    body = client.get(f"/api/scans/{scan_id}/report").json()

    assert body["coverage"]["authorization"]["enabled"] is False
    assert body["coverage"]["authorization"]["has_policy"] is False
    assert body["coverage"]["authorization"]["comparisons"] == 0


def test_another_user_cannot_read_authorization_coverage(client):
    owner_id = register(client)
    scan_id = insert_scan(owner_id, status=ScanStatus.COMPLETED, authz_enabled=True)

    with TestClient(api_app) as other:
        register(other)
        assert other.get(f"/api/scans/{scan_id}").status_code == 404
        assert other.get(f"/api/scans/{scan_id}/report").status_code == 404


@pytest.fixture
def allow_loopback(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "SCANNER_ALLOW_PRIVATE_NETWORKS", True)
    yield


def test_an_end_to_end_scan_persists_coverage_and_no_credential(
    client, allow_loopback, broken_target
):
    from app.scanner.authorization.matrix import AuthorizationPlan as Plan

    user_id = register(client)
    plan = Plan(
        contexts=standard_contexts(broken_target.base_url), matrix=standard_matrix()
    )

    with SessionLocal() as db:
        scan_id = scan_service.enqueue_scan(
            db, db.get(User, user_id), broken_target.base_url, AuthMode.NONE, plan
        )
    scan_service.execute_scan(scan_id, authorization=plan)

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        row = {c.name: getattr(scan, c.name) for c in scan.__table__.columns}

    assert row["authz_enabled"] is True
    assert (row["authz_comparisons"] or 0) > 0
    for secret in (ALICE_TOKEN, BOB_TOKEN, ADMIN_TOKEN):
        assert secret not in str(row)

    for path in ("", "/findings", "/endpoints", "/report"):
        body = client.get(f"/api/scans/{scan_id}{path}").text
        for secret in (ALICE_TOKEN, BOB_TOKEN, ADMIN_TOKEN):
            assert secret not in body, path
        assert "Bearer " not in body, path

    findings = client.get(f"/api/scans/{scan_id}/findings").json()["items"]
    rules = {finding["rule_id"] for finding in findings}
    assert any(rule.startswith("AUTHZ_") for rule in rules), sorted(rules)


def test_application_logging_does_not_emit_an_identity_credential(
    client, allow_loopback, caplog, secure_target
):
    import logging

    from app.scanner.authorization.matrix import AuthorizationPlan as Plan

    user_id = register(client)
    plan = Plan(
        contexts=standard_contexts(secure_target.base_url), matrix=standard_matrix()
    )

    with caplog.at_level(logging.DEBUG, logger="app"):
        with SessionLocal() as db:
            scan_id = scan_service.enqueue_scan(
                db, db.get(User, user_id), secure_target.base_url, AuthMode.NONE, plan
            )
        scan_service.execute_scan(scan_id, authorization=plan)

    emitted = "\n".join(record.getMessage() for record in caplog.records)
    for secret in (ALICE_TOKEN, BOB_TOKEN, ADMIN_TOKEN):
        assert secret not in emitted
    assert "Authorization:" not in emitted
