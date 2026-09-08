"""Active-probe framework: request building, budget, comparison, engine.

All deterministic — the engine's transport is faked, so scope enforcement,
budget exhaustion and error handling are exercised without a network.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlsplit

import pytest

from app.scanner.active.budget import ProbeBudget, ProbeBudgetLimits
from app.scanner.active.comparison import (
    body_similarity,
    compare,
    contains_marker,
    content_type_changed,
    final_url_changed,
    media_type,
    response_text,
    size_delta,
    status_changed,
    timing_delta_ms,
)
from app.scanner.active.engine import ProbeEngine
from app.scanner.active.requests import build_probe_url, generate_unique_marker
from app.scanner.active.types import (
    Eligibility,
    ProbeFailure,
    ProbePurpose,
    ProbeRequest,
    ProbeTarget,
)
from app.scanner.crawler.url_normalizer import Origin
from app.scanner.types import RawHttpResponse, ScanErrorCode, ScannerError

ORIGIN = Origin(scheme="https", host="x.test", port=443)
TARGET = ProbeTarget(url="https://x.test/search?q&page", parameters=("q", "page"),
                     content_type="text/html")


def response(body: str = "<html>ok</html>", *, status: int = 200,
             content_type: str = "text/html; charset=utf-8",
             url: str = "https://x.test/search", elapsed: int = 10) -> RawHttpResponse:
    return RawHttpResponse(
        status_code=status,
        headers={"content-type": content_type},
        final_url=url,
        is_https=True,
        redirect_count=0,
        elapsed_ms=elapsed,
        body=body.encode("utf-8"),
    )


class FakeFetcher:
    """Stands in for HttpFetcher. Records what it was asked to fetch."""

    def __init__(self, result=None, error: ScannerError | None = None):
        self.result = result if result is not None else response()
        self.error = error
        self.urls: list[str] = []

    async def fetch(self, target, *, read_body: bool = True):
        self.urls.append(target.normalized_url)
        if self.error is not None:
            raise self.error
        return self.result


def engine_with(fetcher, limits: ProbeBudgetLimits | None = None) -> ProbeEngine:
    return ProbeEngine(fetcher, ORIGIN, ProbeBudget(limits=limits or ProbeBudgetLimits()))


# =========================================================================== #
# Probe request building
# =========================================================================== #


def test_replaces_only_the_target_parameter():
    url = build_probe_url("https://x.test/s?q=old&page=2", "q", "MARKER")
    query = parse_qs(urlsplit(url).query, keep_blank_values=True)
    assert query["q"] == ["MARKER"]


def test_other_parameters_are_preserved_as_names_with_filler():
    url = build_probe_url("https://x.test/s?q&page&sort", "q", "MARKER")
    query = parse_qs(urlsplit(url).query, keep_blank_values=True)
    assert set(query) == {"q", "page", "sort"}
    assert query["page"] == ["1"] and query["sort"] == ["1"]


def test_scheme_host_port_and_path_are_preserved():
    url = build_probe_url("https://x.test:8443/a/b/c?q", "q", "MARKER")
    parts = urlsplit(url)
    assert parts.scheme == "https"
    assert parts.netloc == "x.test:8443"
    assert parts.path == "/a/b/c"


def test_parameter_ordering_is_deterministic():
    first = build_probe_url("https://x.test/s?a&b&c", "b", "M")
    second = build_probe_url("https://x.test/s?a&b&c", "b", "M")
    assert first == second
    assert [k for k, _ in (p.split("=") for p in urlsplit(first).query.split("&"))] == ["a", "b", "c"]


def test_test_values_are_url_encoded():
    url = build_probe_url("https://x.test/s?q", "q", "a b\"'><&=")
    # Nothing raw survives into the query string itself.
    assert " " not in urlsplit(url).query
    assert parse_qs(urlsplit(url).query)["q"] == ['a b"\'><&=']


def test_fragments_are_not_sent():
    url = build_probe_url("https://x.test/s?q#section", "q", "M")
    assert "#" not in url


def test_missing_parameter_is_added():
    url = build_probe_url("https://x.test/s", "q", "M")
    assert parse_qs(urlsplit(url).query)["q"] == ["M"]


def test_none_parameter_reissues_the_endpoint():
    url = build_probe_url("https://x.test/s?a&b", None, "unused")
    query = parse_qs(urlsplit(url).query)
    assert set(query) == {"a", "b"}
    assert "unused" not in url


def test_markers_are_unique_and_alphanumeric():
    markers = {generate_unique_marker() for _ in range(50)}
    assert len(markers) == 50
    assert all(m.isalnum() for m in markers)
    assert all(m.startswith("ws") for m in markers)


def test_marker_length_is_validated():
    with pytest.raises(ValueError):
        generate_unique_marker(length=2)


# =========================================================================== #
# Budget
# =========================================================================== #


def test_per_parameter_limit():
    budget = ProbeBudget(limits=ProbeBudgetLimits(per_parameter=2, per_endpoint=99, per_scan=99))
    assert budget.reserve("e", "q") and budget.reserve("e", "q")
    assert budget.reserve("e", "q") is False
    # A different parameter on the same endpoint still has its own allowance.
    assert budget.reserve("e", "page") is True


def test_per_endpoint_limit():
    budget = ProbeBudget(limits=ProbeBudgetLimits(per_parameter=9, per_endpoint=3, per_scan=99))
    for i in range(3):
        assert budget.reserve("e", f"p{i}") is True
    assert budget.reserve("e", "other") is False
    assert budget.reserve("other-endpoint", "p") is True


def test_per_scan_limit():
    budget = ProbeBudget(limits=ProbeBudgetLimits(per_parameter=9, per_endpoint=9, per_scan=4))
    for i in range(4):
        assert budget.reserve(f"e{i}", "q") is True
    assert budget.exhausted() is True
    assert budget.reserve("e-new", "q") is False


def test_exhausted_budget_consumes_nothing():
    budget = ProbeBudget(limits=ProbeBudgetLimits(per_parameter=1, per_endpoint=1, per_scan=1))
    assert budget.reserve("e", "q") is True
    before = budget.scan_spent
    assert budget.reserve("e", "q") is False
    assert budget.scan_spent == before, "a refused reservation must not spend"


def test_detectors_share_one_scan_budget():
    """Two detectors probing the same scan draw from the same allowance."""
    budget = ProbeBudget(limits=ProbeBudgetLimits(per_parameter=5, per_endpoint=5, per_scan=3))
    assert budget.reserve("e", "q") is True      # detector A
    assert budget.reserve("e", "q") is True      # detector B
    assert budget.reserve("e", "q") is True      # detector A
    assert budget.reserve("e", "q") is False     # nothing left for either


def test_limits_must_be_positive():
    with pytest.raises(ValueError):
        ProbeBudgetLimits(per_parameter=0)


# =========================================================================== #
# Response comparison
# =========================================================================== #


def test_status_comparison():
    assert status_changed(response(status=200), response(status=200)) is False
    assert status_changed(response(status=200), response(status=500)) is True


def test_content_type_comparison():
    html, json_ = response(), response(content_type="application/json")
    assert content_type_changed(html, html) is False
    assert content_type_changed(html, json_) is True
    assert media_type(json_) == "application/json"


def test_final_url_comparison():
    assert final_url_changed(response(url="https://x.test/a"), response(url="https://x.test/a")) is False
    assert final_url_changed(response(url="https://x.test/a"), response(url="https://x.test/b")) is True


def test_size_and_timing_deltas():
    assert size_delta(response("ab"), response("abcd")) == 2
    assert timing_delta_ms(response(elapsed=10), response(elapsed=35)) == 25


def test_body_similarity():
    assert body_similarity(response("<p>hello world</p>"), response("<p>hello world</p>")) == 1.0
    assert body_similarity(response(""), response("")) == 1.0
    assert body_similarity(response(""), response("<p>x</p>")) == 0.0
    assert body_similarity(response("<p>abcdefgh</p>"), response("<p>abcdefgi</p>")) > 0.8
    assert body_similarity(response("aaaaaaaa"), response("zzzzzzzz")) < 0.5


def test_marker_containment_is_case_sensitive():
    body = response("<div>wsABC123</div>")
    assert contains_marker(body, "wsABC123") is True
    assert contains_marker(body, "wsabc123") is False
    assert contains_marker(body, "") is False


def test_compare_summarises_every_difference():
    delta = compare(response("aaa", status=200), response("bbbbb", status=302, elapsed=40))
    assert delta.status_changed is True
    assert delta.size_delta == 2
    assert delta.timing_delta_ms == 30
    assert 0.0 <= delta.body_similarity <= 1.0


def test_response_text_decodes_using_the_declared_charset():
    raw = RawHttpResponse(
        status_code=200,
        headers={"content-type": "text/html; charset=iso-8859-1"},
        final_url="https://x.test/",
        is_https=True,
        redirect_count=0,
        elapsed_ms=1,
        body="Über".encode("latin-1"),
    )
    assert "Über" in response_text(raw)


# =========================================================================== #
# Engine: scope, budget, errors
# =========================================================================== #


def request_for(parameter: str = "q", value: str = "MARKER") -> ProbeRequest:
    return ProbeRequest(target=TARGET, parameter=parameter, value=value,
                        purpose=ProbePurpose.PROBE)


def test_engine_sends_within_scope():
    fetcher = FakeFetcher()
    outcome = asyncio.run(engine_with(fetcher).send(request_for()))

    assert outcome.ok is True
    assert outcome.status_code == 200
    assert fetcher.urls[0].startswith("https://x.test/search")


def test_engine_refuses_when_budget_is_exhausted():
    fetcher = FakeFetcher()
    engine = engine_with(fetcher, ProbeBudgetLimits(per_parameter=1, per_endpoint=1, per_scan=1))

    first = asyncio.run(engine.send(request_for()))
    second = asyncio.run(engine.send(request_for()))

    assert first.ok is True
    assert second.ok is False
    assert second.failure is ProbeFailure.BUDGET_EXHAUSTED
    # Crucially, the refused probe never reached the transport.
    assert len(fetcher.urls) == 1


def test_engine_rejects_an_out_of_scope_target():
    fetcher = FakeFetcher()
    external = ProbeTarget(url="https://evil.test/s?q", parameters=("q",),
                           content_type="text/html")
    outcome = asyncio.run(
        engine_with(fetcher).send(ProbeRequest(target=external, parameter="q", value="M"))
    )

    assert outcome.failure is ProbeFailure.OUT_OF_SCOPE
    assert fetcher.urls == [], "an out-of-scope probe must never be sent"


def test_engine_rejects_an_unsupported_scheme():
    fetcher = FakeFetcher()
    bad = ProbeTarget(url="javascript:alert(1)", parameters=("q",), content_type="text/html")
    outcome = asyncio.run(
        engine_with(fetcher).send(ProbeRequest(target=bad, parameter="q", value="M"))
    )

    assert outcome.failure in {ProbeFailure.INVALID_URL, ProbeFailure.OUT_OF_SCOPE}
    assert fetcher.urls == []


def test_engine_rejects_a_response_redirected_out_of_scope():
    fetcher = FakeFetcher(result=response(url="https://elsewhere.test/landing"))
    outcome = asyncio.run(engine_with(fetcher).send(request_for()))

    assert outcome.failure is ProbeFailure.OUT_OF_SCOPE
    assert outcome.response is None


@pytest.mark.parametrize(
    "code",
    [ScanErrorCode.TIMEOUT, ScanErrorCode.DNS_FAILURE, ScanErrorCode.CONNECTION_FAILED,
     ScanErrorCode.TLS_ERROR, ScanErrorCode.EXTERNAL_REDIRECT],
)
def test_engine_turns_transport_errors_into_outcomes(code):
    fetcher = FakeFetcher(error=ScannerError(code, "boom"))
    outcome = asyncio.run(engine_with(fetcher).send(request_for()))

    assert outcome.ok is False
    assert outcome.failure is ProbeFailure.REQUEST_FAILED


def test_engine_survives_an_unexpected_transport_exception():
    class Exploding:
        async def fetch(self, target, *, read_body: bool = True):
            raise RuntimeError("unexpected")

    outcome = asyncio.run(engine_with(Exploding()).send(request_for()))
    assert outcome.failure is ProbeFailure.REQUEST_FAILED


def test_engine_never_raises_for_any_failure_mode():
    """A detector can rely on `send` returning rather than throwing."""
    for fetcher in (
        FakeFetcher(error=ScannerError(ScanErrorCode.TIMEOUT, "t")),
        FakeFetcher(result=response(url="https://other.test/")),
    ):
        outcome = asyncio.run(engine_with(fetcher).send(request_for()))
        assert outcome.ok is False


def test_a_failed_probe_carries_no_response_to_analyse():
    fetcher = FakeFetcher(error=ScannerError(ScanErrorCode.TIMEOUT, "t"))
    outcome = asyncio.run(engine_with(fetcher).send(request_for()))

    assert outcome.response is None
    assert outcome.content_type is None


# =========================================================================== #
# Eligibility
# =========================================================================== #


def test_eligibility_helpers():
    assert bool(Eligibility.yes()) is True
    declined = Eligibility.no("non_html_endpoint")
    assert bool(declined) is False
    assert declined.reason == "non_html_endpoint"
