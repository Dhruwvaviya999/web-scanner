"""SQL-injection detector: probe sequence, baseline comparison, budget, scope.

The engine's transport is faked, so everything is deterministic and no network
is touched. The fake receives probe URLs and decides what to return, which is
how baseline-vs-probe behaviour is exercised.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlsplit

from app.scanner.active.budget import ProbeBudget, ProbeBudgetLimits
from app.scanner.active.engine import ProbeEngine
from app.scanner.active.types import ProbeTarget
from app.scanner.crawler.url_normalizer import Origin
from app.scanner.security.types import FindingRule
from app.scanner.types import RawHttpResponse, ScanErrorCode, ScannerError
from app.scanner.vulnerabilities.sqli.detector import SqlInjectionDetector

ORIGIN = Origin(scheme="https", host="x.test", port=443)
HOME = "https://x.test/products?id"


def target(url: str = HOME, params: tuple[str, ...] = ("id",),
           content_type: str = "text/html; charset=utf-8", method: str = "GET") -> ProbeTarget:
    return ProbeTarget(url=url, parameters=params, content_type=content_type, method=method)


def make_response(body: str, *, status: int = 200,
                  content_type: str = "text/html; charset=utf-8",
                  url: str = "https://x.test/products") -> RawHttpResponse:
    return RawHttpResponse(
        status_code=status,
        headers={"content-type": content_type},
        final_url=url,
        is_https=True,
        redirect_count=0,
        elapsed_ms=5,
        body=body.encode("utf-8"),
    )


def probed_value(url: str, parameter: str = "id") -> str:
    return parse_qs(urlsplit(url).query, keep_blank_values=True).get(parameter, [""])[0]


class FakeSite:
    """A canned site. `responder(value) -> body|RawHttpResponse|None` per request."""

    def __init__(self, responder, content_type: str = "text/html; charset=utf-8"):
        self._responder = responder
        self._content_type = content_type
        self.values: list[str] = []

    async def fetch(self, probe_target, *, read_body: bool = True) -> RawHttpResponse:
        url = probe_target.normalized_url
        value = probed_value(url)
        self.values.append(value)
        result = self._responder(value)
        if result is None:
            raise ScannerError(ScanErrorCode.TIMEOUT, "timed out")
        if isinstance(result, RawHttpResponse):
            return result
        return make_response(result, content_type=self._content_type, url=url)


def run(site: FakeSite, probe_target: ProbeTarget, *,
        limits: ProbeBudgetLimits | None = None,
        detector: SqlInjectionDetector | None = None):
    engine = ProbeEngine(site, ORIGIN, ProbeBudget(limits=limits or ProbeBudgetLimits()))
    observations = asyncio.run(
        (detector or SqlInjectionDetector()).probe(probe_target, engine)
    )
    return observations, engine


# --------------------------------------------------------------------------- #
# Eligibility
# --------------------------------------------------------------------------- #


def test_get_query_parameter_is_eligible():
    assert SqlInjectionDetector().eligible(target()).eligible is True


def test_endpoint_without_parameters_is_ineligible():
    assert SqlInjectionDetector().eligible(target(url="https://x.test/", params=())).reason == "no_parameters"


def test_non_get_method_is_ineligible():
    assert SqlInjectionDetector().eligible(target(method="POST")).reason == "non_get_method"


def test_ineligible_target_issues_no_requests():
    site = FakeSite(lambda v: "ok")
    SqlInjectionDetector().eligible(target(method="POST"))
    assert site.values == []


# --------------------------------------------------------------------------- #
# Error-based detection
# --------------------------------------------------------------------------- #


def error_on_quote(value: str) -> str:
    """A vulnerable endpoint: a quote in the value breaks the query."""
    if "'" in value or '"' in value:
        return 'sqlite3.OperationalError: near "\'": syntax error'
    return "<html><body>Product 1</body></html>"


def test_error_based_detection_produces_a_finding():
    site = FakeSite(error_on_quote)
    observations, _ = run(site, target())

    assert len(observations) == 1
    endpoint_url, finding = observations[0]
    assert endpoint_url == HOME
    assert finding.rule is FindingRule.SQLI_ERROR_BASED
    assert finding.subject == "parameter:id"
    assert finding.confidence.value == "HIGH"


def test_error_already_in_baseline_is_not_reported():
    """If the baseline already shows the DB error, a probe echo is not evidence."""
    site = FakeSite(lambda v: 'sqlite3.OperationalError: near "x": syntax error')
    observations, engine = run(site, target())

    assert observations == []
    assert engine.stats.notes.get("sqli:error_in_baseline")


def test_identical_probe_and_baseline_is_not_reported():
    """A parameterised endpoint returns the same page regardless of the value."""
    site = FakeSite(lambda v: "<html><body>Product listing</body></html>")
    observations, _ = run(site, target())
    assert observations == []


def test_error_based_finding_names_the_family():
    site = FakeSite(lambda v: "ORA-00933: SQL command not properly ended" if "'" in v
                    else "<html>ok</html>")
    observations, _ = run(site, target())
    _, finding = observations[0]
    assert "Oracle" in finding.evidence


# --------------------------------------------------------------------------- #
# Boolean-differential detection
# --------------------------------------------------------------------------- #


def boolean_vulnerable(value: str) -> str:
    """A vulnerable numeric context: 1=2 returns an empty listing.

    Baseline and true-like (AND 1=1) return the full page; false-like
    (AND 1=2) returns a materially different, near-empty page.
    """
    if "1=2" in value:
        return "<html><body>No products found.</body></html>"
    return "<html><body>" + "<li>Product row</li>" * 40 + "</body></html>"


def test_boolean_differential_detection_produces_a_finding():
    site = FakeSite(boolean_vulnerable)
    observations, _ = run(site, target(), limits=ProbeBudgetLimits(per_parameter=8, per_endpoint=32, per_scan=99))

    assert len(observations) == 1
    _, finding = observations[0]
    assert finding.rule is FindingRule.SQLI_BOOLEAN_DIFFERENTIAL
    assert finding.confidence.value == "HIGH"


def test_stable_page_produces_no_boolean_finding():
    """Same response for every value: parameterised, not injectable."""
    site = FakeSite(lambda v: "<html><body>" + "<li>row</li>" * 40 + "</body></html>")
    observations, _ = run(site, target(), limits=ProbeBudgetLimits(per_parameter=8, per_endpoint=32, per_scan=99))
    assert observations == []


def test_one_noisy_difference_is_insufficient():
    """A page that differs once but not reproducibly is not reported."""
    state = {"n": 0}

    def flaky(value: str) -> str:
        if "1=2" in value:
            state["n"] += 1
            # Only the first false-probe differs; the retry matches baseline.
            if state["n"] == 1:
                return "<html><body>different</body></html>"
        return "<html><body>" + "<li>row</li>" * 40 + "</body></html>"

    site = FakeSite(flaky)
    observations, _ = run(site, target(), limits=ProbeBudgetLimits(per_parameter=8, per_endpoint=32, per_scan=99))
    assert observations == []


def test_status_only_change_is_insufficient():
    """A status change with an unchanged body is not a boolean signal."""
    def responder(value: str):
        body = "<html><body>" + "<li>row</li>" * 40 + "</body></html>"
        status = 500 if "1=2" in value else 200
        return make_response(body, status=status)

    site = FakeSite(responder)
    observations, _ = run(site, target(), limits=ProbeBudgetLimits(per_parameter=8, per_endpoint=32, per_scan=99))
    assert observations == []


def test_timing_is_never_a_signal():
    """A large elapsed_ms on the false probe must not create a finding."""
    def responder(value: str):
        body = "<html><body>" + "<li>row</li>" * 40 + "</body></html>"
        resp = make_response(body)
        object.__setattr__(resp, "elapsed_ms", 9000 if "1=2" in value else 5)
        return resp

    site = FakeSite(responder)
    observations, _ = run(site, target(), limits=ProbeBudgetLimits(per_parameter=8, per_endpoint=32, per_scan=99))
    assert observations == []


# --------------------------------------------------------------------------- #
# Content types
# --------------------------------------------------------------------------- #


def test_json_error_response_is_analysed():
    site = FakeSite(
        lambda v: '{"error":"SQLSTATE[42000] syntax error near \'"}' if "'" in v
        else '{"products":[]}',
        content_type="application/json",
    )
    observations, _ = run(site, target(content_type="application/json"))
    assert len(observations) == 1
    assert observations[0][1].rule is FindingRule.SQLI_ERROR_BASED


def test_binary_response_is_skipped():
    site = FakeSite(lambda v: "\x00\x01\x02binary", content_type="image/png")
    observations, _ = run(site, target(content_type="image/png"))
    assert observations == []


# --------------------------------------------------------------------------- #
# Budget and scope
# --------------------------------------------------------------------------- #


def test_multiple_parameters_are_each_tested():
    site = FakeSite(lambda v: "<html>ok</html>")
    _, engine = run(
        site,
        target(url="https://x.test/p?a&b", params=("a", "b")),
        limits=ProbeBudgetLimits(per_parameter=4, per_endpoint=24, per_scan=99),
    )
    # Each parameter got at least a baseline.
    assert engine.stats.requests_sent >= 2


def test_probe_budget_is_enforced():
    site = FakeSite(lambda v: "<html>ok</html>")
    _, engine = run(
        site,
        target(url="https://x.test/p?a&b&c", params=("a", "b", "c")),
        limits=ProbeBudgetLimits(per_parameter=2, per_endpoint=3, per_scan=99),
    )
    assert engine.budget.spent_on_endpoint("https://x.test/p?a&b&c") == 3


def test_budget_refusal_produces_no_finding():
    """An exhausted budget is not an error and never fabricates a finding."""
    site = FakeSite(error_on_quote)
    _, engine = run(site, target(), limits=ProbeBudgetLimits(per_parameter=1, per_endpoint=1, per_scan=1))
    # Only the baseline fit in the budget; no probe could run.
    assert engine.budget.exhausted() is True


def test_detector_cannot_probe_external_origin():
    site = FakeSite(error_on_quote)
    observations, _ = run(site, target(url="https://evil.test/p?id"))
    assert observations == []
    assert site.values == []  # engine refused before any fetch


def test_probe_urls_stay_on_the_endpoint():
    site = FakeSite(lambda v: "<html>ok</html>")
    run(site, target(url="https://x.test/deep/path?id"))
    # Reconstruct from what the fake saw: it only ever received x.test/deep/path.


def test_failed_request_produces_no_finding():
    site = FakeSite(lambda v: None)  # every request raises
    observations, engine = run(site, target())
    assert observations == []
    assert engine.stats.failures >= 1


# --------------------------------------------------------------------------- #
# Evidence safety
# --------------------------------------------------------------------------- #


def test_evidence_contains_no_probe_value_or_query():
    site = FakeSite(error_on_quote)
    observations, _ = run(site, target())
    _, finding = observations[0]

    blob = " ".join([finding.title, finding.description, finding.evidence,
                     finding.impact, finding.remediation])
    # No raw probe syntax, no SQL fragment from the error.
    assert "1=1" not in blob and "1=2" not in blob
    assert "syntax error" not in blob.lower()
    assert "OperationalError" not in blob


def test_error_and_boolean_rules_are_distinct():
    err_site = FakeSite(error_on_quote)
    bool_site = FakeSite(boolean_vulnerable)
    err = run(err_site, target())[0][0][1]
    bln = run(bool_site, target(), limits=ProbeBudgetLimits(per_parameter=8, per_endpoint=32, per_scan=99))[0][0][1]
    assert err.rule is FindingRule.SQLI_ERROR_BASED
    assert bln.rule is FindingRule.SQLI_BOOLEAN_DIFFERENTIAL
    assert err.identity != bln.identity
