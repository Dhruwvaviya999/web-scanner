"""Reflected-XSS probe strategy, on the active-probe framework.

The detector no longer owns transport or budget — those moved to the framework
in phase 7 and are covered by `test_active_framework.py`. What remains here is
what is specific to XSS: eligibility, the baseline-then-probe sequence, and
which responses do and do not become findings.

The engine's transport is faked, so no network is touched.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlsplit

from app.scanner.active.budget import ProbeBudget, ProbeBudgetLimits
from app.scanner.active.engine import ProbeEngine
from app.scanner.active.requests import build_probe_url
from app.scanner.active.types import ProbeTarget
from app.scanner.crawler.url_normalizer import Origin
from app.scanner.security.types import FindingRule
from app.scanner.types import RawHttpResponse
from app.scanner.vulnerabilities.xss.detector import ReflectedXssDetector

ORIGIN = Origin(scheme="https", host="x.test", port=443)
HTML = "text/html; charset=utf-8"
HOME = "https://x.test/search?q"


def target(url: str = HOME, params: tuple[str, ...] = ("q",),
           content_type: str = HTML, method: str = "GET") -> ProbeTarget:
    return ProbeTarget(url=url, parameters=params, content_type=content_type, method=method)


class FakeSite:
    """A canned site that echoes a chosen parameter in a chosen context."""

    def __init__(self, *, reflect: str | None = "q",
                 template: str = "<div>{value}</div>",
                 content_type: str = HTML, fail: bool = False, encode: bool = False,
                 echo_all: bool = False):
        self.reflect = reflect
        self.template = template
        self.content_type = content_type
        self.fail = fail
        self.encode = encode
        self.echo_all = echo_all
        self.urls: list[str] = []

    async def fetch(self, probe_target, *, read_body: bool = True) -> RawHttpResponse:
        url = probe_target.normalized_url
        self.urls.append(url)
        if self.fail:
            from app.scanner.types import ScanErrorCode, ScannerError

            raise ScannerError(ScanErrorCode.TIMEOUT, "timed out")

        query = parse_qs(urlsplit(url).query, keep_blank_values=True)
        if self.echo_all:
            value = " ".join(v for values in query.values() for v in values)
        elif self.reflect:
            value = query.get(self.reflect, [""])[0]
        else:
            value = ""

        if self.encode:
            value = (
                value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace('"', "&quot;").replace("'", "&#x27;")
            )

        return RawHttpResponse(
            status_code=200,
            headers={"content-type": self.content_type},
            final_url=url,
            is_https=True,
            redirect_count=0,
            elapsed_ms=5,
            body=self.template.format(value=value).encode("utf-8"),
        )


def run(site: FakeSite, probe_target: ProbeTarget, *,
        limits: ProbeBudgetLimits | None = None,
        detector: ReflectedXssDetector | None = None):
    engine = ProbeEngine(site, ORIGIN, ProbeBudget(limits=limits or ProbeBudgetLimits()))
    observations = asyncio.run(
        (detector or ReflectedXssDetector()).probe(probe_target, engine)
    )
    return observations, engine


# --- Eligibility (pure, no requests) ---------------------------------------- #


def test_html_get_endpoint_with_parameters_is_eligible():
    assert ReflectedXssDetector().eligible(target()).eligible is True


def test_non_html_endpoint_is_ineligible():
    decision = ReflectedXssDetector().eligible(target(content_type="application/json"))
    assert decision.eligible is False
    assert decision.reason == "non_html_endpoint"


def test_endpoint_without_parameters_is_ineligible():
    decision = ReflectedXssDetector().eligible(target(url="https://x.test/", params=()))
    assert decision.reason == "no_parameters"


def test_non_get_method_is_ineligible():
    """Phase 7 keeps phase 6's scope: GET query parameters only."""
    decision = ReflectedXssDetector().eligible(target(method="POST"))
    assert decision.reason == "non_get_method"


def test_ineligible_targets_are_filtered_before_any_request():
    """Eligibility is pure — deciding it must not touch the network."""
    site = FakeSite()
    detector = ReflectedXssDetector()
    detector.eligible(target(content_type="image/png"))
    assert site.urls == []


# --- Probe sequence and budget ---------------------------------------------- #


def test_reflected_parameter_produces_a_finding():
    site = FakeSite()
    observations, _ = run(site, target())

    assert len(observations) == 1
    endpoint_url, finding = observations[0]
    assert endpoint_url == HOME
    assert finding.rule is FindingRule.XSS_REFLECTED
    assert finding.subject == "parameter:q"


def test_unreflected_parameter_costs_one_request():
    """No probe is sent when the baseline token does not come back."""
    site = FakeSite(reflect=None, template="<div>static</div>")
    observations, engine = run(site, target())

    assert engine.stats.requests_sent == 1
    assert observations == []


def test_reflected_parameter_costs_two_requests():
    site = FakeSite()
    _, engine = run(site, target())
    assert engine.stats.requests_sent == 2


def test_multiple_parameters_are_each_tested():
    site = FakeSite(reflect="a")
    observations, engine = run(site, target(url="https://x.test/s?a&b", params=("a", "b")))

    assert engine.stats.requests_sent == 3  # a: baseline+probe, b: baseline only
    assert [f.subject for _, f in observations] == ["parameter:a"]


def test_findings_for_different_parameters_stay_distinguishable():
    site = FakeSite(echo_all=True)
    observations, _ = run(site, target(url="https://x.test/s?a&b", params=("a", "b")))

    assert {f.subject for _, f in observations} == {"parameter:a", "parameter:b"}


def test_parameters_per_endpoint_cap_is_respected():
    site = FakeSite(reflect=None)
    params = tuple(f"p{i}" for i in range(20))
    _, engine = run(
        site,
        target(url="https://x.test/s", params=params),
        limits=ProbeBudgetLimits(per_parameter=4, per_endpoint=99, per_scan=99),
        detector=ReflectedXssDetector(max_parameters_per_endpoint=3),
    )
    assert engine.stats.requests_sent == 3


def test_budget_exhaustion_stops_probing():
    site = FakeSite()
    params = tuple(f"p{i}" for i in range(10))
    observations, engine = run(
        site,
        target(url="https://x.test/s", params=params),
        limits=ProbeBudgetLimits(per_parameter=2, per_endpoint=3, per_scan=99),
    )
    # The per-endpoint ceiling caps total requests regardless of parameter count.
    assert engine.stats.requests_sent == 3
    assert engine.budget.spent_on_endpoint("https://x.test/s") == 3


# --- Response handling ------------------------------------------------------ #


def test_safely_encoded_reflection_produces_no_finding():
    site = FakeSite(encode=True)
    observations, engine = run(site, target())

    assert engine.stats.requests_sent == 2  # it reflected, so it was probed
    assert observations == []


def test_non_html_response_stops_analysis():
    site = FakeSite(content_type="application/json")
    observations, _ = run(site, target())
    assert observations == []


def test_failed_request_produces_no_finding():
    site = FakeSite(fail=True)
    observations, engine = run(site, target())

    assert observations == []
    assert engine.stats.failures == 1


def test_script_context_reflection_reaches_high_confidence():
    site = FakeSite(template='<script>var q = "{value}";</script>')
    observations, _ = run(site, target())

    _, finding = observations[0]
    assert finding.severity.value == "HIGH"
    assert finding.confidence.value == "HIGH"


def test_attribute_context_reflection_is_reported():
    site = FakeSite(template='<input value="{value}">')
    observations, _ = run(site, target())

    _, finding = observations[0]
    assert finding.rule is FindingRule.XSS_REFLECTED
    assert "value" in finding.evidence


def test_probe_values_never_reach_the_finding():
    site = FakeSite()
    observations, _ = run(site, target())
    _, finding = observations[0]

    for url in site.urls:
        marker = parse_qs(urlsplit(url).query)["q"][0]
        assert marker not in finding.evidence
        assert marker not in finding.description


# --- Scope: the detector cannot bypass the engine --------------------------- #


def test_detector_cannot_probe_an_external_origin():
    """Even handed an off-origin target, the engine refuses to send."""
    site = FakeSite()
    observations, engine = run(site, target(url="https://evil.test/s?q"))

    assert observations == []
    assert site.urls == []


def test_probe_urls_stay_on_the_endpoint_path():
    site = FakeSite()
    run(site, target(url="https://x.test/deep/path?q"))

    assert site.urls, "expected probes to be sent"
    for url in site.urls:
        parts = urlsplit(url)
        assert parts.scheme == "https"
        assert parts.netloc == "x.test"
        assert parts.path == "/deep/path"


def test_build_probe_url_is_the_only_url_construction():
    """The detector supplies a value; the framework builds the URL."""
    url = build_probe_url("https://x.test/s?q&page", "q", "MARKER")
    query = parse_qs(urlsplit(url).query, keep_blank_values=True)
    assert query["q"] == ["MARKER"]
    assert query["page"] == ["1"]
