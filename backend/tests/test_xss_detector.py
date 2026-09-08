"""Reflected-XSS probing strategy.

The fetcher is injected, so request budget, scope and failure handling are all
deterministic and no network is touched.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlsplit

from app.scanner.security.types import FindingRule
from app.scanner.vulnerabilities.xss.detector import (
    EndpointTarget,
    ReflectedXssDetector,
    XssConfig,
    XssResponse,
    build_probe_url,
)

HOME = "https://x.test/search?q"
HTML = "text/html; charset=utf-8"


class FakeSite:
    """A canned site that echoes a chosen parameter in a chosen context."""

    def __init__(self, *, reflect: str | None = "q", template: str = "<div>{value}</div>",
                 content_type: str = HTML, fail: bool = False, encode: bool = False):
        self.reflect = reflect
        self.template = template
        self.content_type = content_type
        self.fail = fail
        self.encode = encode
        self.requests: list[str] = []

    async def __call__(self, url: str) -> XssResponse | None:
        self.requests.append(url)
        if self.fail:
            return None

        value = ""
        if self.reflect:
            values = parse_qs(urlsplit(url).query, keep_blank_values=True).get(self.reflect, [""])
            value = values[0]
            if self.encode:
                value = (
                    value.replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
                )

        return XssResponse(
            url=url,
            status_code=200,
            content_type=self.content_type,
            body=self.template.format(value=value),
        )


def run(site: FakeSite, targets, config: XssConfig | None = None):
    detector = ReflectedXssDetector(config or XssConfig(), site)
    return asyncio.run(detector.scan(targets))


def target(url: str = HOME, params: tuple[str, ...] = ("q",), content_type: str = HTML):
    return EndpointTarget(url=url, parameters=params, content_type=content_type)


# --- URL construction ------------------------------------------------------ #


def test_probe_url_sets_only_the_target_parameter():
    url = build_probe_url("https://x.test/s?q&page", "q", "MARKER")
    query = parse_qs(urlsplit(url).query, keep_blank_values=True)

    assert query["q"] == ["MARKER"]
    # Other parameters get inert filler, not the marker.
    assert query["page"] == ["1"]
    assert urlsplit(url).netloc == "x.test"
    assert urlsplit(url).path == "/s"


def test_probe_url_keeps_scheme_host_and_path_unchanged():
    """A probe cannot be pointed elsewhere: only a value is substituted."""
    url = build_probe_url("https://x.test/a/b?q", "q", "MARKER")
    parts = urlsplit(url)
    assert (parts.scheme, parts.netloc, parts.path) == ("https", "x.test", "/a/b")


def test_probe_url_adds_the_parameter_when_absent():
    url = build_probe_url("https://x.test/s", "q", "MARKER")
    assert parse_qs(urlsplit(url).query)["q"] == ["MARKER"]


# --- 1 & 2. Parameters are tested ------------------------------------------ #


def test_reflected_get_parameter_produces_a_finding():
    site = FakeSite(template="<div>{value}</div>")
    result = run(site, [target()])

    assert len(result.observations) == 1
    endpoint_url, finding = result.observations[0]
    assert endpoint_url == HOME
    assert finding.rule is FindingRule.XSS_REFLECTED
    assert finding.subject == "parameter:q"


def test_multiple_parameters_are_each_tested():
    site = FakeSite(reflect="a", template="<div>{value}</div>")
    result = run(site, [target(url="https://x.test/s?a&b", params=("a", "b"))])

    assert result.stats.parameters_tested == 2
    # Only the reflected one yields a finding.
    assert [f.subject for _, f in result.observations] == ["parameter:a"]


def test_findings_for_different_parameters_stay_distinguishable():
    site = FakeSite(reflect=None, template="<div>{value}</div>")

    # A site echoing every parameter it receives, decoded as a server would.
    async def echo(url: str) -> XssResponse:
        site.requests.append(url)
        query = parse_qs(urlsplit(url).query, keep_blank_values=True)
        values = " ".join(v for pair in query.values() for v in pair)
        return XssResponse(url=url, status_code=200, content_type=HTML,
                           body=f"<div>{values}</div>")

    detector = ReflectedXssDetector(XssConfig(), echo)
    result = asyncio.run(detector.scan([target(url="https://x.test/s?a&b", params=("a", "b"))]))

    subjects = {f.subject for _, f in result.observations}
    assert subjects == {"parameter:a", "parameter:b"}


# --- 3. Bounded request volume --------------------------------------------- #


def test_unreflected_parameter_costs_one_request():
    """No probe is sent when the baseline does not come back."""
    site = FakeSite(reflect=None, template="<div>static</div>")
    result = run(site, [target()])

    assert result.stats.requests_sent == 1
    assert result.observations == []


def test_reflected_parameter_costs_two_requests():
    site = FakeSite()
    result = run(site, [target()])
    assert result.stats.requests_sent == 2


def test_request_budget_is_enforced():
    site = FakeSite()
    targets = [target(url=f"https://x.test/p{i}?q") for i in range(20)]
    result = run(site, targets, XssConfig(max_requests_per_scan=5))

    assert result.stats.requests_sent <= 6  # the in-flight parameter may finish
    assert result.stats.limit_reached is True


def test_parameters_per_endpoint_is_capped():
    site = FakeSite(reflect=None)
    params = tuple(f"p{i}" for i in range(20))
    result = run(site, [target(url="https://x.test/s", params=params)],
                 XssConfig(max_parameters_per_endpoint=3))

    assert result.stats.parameters_tested == 3


def test_endpoint_count_is_capped():
    site = FakeSite(reflect=None)
    targets = [target(url=f"https://x.test/p{i}?q") for i in range(20)]
    result = run(site, targets, XssConfig(max_endpoints=4))

    assert result.stats.endpoints_tested == 4


def test_disabled_config_is_respected_by_the_module_not_the_detector():
    """The detector itself always runs; the module checks `enabled`."""
    assert XssConfig(enabled=False).enabled is False


# --- 4. Non-HTML endpoints -------------------------------------------------- #


def test_non_html_endpoint_is_skipped_without_any_request():
    site = FakeSite()
    result = run(site, [target(content_type="application/json")])

    assert site.requests == []
    assert result.stats.parameters_skipped == 1
    assert result.observations == []


def test_non_html_response_stops_analysis_even_if_the_endpoint_looked_html():
    site = FakeSite(content_type="application/json")
    result = run(site, [target()])

    assert result.observations == []
    assert result.stats.notes.get("non_html_response")


# --- 5. Failure handling ---------------------------------------------------- #


def test_failed_request_is_recorded_and_produces_no_finding():
    site = FakeSite(fail=True)
    result = run(site, [target()])

    assert result.stats.request_failures == 1
    assert result.observations == []


def test_a_raising_fetcher_does_not_end_the_scan():
    calls = {"n": 0}

    async def flaky(url: str) -> XssResponse | None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("connection reset")
        return XssResponse(url=url, status_code=200, content_type=HTML,
                           body="<div>ok</div>")

    detector = ReflectedXssDetector(XssConfig(), flaky)
    result = asyncio.run(detector.scan([target(url="https://x.test/a?q"),
                                        target(url="https://x.test/b?q")]))

    # First endpoint failed, second was still attempted.
    assert result.stats.request_failures == 1
    assert calls["n"] >= 2


def test_endpoint_with_no_parameters_is_not_probed():
    site = FakeSite()
    result = run(site, [target(url="https://x.test/", params=())])
    assert site.requests == []


# --- Encoding-aware outcomes ------------------------------------------------ #


def test_safely_encoded_reflection_produces_no_finding():
    site = FakeSite(encode=True)
    result = run(site, [target()])

    assert result.stats.requests_sent == 2  # it did reflect, so it was probed
    assert result.observations == []


def test_script_context_reflection_is_reported():
    site = FakeSite(template='<script>var q = "{value}";</script>')
    result = run(site, [target()])

    assert len(result.observations) == 1
    _, finding = result.observations[0]
    assert finding.confidence.value == "HIGH"


def test_probe_values_never_appear_in_the_finding():
    site = FakeSite()
    result = run(site, [target()])
    _, finding = result.observations[0]

    # Every request URL carried a marker; none of it reaches the finding.
    for request in site.requests:
        marker = parse_qs(urlsplit(request).query)["q"][0]
        assert marker not in finding.evidence
        assert marker not in finding.description
