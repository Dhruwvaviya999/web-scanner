"""Crawler algorithm tests.

The crawler takes an injected fetcher, so these run against canned pages with no
network at all — which is what makes limits, cycles and failure handling
deterministic to test.
"""

from __future__ import annotations

import asyncio

import pytest

from app.scanner.crawler.crawler import Crawler
from app.scanner.crawler.types import CrawlConfig, FetchedPage, SkipReason

ORIGIN = "https://example.com"


def page(html: str = "", *, status: int = 200, content_type: str = "text/html") -> dict:
    return {"html": html, "status": status, "content_type": content_type}


def fake_fetcher(pages: dict[str, dict], *, record: list[str] | None = None):
    """Serve canned pages by URL. Anything not in the map behaves as unreachable."""

    async def fetch(url: str) -> FetchedPage | None:
        if record is not None:
            record.append(url)
        entry = pages.get(url)
        if entry is None:
            return None
        content_type = entry["content_type"]
        is_html = content_type is not None and content_type.split(";")[0].strip() == "text/html"
        return FetchedPage(
            url=url,
            status_code=entry["status"],
            content_type=content_type,
            body=entry["html"].encode("utf-8") if is_html else b"",
            is_html=is_html,
        )

    return fetch


def run(pages: dict[str, dict], config: CrawlConfig | None = None, seed: str = f"{ORIGIN}/", **kw):
    crawler = Crawler(config or CrawlConfig(), fake_fetcher(pages, **kw))
    return asyncio.run(crawler.crawl(seed))


def urls(result) -> list[str]:
    return [e.url for e in result.endpoints]


# --- 1. Single page -------------------------------------------------------- #


def test_single_page_with_no_links():
    result = run({f"{ORIGIN}/": page("<html><head><title>Home</title></head></html>")})

    assert result.pages_crawled == 1
    assert urls(result) == [f"{ORIGIN}/"]
    assert result.endpoints[0].page_title == "Home"
    assert result.endpoints[0].depth == 0
    assert result.limit_reached is False


# --- 2. Multiple internal pages -------------------------------------------- #


def test_follows_internal_links_breadth_first():
    result = run({
        f"{ORIGIN}/": page('<a href="/a">a</a><a href="/b">b</a>'),
        f"{ORIGIN}/a": page('<a href="/c">c</a>'),
        f"{ORIGIN}/b": page(""),
        f"{ORIGIN}/c": page(""),
    })

    assert result.pages_crawled == 4
    assert set(urls(result)) == {f"{ORIGIN}/", f"{ORIGIN}/a", f"{ORIGIN}/b", f"{ORIGIN}/c"}
    # Breadth-first: depth 1 pages come before the depth 2 page.
    assert [e.depth for e in result.endpoints] == [0, 1, 1, 2]


# --- 3. Duplicate links ---------------------------------------------------- #


def test_duplicate_links_are_fetched_once():
    fetched: list[str] = []
    result = run(
        {
            f"{ORIGIN}/": page('<a href="/a">1</a><a href="/a">2</a><a href="/a#x">3</a>'),
            f"{ORIGIN}/a": page(""),
        },
        record=fetched,
    )

    assert fetched.count(f"{ORIGIN}/a") == 1
    assert result.pages_crawled == 2


# --- 4. Depth limit -------------------------------------------------------- #


def test_depth_limit_stops_descent():
    result = run(
        {
            f"{ORIGIN}/": page('<a href="/a">a</a>'),
            f"{ORIGIN}/a": page('<a href="/b">b</a>'),
            f"{ORIGIN}/b": page('<a href="/c">c</a>'),
            f"{ORIGIN}/c": page(""),
        },
        CrawlConfig(max_depth=1),
    )

    assert result.pages_crawled == 2
    assert set(urls(result)) == {f"{ORIGIN}/", f"{ORIGIN}/a"}
    assert result.max_depth_reached == 1
    assert result.skip_reasons.get(SkipReason.DEPTH_LIMIT.value) == 1


def test_depth_zero_crawls_only_the_seed():
    result = run(
        {f"{ORIGIN}/": page('<a href="/a">a</a>'), f"{ORIGIN}/a": page("")},
        CrawlConfig(max_depth=0),
    )
    assert result.pages_crawled == 1


# --- 5. Page limit --------------------------------------------------------- #


def test_page_limit_stops_the_crawl_and_is_normal_termination():
    pages = {f"{ORIGIN}/": page("".join(f'<a href="/p{i}">{i}</a>' for i in range(10)))}
    for i in range(10):
        pages[f"{ORIGIN}/p{i}"] = page("")

    result = run(pages, CrawlConfig(max_pages=3))

    assert result.pages_crawled == 3
    assert result.limit_reached is True
    assert result.pages_skipped > 0


# --- 6. External links ignored --------------------------------------------- #


def test_external_origins_are_never_fetched():
    fetched: list[str] = []
    result = run(
        {
            f"{ORIGIN}/": page(
                '<a href="https://evil.com/x">e</a>'
                '<a href="http://example.com/insecure">scheme</a>'
                '<a href="https://sub.example.com/s">sub</a>'
                '<a href="/ok">ok</a>'
            ),
            f"{ORIGIN}/ok": page(""),
        },
        record=fetched,
    )

    assert not any("evil.com" in u for u in fetched)
    assert not any("sub.example.com" in u for u in fetched)
    # A scheme change is an origin change, so http:// is external too.
    assert not any(u.startswith("http://") for u in fetched)
    assert result.pages_crawled == 2
    assert result.skip_reasons.get(SkipReason.EXTERNAL_ORIGIN.value) == 3


# --- 7. Redirect handling -------------------------------------------------- #


def test_page_reporting_a_different_final_url_is_recorded_under_that_url():
    """The fetcher resolves redirects; the crawler records where it landed."""

    async def fetch(url: str) -> FetchedPage | None:
        if url == f"{ORIGIN}/old":
            return FetchedPage(
                url=f"{ORIGIN}/new", status_code=200, content_type="text/html",
                body=b"<title>New</title>", is_html=True,
            )
        return None

    result = asyncio.run(Crawler(CrawlConfig(), fetch).crawl(f"{ORIGIN}/old"))

    assert urls(result) == [f"{ORIGIN}/new"]
    assert result.endpoints[0].page_title == "New"


# --- 8. Non-HTML responses ------------------------------------------------- #


def test_non_html_responses_are_recorded_but_not_parsed():
    result = run({
        f"{ORIGIN}/": page('<a href="/data.json">j</a><a href="/img.png">i</a>'),
        f"{ORIGIN}/data.json": page('{"links":"<a href=\\"/hidden\\">"}', content_type="application/json"),
        f"{ORIGIN}/img.png": page("", content_type="image/png"),
        f"{ORIGIN}/hidden": page(""),
    })

    recorded = urls(result)
    assert f"{ORIGIN}/data.json" in recorded
    assert f"{ORIGIN}/img.png" in recorded
    # The JSON body is never parsed as HTML, so /hidden is not discovered.
    assert f"{ORIGIN}/hidden" not in recorded

    json_endpoint = next(e for e in result.endpoints if e.path == "/data.json")
    assert json_endpoint.content_type == "application/json"
    assert json_endpoint.page_title is None


# --- 9. Failed pages ------------------------------------------------------- #


def test_unreachable_page_is_skipped_without_ending_the_crawl():
    result = run({
        f"{ORIGIN}/": page('<a href="/broken">b</a><a href="/fine">f</a>'),
        # "/broken" is absent from the map, so the fetcher returns None.
        f"{ORIGIN}/fine": page(""),
    })

    assert result.pages_crawled == 2
    assert f"{ORIGIN}/fine" in urls(result)
    assert result.skip_reasons.get(SkipReason.FETCH_FAILED.value) == 1


def test_unreachable_seed_yields_an_empty_result():
    result = run({})
    assert result.pages_crawled == 0
    assert result.endpoints == []


def test_error_status_pages_are_still_recorded():
    result = run({
        f"{ORIGIN}/": page('<a href="/missing">m</a>'),
        f"{ORIGIN}/missing": page("<title>404</title>", status=404),
    })
    assert next(e for e in result.endpoints if e.path == "/missing").status_code == 404


# --- 10. Circular links ---------------------------------------------------- #


def test_circular_links_terminate():
    result = run({
        f"{ORIGIN}/": page('<a href="/a">a</a>'),
        f"{ORIGIN}/a": page('<a href="/b">b</a><a href="/">home</a>'),
        f"{ORIGIN}/b": page('<a href="/a">a</a><a href="/">home</a>'),
    }, CrawlConfig(max_pages=50, max_depth=10))

    assert result.pages_crawled == 3
    assert result.limit_reached is False


def test_self_referencing_page_terminates():
    result = run({f"{ORIGIN}/": page('<a href="/">self</a><a href="/#x">self2</a>')})
    assert result.pages_crawled == 1


# --- 11. Query parameter discovery ----------------------------------------- #


def test_query_parameters_are_discovered_without_their_values():
    result = run({
        f"{ORIGIN}/": page('<a href="/search?q=phone&category=shoes">s</a>'),
        f"{ORIGIN}/search?q=phone&category=shoes": page("<title>Search</title>"),
    })

    endpoint = next(e for e in result.endpoints if e.path == "/search")
    assert endpoint.parameters == ("category", "q")
    # The stored URL keeps names, drops values.
    assert endpoint.url == f"{ORIGIN}/search?category&q"
    assert "phone" not in endpoint.url
    assert "shoes" not in endpoint.url


def test_same_endpoint_with_different_values_is_crawled_once():
    """/search?q=a and /search?q=b are one endpoint, not two."""
    fetched: list[str] = []
    run(
        {
            f"{ORIGIN}/": page('<a href="/s?q=a">1</a><a href="/s?q=b">2</a>'),
            f"{ORIGIN}/s?q=a": page(""),
            f"{ORIGIN}/s?q=b": page(""),
        },
        record=fetched,
    )
    assert len([u for u in fetched if u.startswith(f"{ORIGIN}/s")]) == 1


def test_sensitive_query_values_are_not_retained_anywhere():
    token = "eyJhbGci-super-secret"
    result = run({
        f"{ORIGIN}/": page(f'<a href="/cb?access_token={token}">cb</a>'),
        f"{ORIGIN}/cb?access_token={token}": page(""),
    })

    for endpoint in result.endpoints:
        assert token not in endpoint.url
        assert token not in repr(endpoint)


# --- 12. Forms discovered -------------------------------------------------- #


def test_forms_are_discovered_across_pages():
    result = run({
        f"{ORIGIN}/": page('<a href="/login">l</a><form action="/search"><input name="q"></form>'),
        f"{ORIGIN}/login": page(
            '<form action="/login" method="post">'
            '<input name="email" type="email"><input name="password" type="password"></form>'
        ),
    })

    assert len(result.forms) == 2
    login = next(f for f in result.forms if f.method == "POST")
    assert login.action == f"{ORIGIN}/login"
    assert [f.name for f in login.fields] == ["email", "password"]


def test_forms_are_never_submitted():
    """Only the two pages are fetched; no form action is requested."""
    fetched: list[str] = []
    run(
        {f"{ORIGIN}/": page('<form action="/submit" method="post"><input name="a"></form>')},
        record=fetched,
    )
    assert fetched == [f"{ORIGIN}/"]


# --- 13. Termination and summary ------------------------------------------- #


def test_crawl_terminates_and_reports_a_consistent_summary():
    result = run({
        f"{ORIGIN}/": page('<a href="/a">a</a><a href="/b">b</a><a href="https://x.com/">x</a>'),
        f"{ORIGIN}/a": page('<form action="/f"><input name="n"></form>'),
        f"{ORIGIN}/b": page('<a href="/c?p=1">c</a>'),
        f"{ORIGIN}/c?p=1": page(""),
    })

    assert result.pages_crawled == 4
    assert len(result.endpoints) == 4
    assert len(result.forms) == 1
    assert result.parameter_count == 1
    assert result.max_depth_reached == 2
    assert result.limit_reached is False
    assert result.pages_skipped == sum(result.skip_reasons.values())


def test_disabled_crawl_config_is_respected_by_limits():
    """max_pages of 1 crawls only the seed."""
    result = run(
        {f"{ORIGIN}/": page('<a href="/a">a</a>'), f"{ORIGIN}/a": page("")},
        CrawlConfig(max_pages=1),
    )
    assert result.pages_crawled == 1
    assert result.limit_reached is True


def test_non_crawlable_seed_returns_empty_result():
    for seed in ("mailto:a@b.com", "not a url", ""):
        result = run({}, seed=seed)
        assert result.pages_crawled == 0, seed


@pytest.mark.parametrize("budget", [0.0001])
def test_time_budget_stops_the_crawl(budget):
    pages = {f"{ORIGIN}/": page("".join(f'<a href="/p{i}">{i}</a>' for i in range(20)))}
    for i in range(20):
        pages[f"{ORIGIN}/p{i}"] = page("")

    result = run(pages, CrawlConfig(time_budget_seconds=budget, max_pages=100))
    assert result.limit_reached is True
    assert result.pages_crawled < 21
