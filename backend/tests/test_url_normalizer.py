"""URL normalisation and same-origin scoping tests. Pure functions, no I/O."""

from __future__ import annotations

from app.scanner.crawler.url_normalizer import (
    Origin,
    canonical_url,
    is_same_origin,
    normalize_url,
    origin_of,
    path_of,
    query_parameter_names,
)

BASE = "https://example.com/products/list"
ORIGIN = Origin(scheme="https", host="example.com", port=443)


# --- 1. Fragment removal --------------------------------------------------- #


def test_fragments_are_stripped():
    assert normalize_url("https://example.com/#section") == "https://example.com/"
    assert normalize_url("https://example.com/a?b=1#top") == "https://example.com/a?b=1"


def test_bare_fragment_link_is_not_crawlable():
    """"#section" points at the current page, so there is nothing new to fetch."""
    assert normalize_url("#section", BASE) is None


# --- 2. Relative URL resolution -------------------------------------------- #


def test_relative_urls_resolve_against_the_base():
    cases = {
        "/login": "https://example.com/login",
        "detail": "https://example.com/products/detail",
        "../about": "https://example.com/about",
        "./sibling": "https://example.com/products/sibling",
        "//example.com/proto": "https://example.com/proto",
    }
    for href, expected in cases.items():
        assert normalize_url(href, BASE) == expected, href


# --- 3. Absolute URL resolution -------------------------------------------- #


def test_absolute_urls_are_kept():
    assert normalize_url("https://example.com/products", BASE) == "https://example.com/products"


def test_scheme_and_host_are_lowercased_and_default_ports_dropped():
    assert normalize_url("HTTPS://EXAMPLE.COM:443/Path") == "https://example.com/Path"
    assert normalize_url("http://Example.com:80/") == "http://example.com/"
    # A non-default port is significant and must be preserved.
    assert normalize_url("https://example.com:8443/x") == "https://example.com:8443/x"


def test_empty_path_becomes_root():
    assert normalize_url("https://example.com") == "https://example.com/"


# --- 4. Duplicate normalisation -------------------------------------------- #


def test_equivalent_urls_normalise_to_one_value():
    variants = [
        "https://example.com/",
        "https://example.com/#a",
        "https://EXAMPLE.com:443/",
        "https://example.com",
    ]
    assert len({normalize_url(v) for v in variants}) == 1


def test_canonical_url_ignores_parameter_order_and_values():
    a = canonical_url("https://example.com/search?q=phone&category=shoes")
    b = canonical_url("https://example.com/search?category=hats&q=laptop")
    assert a == b == "https://example.com/search?category&q"


# --- 5. External URL rejection --------------------------------------------- #


def test_same_origin_requires_scheme_host_and_port_to_match():
    assert is_same_origin("https://example.com/a", ORIGIN)
    assert not is_same_origin("https://google.com/", ORIGIN)
    assert not is_same_origin("https://sub.example.com/", ORIGIN)
    # A scheme change is an origin change.
    assert not is_same_origin("http://example.com/", ORIGIN)
    assert not is_same_origin("https://example.com:8443/", ORIGIN)


def test_origin_of_rejects_non_web_urls():
    assert origin_of("mailto:a@b.com") is None
    assert origin_of("not a url") is None
    assert origin_of("https://example.com/x") == ORIGIN


# --- 6. Unsupported scheme rejection --------------------------------------- #


def test_non_web_schemes_are_rejected():
    for href in (
        "mailto:someone@example.com",
        "javascript:alert(1)",
        "tel:+15551234",
        "data:text/html,<h1>x</h1>",
        "ftp://example.com/file",
        "file:///etc/passwd",
    ):
        assert normalize_url(href, BASE) is None, href


def test_blank_and_none_inputs_are_rejected():
    assert normalize_url("") is None
    assert normalize_url("   ") is None
    assert normalize_url(None) is None  # type: ignore[arg-type]


def test_absurdly_long_urls_are_rejected():
    assert normalize_url("https://example.com/" + "a" * 3000) is None


# --- 7. Query parameter preservation --------------------------------------- #


def test_query_string_survives_normalisation():
    """Values are needed to fetch a real page; only storage strips them."""
    assert (
        normalize_url("https://example.com/search?q=phone&category=shoes")
        == "https://example.com/search?q=phone&category=shoes"
    )


def test_parameter_names_are_extracted_sorted_and_deduplicated():
    assert query_parameter_names("https://example.com/s?q=1&category=2&q=3") == (
        "category",
        "q",
    )
    assert query_parameter_names("https://example.com/s") == ()
    # A blank value still evidences the parameter's existence.
    assert query_parameter_names("https://example.com/s?token=") == ("token",)


def test_canonical_url_never_retains_a_secret_looking_value():
    secret = "eyJhbGciOiJIUzI1NiJ9.super-secret-token"
    canonical = canonical_url(f"https://example.com/cb?access_token={secret}&state=xyz")

    assert secret not in canonical
    assert "xyz" not in canonical
    assert canonical == "https://example.com/cb?access_token&state"


def test_path_of_defaults_to_root():
    assert path_of("https://example.com") == "/"
    assert path_of("https://example.com/a/b?c=1") == "/a/b"
