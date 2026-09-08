"""Link and form extraction tests. Pure parsing, no network."""

from __future__ import annotations

from app.scanner.crawler.html_parser import (
    extract_forms,
    extract_links,
    normalize_form_method,
)
from app.scanner.crawler.types import FormFieldKind

BASE = "https://example.com/page"


# =========================================================================== #
# Link extraction
# =========================================================================== #


def test_internal_links_are_discovered_and_resolved():
    html = """
    <a href="/login">Login</a>
    <a href="products">Products</a>
    <a href="../about">About</a>
    <a href="https://example.com/contact">Contact</a>
    """
    assert extract_links(html, BASE) == [
        "https://example.com/login",
        "https://example.com/products",
        "https://example.com/about",
        "https://example.com/contact",
    ]


def test_external_links_are_returned_but_distinguishable():
    """Extraction is origin-agnostic; the crawler applies the same-origin filter."""
    html = '<a href="https://google.com/">g</a><a href="/local">l</a>'
    links = extract_links(html, BASE)
    assert "https://google.com/" in links
    assert "https://example.com/local" in links


def test_mailto_links_are_ignored():
    assert extract_links('<a href="mailto:a@example.com">mail</a>', BASE) == []


def test_javascript_links_are_ignored():
    html = '<a href="javascript:void(0)">x</a><a href="JavaScript:alert(1)">y</a>'
    assert extract_links(html, BASE) == []


def test_tel_and_data_links_are_ignored():
    html = '<a href="tel:+15551234">call</a><a href="data:text/html,x">d</a>'
    assert extract_links(html, BASE) == []


def test_fragment_only_links_are_ignored_but_fragments_on_paths_are_kept():
    html = '<a href="#top">top</a><a href="/docs#intro">docs</a>'
    assert extract_links(html, BASE) == ["https://example.com/docs"]


def test_duplicate_links_are_removed_preserving_first_appearance():
    html = """
    <a href="/a">1</a><a href="/b">2</a><a href="/a">3</a>
    <a href="/a#frag">4</a><a href="https://example.com/a">5</a>
    """
    assert extract_links(html, BASE) == ["https://example.com/a", "https://example.com/b"]


def test_anchors_without_href_are_ignored():
    assert extract_links("<a>no href</a><a href=''>blank</a>", BASE) == []


def test_html_entities_in_hrefs_are_decoded():
    html = '<a href="/search?a=1&amp;b=2">s</a>'
    assert extract_links(html, BASE) == ["https://example.com/search?a=1&b=2"]


def test_malformed_html_does_not_raise():
    html = "<a href='/a'><div><p>unclosed <a href='/b'>"
    assert extract_links(html, BASE) == ["https://example.com/a", "https://example.com/b"]


# =========================================================================== #
# Form extraction
# =========================================================================== #


def test_get_form_is_extracted():
    html = '<form action="/search" method="get"><input name="q" type="text"></form>'
    form = extract_forms(html, BASE)[0]

    assert form.method == "GET"
    assert form.action == "https://example.com/search"
    assert [f.name for f in form.fields] == ["q"]


def test_post_form_is_extracted():
    html = """
    <form action="/login" method="POST">
      <input name="email" type="email">
      <input name="password" type="password">
    </form>
    """
    form = extract_forms(html, BASE)[0]

    assert form.method == "POST"
    assert form.action == "https://example.com/login"
    assert [(f.name, f.input_type) for f in form.fields] == [
        ("email", "email"),
        ("password", "password"),
    ]


def test_missing_method_defaults_to_get():
    """HTML's own default when the attribute is absent."""
    form = extract_forms('<form action="/x"><input name="a"></form>', BASE)[0]
    assert form.method == "GET"


def test_unexpected_methods_normalise_to_get():
    for method in ("PUT", "DELETE", "PATCH", "nonsense", ""):
        html = f'<form action="/x" method="{method}"><input name="a"></form>'
        assert extract_forms(html, BASE)[0].method == "GET", method
    assert normalize_form_method(None) == "GET"


def test_relative_action_resolves_against_the_page():
    form = extract_forms('<form action="submit"><input name="a"></form>', BASE)[0]
    assert form.action == "https://example.com/submit"


def test_absolute_same_origin_action_is_kept():
    html = '<form action="https://example.com/api/x" method="post"></form>'
    assert extract_forms(html, BASE)[0].action == "https://example.com/api/x"


def test_external_action_is_recorded_as_is():
    """Recording it is discovery; the crawler never submits or follows it."""
    html = '<form action="https://other.com/collect" method="post"></form>'
    assert extract_forms(html, BASE)[0].action == "https://other.com/collect"


def test_omitted_action_falls_back_to_the_page_url():
    assert extract_forms('<form method="post"></form>', BASE)[0].action == BASE


def test_multiple_input_fields_are_captured_in_order():
    html = """
    <form action="/r" method="post">
      <input name="first" type="text"><input name="last" type="text">
      <input name="age" type="number"><input name="agree" type="checkbox">
    </form>
    """
    fields = extract_forms(html, BASE)[0].fields
    assert [f.name for f in fields] == ["first", "last", "age", "agree"]
    assert all(f.kind is FormFieldKind.INPUT for f in fields)


def test_textarea_is_captured():
    html = '<form action="/c"><textarea name="message"></textarea></form>'
    field = extract_forms(html, BASE)[0].fields[0]
    assert field.name == "message"
    assert field.kind is FormFieldKind.TEXTAREA


def test_select_is_captured():
    html = """
    <form action="/c">
      <select name="country"><option value="uk">UK</option></select>
    </form>
    """
    field = extract_forms(html, BASE)[0].fields[0]
    assert field.name == "country"
    assert field.kind is FormFieldKind.SELECT


def test_named_button_is_captured():
    html = '<form action="/c"><button name="action" type="submit">Go</button></form>'
    field = extract_forms(html, BASE)[0].fields[0]
    assert field.name == "action"
    assert field.kind is FormFieldKind.BUTTON


def test_password_field_records_type_but_never_a_value():
    html = '<form action="/login" method="post"><input name="password" type="password" value="hunter2"></form>'
    form = extract_forms(html, BASE)[0]
    field = form.fields[0]

    assert field.input_type == "password"
    assert "hunter2" not in repr(form)


def test_form_values_are_never_stored():
    """A hidden input's value is often a CSRF token; it must not be captured."""
    html = """
    <form action="/transfer" method="post">
      <input type="hidden" name="csrf" value="a1b2c3-secret-token">
      <input type="text" name="amount" value="1000">
      <textarea name="note">private note</textarea>
    </form>
    """
    form = extract_forms(html, BASE)[0]
    dumped = repr(form)

    assert [f.name for f in form.fields] == ["csrf", "amount", "note"]
    for secret in ("a1b2c3-secret-token", "1000", "private note"):
        assert secret not in dumped, secret


def test_unnamed_controls_are_skipped():
    """A control with no name is never submitted, so it is not input surface."""
    html = '<form action="/x"><input type="submit"><input name="real"></form>'
    assert [f.name for f in extract_forms(html, BASE)[0].fields] == ["real"]


def test_self_closing_inputs_are_captured():
    html = '<form action="/x"><input name="a" type="text" /><input name="b" /></form>'
    assert [f.name for f in extract_forms(html, BASE)[0].fields] == ["a", "b"]


def test_multiple_forms_on_one_page():
    html = """
    <form action="/one" method="get"><input name="a"></form>
    <form action="/two" method="post"><input name="b"></form>
    """
    forms = extract_forms(html, BASE)
    assert [(f.method, f.action) for f in forms] == [
        ("GET", "https://example.com/one"),
        ("POST", "https://example.com/two"),
    ]


def test_unclosed_form_is_still_recorded():
    html = '<form action="/x" method="post"><input name="a">'
    forms = extract_forms(html, BASE)
    assert len(forms) == 1
    assert [f.name for f in forms[0].fields] == ["a"]


def test_inputs_outside_a_form_are_ignored():
    assert extract_forms('<input name="loose" type="text">', BASE) == []


def test_page_with_no_forms_returns_empty():
    assert extract_forms("<html><body><p>hi</p></body></html>", BASE) == []


def test_radio_and_checkbox_groups_collapse_to_one_field():
    """A group of controls sharing a name is one input, not several."""
    html = """
    <form action="/order" method="post">
      <input type="radio" name="size" value="small">
      <input type="radio" name="size" value="large">
      <input type="checkbox" name="topping" value="cheese">
      <input type="checkbox" name="topping" value="ham">
      <input type="text" name="note">
    </form>
    """
    fields = extract_forms(html, BASE)[0].fields
    assert [f.name for f in fields] == ["size", "topping", "note"]
