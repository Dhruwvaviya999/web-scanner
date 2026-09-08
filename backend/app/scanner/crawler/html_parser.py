"""Link and form extraction from HTML.

Built on the standard library's `html.parser` — no third-party parser, and no
browser. JavaScript is never executed, so URLs a page builds at runtime are
invisible to this crawler by design.

Form *values* are deliberately not collected. A `value` attribute on a hidden
input is frequently a CSRF token or a session identifier, and this phase only
needs to know the shape of the input surface: names, types and structure.
"""

from __future__ import annotations

from html.parser import HTMLParser

from app.scanner.crawler.types import DiscoveredForm, DiscoveredFormField, FormFieldKind
from app.scanner.crawler.url_normalizer import normalize_url

#: HTML's own default when a <form> omits its method attribute.
DEFAULT_FORM_METHOD = "GET"

#: Methods a plain HTML form can actually issue. Anything else is normalised to
#: GET rather than recorded, because the browser would do the same.
_HTML_FORM_METHODS = frozenset({"GET", "POST"})

_MAX_FIELD_NAME_LENGTH = 255
_MAX_INPUT_TYPE_LENGTH = 40


def _attr(attrs: list[tuple[str, str | None]], name: str) -> str | None:
    for key, value in attrs:
        if key.lower() == name:
            return value
    return None


def normalize_form_method(raw: str | None) -> str:
    """A form's effective HTTP method.

    An omitted, blank or unrecognised method becomes GET, matching how a browser
    treats the attribute. Phase 4 records methods; it never issues them.
    """
    if not raw:
        return DEFAULT_FORM_METHOD
    method = raw.strip().upper()
    return method if method in _HTML_FORM_METHODS else DEFAULT_FORM_METHOD


class _DocumentParser(HTMLParser):
    """Collects anchor targets and forms in a single pass.

    `convert_charrefs` is on so `&amp;` in an href resolves before the URL is
    normalised.
    """

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[DiscoveredForm] = []

        self._form_action: str | None = None
        self._form_method: str = DEFAULT_FORM_METHOD
        self._form_fields: list[DiscoveredFormField] = []
        self._in_form = False
        self._pending_select: str | None = None

    # --- anchors --------------------------------------------------------- #

    def _handle_anchor(self, attrs: list[tuple[str, str | None]]) -> None:
        href = _attr(attrs, "href")
        if href:
            self.links.append(href)

    # --- forms ----------------------------------------------------------- #

    def _open_form(self, attrs: list[tuple[str, str | None]]) -> None:
        # A nested <form> is invalid HTML; close the outer one rather than lose it.
        if self._in_form:
            self._close_form()
        self._in_form = True
        self._form_action = _attr(attrs, "action")
        self._form_method = normalize_form_method(_attr(attrs, "method"))
        self._form_fields = []

    def _close_form(self) -> None:
        if not self._in_form:
            return
        # An omitted action submits back to the page itself.
        action = (self._form_action or "").strip() or self.base_url
        resolved = normalize_url(action, self.base_url) or action

        self.forms.append(
            DiscoveredForm(
                page_url=self.base_url,
                action=resolved,
                method=self._form_method,
                fields=tuple(self._form_fields),
            )
        )
        self._in_form = False
        self._form_action = None
        self._form_fields = []
        self._pending_select = None

    def _add_field(
        self, name: str | None, kind: FormFieldKind, input_type: str | None = None
    ) -> None:
        """Record a named field. Unnamed controls are not submitted, so are skipped."""
        if not self._in_form or not name:
            return
        cleaned = name.strip()[:_MAX_FIELD_NAME_LENGTH]
        if not cleaned:
            return
        normalized_type = (
            input_type.strip().lower()[:_MAX_INPUT_TYPE_LENGTH] if input_type else None
        )
        # Radio and checkbox groups repeat one name across several controls.
        # They are a single input as far as attack surface goes, so the first
        # occurrence wins and the rest are folded into it.
        if any(existing.name == cleaned for existing in self._form_fields):
            return

        self._form_fields.append(
            DiscoveredFormField(name=cleaned, kind=kind, input_type=normalized_type or None)
        )

    def _handle_control(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        name = _attr(attrs, "name")

        if tag == "input":
            # Only the name and type are kept; any `value` attribute is ignored
            # because it is often a CSRF token or prefilled personal data.
            self._add_field(name, FormFieldKind.INPUT, _attr(attrs, "type") or "text")
        elif tag == "textarea":
            self._add_field(name, FormFieldKind.TEXTAREA)
        elif tag == "select":
            self._pending_select = name
            self._add_field(name, FormFieldKind.SELECT)
        elif tag == "button":
            self._add_field(name, FormFieldKind.BUTTON, _attr(attrs, "type") or "submit")

    # --- HTMLParser hooks ------------------------------------------------ #

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.lower()
        if lowered == "a":
            self._handle_anchor(attrs)
        elif lowered == "form":
            self._open_form(attrs)
        elif lowered in {"input", "textarea", "select", "button"}:
            self._handle_control(lowered, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Self-closing form controls, e.g. <input ... />.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered == "form":
            self._close_form()
        elif lowered == "select":
            self._pending_select = None

    def close(self) -> None:
        super().close()
        # Tolerate a document that never closes its <form>.
        self._close_form()


def _parse(html: str, base_url: str) -> _DocumentParser:
    parser = _DocumentParser(base_url)
    try:
        parser.feed(html)
        parser.close()
    except (AssertionError, ValueError):
        # html.parser is lenient, but a hostile page must never fail a crawl;
        # whatever was collected before the failure is still usable.
        pass
    return parser


def extract_links(html: str, base_url: str) -> list[str]:
    """Absolute, normalised, de-duplicated links from a document.

    Relative hrefs are resolved against `base_url`. Fragments, `mailto:`,
    `javascript:`, `tel:`, `data:` and every other non-web scheme are dropped by
    `normalize_url`. Order of first appearance is preserved so a crawl is
    deterministic.
    """
    seen: set[str] = set()
    links: list[str] = []

    for href in _parse(html, base_url).links:
        normalized = normalize_url(href, base_url)
        if normalized and normalized not in seen:
            seen.add(normalized)
            links.append(normalized)

    return links


def extract_forms(html: str, base_url: str) -> list[DiscoveredForm]:
    """Every form in the document, with its fields. Nothing is submitted."""
    return _parse(html, base_url).forms


def decode_html(body: bytes, content_type: str | None) -> str:
    """Decode a response body for parsing, preferring the declared charset."""
    charset = None
    if content_type and "charset=" in content_type.lower():
        charset = content_type.lower().split("charset=", 1)[1].split(";")[0].strip(' "')

    for encoding in (charset, "utf-8"):
        if not encoding:
            continue
        try:
            return body.decode(encoding, errors="replace")
        except LookupError:
            continue
    return body.decode("utf-8", errors="replace")
