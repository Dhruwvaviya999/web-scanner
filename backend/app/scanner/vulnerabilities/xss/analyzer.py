"""Static analysis of where a reflected marker landed.

Pure functions: markup and a token in, a classification out. No network, no
database, and — importantly — **no JavaScript execution and no browser**. This
module reasons about where bytes ended up in the returned document, which is a
weaker claim than "a browser would execute this", and the severity rules are
written to respect that difference.

The document scan is a small deterministic state machine, not a full HTML
parser. It tracks the handful of structures that change how a value is
interpreted: comments, raw-text elements, tags, and attribute values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.scanner.vulnerabilities.xss.types import (
    EncodingState,
    HtmlContext,
    Reflection,
    ReflectionAnalysis,
    ReflectionOutcome,
)

#: Elements whose content is raw text rather than markup.
_RAWTEXT_ELEMENTS = {"script": HtmlContext.SCRIPT, "style": HtmlContext.STYLE}

#: Attributes that carry a URL, where a `javascript:` value is executable.
_URL_ATTRIBUTES = frozenset({"href", "src", "action", "formaction", "xlink:href"})

_ATTR_NAME_CHARS = re.compile(r"[^\s=>/]")

#: Ordering used to pick which reflection to report when a marker appears more
#: than once. Most dangerous first.
_CONTEXT_RANK = {
    HtmlContext.SCRIPT: 0,
    HtmlContext.EVENT_HANDLER: 1,
    HtmlContext.JAVASCRIPT_URI: 2,
    HtmlContext.ATTRIBUTE_UNQUOTED: 3,
    HtmlContext.ATTRIBUTE_QUOTED: 4,
    HtmlContext.HTML_TEXT: 5,
    HtmlContext.STYLE: 6,
    HtmlContext.HTML_COMMENT: 7,
    HtmlContext.UNKNOWN: 8,
}


@dataclass(frozen=True, slots=True)
class _Region:
    """A span of the document with a known interpretation."""

    start: int
    end: int
    context: HtmlContext
    attribute_name: str | None = None
    delimiter: str | None = None


def _scan_regions(markup: str) -> list[_Region]:
    """Walk the document once, recording spans that are not plain text.

    Anything not covered by a region is HTML text. Deliberately lenient: a
    malformed document yields a partial region list rather than an error,
    because a broken page must still be analysable.
    """
    regions: list[_Region] = []
    lowered = markup.lower()
    index = 0
    length = len(markup)

    while index < length:
        char = markup[index]

        if char != "<":
            index += 1
            continue

        # --- comment ---------------------------------------------------- #
        if markup.startswith("<!--", index):
            close = markup.find("-->", index + 4)
            end = length if close == -1 else close + 3
            regions.append(_Region(index + 4, end, HtmlContext.HTML_COMMENT))
            index = end
            continue

        # --- doctype / processing instruction --------------------------- #
        if markup.startswith("<!", index) or markup.startswith("<?", index):
            close = markup.find(">", index)
            index = length if close == -1 else close + 1
            continue

        if index + 1 >= length:
            break

        following = markup[index + 1]
        if not (following.isalpha() or following == "/"):
            index += 1
            continue

        is_closing = following == "/"
        cursor = index + (2 if is_closing else 1)
        name_start = cursor
        while cursor < length and (markup[cursor].isalnum() or markup[cursor] in "-_:"):
            cursor += 1
        tag_name = lowered[name_start:cursor]

        # --- attributes -------------------------------------------------- #
        while cursor < length and markup[cursor] != ">":
            if markup[cursor].isspace() or markup[cursor] == "/":
                cursor += 1
                continue

            attr_start = cursor
            while cursor < length and _ATTR_NAME_CHARS.match(markup[cursor]):
                cursor += 1
            attribute = lowered[attr_start:cursor]
            if not attribute:
                cursor += 1
                continue

            while cursor < length and markup[cursor].isspace():
                cursor += 1
            if cursor >= length or markup[cursor] != "=":
                continue  # Valueless attribute.

            cursor += 1
            while cursor < length and markup[cursor].isspace():
                cursor += 1
            if cursor >= length:
                break

            if markup[cursor] in "\"'":
                quote = markup[cursor]
                cursor += 1
                value_start = cursor
                while cursor < length and markup[cursor] != quote:
                    cursor += 1
                value = markup[value_start:cursor]
                regions.append(
                    _Region(
                        value_start,
                        cursor,
                        _attribute_context(attribute, value, quoted=True),
                        attribute,
                        quote,
                    )
                )
                if cursor < length:
                    cursor += 1
            else:
                value_start = cursor
                while cursor < length and not markup[cursor].isspace() and markup[cursor] != ">":
                    cursor += 1
                value = markup[value_start:cursor]
                regions.append(
                    _Region(
                        value_start,
                        cursor,
                        _attribute_context(attribute, value, quoted=False),
                        attribute,
                        None,
                    )
                )

        index = cursor + 1 if cursor < length else length

        # --- raw-text element content ------------------------------------ #
        if not is_closing and tag_name in _RAWTEXT_ELEMENTS:
            closing = f"</{tag_name}"
            close = lowered.find(closing, index)
            end = length if close == -1 else close
            regions.append(_Region(index, end, _RAWTEXT_ELEMENTS[tag_name]))
            index = end

    return regions


def _attribute_context(attribute: str, value: str, *, quoted: bool) -> HtmlContext:
    if attribute.startswith("on"):
        # An on* attribute is a JavaScript sink regardless of quoting.
        return HtmlContext.EVENT_HANDLER
    if attribute in _URL_ATTRIBUTES and value.strip().lower().startswith("javascript:"):
        return HtmlContext.JAVASCRIPT_URI
    return HtmlContext.ATTRIBUTE_QUOTED if quoted else HtmlContext.ATTRIBUTE_UNQUOTED


def _region_for(regions: list[_Region], position: int) -> _Region | None:
    """The innermost region containing `position`, if any."""
    match: _Region | None = None
    for region in regions:
        if region.start <= position < region.end:
            if match is None or (region.end - region.start) <= (match.end - match.start):
                match = region
    return match


def _surviving_characters(rendered: str, canary: str) -> set[str]:
    """Which canary characters came back raw, given exactly what was rendered.

    `rendered` is the text the application produced between the two bracket
    markers — nothing else. A raw character here really did survive, because no
    surrounding page markup can reach this slice.
    """
    return {char for char in set(canary) if char in rendered}


def _script_string_delimiter(markup: str, region: _Region, position: int) -> str | None:
    """The quote delimiting the JS string the token sits in, if it is in one.

    A simple left-scan across the script body: a value inside `var x = "TOKEN"`
    can only escape by closing that quote, which is what raises confidence.
    """
    body = markup[region.start : position]
    delimiter: str | None = None
    escaped = False
    for char in body:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if delimiter is None:
            if char in "\"'`":
                delimiter = char
        elif char == delimiter:
            delimiter = None
    return delimiter


def analyze_reflection(
    markup: str, open_marker: str, close_marker: str, canary: str
) -> ReflectionAnalysis:
    """Classify every place the marker appears in `markup`.

    Returns NOT_REFLECTED when the opening marker is absent. When present, each
    occurrence is classified by context, and by which canary characters survived
    between the two brackets. The most dangerous occurrence is reported first.
    """
    if not markup or not open_marker:
        return ReflectionAnalysis(outcome=ReflectionOutcome.NOT_REFLECTED)

    positions: list[int] = []
    start = markup.find(open_marker)
    while start != -1:
        positions.append(start)
        start = markup.find(open_marker, start + 1)

    if not positions:
        return ReflectionAnalysis(outcome=ReflectionOutcome.NOT_REFLECTED)

    regions = _scan_regions(markup)
    reflections: list[Reflection] = []

    for position in positions:
        end = position + len(open_marker)

        # Everything the application rendered for the canary sits between the
        # brackets. A missing closing bracket means the value was truncated or
        # rewritten, so nothing is credited as surviving.
        close_at = markup.find(close_marker, end)
        rendered = markup[end:close_at] if close_at != -1 else ""

        region = _region_for(regions, position)
        context = region.context if region else HtmlContext.HTML_TEXT
        survived = _surviving_characters(rendered, canary)

        if not survived:
            encoding = EncodingState.SAFELY_ENCODED
        elif len(survived) == len(set(canary)):
            encoding = EncodingState.NOT_ENCODED
        else:
            encoding = EncodingState.PARTIALLY_ENCODED

        delimiter = region.delimiter if region else None
        if context is HtmlContext.SCRIPT and region is not None:
            delimiter = _script_string_delimiter(markup, region, position)

        # "Breaks out" means the value can leave its enclosing construct: the
        # delimiter survived, or in text/script/comment a raw '<' is available
        # to open a new tag.
        if delimiter is not None:
            breaks_out = delimiter in survived
        elif context in {HtmlContext.HTML_TEXT, HtmlContext.SCRIPT, HtmlContext.HTML_COMMENT}:
            breaks_out = "<" in survived
        else:
            breaks_out = bool(survived)

        reflections.append(
            Reflection(
                context=context,
                encoding=encoding,
                raw_characters=frozenset(survived),
                attribute_name=region.attribute_name if region else None,
                delimiter=delimiter,
                breaks_out=breaks_out,
            )
        )

    reflections.sort(
        key=lambda r: (_CONTEXT_RANK[r.context], not r.breaks_out, -len(r.raw_characters))
    )

    outcome = (
        ReflectionOutcome.REFLECTED_BUT_ENCODED
        if all(r.encoding is EncodingState.SAFELY_ENCODED for r in reflections)
        else ReflectionOutcome.POTENTIALLY_EXECUTABLE_REFLECTION
    )
    return ReflectionAnalysis(outcome=outcome, reflections=tuple(reflections))


def is_html_document(content_type: str | None) -> bool:
    """Only real documents are candidates for HTML-context XSS analysis."""
    if not content_type:
        return False
    media = content_type.split(";", 1)[0].strip().lower()
    return media in {"text/html", "application/xhtml+xml"}
