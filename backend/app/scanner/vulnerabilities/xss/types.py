"""Typed results for reflected-XSS analysis.

Plain dataclasses and enums. Nothing here performs I/O or touches the database.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class HtmlContext(str, enum.Enum):
    """Where a reflected value landed in the returned document.

    Determined by a deterministic scan of the markup — no browser, no
    JavaScript execution, so this describes *where the bytes are*, not what a
    browser would ultimately do with them.
    """

    #: Between tags: <div>HERE</div>
    HTML_TEXT = "HTML_TEXT"
    #: Inside a quoted attribute: <input value="HERE">
    ATTRIBUTE_QUOTED = "ATTRIBUTE_QUOTED"
    #: Inside an unquoted attribute: <input value=HERE>
    ATTRIBUTE_UNQUOTED = "ATTRIBUTE_UNQUOTED"
    #: Inside an on* handler: <button onclick="f('HERE')">
    EVENT_HANDLER = "EVENT_HANDLER"
    #: Inside a javascript: URL: <a href="javascript:f('HERE')">
    JAVASCRIPT_URI = "JAVASCRIPT_URI"
    #: Inside <script> content.
    SCRIPT = "SCRIPT"
    #: Inside <style> content.
    STYLE = "STYLE"
    #: Inside an HTML comment.
    HTML_COMMENT = "HTML_COMMENT"
    #: Reflected, but the surrounding structure could not be classified.
    UNKNOWN = "UNKNOWN"


#: Contexts where unencoded input can plausibly reach an execution sink.
EXECUTABLE_CONTEXTS = frozenset(
    {
        HtmlContext.SCRIPT,
        HtmlContext.EVENT_HANDLER,
        HtmlContext.JAVASCRIPT_URI,
    }
)


class EncodingState(str, enum.Enum):
    """How the application treated the metacharacters that matter for XSS."""

    #: Every probed metacharacter came back HTML-encoded or was removed.
    SAFELY_ENCODED = "SAFELY_ENCODED"
    #: Some came back raw, some encoded.
    PARTIALLY_ENCODED = "PARTIALLY_ENCODED"
    #: Every probed metacharacter came back raw.
    NOT_ENCODED = "NOT_ENCODED"


class ReflectionOutcome(str, enum.Enum):
    """The conclusion for one parameter."""

    NOT_REFLECTED = "NOT_REFLECTED"
    #: Reflected, but the dangerous characters were neutralised. Not a finding.
    REFLECTED_BUT_ENCODED = "REFLECTED_BUT_ENCODED"
    #: Reflected with at least one dangerous character intact.
    POTENTIALLY_EXECUTABLE_REFLECTION = "POTENTIALLY_EXECUTABLE_REFLECTION"


@dataclass(frozen=True, slots=True)
class Reflection:
    """One place the marker was found in a response."""

    context: HtmlContext
    encoding: EncodingState
    #: Which metacharacters survived unencoded, e.g. {'<', '"'}.
    raw_characters: frozenset[str] = frozenset()
    #: The attribute the value landed in, when the context is an attribute.
    attribute_name: str | None = None
    #: The quote character delimiting the attribute or JS string, if any.
    delimiter: str | None = None
    #: True when the surviving characters include the delimiter, meaning the
    #: value can escape its enclosing string or attribute.
    breaks_out: bool = False


@dataclass(frozen=True, slots=True)
class ReflectionAnalysis:
    """The conclusion for one parameter on one endpoint."""

    outcome: ReflectionOutcome
    #: Every place the marker appeared, worst first.
    reflections: tuple[Reflection, ...] = ()

    @property
    def primary(self) -> Reflection | None:
        return self.reflections[0] if self.reflections else None

    @property
    def is_reflected(self) -> bool:
        return self.outcome is not ReflectionOutcome.NOT_REFLECTED


@dataclass(frozen=True, slots=True)
class XssProbe:
    """The marker sent for one test.

    The canary is *bracketed* between two unique alphanumeric markers:

        ws4f1a...a "'>< ws4f1a...b
        ^^^^^^^^^^  ^^^^  ^^^^^^^^^^
        open        canary   close

    Bracketing is what makes the evidence unambiguous. Without it, a page that
    strips the canary entirely would leave the marker sitting directly against
    the application's own markup — and the `<` of a following `</div>` could be
    mistaken for a surviving metacharacter. With both brackets, whatever the
    application rendered for the canary is exactly the text between them.

    The probe is inert: no script, no event handler, no executable construct.
    """

    token: str
    canary: str

    @property
    def open_marker(self) -> str:
        return f"{self.token}a"

    @property
    def close_marker(self) -> str:
        return f"{self.token}b"

    @property
    def value(self) -> str:
        return f"{self.open_marker}{self.canary}{self.close_marker}"


@dataclass(slots=True)
class XssScanStats:
    """Bookkeeping for one scan, so probe volume stays observable and bounded."""

    requests_sent: int = 0
    parameters_tested: int = 0
    endpoints_tested: int = 0
    parameters_skipped: int = 0
    request_failures: int = 0
    limit_reached: bool = False
    notes: dict[str, int] = field(default_factory=dict)

    def note(self, key: str) -> None:
        self.notes[key] = self.notes.get(key, 0) + 1
