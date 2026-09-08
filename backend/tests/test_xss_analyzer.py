"""Reflected-XSS analyser tests.

Pure: markup in, classification out. No network, no database, no browser.
"""

from __future__ import annotations

from app.scanner.security.types import FindingCategory, FindingConfidence, FindingRule, FindingSeverity
from app.scanner.vulnerabilities.xss.analyzer import analyze_reflection, is_html_document
from app.scanner.vulnerabilities.xss.findings import build_finding, subject_for
from app.scanner.vulnerabilities.xss.payloads import CANARY, new_probe
from app.scanner.vulnerabilities.xss.types import (
    EncodingState,
    HtmlContext,
    ReflectionOutcome,
    XssProbe,
)

PROBE = XssProbe(token="wsdeadbeef1234", canary=CANARY)
OPEN, CLOSE = PROBE.open_marker, PROBE.close_marker

#: Canary returned untouched.
RAW = PROBE.value
#: Canary returned HTML-encoded.
ENCODED = f"{OPEN}&quot;&#x27;&gt;&lt;{CLOSE}"
#: Canary removed entirely by the application.
STRIPPED = f"{OPEN}{CLOSE}"


def analyze(markup: str):
    return analyze_reflection(markup, OPEN, CLOSE, CANARY)


def finding_for(markup: str, parameter: str = "q"):
    return build_finding(parameter, analyze(markup))


# =========================================================================== #
# Reflection detection
# =========================================================================== #


def test_marker_not_reflected():
    analysis = analyze("<html><body>nothing to see</body></html>")
    assert analysis.outcome is ReflectionOutcome.NOT_REFLECTED
    assert analysis.primary is None
    assert finding_for("<html><body>nothing</body></html>") is None


def test_marker_reflected_in_html_text():
    analysis = analyze(f"<div>{RAW}</div>")
    assert analysis.primary.context is HtmlContext.HTML_TEXT
    assert analysis.outcome is ReflectionOutcome.POTENTIALLY_EXECUTABLE_REFLECTION


def test_marker_html_encoded_is_not_a_finding():
    analysis = analyze(f"<div>{ENCODED}</div>")
    assert analysis.primary.encoding is EncodingState.SAFELY_ENCODED
    assert analysis.outcome is ReflectionOutcome.REFLECTED_BUT_ENCODED
    assert finding_for(f"<div>{ENCODED}</div>") is None


def test_marker_inside_quoted_attribute():
    analysis = analyze(f'<input type="text" value="{RAW}">')
    reflection = analysis.primary
    assert reflection.context is HtmlContext.ATTRIBUTE_QUOTED
    assert reflection.attribute_name == "value"
    assert reflection.delimiter == '"'
    assert reflection.breaks_out is True


def test_marker_inside_unquoted_attribute():
    analysis = analyze(f"<input value={RAW}>")
    assert analysis.primary.context is HtmlContext.ATTRIBUTE_UNQUOTED


def test_marker_inside_script():
    analysis = analyze(f"<script>var t = {RAW};</script>")
    assert analysis.primary.context is HtmlContext.SCRIPT


def test_marker_inside_event_handler_attribute():
    analysis = analyze(f"<button onclick=\"go('{RAW}')\">x</button>")
    reflection = analysis.primary
    assert reflection.context is HtmlContext.EVENT_HANDLER
    assert reflection.attribute_name == "onclick"


def test_marker_inside_html_comment():
    analysis = analyze(f"<!-- debug: {RAW} -->")
    assert analysis.primary.context is HtmlContext.HTML_COMMENT


def test_marker_inside_javascript_string():
    analysis = analyze(f'<script>\n  var query = "{RAW}";\n</script>')
    reflection = analysis.primary
    assert reflection.context is HtmlContext.SCRIPT
    # The enclosing string delimiter is identified, and the canary breaks it.
    assert reflection.delimiter == '"'
    assert reflection.breaks_out is True


def test_marker_inside_single_quoted_javascript_string():
    analysis = analyze(f"<script>var q = '{RAW}';</script>")
    assert analysis.primary.delimiter == "'"


def test_marker_appearing_multiple_times_reports_the_worst_context():
    markup = f"<div>{ENCODED}</div><script>var a = '{RAW}';</script><p>{ENCODED}</p>"
    analysis = analyze(markup)
    assert len(analysis.reflections) == 3
    # Script outranks text.
    assert analysis.primary.context is HtmlContext.SCRIPT


def test_marker_with_partial_encoding():
    """Only the angle brackets encoded: quotes still escape an attribute."""
    markup = f'<input value="{OPEN}&quot;\'&gt;&lt;{CLOSE}">'
    reflection = analyze(markup).primary
    assert reflection.encoding is EncodingState.PARTIALLY_ENCODED
    assert "'" in reflection.raw_characters
    assert "<" not in reflection.raw_characters


def test_marker_in_json_body_is_not_an_html_finding():
    """JSON is not a document, so it is never analysed as one."""
    assert is_html_document("application/json") is False
    assert is_html_document("image/png") is False
    assert is_html_document("text/html; charset=utf-8") is True
    assert is_html_document(None) is False


def test_empty_response():
    assert analyze("").outcome is ReflectionOutcome.NOT_REFLECTED


def test_malformed_html_does_not_raise():
    for markup in (
        f"<div><p>unclosed {RAW}",
        f"<input value='{RAW}",
        f"<script>var a = '{RAW}",
        f"<!-- {RAW}",
        f"<<>>{RAW}<<",
    ):
        analysis = analyze(markup)
        assert analysis.is_reflected, markup


def test_marker_matching_is_case_sensitive():
    """An uppercased echo is a transformation, not a verbatim reflection."""
    assert analyze(f"<div>{RAW.upper()}</div>").outcome is ReflectionOutcome.NOT_REFLECTED


def test_special_characters_around_the_marker_are_not_credited():
    """The canary is bracketed, so adjacent page markup can never be counted."""
    reflection = analyze(f"<div>{STRIPPED}</div>").primary
    # The '<' of "</div>" sits right after the marker but is not the canary.
    assert reflection.encoding is EncodingState.SAFELY_ENCODED
    assert reflection.raw_characters == frozenset()


def test_missing_close_marker_credits_nothing():
    """A truncated or rewritten value yields no evidence of survival."""
    reflection = analyze(f'<div>{OPEN}"\'></div>').primary
    assert reflection.encoding is EncodingState.SAFELY_ENCODED


# =========================================================================== #
# False-positive control
# =========================================================================== #


def test_encoded_reflection_is_never_reported():
    for markup in (
        f"<div>{ENCODED}</div>",
        f'<input value="{ENCODED}">',
        f'<script>var q = "{ENCODED}";</script>',
        f"<button onclick=\"f('{ENCODED}')\">x</button>",
        f"<!-- {ENCODED} -->",
    ):
        assert finding_for(markup) is None, markup


def test_stripped_reflection_is_never_reported():
    for markup in (
        f"<div>{STRIPPED}</div>",
        f'<input value="{STRIPPED}">',
        f"<script>var q = '{STRIPPED}';</script>",
    ):
        assert finding_for(markup) is None, markup


def test_comment_reflection_is_informational_not_executable():
    finding = finding_for(f"<!-- {RAW} -->")
    assert finding is not None
    assert finding.severity is FindingSeverity.INFO
    assert finding.confidence is FindingConfidence.LOW


def test_plain_text_reflection_is_not_high_confidence():
    """Bytes in the page is weaker evidence than escaping a construct."""
    finding = finding_for(f"<div>{RAW}</div>")
    assert finding.severity is FindingSeverity.HIGH
    assert finding.confidence is FindingConfidence.MEDIUM


def test_quoted_attribute_without_quote_survival_is_only_medium():
    """Angle brackets survive but the delimiting quote does not."""
    markup = f'<input value="{OPEN}&quot;&#x27;><{CLOSE}">'
    finding = build_finding("q", analyze(markup))
    assert finding.severity is FindingSeverity.MEDIUM
    assert finding.confidence is FindingConfidence.LOW


def test_nothing_is_ever_critical():
    for markup in (
        f"<script>var q = '{RAW}';</script>",
        f"<button onclick=\"f('{RAW}')\">x</button>",
        f'<a href="javascript:f(\'{RAW}\')">x</a>',
        f"<div>{RAW}</div>",
        f'<input value="{RAW}">',
    ):
        finding = build_finding("q", analyze(markup))
        assert finding is not None
        assert finding.severity is not FindingSeverity.CRITICAL, markup


# =========================================================================== #
# Finding shape
# =========================================================================== #


def test_finding_uses_the_stable_rule_and_category():
    finding = finding_for(f"<script>var q = '{RAW}';</script>")
    assert finding.rule is FindingRule.XSS_REFLECTED
    assert finding.rule.value == "XSS_REFLECTED"
    assert finding.category is FindingCategory.XSS


def test_subject_identifies_the_parameter_deterministically():
    assert subject_for("q") == "parameter:q"
    finding = finding_for(f"<div>{RAW}</div>", parameter="search")
    assert finding.subject == "parameter:search"


def test_different_parameters_produce_different_identities():
    a = finding_for(f"<div>{RAW}</div>", parameter="q")
    b = finding_for(f"<div>{RAW}</div>", parameter="page")
    assert a.identity != b.identity


def test_executable_context_reaches_high_confidence():
    finding = finding_for(f"<script>var q = \"{RAW}\";</script>")
    assert finding.severity is FindingSeverity.HIGH
    assert finding.confidence is FindingConfidence.HIGH


def test_finding_never_contains_the_marker_or_a_parameter_value():
    """Evidence names the parameter and the context, never the probe itself."""
    finding = finding_for(f'<input value="{RAW}">')
    blob = " ".join(
        [finding.title, finding.description, finding.evidence, finding.impact, finding.remediation]
    )
    assert PROBE.token not in blob
    assert OPEN not in blob
    assert CLOSE not in blob


def test_finding_wording_does_not_claim_confirmed_execution():
    for markup in (f"<script>var q = '{RAW}';</script>", f"<div>{RAW}</div>"):
        finding = build_finding("q", analyze(markup))
        lowered = f"{finding.impact} {finding.description}".lower()
        assert "may be able to" in lowered or "may allow" in lowered
        assert "no javascript was executed" in lowered or "did not test" in lowered


def test_every_finding_carries_complete_guidance():
    finding = finding_for(f'<input value="{RAW}">')
    assert finding.title and finding.description
    assert finding.evidence and finding.impact and finding.remediation
    assert "encoding" in finding.remediation.lower()


def test_probe_marker_is_inert():
    """The probe must contain nothing executable."""
    probe = new_probe()
    lowered = probe.value.lower()
    for dangerous in ("<script", "javascript:", "onerror", "onload", "alert(", "</"):
        assert dangerous not in lowered, dangerous
