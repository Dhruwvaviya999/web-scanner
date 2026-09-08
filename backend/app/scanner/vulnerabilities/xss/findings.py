"""Turning a reflection analysis into a finding — or into nothing.

Pure. This is where the scanner decides what it is willing to claim, and the
rules are deliberately cautious:

* A safely encoded reflection is **not a vulnerability** and produces no
  finding, no matter which context it landed in.
* Nothing here is ever CRITICAL. This detector observes that input reaches a
  context unencoded; it never confirms execution.
* Confidence is HIGH only when the marker demonstrably escapes its enclosing
  construct — the delimiting quote came back raw, or a raw `<` reached a text
  or script context. Otherwise it stays MEDIUM or LOW, because "the bytes are
  here" is weaker evidence than "a browser runs this".
"""

from __future__ import annotations

from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingData,
    FindingRule,
    FindingSeverity,
)
from app.scanner.vulnerabilities.xss.types import (
    EncodingState,
    HtmlContext,
    Reflection,
    ReflectionAnalysis,
    ReflectionOutcome,
)

#: Human wording for each context, used in evidence and descriptions.
CONTEXT_LABELS: dict[HtmlContext, str] = {
    HtmlContext.HTML_TEXT: "HTML text",
    HtmlContext.ATTRIBUTE_QUOTED: "quoted HTML attribute",
    HtmlContext.ATTRIBUTE_UNQUOTED: "unquoted HTML attribute",
    HtmlContext.EVENT_HANDLER: "HTML event-handler attribute",
    HtmlContext.JAVASCRIPT_URI: "javascript: URL",
    HtmlContext.SCRIPT: "inline script",
    HtmlContext.STYLE: "inline stylesheet",
    HtmlContext.HTML_COMMENT: "HTML comment",
    HtmlContext.UNKNOWN: "unclassified location",
}


def subject_for(parameter: str) -> str:
    """Deterministic finding subject.

    The parameter *name* only — never its value, which could carry a token or
    other secret. Two parameters on the same endpoint stay distinguishable
    because the subject differs, which is what the phase-5 identity requires.
    """
    return f"parameter:{parameter}"


def _severity_and_confidence(
    reflection: Reflection,
) -> tuple[FindingSeverity, FindingConfidence] | None:
    """Grade one reflection, or return None when it is not worth reporting."""
    if reflection.encoding is EncodingState.SAFELY_ENCODED:
        # Output encoding did its job. Not a vulnerability.
        return None

    context = reflection.context

    if context is HtmlContext.HTML_COMMENT:
        # Escaping a comment needs "-->" as well; without demonstrating that,
        # this is an observation rather than an executable finding.
        if not reflection.breaks_out:
            return None
        return FindingSeverity.INFO, FindingConfidence.LOW

    if context is HtmlContext.STYLE:
        # Style-context injection is real but rarely directly executable in
        # current browsers, and this detector does not test it properly.
        return FindingSeverity.LOW, FindingConfidence.LOW

    if context in {HtmlContext.SCRIPT, HtmlContext.EVENT_HANDLER, HtmlContext.JAVASCRIPT_URI}:
        # Already a script sink. Escaping the enclosing string makes injection
        # of arbitrary code straightforward, which is the strongest evidence
        # this detector can gather without executing anything.
        if reflection.breaks_out:
            return FindingSeverity.HIGH, FindingConfidence.HIGH
        return FindingSeverity.HIGH, FindingConfidence.MEDIUM

    if context is HtmlContext.ATTRIBUTE_UNQUOTED:
        # No delimiter to escape: a space is enough to add a new attribute.
        return FindingSeverity.HIGH, FindingConfidence.MEDIUM

    if context is HtmlContext.ATTRIBUTE_QUOTED:
        if reflection.breaks_out:
            # The closing quote survived, so a new attribute can be introduced.
            return FindingSeverity.HIGH, FindingConfidence.MEDIUM
        return FindingSeverity.MEDIUM, FindingConfidence.LOW

    if context is HtmlContext.HTML_TEXT:
        if reflection.breaks_out:
            # A raw '<' in text can open a tag.
            return FindingSeverity.HIGH, FindingConfidence.MEDIUM
        return FindingSeverity.MEDIUM, FindingConfidence.LOW

    return FindingSeverity.MEDIUM, FindingConfidence.LOW


def _describe_characters(reflection: Reflection) -> str:
    if not reflection.raw_characters:
        return "none"
    order = [c for c in "\"'><" if c in reflection.raw_characters]
    return " ".join(f"`{c}`" for c in order)


def build_finding(parameter: str, analysis: ReflectionAnalysis) -> FindingData | None:
    """Produce a finding for one reflected parameter, or None.

    None is returned whenever the evidence does not justify a claim: no
    reflection, or a reflection whose dangerous characters were all encoded.
    """
    if analysis.outcome is ReflectionOutcome.NOT_REFLECTED:
        return None

    reflection = analysis.primary
    if reflection is None:
        return None

    graded = _severity_and_confidence(reflection)
    if graded is None:
        return None

    severity, confidence = graded
    label = CONTEXT_LABELS[reflection.context]
    survived = _describe_characters(reflection)

    where = f"a {label}"
    if reflection.attribute_name:
        # The attribute name is markup structure, never user data.
        where = f'the "{reflection.attribute_name}" attribute'

    evidence = (
        f'A controlled scanner marker supplied in the "{parameter}" query parameter was '
        f"reflected into {where}. Metacharacters returned unencoded: {survived}."
    )
    if reflection.breaks_out and reflection.delimiter:
        evidence += (
            f" The enclosing {reflection.delimiter} delimiter was also returned unencoded, "
            "so the value can escape its surrounding construct."
        )

    description = (
        f'The value of the "{parameter}" query parameter is echoed back in the response '
        f"inside {where}, without encoding that would make it inert there. "
        "Detection used an inert marker: no script, event handler or executable "
        "construct was sent, and no JavaScript was executed by the scanner."
    )

    if confidence is FindingConfidence.HIGH:
        impact = (
            "An attacker who can get a victim to open a crafted link to this endpoint may be "
            "able to run script in that victim's browser, in the site's origin — enabling "
            "actions such as reading page content or acting as the user. The marker was "
            "observed escaping its enclosing construct, which is strong evidence, but this "
            "scanner does not execute the page and so has not confirmed execution."
        )
    else:
        impact = (
            "Unencoded reflection into this context may allow an attacker to influence the "
            "rendered page via a crafted link. Whether that reaches script execution depends "
            "on application specifics this scanner did not test — treat it as a lead to "
            "verify by hand rather than a confirmed vulnerability."
        )

    remediation = (
        "Apply output encoding appropriate to the context the value is rendered in — HTML "
        "entity encoding for text and attribute values, JavaScript string escaping inside "
        "script, and URL encoding in URL positions. Prefer a template engine that encodes by "
        "default, and validate the parameter against what the feature actually needs. A "
        "Content-Security-Policy limits the impact but is not a substitute for encoding."
    )

    return FindingData(
        rule=FindingRule.XSS_REFLECTED,
        title="Reflected cross-site scripting",
        category=FindingCategory.XSS,
        severity=severity,
        confidence=confidence,
        description=description,
        evidence=evidence,
        impact=impact,
        remediation=remediation,
        subject=subject_for(parameter),
    )
