"""Finding identity and deduplication.

Pure aggregation logic — no network, no database.
"""

from __future__ import annotations

import dataclasses

from app.scanner.analysis.aggregator import aggregate_findings
from app.scanner.security.cookies import analyze_cookies, parse_set_cookie
from app.scanner.security.headers import analyze_security_headers
from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingData,
    FindingRule,
    FindingSeverity,
)


def make(rule: FindingRule, *, subject: str | None = None, evidence: str = "e") -> FindingData:
    return FindingData(
        rule=rule,
        title=f"title for {rule.value}",
        category=FindingCategory.SECURITY_HEADER,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.HIGH,
        description="d",
        evidence=evidence,
        impact="i",
        remediation="r",
        subject=subject,
    )


# --- 1. Stable rule identifiers -------------------------------------------- #


def test_detectors_emit_stable_rule_identifiers():
    findings = analyze_security_headers({}, is_https=True, content_type="text/html")
    rules = {f.rule for f in findings}

    assert FindingRule.SECURITY_HEADER_CSP_MISSING in rules
    assert FindingRule.SECURITY_HEADER_HSTS_MISSING in rules
    # Every rule is a real enum member, never a free-form string.
    assert all(isinstance(f.rule, FindingRule) for f in findings)


def test_rule_identity_is_independent_of_the_display_title():
    a = make(FindingRule.SECURITY_HEADER_CSP_MISSING)
    b = dataclasses.replace(a, title="Completely reworded title")
    assert a.identity == b.identity


def test_identity_is_rule_and_subject():
    assert make(FindingRule.COOKIE_SECURE_MISSING, subject="session").identity == (
        "COOKIE_SECURE_MISSING",
        "session",
    )
    assert make(FindingRule.SECURITY_HEADER_CSP_MISSING).identity == (
        "SECURITY_HEADER_CSP_MISSING",
        None,
    )


# --- 2. One rule affecting many endpoints ---------------------------------- #


def test_same_rule_across_endpoints_becomes_one_finding_with_many_occurrences():
    pages = ["https://x.test/", "https://x.test/a", "https://x.test/b"]
    grouped = aggregate_findings(
        (url, make(FindingRule.SECURITY_HEADER_CSP_MISSING)) for url in pages
    )

    assert len(grouped) == 1
    assert grouped[0].occurrence_count == 3
    assert [o.endpoint_url for o in grouped[0].occurrences] == pages
    # The first endpoint seen becomes the finding's own link.
    assert grouped[0].primary_endpoint_url == "https://x.test/"


def test_repeat_of_the_same_endpoint_is_not_double_counted():
    grouped = aggregate_findings(
        [
            ("https://x.test/", make(FindingRule.SECURITY_HEADER_CSP_MISSING)),
            ("https://x.test/", make(FindingRule.SECURITY_HEADER_CSP_MISSING)),
        ]
    )
    assert grouped[0].occurrence_count == 1


# --- 3. Similar titles stay separate --------------------------------------- #


def test_different_cookie_rules_never_merge():
    """"Missing HttpOnly" and "Missing Secure" are different rules."""
    cookie = parse_set_cookie("session=v")
    findings = analyze_cookies([cookie], is_https=True)
    grouped = aggregate_findings(("https://x.test/", f) for f in findings)

    rules = {g.data.rule for g in grouped}
    assert FindingRule.COOKIE_SECURE_MISSING in rules
    assert FindingRule.COOKIE_HTTPONLY_MISSING in rules
    assert FindingRule.COOKIE_SAMESITE_MISSING in rules
    assert len(grouped) == 3


def test_same_rule_on_different_cookies_stays_separate():
    """Merging these would erase which cookie was at fault."""
    grouped = aggregate_findings(
        [
            ("https://x.test/", make(FindingRule.COOKIE_SECURE_MISSING, subject="session")),
            ("https://x.test/", make(FindingRule.COOKIE_SECURE_MISSING, subject="theme")),
        ]
    )

    assert len(grouped) == 2
    assert {g.data.subject for g in grouped} == {"session", "theme"}


def test_same_cookie_same_rule_across_pages_does_merge():
    grouped = aggregate_findings(
        [
            ("https://x.test/a", make(FindingRule.COOKIE_SECURE_MISSING, subject="session")),
            ("https://x.test/b", make(FindingRule.COOKIE_SECURE_MISSING, subject="session")),
        ]
    )
    assert len(grouped) == 1
    assert grouped[0].occurrence_count == 2


# --- 4. Evidence and ordering ---------------------------------------------- #


def test_each_occurrence_keeps_its_own_evidence():
    grouped = aggregate_findings(
        [
            ("https://x.test/a", make(FindingRule.COOKIE_SECURE_MISSING, evidence="on /a")),
            ("https://x.test/b", make(FindingRule.COOKIE_SECURE_MISSING, evidence="on /b")),
        ]
    )
    assert [o.evidence for o in grouped[0].occurrences] == ["on /a", "on /b"]


def test_aggregated_findings_are_ordered_most_severe_first():
    low = dataclasses.replace(
        make(FindingRule.SECURITY_HEADER_REFERRER_POLICY_MISSING),
        severity=FindingSeverity.LOW,
    )
    info = dataclasses.replace(
        make(FindingRule.SECURITY_HEADER_PERMISSIONS_POLICY_MISSING),
        severity=FindingSeverity.INFO,
    )
    medium = make(FindingRule.SECURITY_HEADER_CSP_MISSING)

    grouped = aggregate_findings([("u", info), ("u", low), ("u", medium)])
    assert [g.data.severity for g in grouped] == [
        FindingSeverity.MEDIUM,
        FindingSeverity.LOW,
        FindingSeverity.INFO,
    ]


def test_scan_level_finding_has_a_null_endpoint():
    grouped = aggregate_findings([(None, make(FindingRule.SECURITY_HEADER_CSP_MISSING))])
    assert grouped[0].primary_endpoint_url is None
    assert grouped[0].occurrences[0].endpoint_url is None


def test_empty_input_aggregates_to_nothing():
    assert aggregate_findings([]) == []


# --- Legacy compatibility --------------------------------------------------- #


def test_every_legacy_code_maps_to_a_real_rule():
    """The 0005 migration relies on this mapping being complete and valid."""
    from app.scanner.security.types import LEGACY_CODE_TO_RULE

    assert len(LEGACY_CODE_TO_RULE) == len(list(FindingRule))
    assert all(isinstance(rule, FindingRule) for rule in LEGACY_CODE_TO_RULE.values())
    # No two legacy codes collapse onto the same rule.
    assert len(set(LEGACY_CODE_TO_RULE.values())) == len(LEGACY_CODE_TO_RULE)
