"""Security-header detector tests.

The detector is a pure function, so every case here is just headers in,
findings out — no network, no database.
"""

from __future__ import annotations

from app.scanner.security.headers import analyze_security_headers
from app.scanner.security.types import FindingCategory, FindingSeverity

HTML = "text/html; charset=utf-8"

COMPLETE_HEADERS = {
    "content-type": HTML,
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
}


def codes(headers, *, is_https=True, content_type=HTML) -> set[str]:
    findings = analyze_security_headers(
        headers, is_https=is_https, content_type=content_type
    )
    return {f.code for f in findings}


def find(headers, code, *, is_https=True, content_type=HTML):
    for finding in analyze_security_headers(
        headers, is_https=is_https, content_type=content_type
    ):
        if finding.code == code:
            return finding
    return None


# --- 1. All recommended headers present ------------------------------------ #


def test_fully_configured_response_produces_no_findings():
    assert codes(COMPLETE_HEADERS) == set()


# --- 2. CSP missing -------------------------------------------------------- #


def test_missing_csp_is_reported_as_medium():
    headers = {k: v for k, v in COMPLETE_HEADERS.items() if k != "content-security-policy"}
    finding = find(headers, "missing_csp")

    assert finding is not None
    assert finding.severity is FindingSeverity.MEDIUM
    assert finding.category is FindingCategory.SECURITY_HEADER
    # The wording must not claim an XSS flaw was found.
    assert "no injection testing" in finding.impact.lower()


# --- 3. HSTS missing on HTTPS ---------------------------------------------- #


def test_missing_hsts_reported_on_https():
    headers = {k: v for k, v in COMPLETE_HEADERS.items() if k != "strict-transport-security"}
    finding = find(headers, "missing_hsts", is_https=True)

    assert finding is not None
    assert finding.severity is FindingSeverity.MEDIUM


# --- 4. HSTS NOT reported on plain HTTP ------------------------------------ #


def test_missing_hsts_not_reported_on_http():
    """HSTS is ignored by browsers over HTTP, so reporting it would be a false positive."""
    headers = {k: v for k, v in COMPLETE_HEADERS.items() if k != "strict-transport-security"}
    assert "missing_hsts" not in codes(headers, is_https=False)


def test_hsts_short_max_age_is_informational_only():
    headers = {**COMPLETE_HEADERS, "strict-transport-security": "max-age=600"}
    finding = find(headers, "hsts_short_max_age")

    assert finding is not None
    assert finding.severity is FindingSeverity.INFO


def test_hsts_max_age_zero_is_reported():
    headers = {**COMPLETE_HEADERS, "strict-transport-security": "max-age=0"}
    finding = find(headers, "hsts_disabled")

    assert finding is not None
    assert finding.severity is FindingSeverity.LOW


# --- 5. X-Content-Type-Options missing ------------------------------------- #


def test_missing_content_type_options_is_low():
    headers = {k: v for k, v in COMPLETE_HEADERS.items() if k != "x-content-type-options"}
    finding = find(headers, "missing_content_type_options")

    assert finding is not None
    assert finding.severity is FindingSeverity.LOW


# --- 6. X-Frame-Options missing -------------------------------------------- #


def test_missing_frame_options_is_low():
    headers = {k: v for k, v in COMPLETE_HEADERS.items() if k != "x-frame-options"}
    finding = find(headers, "missing_frame_options")

    assert finding is not None
    assert finding.severity is FindingSeverity.LOW


# --- 7. Referrer-Policy missing -------------------------------------------- #


def test_missing_referrer_policy_is_low():
    headers = {k: v for k, v in COMPLETE_HEADERS.items() if k != "referrer-policy"}
    finding = find(headers, "missing_referrer_policy")

    assert finding is not None
    assert finding.severity is FindingSeverity.LOW


# --- 8. Permissions-Policy missing ----------------------------------------- #


def test_missing_permissions_policy_is_info():
    headers = {k: v for k, v in COMPLETE_HEADERS.items() if k != "permissions-policy"}
    finding = find(headers, "missing_permissions_policy")

    assert finding is not None
    assert finding.severity is FindingSeverity.INFO


# --- 9. Valid X-Frame-Options is not reported ------------------------------ #


def test_valid_frame_options_values_are_accepted():
    for value in ("DENY", "SAMEORIGIN", "sameorigin", "  Deny  "):
        headers = {**COMPLETE_HEADERS, "x-frame-options": value}
        assert "missing_frame_options" not in codes(headers), value


def test_invalid_frame_options_value_is_reported():
    headers = {**COMPLETE_HEADERS, "x-frame-options": "ALLOW-FROM https://example.com"}
    assert "missing_frame_options" in codes(headers)


def test_csp_frame_ancestors_supersedes_x_frame_options():
    """frame-ancestors replaces X-Frame-Options, so its absence is not a gap."""
    headers = {k: v for k, v in COMPLETE_HEADERS.items() if k != "x-frame-options"}
    headers["content-security-policy"] = "default-src 'self'; frame-ancestors 'none'"
    assert "missing_frame_options" not in codes(headers)


# --- 10. Valid X-Content-Type-Options is not reported ---------------------- #


def test_valid_content_type_options_is_accepted():
    for value in ("nosniff", "NOSNIFF", " nosniff "):
        headers = {**COMPLETE_HEADERS, "x-content-type-options": value}
        assert "missing_content_type_options" not in codes(headers), value


def test_wrong_content_type_options_value_is_reported():
    headers = {**COMPLETE_HEADERS, "x-content-type-options": "sniff"}
    assert "missing_content_type_options" in codes(headers)


# --- Extra: permissive CSP, casing, blank values, non-document responses ---- #


def test_permissive_csp_is_informational_not_a_vulnerability():
    headers = {
        **COMPLETE_HEADERS,
        "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'",
    }
    finding = find(headers, "permissive_csp")

    assert finding is not None
    assert finding.severity is FindingSeverity.INFO
    assert "missing_csp" not in codes(headers)


def test_header_lookup_is_case_insensitive():
    headers = {key.upper(): value for key, value in COMPLETE_HEADERS.items()}
    assert codes(headers) == set()


def test_blank_header_value_counts_as_absent():
    headers = {**COMPLETE_HEADERS, "referrer-policy": "   "}
    assert "missing_referrer_policy" in codes(headers)


def test_document_scoped_headers_skipped_for_json_responses():
    """A JSON API is not a document, so CSP/framing findings would be noise."""
    headers = {"content-type": "application/json"}
    result = codes(headers, content_type="application/json")

    assert "missing_csp" not in result
    assert "missing_frame_options" not in result
    assert "missing_referrer_policy" not in result
    assert "missing_permissions_policy" not in result
    # These still apply to any response.
    assert "missing_hsts" in result
    assert "missing_content_type_options" in result


def test_missing_content_type_is_treated_as_a_document():
    """An absent Content-Type must not silently exempt a response from checks."""
    assert "missing_csp" in codes({}, content_type=None)


def test_every_finding_carries_complete_guidance():
    findings = analyze_security_headers({}, is_https=True, content_type=HTML)
    assert findings, "expected findings for a response with no security headers"
    for finding in findings:
        assert finding.code and finding.title
        assert finding.description and finding.evidence
        assert finding.impact and finding.remediation
        assert finding.category is FindingCategory.SECURITY_HEADER


def test_no_finding_exceeds_medium_severity():
    """Missing headers are configuration observations, never HIGH or CRITICAL."""
    findings = analyze_security_headers({}, is_https=True, content_type=HTML)
    assert all(
        f.severity in {FindingSeverity.MEDIUM, FindingSeverity.LOW, FindingSeverity.INFO}
        for f in findings
    )
