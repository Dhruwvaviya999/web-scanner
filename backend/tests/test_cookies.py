"""Cookie parser and detector tests.

The most important case here is `test_cookie_values_are_never_retained`: a
session cookie is a live credential, so the parser must drop values structurally
rather than by convention.
"""

from __future__ import annotations

import dataclasses

from app.scanner.security.cookies import (
    CookieInfo,
    analyze_cookies,
    is_session_cookie,
    parse_set_cookie,
    parse_set_cookie_headers,
)
from app.scanner.security.types import FindingCategory, FindingSeverity


def codes(cookies, *, is_https=True) -> set[str]:
    return {f.code for f in analyze_cookies(cookies, is_https=is_https)}


def find(cookies, code, *, is_https=True):
    for finding in analyze_cookies(cookies, is_https=is_https):
        if finding.code == code:
            return finding
    return None


# --- 1. A fully secured cookie -------------------------------------------- #


def test_secure_session_cookie_produces_no_findings():
    cookie = parse_set_cookie(
        "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"
    )
    assert cookie is not None
    assert codes([cookie]) == set()


# --- 2. Cookie missing Secure on HTTPS ------------------------------------ #


def test_missing_secure_on_https_is_reported():
    cookie = parse_set_cookie("session=abc; HttpOnly; SameSite=Lax")
    finding = find([cookie], "cookie_missing_secure")

    assert finding is not None
    assert finding.severity is FindingSeverity.MEDIUM  # session-like
    assert finding.category is FindingCategory.COOKIE


def test_missing_secure_not_reported_on_http():
    """Over plain HTTP the Secure attribute would be ignored anyway."""
    cookie = parse_set_cookie("session=abc; HttpOnly; SameSite=Lax")
    assert "cookie_missing_secure" not in codes([cookie], is_https=False)


def test_non_session_cookie_missing_secure_is_only_low():
    cookie = parse_set_cookie("theme=dark; SameSite=Lax")
    finding = find([cookie], "cookie_missing_secure")

    assert finding is not None
    assert finding.severity is FindingSeverity.LOW


# --- 3. Session cookie missing HttpOnly ----------------------------------- #


def test_session_cookie_missing_httponly_is_medium_with_medium_confidence():
    cookie = parse_set_cookie("session_id=abc; Secure; SameSite=Lax")
    finding = find([cookie], "session_cookie_missing_httponly")

    assert finding is not None
    assert finding.severity is FindingSeverity.MEDIUM
    # The cookie's purpose is inferred from its name, so never HIGH confidence.
    assert finding.confidence.value == "MEDIUM"
    assert "inferred from its name" in finding.description


# --- 4. Non-session cookie without HttpOnly is NOT reported --------------- #


def test_non_session_cookie_without_httponly_is_not_reported():
    """Many cookies are read by scripts by design; flagging them all is noise."""
    cookie = parse_set_cookie("theme=dark; Secure; SameSite=Lax")
    assert "session_cookie_missing_httponly" not in codes([cookie])


def test_sidebar_like_name_is_not_mistaken_for_a_session_cookie():
    assert not is_session_cookie("sidebar_state")
    assert not is_session_cookie("theme")
    assert not is_session_cookie("locale")


def test_common_framework_session_names_are_recognised():
    for name in (
        "session",
        "sessionid",
        "PHPSESSID",
        "JSESSIONID",
        "connect.sid",
        "laravel_session",
        "access_token",
        "refresh_token",
        "jwt",
        "auth_token",
        "user_session",
    ):
        assert is_session_cookie(name), name


# --- 5 & 6. SameSite present / missing ------------------------------------ #


def test_samesite_present_produces_no_samesite_finding():
    cookie = parse_set_cookie("session=abc; Secure; HttpOnly; SameSite=Strict")
    assert "cookie_missing_samesite" not in codes([cookie])


def test_samesite_missing_is_low_for_session_and_info_otherwise():
    session = parse_set_cookie("session=abc; Secure; HttpOnly")
    other = parse_set_cookie("theme=dark; Secure")

    assert find([session], "cookie_missing_samesite").severity is FindingSeverity.LOW
    assert find([other], "cookie_missing_samesite").severity is FindingSeverity.INFO


def test_samesite_none_without_secure_is_reported():
    cookie = parse_set_cookie("tracker=1; SameSite=None")
    finding = find([cookie], "cookie_samesite_none_without_secure", is_https=False)

    assert finding is not None
    assert finding.severity is FindingSeverity.MEDIUM


# --- 7. Multiple cookies --------------------------------------------------- #


def test_multiple_cookies_are_each_analysed():
    cookies = parse_set_cookie_headers(
        [
            "session=abc; Path=/",
            "theme=dark; Secure; SameSite=Lax",
            "csrftoken=xyz; Secure; HttpOnly; SameSite=Strict",
        ]
    )
    assert [c.name for c in cookies] == ["session", "theme", "csrftoken"]

    findings = analyze_cookies(cookies, is_https=True)
    # Only the insecure "session" cookie should generate the serious findings.
    assert {f.code for f in findings} == {
        "cookie_missing_secure",
        "session_cookie_missing_httponly",
        "cookie_missing_samesite",
    }
    assert all('"session"' in f.evidence for f in findings)


# --- 8. Cookie values are never persisted --------------------------------- #


def test_cookie_values_are_never_retained():
    secret = "s3cr3t-session-value-do-not-store"
    cookie = parse_set_cookie(f"session={secret}; Path=/")

    assert cookie is not None
    # Structural guarantee: there is no field that could hold the value.
    assert "value" not in {f.name for f in dataclasses.fields(CookieInfo)}
    assert secret not in repr(cookie)

    for finding in analyze_cookies([cookie], is_https=True):
        for field in (finding.title, finding.description, finding.evidence,
                      finding.impact, finding.remediation):
            assert secret not in field


# --- 9. Attribute ordering and formatting --------------------------------- #


def test_attribute_order_and_casing_do_not_matter():
    variants = [
        "session=v; Secure; HttpOnly; SameSite=Lax",
        "session=v; samesite=lax; httponly; secure",
        "session=v;SECURE;HTTPONLY;SAMESITE=Lax",
        "session=v; HttpOnly ; SameSite = Lax ; Secure ",
    ]
    for header in variants:
        cookie = parse_set_cookie(header)
        assert cookie is not None, header
        assert cookie.secure is True, header
        assert cookie.http_only is True, header
        assert cookie.same_site is not None, header
        assert cookie.same_site.lower() == "lax", header


def test_domain_path_and_expiry_attributes_are_captured():
    cookie = parse_set_cookie(
        "sid=v; Domain=.example.com; Path=/app; Max-Age=3600; "
        "Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax"
    )
    assert cookie is not None
    assert cookie.domain == ".example.com"
    assert cookie.path == "/app"


def test_value_containing_equals_signs_is_handled():
    cookie = parse_set_cookie("token=abc==def=; Secure; HttpOnly; SameSite=Lax")
    assert cookie is not None
    assert cookie.name == "token"


# --- 10. Malformed input does not crash ----------------------------------- #


def test_malformed_cookies_are_skipped_without_raising():
    for header in ("", "   ", ";;;", "no-equals-sign", "=novalue", "; Secure; HttpOnly"):
        assert parse_set_cookie(header) is None, header


def test_malformed_headers_do_not_stop_valid_ones_being_parsed():
    cookies = parse_set_cookie_headers(
        ["garbage", "", "session=abc; Secure; HttpOnly; SameSite=Lax", ";;;"]
    )
    assert [c.name for c in cookies] == ["session"]


def test_analysis_of_no_cookies_is_empty():
    assert analyze_cookies([], is_https=True) == []


def test_every_cookie_finding_carries_complete_guidance():
    cookie = parse_set_cookie("session=abc")
    findings = analyze_cookies([cookie], is_https=True)

    assert findings
    for finding in findings:
        assert finding.code and finding.title
        assert finding.description and finding.evidence
        assert finding.impact and finding.remediation
        assert finding.category is FindingCategory.COOKIE
        # Cookie hygiene is never CRITICAL/HIGH on its own evidence.
        assert finding.severity in {
            FindingSeverity.MEDIUM,
            FindingSeverity.LOW,
            FindingSeverity.INFO,
        }
