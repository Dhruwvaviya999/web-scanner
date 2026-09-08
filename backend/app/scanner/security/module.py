"""The scan module that runs the security detectors.

Glue only: it takes the response `HttpProbeModule` already fetched and hands it
to the pure analysers, then attaches what they return to the report. It performs
no I/O of its own — no extra requests are made to the target, which is what
keeps this phase passive.
"""

from __future__ import annotations

from app.scanner.security.cookies import analyze_cookies, parse_set_cookie_headers
from app.scanner.security.headers import analyze_security_headers
from app.scanner.security.types import sort_findings
from app.scanner.types import ScanReport, ScanTarget


class SecurityAnalysisModule:
    """Derives security findings from the response already collected."""

    name = "security_analysis"

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        raw = report.raw
        if raw is None:
            # The probe did not produce a response, so there is nothing to judge.
            # A failed scan gets no findings rather than misleading ones.
            return

        content_type = raw.headers.get("content-type")
        cookies = parse_set_cookie_headers(raw.set_cookie)

        findings = [
            *analyze_security_headers(
                raw.headers, is_https=raw.is_https, content_type=content_type
            ),
            *analyze_cookies(cookies, is_https=raw.is_https),
        ]

        report.findings = sort_findings(findings)
        report.metadata["cookies_analyzed"] = len(cookies)
