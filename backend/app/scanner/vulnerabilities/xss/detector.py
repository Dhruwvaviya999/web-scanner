"""Reflected-XSS detector, built on the active-probe framework.

The detector owns only what is specific to reflected XSS:

* which targets are worth testing (`eligible`),
* the baseline-then-probe sequence (`probe`),
* interpreting the response — delegated to `analyzer.py`, pure,
* deciding what to claim — delegated to `findings.py`, pure.

Everything generic is the framework's: URL construction, scope revalidation,
the SSRF guard, redirect policy, timeouts, probe budget and error handling. The
detector is handed a `ProbeEngine` rather than a transport, so it has no way to
reach the network outside those rules.

Request budget per parameter, unchanged from phase 6:

* **1 request** when the parameter is not reflected — the baseline. If its
  token does not come back, the probe is never sent.
* **2 requests** when it is reflected — baseline, then the encoding probe.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from app.scanner.active.comparison import contains_marker, media_type, response_text
from app.scanner.active.engine import ProbeEngine
from app.scanner.active.types import (
    DetectorObservation,
    Eligibility,
    ProbePurpose,
    ProbeRequest,
    ProbeTarget,
)
from app.scanner.vulnerabilities.xss.analyzer import analyze_reflection, is_html_document
from app.scanner.vulnerabilities.xss.findings import build_finding
from app.scanner.vulnerabilities.xss.payloads import new_baseline_token, new_probe
from app.scanner.vulnerabilities.xss.types import ReflectionAnalysis

logger = logging.getLogger(__name__)

#: Parameters probed on any one endpoint. The framework's per-parameter and
#: per-scan budgets still apply on top of this.
DEFAULT_MAX_PARAMETERS_PER_ENDPOINT = 8


class ReflectedXssDetector:
    """Tests discovered GET query parameters for reflected XSS."""

    name = "xss_reflected"

    def __init__(
        self, max_parameters_per_endpoint: int = DEFAULT_MAX_PARAMETERS_PER_ENDPOINT
    ) -> None:
        self._max_parameters = max_parameters_per_endpoint

    # --- eligibility (pure, no I/O) ------------------------------------- #

    def eligible(self, target: ProbeTarget) -> Eligibility:
        """Only GET endpoints that return a document and accept parameters.

        HTML-context analysis of a JSON or binary response would be meaningless,
        and an endpoint with no discovered parameters has no input surface for
        this detector to test.
        """
        if target.method.upper() != "GET":
            return Eligibility.no("non_get_method")
        if not target.parameters:
            return Eligibility.no("no_parameters")
        if not is_html_document(target.content_type):
            return Eligibility.no("non_html_endpoint")
        return Eligibility.yes()

    # --- probing --------------------------------------------------------- #

    async def probe(
        self, target: ProbeTarget, engine: ProbeEngine
    ) -> Sequence[DetectorObservation]:
        observations: list[DetectorObservation] = []

        for parameter in target.parameters[: self._max_parameters]:
            finding = await self._probe_parameter(target, parameter, engine)
            if finding is not None:
                observations.append((target.url, finding))

        return observations

    async def _probe_parameter(self, target: ProbeTarget, parameter: str, engine: ProbeEngine):
        # --- baseline: is this parameter reflected at all? ----------------- #
        baseline_token = new_baseline_token()
        baseline = await engine.send(
            ProbeRequest(
                target=target,
                parameter=parameter,
                value=baseline_token,
                purpose=ProbePurpose.BASELINE,
            )
        )
        if not baseline.ok:
            # A failed request yields no finding: fabricating one for a page
            # that was never read would be inventing evidence.
            return None

        assert baseline.response is not None
        if not is_html_document(media_type(baseline.response)):
            engine.stats.note("xss:non_html_response")
            return None

        if not contains_marker(baseline.response, baseline_token):
            engine.stats.note("xss:not_reflected")
            return None

        # --- probe: which metacharacters survive encoding? ----------------- #
        marker = new_probe()
        probe = await engine.send(
            ProbeRequest(
                target=target,
                parameter=parameter,
                value=marker.value,
                purpose=ProbePurpose.PROBE,
            )
        )
        if not probe.ok:
            return None

        assert probe.response is not None
        if not is_html_document(media_type(probe.response)):
            engine.stats.note("xss:non_html_response")
            return None

        analysis = self._analyze(response_text(probe.response), marker)
        finding = build_finding(parameter, analysis)

        if finding is None:
            # Reflected but safely encoded, or not reflected on the probe.
            engine.stats.note(f"xss:{analysis.outcome.value.lower()}")
            return None

        logger.debug(
            "Reflected XSS observed: parameter=%s context=%s",
            parameter,
            analysis.primary.context.value if analysis.primary else "unknown",
        )
        return finding

    # --- interpretation (delegated, pure) -------------------------------- #

    @staticmethod
    def _analyze(body: str, marker) -> ReflectionAnalysis:
        """Where the marker landed and what survived encoding."""
        return analyze_reflection(body, marker.open_marker, marker.close_marker, marker.canary)
