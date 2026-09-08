"""SQL-injection detector, built on the active-probe framework.

Owns only what is specific to SQLi: eligibility, the probe sequence, and calling
the pure analyzer. Transport, scope, budget, timeouts and error handling all
belong to the `ProbeEngine` it is handed — the detector has no other route to
the network, so it cannot escape the scan's safety rules.

Detection-only. Every probe is a syntax probe; none extracts data, enumerates a
schema, or writes. Timing is never used as a signal.

Per-parameter request budget (all subject to the shared `ProbeBudget`):

* 1 baseline.
* Error-based: up to 2 error probes, each stopping early on the first
  baseline-absent error signature.
* Boolean-differential: 2 pairs × 2 attempts = up to 4 probes, only reached if
  error-based found nothing.

The framework's per-parameter cap (default 4) means the boolean stage is only
partly exercised on a well-behaved endpoint — which is fine, since a real
error-based hit short-circuits it, and the budget is authoritative regardless.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from app.scanner.active.comparison import body_similarity, media_type, response_text
from app.scanner.active.engine import ProbeEngine
from app.scanner.active.types import (
    DetectorObservation,
    Eligibility,
    ProbeOutcome,
    ProbePurpose,
    ProbeRequest,
    ProbeTarget,
)
from app.scanner.security.types import FindingData
from app.scanner.types import RawHttpResponse
from app.scanner.vulnerabilities.sqli.analyzer import (
    analyze_error_signals,
    assess_differential,
)
from app.scanner.vulnerabilities.sqli.findings import (
    build_boolean_finding,
    build_error_based_finding,
)
from app.scanner.vulnerabilities.sqli.payloads import boolean_probe_values, error_probe_values
from app.scanner.vulnerabilities.sqli.types import (
    DifferentialSignal,
    ErrorSignalStrength,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_PARAMETERS_PER_ENDPOINT = 6

#: Media types worth analysing as text. SQL errors surface in HTML, JSON and
#: plain text alike, so — unlike XSS — this is not limited to documents. Binary
#: types are skipped: there is no meaningful text to match against.
_ANALYSABLE_MEDIA_PREFIXES = ("text/",)
_ANALYSABLE_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/xml",
        "application/xhtml+xml",
        "application/javascript",
        "application/ld+json",
    }
)

#: The default baseline value when the crawler recorded only a parameter name.
#: A digit suits the commonest injectable shape, a numeric id.
_DEFAULT_BASELINE_VALUE = "1"


def _is_analysable(content_type: str | None) -> bool:
    media = (content_type or "").split(";", 1)[0].strip().lower()
    if not media:
        # No declared type: treat as analysable text rather than skip silently.
        return True
    if media in _ANALYSABLE_MEDIA_TYPES:
        return True
    return media.startswith(_ANALYSABLE_MEDIA_PREFIXES)


class SqlInjectionDetector:
    """Tests discovered GET query parameters for SQL-injection signals."""

    name = "sqli"

    def __init__(
        self, max_parameters_per_endpoint: int = DEFAULT_MAX_PARAMETERS_PER_ENDPOINT
    ) -> None:
        self._max_parameters = max_parameters_per_endpoint

    # --- eligibility (pure, no I/O) ------------------------------------- #

    def eligible(self, target: ProbeTarget) -> Eligibility:
        if target.method.upper() != "GET":
            return Eligibility.no("non_get_method")
        if not target.parameters:
            return Eligibility.no("no_parameters")
        # Content type is checked per-response during probing, not here: the
        # crawler's recorded type can differ from what a probe elicits.
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

    async def _probe_parameter(
        self, target: ProbeTarget, parameter: str, engine: ProbeEngine
    ) -> FindingData | None:
        baseline = await engine.send(
            ProbeRequest(
                target=target,
                parameter=parameter,
                value=_DEFAULT_BASELINE_VALUE,
                purpose=ProbePurpose.BASELINE,
            )
        )
        if not self._usable(baseline):
            return None

        assert baseline.response is not None
        baseline_text = response_text(baseline.response)
        baseline_errors = analyze_error_signals(baseline_text)

        # --- error-based ---------------------------------------------------- #
        error_finding = await self._try_error_based(
            target, parameter, engine, baseline_errors
        )
        if error_finding is not None:
            return error_finding

        # --- boolean-differential (only if error-based found nothing) ------- #
        return await self._try_boolean(
            target, parameter, engine, baseline.response, baseline_text
        )

    async def _try_error_based(
        self, target: ProbeTarget, parameter: str, engine: ProbeEngine, baseline_errors
    ) -> FindingData | None:
        for label, value in error_probe_values(_DEFAULT_BASELINE_VALUE):
            if not engine.can_send(_probe_request(target, parameter, value)):
                return None

            outcome = await engine.send(_probe_request(target, parameter, value))
            if not self._usable(outcome):
                continue

            assert outcome.response is not None
            analysis = analyze_error_signals(response_text(outcome.response))
            if not analysis.has_error or analysis.primary is None:
                continue

            # False-positive control: an error already in the baseline is not
            # evidence that this probe caused anything.
            if _same_signature_in_baseline(analysis, baseline_errors):
                engine.stats.note("sqli:error_in_baseline")
                continue

            signal = analysis.primary
            logger.debug(
                "SQLi error signal: parameter=%s family=%s probe=%s",
                parameter,
                signal.family.value,
                label,
            )
            return build_error_based_finding(parameter, signal.family, signal.strength, label)

        return None

    async def _try_boolean(
        self,
        target: ProbeTarget,
        parameter: str,
        engine: ProbeEngine,
        baseline_response: RawHttpResponse,
        baseline_text: str,
    ) -> FindingData | None:
        for label, true_value, false_value in boolean_probe_values(_DEFAULT_BASELINE_VALUE):
            # Each pair needs four probes (two attempts). If the budget cannot
            # cover a full pair, stop rather than draw a conclusion from half of
            # one.
            if not self._budget_for_pair(target, parameter, engine):
                return None

            first = await self._differential_attempt(
                target, parameter, engine, baseline_response, true_value, false_value
            )
            if first is None:
                continue

            second = await self._differential_attempt(
                target, parameter, engine, baseline_response, true_value, false_value
            )

            if assess_differential(first, second):
                logger.debug("SQLi boolean differential: parameter=%s pair=%s", parameter, label)
                return build_boolean_finding(parameter, label)

        return None

    async def _differential_attempt(
        self,
        target: ProbeTarget,
        parameter: str,
        engine: ProbeEngine,
        baseline_response: RawHttpResponse,
        true_value: str,
        false_value: str,
    ) -> DifferentialSignal | None:
        true_outcome = await engine.send(_probe_request(target, parameter, true_value))
        false_outcome = await engine.send(_probe_request(target, parameter, false_value))
        if not self._usable(true_outcome) or not self._usable(false_outcome):
            return None

        assert true_outcome.response is not None and false_outcome.response is not None
        return DifferentialSignal(
            true_similarity=body_similarity(baseline_response, true_outcome.response),
            false_similarity=body_similarity(baseline_response, false_outcome.response),
            reproduced=False,
            status_differs=baseline_response.status_code != false_outcome.response.status_code,
        )

    # --- helpers --------------------------------------------------------- #

    def _usable(self, outcome: ProbeOutcome) -> bool:
        """A response worth analysing: present, and textual."""
        if not outcome.ok or outcome.response is None:
            return False
        return _is_analysable(media_type(outcome.response))

    def _budget_for_pair(self, target: ProbeTarget, parameter: str, engine: ProbeEngine) -> bool:
        """Whether at least one differential probe is still affordable.

        The budget is authoritative and checked before every send regardless;
        this only avoids starting a pair with nothing left, so a half-pair never
        produces a conclusion.
        """
        return engine.can_send(_probe_request(target, parameter, _DEFAULT_BASELINE_VALUE))


def _probe_request(target: ProbeTarget, parameter: str, value: str) -> ProbeRequest:
    return ProbeRequest(
        target=target, parameter=parameter, value=value, purpose=ProbePurpose.PROBE
    )


def _same_signature_in_baseline(analysis, baseline_errors) -> bool:
    """True when the probe's error signature already appeared in the baseline."""
    baseline_signatures = {signal.signature for signal in baseline_errors.signals}
    return any(signal.signature in baseline_signatures for signal in analysis.signals)
