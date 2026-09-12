"""Path-traversal / LFI detector, built on the active-probe framework.

Implements the `ActiveDetector` contract — `eligible` (pure) and `probe` (given
the engine) — so it reaches the network only through the `ProbeEngine`, and
inherits that layer's scope, SSRF revalidation, redirect bounds, budget and
credential scoping. It never opens a connection of its own.

The sequence per file-like parameter is deliberate and conservative:

1. **Baseline.** Request the parameter with an ordinary value. If the baseline
   is not a healthy 2xx/3xx, the parameter is skipped — a broken endpoint
   cannot anchor a differential.
2. **Probe.** Send the bounded, fixed traversal set (at most eight), each aimed
   at the controlled canary. Stop at the first probe that returns the marker.
3. **Reproduce.** Re-send that one probe. A one-off is not a finding.
4. **Analyze.** Hand the evidence to the pure analyzer, which alone decides the
   verdict.

Detection-only. Every probe is a GET; nothing writes, deletes, or executes, and
the only file it can retrieve is the fixture's harmless canary.
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
from app.scanner.path_security.analyzer import (
    BaselineEvidence,
    ProbeEvidence,
    analyze,
    baseline_is_usable,
)
from app.scanner.path_security.findings import build_traversal_finding
from app.scanner.path_security.parameter_classifier import classify
from app.scanner.path_security.payloads import (
    CANARY_MARKER,
    CANARY_SUFFIX,
    TraversalProbe,
    traversal_probes,
)
from app.scanner.path_security.types import (
    InclusionMechanism,
    ParameterClass,
    PathSecurityLimits,
    PathSecurityStats,
    TargetPlatform,
    TraversalObservation,
    TraversalVerdict,
)
from app.scanner.security.types import FindingData
from app.scanner.types import RawHttpResponse

logger = logging.getLogger(__name__)

#: An ordinary baseline value. A plausible filename, so an endpoint that serves
#: files behaves normally rather than erroring before any probe is sent.
_BASELINE_VALUE = "readme.txt"

#: Parameter names that point at inclusion rather than plain file serving. Used
#: only to label the mechanism once the canary proves the escape — never to
#: conclude anything on its own.
_LFI_NAMES = frozenset(
    {"template", "include", "view", "page", "content", "module", "skin", "theme"}
)

#: A distinctive slice of the canary path. Its presence *without* the marker is
#: reflection — the app echoed the input but did not read the file.
_REFLECTION_TOKEN = "traversal-marker"


class PathTraversalDetector:
    """Tests file-like GET parameters for controlled directory traversal."""

    name = "path_traversal"

    def __init__(
        self,
        limits: PathSecurityLimits | None = None,
        stats: PathSecurityStats | None = None,
        *,
        authenticated: bool = False,
        context_label: str | None = None,
    ) -> None:
        self._limits = limits or PathSecurityLimits()
        #: Coverage is accumulated here and read by the module after the run.
        self.stats = stats or PathSecurityStats()
        self._authenticated = authenticated
        self._context_label = context_label
        #: Every observation, reportable or not, for the coverage block.
        self._observations: list[TraversalObservation] = []

    @property
    def observations(self) -> tuple[TraversalObservation, ...]:
        return tuple(self._observations)

    # --- eligibility (pure, no I/O) ------------------------------------- #

    def eligible(self, target: ProbeTarget) -> Eligibility:
        if target.method.upper() != "GET":
            return Eligibility.no("non_get_method")
        if not target.parameters:
            return Eligibility.no("no_parameters")
        if not any(self._classify(target, p).eligible for p in target.parameters):
            return Eligibility.no("no_file_parameter")
        return Eligibility.yes()

    # --- probing --------------------------------------------------------- #

    async def probe(
        self, target: ProbeTarget, engine: ProbeEngine
    ) -> Sequence[DetectorObservation]:
        observations: list[DetectorObservation] = []

        eligible_params = [
            p for p in target.parameters if self._classify(target, p).eligible
        ]

        # Coverage: count everything considered on this endpoint, so the report
        # shows how much surface was looked at versus actively probed.
        for parameter in target.parameters:
            self.stats.parameters_considered += 1
            assessment = self._classify(target, parameter)
            if assessment.eligible:
                self.stats.file_parameters += 1
            elif assessment.classification is ParameterClass.UNKNOWN:
                self.stats.uncertain_classifications += 1

        tested_any = False
        for parameter in eligible_params[: self._limits.max_parameters_per_endpoint]:
            finding, tested = await self._probe_parameter(target, parameter, engine)
            tested_any = tested_any or tested
            if finding is not None:
                observations.append((target.url, finding))
                self.stats.findings_count += 1

        if tested_any:
            self.stats.endpoints_tested += 1

        return observations

    async def _probe_parameter(
        self, target: ProbeTarget, parameter: str, engine: ProbeEngine
    ) -> tuple[FindingData | None, bool]:
        # --- baseline ---------------------------------------------------- #
        baseline_outcome = await engine.send(
            ProbeRequest(
                target=target,
                parameter=parameter,
                value=_BASELINE_VALUE,
                purpose=ProbePurpose.BASELINE,
            )
        )
        baseline, baseline_response = self._baseline_evidence(baseline_outcome)
        if not baseline.usable or baseline_response is None:
            self.stats.parameters_skipped += 1
            self.stats.note("skipped:baseline_unusable")
            return None, False

        self.stats.parameters_tested += 1

        # --- traversal probes, stopping at the first canary hit ---------- #
        probes: list[ProbeEvidence] = []
        hit_probe: TraversalProbe | None = None

        for probe in traversal_probes(self._limits.max_variants_per_parameter):
            if not engine.can_send(_request(target, parameter, probe.render())):
                self.stats.budget_exhausted = True
                self.stats.note("budget_exhausted")
                break

            outcome = await engine.send(_request(target, parameter, probe.render()))
            self.stats.traversal_probes += 1
            evidence = self._probe_evidence(outcome, baseline_response)
            if evidence is None:
                self.stats.failed_probes += 1
                continue
            probes.append(evidence)

            if evidence.canary_present:
                hit_probe = probe
                self.stats.canary_matches += 1
                break

        # --- reproduction ------------------------------------------------- #
        if hit_probe is not None and engine.can_send(
            _request(target, parameter, hit_probe.render())
        ):
            repeat = await engine.send(_request(target, parameter, hit_probe.render()))
            self.stats.traversal_probes += 1
            repeat_evidence = self._probe_evidence(repeat, baseline_response)
            if repeat_evidence is not None:
                probes.append(repeat_evidence)
                if repeat_evidence.canary_present:
                    self.stats.canary_matches += 1

        # --- verdict (pure) ---------------------------------------------- #
        assessment = analyze(baseline, tuple(probes))
        mechanism = self._mechanism_for(parameter)
        if (
            mechanism is InclusionMechanism.LOCAL_FILE_INCLUSION
            and assessment.canary_matched
        ):
            self.stats.lfi_candidates += 1

        observation = TraversalObservation(
            endpoint=target.url,
            method=target.method.upper(),
            parameter=parameter,
            verdict=assessment.verdict,
            mechanism=mechanism,
            canary_matched=assessment.canary_matched,
            reproduced=assessment.reproduced,
            baseline_status=baseline.status,
            probe_status=_first_probe_status(probes),
            baseline_media_type=baseline.media_type,
            probe_media_type=_canary_probe_media(probes),
            platform=TargetPlatform.UNKNOWN,
            authenticated=self._authenticated,
            context_label=self._context_label,
            signals=assessment.signals,
        )
        self._observations.append(observation)

        if assessment.verdict is TraversalVerdict.STRONG:
            logger.debug(
                "Path traversal confirmed: parameter=%s mechanism=%s",
                parameter,
                mechanism.value,
            )
            return build_traversal_finding(observation), True
        return None, True

    # --- helpers --------------------------------------------------------- #

    def _classify(self, target: ProbeTarget, parameter: str):
        return classify(
            parameter, endpoint=target.url, content_type=target.content_type
        )

    def _mechanism_for(self, parameter: str) -> InclusionMechanism:
        normalized = parameter.strip().lower()
        if any(name in normalized for name in _LFI_NAMES):
            return InclusionMechanism.LOCAL_FILE_INCLUSION
        return InclusionMechanism.PATH_TRAVERSAL

    def _baseline_evidence(
        self, outcome: ProbeOutcome
    ) -> tuple[BaselineEvidence, RawHttpResponse | None]:
        if not outcome.ok or outcome.response is None:
            return BaselineEvidence(usable=False), None
        response = outcome.response
        text = self._bounded_text(response)
        evidence = BaselineEvidence(
            usable=baseline_is_usable(response.status_code),
            status=response.status_code,
            media_type=media_type(response),
            canary_present=CANARY_MARKER in text,
        )
        return evidence, response

    def _probe_evidence(
        self, outcome: ProbeOutcome, baseline_response: RawHttpResponse
    ) -> ProbeEvidence | None:
        if not outcome.ok or outcome.response is None:
            return None
        response = outcome.response
        text = self._bounded_text(response)
        canary = CANARY_MARKER in text
        # Reflection: the app echoed the canary path but did not return the
        # marker content. Distinct from retrieval, and never a finding.
        reflected = (not canary) and (
            _REFLECTION_TOKEN in text or "traversal-marker.txt" in text
        )
        return ProbeEvidence(
            status=response.status_code,
            media_type=media_type(response),
            canary_present=canary,
            body_similarity=body_similarity(baseline_response, response),
            reflected=reflected,
        )

    def _bounded_text(self, response: RawHttpResponse) -> str:
        """Decoded response text, bounded, then discarded by the caller.

        The body exists only for the duration of this call; what leaves is a
        boolean (marker present) computed here. Nothing downstream keeps it.
        """
        limit = self._limits.max_response_bytes
        if len(response.body) <= limit:
            return response_text(response)
        from app.scanner.response_analyzer import decode_html

        return decode_html(response.body[:limit], response.headers.get("content-type"))


def _request(target: ProbeTarget, parameter: str, value: str) -> ProbeRequest:
    return ProbeRequest(
        target=target, parameter=parameter, value=value, purpose=ProbePurpose.PROBE
    )


def _first_probe_status(probes: Sequence[ProbeEvidence]) -> int | None:
    return probes[0].status if probes else None


def _canary_probe_media(probes: Sequence[ProbeEvidence]) -> str | None:
    for probe in probes:
        if probe.canary_present:
            return probe.media_type
    return probes[0].media_type if probes else None
