"""Pure differential and canary analysis for traversal probes.

No network, no state — primitive evidence in, a verdict out — so every branch is
trivially testable, which for a detector that could otherwise cry wolf is the
point.

The evidence hierarchy, strongest first:

1. **Canary retrieval, reproduced.** A probe response contained the controlled
   marker the baseline did not, and a second identical probe did too. This is
   the only path to `STRONG`, because it is the only evidence that the
   application actually returned a file from outside its boundary. Reflection of
   the payload cannot produce it — the marker is file content, not the input.
2. **Canary retrieval, once.** Real but unconfirmed; `POSSIBLE`.
3. **A material differential with no canary.** The endpoint behaved differently
   under a traversal probe, but nothing proves a file was read. `POSSIBLE` at
   most, and only when the difference is more than noise.
4. **Anything else** — a reflected payload, a 404, an error page, a body that
   merely changed size — is `NONE`.

The most important false-positive guard sits at the very top: if the *baseline*
already contained the marker, nothing can be attributed to a probe, and the
verdict is `UNKNOWN`.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.scanner.path_security.types import TraversalVerdict

#: Below this body similarity, a probe response is "materially different" from
#: the baseline. High bar: shared page templates make unrelated pages look
#: alike, so only a large divergence counts as a differential.
_MATERIAL_DIVERGENCE = 0.5


@dataclass(frozen=True, slots=True)
class BaselineEvidence:
    """What the unmodified request established. Safe metadata only."""

    usable: bool
    status: int | None = None
    media_type: str | None = None
    #: Whether the marker was already present without any probe. If true, the
    #: endpoint is not attributable and nothing is concluded.
    canary_present: bool = False


@dataclass(frozen=True, slots=True)
class ProbeEvidence:
    """What one traversal probe produced. Carries no body, no payload."""

    status: int | None = None
    media_type: str | None = None
    #: The controlled marker appeared in this response body.
    canary_present: bool = False
    #: Rough similarity to the baseline body, 0.0-1.0.
    body_similarity: float = 1.0
    #: The probe value was echoed back. Reflection is not retrieval.
    reflected: bool = False


@dataclass(frozen=True, slots=True)
class TraversalAssessment:
    """The analyzer's conclusion for one parameter."""

    verdict: TraversalVerdict
    canary_matched: bool = False
    reproduced: bool = False
    signals: tuple[str, ...] = ()


def baseline_is_usable(status: int | None) -> bool:
    """Whether a baseline is worth probing against.

    A failing baseline — missing, server error, or no response — cannot anchor a
    differential, so the parameter is skipped rather than probed against noise.
    """
    if status is None:
        return False
    return 200 <= status < 400 and status != 304


def analyze(
    baseline: BaselineEvidence, probes: tuple[ProbeEvidence, ...]
) -> TraversalAssessment:
    """Reduce baseline-plus-probes to a verdict. Pure."""
    if not baseline.usable:
        return TraversalAssessment(
            verdict=TraversalVerdict.UNKNOWN, signals=("baseline:unusable",)
        )

    # The top guard: a marker already in the baseline means nothing a probe does
    # can be attributed to the probe.
    if baseline.canary_present:
        return TraversalAssessment(
            verdict=TraversalVerdict.UNKNOWN,
            signals=("baseline:canary-already-present",),
        )

    if not probes:
        return TraversalAssessment(
            verdict=TraversalVerdict.NONE, signals=("probes:none",)
        )

    canary_hits = tuple(p for p in probes if p.canary_present)

    # --- canary retrieval: the only route to a finding -------------------- #
    if canary_hits:
        reproduced = len(canary_hits) >= 2
        signals = [f"canary:matched×{len(canary_hits)}"]
        if reproduced:
            signals.append("canary:reproduced")
            return TraversalAssessment(
                verdict=TraversalVerdict.STRONG,
                canary_matched=True,
                reproduced=True,
                signals=tuple(signals),
            )
        # One hit, not reproduced. Real, but held below a finding.
        signals.append("canary:unreproduced")
        return TraversalAssessment(
            verdict=TraversalVerdict.POSSIBLE,
            canary_matched=True,
            reproduced=False,
            signals=tuple(signals),
        )

    # --- no canary: a differential is at most POSSIBLE -------------------- #
    material = _material_differential(baseline, probes)
    if material:
        return TraversalAssessment(
            verdict=TraversalVerdict.POSSIBLE, signals=material
        )

    # Reflection-only, generic errors, and unchanged responses all land here.
    if any(p.reflected for p in probes):
        return TraversalAssessment(
            verdict=TraversalVerdict.NONE, signals=("probe:reflected-not-retrieved",)
        )
    return TraversalAssessment(verdict=TraversalVerdict.NONE, signals=("probe:no-change",))


def _material_differential(
    baseline: BaselineEvidence, probes: tuple[ProbeEvidence, ...]
) -> tuple[str, ...]:
    """Signals of a differential worth calling POSSIBLE, or empty.

    Deliberately demanding. A status change alone is not enough — a 404 under a
    probe is the *normal* answer to a bad path — so a differential needs the
    probe to have stayed successful while the *content* diverged: a changed
    media type, or a body that stopped resembling the baseline. That is the
    shape of "a different resource was served" without the canary to prove it.
    """
    for probe in probes:
        if probe.status is None or not (200 <= probe.status < 300):
            continue
        if probe.reflected:
            # A reflected payload explains a body change without a file read.
            continue
        if probe.media_type and baseline.media_type and probe.media_type != baseline.media_type:
            return ("differential:media-type-changed",)
        if probe.body_similarity < _MATERIAL_DIVERGENCE:
            return ("differential:body-diverged",)
    return ()
