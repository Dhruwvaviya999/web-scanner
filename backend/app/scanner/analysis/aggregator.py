"""Finding deduplication.

Pure. Groups equivalent findings so that a rule failing across twelve pages is
reported once with twelve affected endpoints, instead of twelve near-identical
entries.

The grouping key is the finding's `identity` — `(rule, subject)` — never its
title. Two consequences that matter:

* "Session Cookie Missing HttpOnly" and "Session Cookie Missing Secure" are
  different rules, so they never merge even though their titles are similar.
* Cookie `session` and cookie `theme` failing the same rule have different
  subjects, so they stay separate findings. Merging them would erase which
  cookie was at fault.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.scanner.analysis.types import AggregatedFinding, FindingOccurrence
from app.scanner.security.types import FindingData, sort_findings


def aggregate_findings(
    observations: Iterable[tuple[str | None, FindingData]],
) -> list[AggregatedFinding]:
    """Group `(endpoint_url, finding)` pairs by finding identity.

    Input order is preserved within a group, so the first endpoint a rule was
    seen on becomes that finding's primary endpoint. The result is sorted most
    severe first.
    """
    grouped: dict[tuple[str, str | None], AggregatedFinding] = {}

    for endpoint_url, data in observations:
        key = data.identity
        existing = grouped.get(key)

        if existing is None:
            grouped[key] = AggregatedFinding(
                data=data,
                occurrences=[
                    FindingOccurrence(endpoint_url=endpoint_url, evidence=data.evidence)
                ],
            )
            continue

        # Same rule and subject seen again. Record the endpoint, but only once:
        # a rule can only fail one way per endpoint, so a repeat is noise.
        if any(o.endpoint_url == endpoint_url for o in existing.occurrences):
            continue

        existing.occurrences.append(
            FindingOccurrence(endpoint_url=endpoint_url, evidence=data.evidence)
        )

    ordered = sort_findings([group.data for group in grouped.values()])
    by_identity = {data.identity: data for data in ordered}
    return [grouped[identity] for identity in by_identity]
