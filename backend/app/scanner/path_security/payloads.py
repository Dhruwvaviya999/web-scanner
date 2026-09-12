"""Controlled traversal probes aimed at a harmless canary.

**This module never targets a real system file.** There is no `/etc/passwd`,
no Windows SAM, no SSH key, no cloud-metadata path, no environment file — and
there is no code path that could construct one, because every probe is a fixed
traversal prefix joined to one constant canary suffix. The proof of a
vulnerability is that the application returned *the canary*, a file the local
test fixture deliberately placed outside the intended directory and filled with
a known marker string. That keeps the whole detector safe to run: the worst it
can retrieve is a file that exists only to be retrieved.

The set is small, fixed and deterministic. Eight variants at most, covering four
conceptual classes — plain parent traversal, URL-encoded, doubly-encoded, and a
normalized/mixed form — at a couple of climb depths. It is not a bypass engine
and not a WAF-evasion wordlist; a real assessment against a hardened target is a
human's job, and this is a safe confirmation of a class of bug against a
cooperative fixture.
"""

from __future__ import annotations

from dataclasses import dataclass

#: The marker the local fixture writes into its out-of-boundary canary file. A
#: finding requires this string to appear in a probe response — reflection of a
#: payload cannot produce it, because it is file *content*, not the payload.
CANARY_MARKER = "PATH_TRAVERSAL_CANARY_2026"

#: The logical resource the traversal aims at, relative to wherever the input is
#: resolved. A fixed, harmless path the fixture serves outside the intended
#: directory. The detector knows only this — it never enumerates a filesystem.
CANARY_SUFFIX = "scanner-canary/traversal-marker.txt"

#: How many parent hops each depth variant climbs. Two depths keep the set small
#: while covering both a shallow and a deeper intended directory.
_DEPTHS = (3, 5)


@dataclass(frozen=True, slots=True)
class TraversalProbe:
    """One traversal payload and how it is built.

    `label` is stable, safe to log and to place in evidence: it names the
    *technique*, never the payload string, and carries no file content.
    """

    label: str
    #: The parent-directory token repeated per depth.
    parent_token: str
    #: How the canary suffix is encoded when appended.
    suffix_style: str
    depth: int

    def render(self) -> str:
        """The concrete probe value. Exists only in memory, never persisted."""
        prefix = self.parent_token * self.depth
        suffix = _encode_suffix(CANARY_SUFFIX, self.suffix_style)
        return f"{prefix}{suffix}"


def _encode_suffix(suffix: str, style: str) -> str:
    if style == "plain":
        return suffix
    if style == "encoded":
        return suffix.replace("/", "%2f")
    if style == "backslash":
        return suffix.replace("/", "\\")
    return suffix  # pragma: no cover - defensive


#: The four conceptual classes, each at the shallower depth, plus the two
#: highest-value classes repeated at the deeper one — eight total, deterministic
#: and ordered most-common-first.
def _build() -> tuple[TraversalProbe, ...]:
    probes: list[TraversalProbe] = []

    # Class 1 — plain parent traversal, both depths. The commonest real bug.
    for depth in _DEPTHS:
        probes.append(
            TraversalProbe(
                label=f"parent_plain_d{depth}",
                parent_token="../",
                suffix_style="plain",
                depth=depth,
            )
        )

    # Class 2 — URL-encoded separators, both depths. Defeats naive string
    # filters that look for a literal "../".
    for depth in _DEPTHS:
        probes.append(
            TraversalProbe(
                label=f"encoded_d{depth}",
                parent_token="%2e%2e%2f",
                suffix_style="encoded",
                depth=depth,
            )
        )

    # Class 3 — doubly-encoded, shallow only. Defeats a single decode pass.
    probes.append(
        TraversalProbe(
            label="double_encoded_d3",
            parent_token="%252e%252e%252f",
            suffix_style="encoded",
            depth=_DEPTHS[0],
        )
    )

    # Class 4 — normalized/mixed: `....//` collapses to `../` under a naive
    # single-pass normaliser. Both depths.
    for depth in _DEPTHS:
        probes.append(
            TraversalProbe(
                label=f"normalized_d{depth}",
                parent_token="....//",
                suffix_style="plain",
                depth=depth,
            )
        )

    # Separator variant for a Windows-style resolver, shallow only. The fixture
    # is platform-neutral, so this is a representation variant, not an OS probe.
    probes.append(
        TraversalProbe(
            label="backslash_d3",
            parent_token="..\\",
            suffix_style="backslash",
            depth=_DEPTHS[0],
        )
    )

    return tuple(probes)


#: The complete, fixed probe set. Exactly eight.
TRAVERSAL_PROBES: tuple[TraversalProbe, ...] = _build()


def traversal_probes(limit: int = 8) -> tuple[TraversalProbe, ...]:
    """The bounded, deterministic probe set, capped at `limit`."""
    return TRAVERSAL_PROBES[: max(0, limit)]


def is_safe_probe(value: str) -> bool:
    """Whether a rendered probe stays within the controlled canary design.

    A guard used by tests and by the detector: a probe must aim at the canary
    suffix and must not name any real sensitive file. This is what makes
    "no system-file targets exist" an assertion rather than a hope.
    """
    lowered = value.lower()
    if "scanner-canary" not in lowered and "traversal-marker" not in lowered:
        return False
    forbidden = (
        "etc/passwd",
        "etc/shadow",
        ".ssh",
        "id_rsa",
        "sam",
        "system32",
        "win.ini",
        "boot.ini",
        ".env",
        ".aws",
        "metadata",
        "proc/self",
        "windows/",
    )
    return not any(token in lowered for token in forbidden)
