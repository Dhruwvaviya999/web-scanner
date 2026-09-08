"""Conservative SQL-injection probes.

Every probe here is a *syntax* probe. None extracts data, enumerates a schema,
writes, reads files or runs commands. They exist to make a vulnerable query
either break (error-based) or change its truth value (boolean-differential) —
nothing more. The set is small, fixed and deterministic.

Two families of probe:

* **Error probes** append a lone quote or an unbalanced fragment. A query that
  concatenates the value unsafely becomes syntactically invalid and the engine
  emits an error. A parameterised query treats the same input as data and does
  not.

* **Boolean probes** come in true-like / false-like pairs designed to leave the
  surrounding query valid either way, so the *only* thing that changes is the
  truth value. A vulnerable numeric context returns the normal page for the
  true pair and a different (often empty) page for the false pair; a safe
  endpoint returns the same page for both, because the input is just data.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ErrorProbe:
    """A value that should break an unsafely-built query."""

    #: Stable label for evidence and logs. Never interpolated with user data.
    label: str
    #: Appended to the parameter's baseline value.
    suffix: str


@dataclass(frozen=True, slots=True)
class BooleanProbePair:
    """A true-like / false-like pair, appended to the baseline value.

    Both keep the query syntactically valid; only the boolean result differs.
    `numeric` pairs suit an integer context (`id=10`), `string` pairs a quoted
    one (`name='ada'`).
    """

    label: str
    true_suffix: str
    false_suffix: str
    numeric: bool


#: Error probes, worst-behaved first. A single quote is the classic trigger; the
#: paired-quote variant helps distinguish a genuine break from an endpoint that
#: merely dislikes quotes.
ERROR_PROBES: tuple[ErrorProbe, ...] = (
    ErrorProbe(label="single_quote", suffix="'"),
    ErrorProbe(label="double_quote", suffix='"'),
)

#: Boolean pairs. Numeric first: `id=10` is the commonest injectable shape.
#:   true : 10 AND 1=1   -> same rows as baseline
#:   false: 10 AND 1=2   -> no rows
#: String pairs close the quote, apply the same 1=1 / 1=2, and re-open it so the
#: trailing quote in the original query still balances.
BOOLEAN_PAIRS: tuple[BooleanProbePair, ...] = (
    BooleanProbePair(
        label="numeric_and", true_suffix=" AND 1=1", false_suffix=" AND 1=2", numeric=True
    ),
    BooleanProbePair(
        label="quoted_and",
        true_suffix="' AND '1'='1",
        false_suffix="' AND '1'='2",
        numeric=False,
    ),
)


def error_probe_values(baseline_value: str) -> list[tuple[str, str]]:
    """`(label, probe_value)` pairs for error-based testing."""
    return [(probe.label, f"{baseline_value}{probe.suffix}") for probe in ERROR_PROBES]


def boolean_probe_values(baseline_value: str) -> list[tuple[str, str, str]]:
    """`(label, true_value, false_value)` triples for differential testing."""
    return [
        (pair.label, f"{baseline_value}{pair.true_suffix}", f"{baseline_value}{pair.false_suffix}")
        for pair in BOOLEAN_PAIRS
    ]
