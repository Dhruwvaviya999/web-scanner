"""Probe budgeting.

Three nested limits — per parameter, per endpoint, per scan — all enforced in
one place so no detector can spend more than its share, and no combination of
detectors can spend more than the scan allows.

The budget **fails closed**: when a limit is reached, `reserve` returns False
and the engine refuses to send. There is no path that treats an exhausted
budget as permission to continue.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ProbeBudgetLimits:
    """Configured ceilings. Every one of them is required."""

    per_parameter: int = 8
    per_endpoint: int = 32
    per_scan: int = 160

    def __post_init__(self) -> None:
        for name in ("per_parameter", "per_endpoint", "per_scan"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")


@dataclass(slots=True)
class ProbeBudget:
    """Live spend against `limits`, shared by every detector in one scan."""

    limits: ProbeBudgetLimits = field(default_factory=ProbeBudgetLimits)
    scan_spent: int = 0
    _endpoint_spent: dict[str, int] = field(default_factory=dict)
    _parameter_spent: dict[tuple[str, str | None], int] = field(default_factory=dict)

    def remaining_in_scan(self) -> int:
        return max(0, self.limits.per_scan - self.scan_spent)

    def exhausted(self) -> bool:
        """True once the scan-wide ceiling is reached."""
        return self.scan_spent >= self.limits.per_scan

    def can_spend(self, endpoint: str, parameter: str | None) -> bool:
        """Whether one more request is permitted, without consuming it."""
        if self.scan_spent >= self.limits.per_scan:
            return False
        if self._endpoint_spent.get(endpoint, 0) >= self.limits.per_endpoint:
            return False
        return self._parameter_spent.get((endpoint, parameter), 0) < self.limits.per_parameter

    def reserve(self, endpoint: str, parameter: str | None) -> bool:
        """Consume one request if all three limits allow it.

        Returns False without consuming anything when any limit is reached, so a
        caller that ignores the result still cannot overspend.
        """
        if not self.can_spend(endpoint, parameter):
            return False

        self.scan_spent += 1
        self._endpoint_spent[endpoint] = self._endpoint_spent.get(endpoint, 0) + 1
        key = (endpoint, parameter)
        self._parameter_spent[key] = self._parameter_spent.get(key, 0) + 1
        return True

    def spent_on_endpoint(self, endpoint: str) -> int:
        return self._endpoint_spent.get(endpoint, 0)

    def spent_on_parameter(self, endpoint: str, parameter: str | None) -> int:
        return self._parameter_spent.get((endpoint, parameter), 0)
