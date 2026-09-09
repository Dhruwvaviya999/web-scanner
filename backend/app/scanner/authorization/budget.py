"""The authorization request budget.

Authorization testing multiplies traffic: every additional identity re-tests
every eligible endpoint. Four contexts against a hundred endpoints is four
hundred requests before a single comparison is drawn, and the scanner is a
guest on a system somebody depends on.

Fails closed, like `ProbeBudget`. `reserve` is called *before* a request is
sent, never after, so an exhausted budget means no request rather than one more.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.scanner.authorization.types import AuthorizationBudgetLimits


@dataclass(slots=True)
class AuthorizationBudget:
    """Tracks how much authorization traffic has been spent."""

    limits: AuthorizationBudgetLimits = field(default_factory=AuthorizationBudgetLimits)
    requests_spent: int = 0
    endpoints_started: int = 0
    _per_endpoint_comparisons: dict[str, int] = field(default_factory=dict)

    # --- requests -------------------------------------------------------- #

    def can_send(self) -> bool:
        return self.requests_spent < self.limits.max_requests

    def reserve_request(self) -> bool:
        """Claim one request. False means the budget is spent — send nothing."""
        if not self.can_send():
            return False
        self.requests_spent += 1
        return True

    # --- endpoints ------------------------------------------------------- #

    def can_start_endpoint(self) -> bool:
        return self.endpoints_started < self.limits.max_endpoints

    def start_endpoint(self) -> bool:
        if not self.can_start_endpoint():
            return False
        self.endpoints_started += 1
        return True

    # --- comparisons ----------------------------------------------------- #

    def reserve_comparison(self, url: str) -> bool:
        """Claim one comparison against one endpoint.

        Capped per endpoint rather than globally: an endpoint with many
        identities pointed at it should not consume the whole scan's attention.
        """
        spent = self._per_endpoint_comparisons.get(url, 0)
        if spent >= self.limits.max_comparisons_per_endpoint:
            return False
        self._per_endpoint_comparisons[url] = spent + 1
        return True

    def exhausted(self) -> bool:
        """True once no further request could be sent under any circumstance."""
        return not self.can_send()
