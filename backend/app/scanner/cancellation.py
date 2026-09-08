"""Cooperative cancellation for a running scan.

Cancellation here is *cooperative*: nothing is killed. A running scan asks, at
safe boundaries, whether it has been cancelled and stops cleanly if so. That
keeps every stop point somewhere the scan is not mid-request and not mid-write,
so partial results stay consistent and no transaction is torn in half.

This module is deliberately pure — it holds a callable, not a database session.
The scanner package must not know how cancellation is stored, so the concrete
"read the flag" implementation lives in `app.services.cancellation` and is
injected. That also makes the whole mechanism trivially testable: hand it
`lambda: True` and every boundary trips.
"""

from __future__ import annotations

from collections.abc import Callable


class ScanCancelled(Exception):
    """Raised at a safe boundary when a scan has been cancelled.

    Carries the stage that was interrupted so the orchestrator can record where
    the scan stopped. Not an error condition — a cancelled scan is a normal
    terminal outcome, not a failure.
    """

    def __init__(self, stage: str | None = None) -> None:
        self.stage = stage
        super().__init__("The scan was cancelled.")


class CancellationToken:
    """Asks an injected predicate whether the scan is still wanted.

    Cheap by construction: the predicate is expected to be throttled by its
    owner, and once cancellation is observed the answer is latched, so a hot
    loop calling `raise_if_cancelled()` on every iteration cannot turn into a
    stream of database reads.
    """

    __slots__ = ("_is_cancelled", "_latched")

    def __init__(self, is_cancelled: Callable[[], bool] | None = None) -> None:
        self._is_cancelled = is_cancelled
        self._latched = False

    @classmethod
    def none(cls) -> "CancellationToken":
        """A token that is never cancelled. The default for callers that do not care."""
        return cls(None)

    @property
    def cancelled(self) -> bool:
        if self._latched:
            return True
        if self._is_cancelled is None:
            return False
        try:
            if self._is_cancelled():
                self._latched = True
        except Exception:  # noqa: BLE001 - a failing check must not fail the scan
            # If the flag cannot be read, carry on scanning. Erring towards
            # "not cancelled" keeps a transient database blip from silently
            # aborting work the user asked for.
            return False
        return self._latched

    def raise_if_cancelled(self, stage: str | None = None) -> None:
        """Stop here if the scan has been cancelled."""
        if self.cancelled:
            raise ScanCancelled(stage)
