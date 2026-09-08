"""The database-backed half of cooperative cancellation.

The scanner holds a `CancellationToken` built from a plain callable and knows
nothing about how the flag is stored. This module supplies that callable.

Two properties matter here:

* **It never uses the caller's session.** Each check opens its own short-lived
  session and closes it immediately. A running scan must not read the cancel
  flag through a session it is also holding open for writes, and the cancelling
  request must never be blocked behind the scan's work.

* **It is throttled.** A hot loop may ask on every iteration; without a floor
  between reads that would be a database query per crawled page and per probe.
  Checks inside the interval reuse the last answer, and once cancellation is
  seen the token latches, so the query count stays proportional to elapsed time
  rather than to work done.
"""

from __future__ import annotations

import logging
import time
import uuid

from sqlalchemy import select

from app.core.database import SessionLocal
from app.models.scan import Scan
from app.scanner.cancellation import CancellationToken

logger = logging.getLogger(__name__)

#: Minimum seconds between two reads of the cancel flag. A user waits at most
#: this long past a safe boundary for cancellation to take effect, which is a
#: fair trade for keeping the query rate independent of scan size.
DEFAULT_POLL_INTERVAL_SECONDS = 1.5


def cancellation_token_for(
    scan_id: uuid.UUID, *, poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS
) -> CancellationToken:
    """A token that reports whether `scan_id` has been asked to stop."""
    state = {"checked_at": 0.0, "cancelled": False}

    def is_cancelled() -> bool:
        if state["cancelled"]:
            return True

        now = time.monotonic()
        if now - state["checked_at"] < poll_interval_seconds:
            return False
        state["checked_at"] = now

        # Its own session, opened and closed here, so this read is never part of
        # the scan's transaction and holds no locks the canceller would wait on.
        try:
            with SessionLocal() as session:
                requested = session.scalar(
                    select(Scan.cancel_requested).where(Scan.id == scan_id)
                )
        except Exception:  # noqa: BLE001 - a failed check must not fail the scan
            logger.debug("Cancellation check failed for scan %s", scan_id, exc_info=True)
            return False

        if requested:
            state["cancelled"] = True
        return bool(requested)

    return CancellationToken(is_cancelled)
