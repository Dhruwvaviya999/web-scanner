"use client";

import { useEffect, useRef } from "react";

/** How often a live scan is re-read. Slow enough to be cheap, fast enough to feel live. */
export const SCAN_POLL_INTERVAL_MS = 3000;

/**
 * Calls `callback` on an interval while `intervalMs` is a number.
 *
 * Passing `null` stops polling, which is how a caller says "this thing has
 * reached a terminal state". Ticks are skipped while the document is hidden:
 * a backgrounded tab has nobody watching it, and there is no reason to keep
 * asking the server on its behalf. The interval keeps running so the next
 * visible tick is immediate.
 *
 * Deliberately plain polling — no WebSocket, no SSE, no shared connection.
 */
export function usePolling(callback: () => void, intervalMs: number | null): void {
  const latest = useRef(callback);

  useEffect(() => {
    latest.current = callback;
  }, [callback]);

  useEffect(() => {
    if (intervalMs === null) return;

    const id = window.setInterval(() => {
      if (document.visibilityState === "hidden") return;
      latest.current();
    }, intervalMs);

    return () => window.clearInterval(id);
  }, [intervalMs]);
}
