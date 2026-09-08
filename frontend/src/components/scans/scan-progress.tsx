"use client";

import { useEffect, useState } from "react";

import { cn } from "@/lib/utils";
import { elapsedSeconds, formatElapsed } from "@/lib/format";
import { isScanActive, type Scan } from "@/types/scan";

/** Stage identifier to a label. Unknown values are shown as they arrive. */
const STAGE_LABELS: Record<string, string> = {
  QUEUED: "Queued",
  INITIALIZING: "Initialising",
  PROBING: "Probing",
  CRAWLING: "Crawling",
  ANALYZING: "Analysing",
  AGGREGATING: "Aggregating",
  FINALIZING: "Finalising",
  COMPLETED: "Completed",
  FAILED: "Failed",
  CANCELLED: "Cancelled",
};

function stageLabel(stage: string | null): string | null {
  if (!stage) return null;
  return STAGE_LABELS[stage] ?? stage;
}

/** Seconds since a scan started, ticking while it is still running. */
function useElapsed(scan: Scan): number | null {
  const running = isScanActive(scan);
  const [, tick] = useState(0);

  useEffect(() => {
    if (!running) return;
    // The tick only forces a re-render; the value below is always recomputed
    // from the timestamps, so a throttled tab cannot make the clock drift.
    const id = window.setInterval(() => tick((value) => value + 1), 1000);
    return () => window.clearInterval(id);
  }, [running]);

  return elapsedSeconds(scan.started_at, running ? null : scan.completed_at);
}

/**
 * Live progress for one scan: stage, an indicative bar, and elapsed time.
 *
 * The bar is explicitly labelled indicative. The scanner discovers its own
 * workload as it crawls, so a precise percentage cannot be justified — the
 * stage is the honest signal and the bar only positions it.
 */
export function ScanProgress({ scan, className }: { scan: Scan; className?: string }) {
  const elapsed = useElapsed(scan);
  const active = isScanActive(scan);
  const stopping = scan.cancel_requested && active;
  const percent = Math.min(100, Math.max(0, scan.progress_percent ?? 0));
  const label = stageLabel(scan.current_stage);

  return (
    <div className={cn("space-y-2", className)}>
      <div className="flex items-center justify-between gap-4 text-sm">
        <span className="font-medium">
          {stopping ? "Stopping" : (label ?? "Waiting to start")}
          {scan.progress_message ? (
            <span className="ml-2 font-normal text-muted-foreground">
              {stopping ? "Waiting for the scan to reach a safe stopping point." : scan.progress_message}
            </span>
          ) : null}
        </span>
        <span className="shrink-0 font-mono text-xs text-muted-foreground tabular-nums">
          {formatElapsed(elapsed)}
        </span>
      </div>

      <div
        className="h-1.5 w-full overflow-hidden rounded-full bg-muted"
        role="progressbar"
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Scan progress (indicative)"
      >
        <div
          className={cn(
            "h-full rounded-full transition-[width] duration-500 ease-out",
            stopping ? "bg-warning" : active ? "bg-info" : "bg-muted-foreground/40",
          )}
          style={{ width: `${percent}%` }}
        />
      </div>

      {active ? (
        <p className="text-xs text-muted-foreground">
          Progress is indicative: the crawler discovers its own workload, so the bar shows the
          stage reached rather than work completed.
        </p>
      ) : null}
    </div>
  );
}
