import {
  CheckCircle2,
  CircleDashed,
  CircleSlash,
  Loader2,
  XCircle,
  type LucideIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { ScanStatus } from "@/types/scan";

const STATUS_STYLES: Record<ScanStatus, { icon: LucideIcon; className: string; label: string }> = {
  QUEUED: {
    icon: CircleDashed,
    label: "Queued",
    className: "border-muted-foreground/30 bg-muted text-muted-foreground",
  },
  RUNNING: {
    icon: Loader2,
    label: "Running",
    className: "border-info/40 bg-info/15 text-info",
  },
  COMPLETED: {
    icon: CheckCircle2,
    label: "Completed",
    className: "border-success/40 bg-success/15 text-success",
  },
  FAILED: {
    icon: XCircle,
    label: "Failed",
    className: "border-destructive/40 bg-destructive/15 text-destructive",
  },
  // Neither green nor red: a cancelled scan did not fail, but it did not
  // finish either, and it must never be mistaken for a clean pass.
  CANCELLED: {
    icon: CircleSlash,
    label: "Cancelled",
    className: "border-warning/40 bg-warning/15 text-warning",
  },
};

interface ScanStatusBadgeProps {
  status: ScanStatus;
  /**
   * True once cancellation has been asked for. A running scan then reads
   * "Stopping", which says the request was accepted without claiming the scan
   * has already stopped — only the status can say that.
   */
  cancelRequested?: boolean;
}

export function ScanStatusBadge({ status, cancelRequested = false }: ScanStatusBadgeProps) {
  const stopping = cancelRequested && (status === "RUNNING" || status === "QUEUED");
  const { icon: Icon, className, label } = STATUS_STYLES[status];
  const spinning = status === "RUNNING";

  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1.5 font-medium",
        stopping ? "border-warning/40 bg-warning/15 text-warning" : className,
      )}
    >
      <Icon className={cn("size-3.5", spinning && "animate-spin")} aria-hidden />
      {stopping ? "Stopping…" : label}
    </Badge>
  );
}
