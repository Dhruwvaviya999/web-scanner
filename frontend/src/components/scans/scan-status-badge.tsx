import { CheckCircle2, CircleDashed, Loader2, XCircle, type LucideIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { ScanStatus } from "@/types/scan";

const STATUS_STYLES: Record<ScanStatus, { icon: LucideIcon; className: string; label: string }> = {
  PENDING: {
    icon: CircleDashed,
    label: "Pending",
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
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const { icon: Icon, className, label } = STATUS_STYLES[status];
  return (
    <Badge variant="outline" className={cn("gap-1.5 font-medium", className)}>
      <Icon className={cn("size-3.5", status === "RUNNING" && "animate-spin")} aria-hidden />
      {label}
    </Badge>
  );
}
