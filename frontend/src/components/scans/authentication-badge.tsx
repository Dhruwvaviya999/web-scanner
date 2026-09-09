import { KeyRound, ShieldCheck, ShieldQuestion, ShieldX, type LucideIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import {
  AUTH_MODE_LABELS,
  AUTH_STATUS_LABELS,
  type AuthMode,
  type AuthStatus,
} from "@/types/scan";

const STATUS_STYLES: Record<AuthStatus, { icon: LucideIcon; className: string }> = {
  NOT_CONFIGURED: {
    icon: KeyRound,
    className: "border-muted-foreground/30 bg-muted text-muted-foreground",
  },
  AVAILABLE: {
    icon: ShieldCheck,
    className: "border-success/40 bg-success/15 text-success",
  },
  // Not an error state — the scan ran fine. It is a warning that the results
  // only cover the anonymous surface.
  REJECTED: {
    icon: ShieldX,
    className: "border-warning/40 bg-warning/15 text-warning",
  },
  UNKNOWN: {
    icon: ShieldQuestion,
    className: "border-warning/40 bg-warning/15 text-warning",
  },
};

/**
 * Safe authentication metadata for a scan: the mode used and what one access
 * check concluded. There is no prop here that could carry a credential.
 */
export function AuthenticationBadge({
  mode,
  status,
}: {
  mode: AuthMode;
  status: AuthStatus;
}) {
  if (mode === "NONE") {
    return (
      <Badge
        variant="outline"
        className="gap-1.5 border-muted-foreground/30 bg-muted font-medium text-muted-foreground"
      >
        <KeyRound className="size-3.5" aria-hidden />
        Unauthenticated
      </Badge>
    );
  }

  const { icon: Icon, className } = STATUS_STYLES[status];

  return (
    <Badge variant="outline" className={cn("gap-1.5 font-medium", className)}>
      <Icon className="size-3.5" aria-hidden />
      {AUTH_MODE_LABELS[mode]} · {AUTH_STATUS_LABELS[status]}
    </Badge>
  );
}
