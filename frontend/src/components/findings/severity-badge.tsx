import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { FindingConfidence, FindingSeverity } from "@/types/finding";

const SEVERITY_STYLES: Record<FindingSeverity, string> = {
  CRITICAL: "border-destructive/50 bg-destructive/20 text-destructive",
  HIGH: "border-destructive/40 bg-destructive/15 text-destructive",
  MEDIUM: "border-warning/40 bg-warning/15 text-warning",
  LOW: "border-info/40 bg-info/15 text-info",
  INFO: "border-muted-foreground/30 bg-muted text-muted-foreground",
};

/** Small colour chip used in the summary row and the finding list. */
export function SeverityDot({ severity }: { severity: FindingSeverity }) {
  const tone: Record<FindingSeverity, string> = {
    CRITICAL: "bg-destructive",
    HIGH: "bg-destructive",
    MEDIUM: "bg-warning",
    LOW: "bg-info",
    INFO: "bg-muted-foreground",
  };
  return <span className={cn("size-2 shrink-0 rounded-full", tone[severity])} aria-hidden />;
}

export function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  return (
    <Badge
      variant="outline"
      className={cn("font-medium tracking-wide uppercase", SEVERITY_STYLES[severity])}
    >
      {severity}
    </Badge>
  );
}

/**
 * How sure the detector is. Shown next to severity because a MEDIUM finding at
 * MEDIUM confidence deserves less alarm than one at HIGH.
 */
export function ConfidenceBadge({ confidence }: { confidence: FindingConfidence }) {
  return (
    <Badge variant="outline" className="border-border text-muted-foreground">
      {confidence.charAt(0) + confidence.slice(1).toLowerCase()} confidence
    </Badge>
  );
}
