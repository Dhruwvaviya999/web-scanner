import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { statusCodeText, statusFamily, type StatusFamily } from "@/lib/format";

const FAMILY_STYLES: Record<StatusFamily, string> = {
  success: "border-success/40 bg-success/15 text-success",
  redirect: "border-info/40 bg-info/15 text-info",
  "client-error": "border-warning/40 bg-warning/15 text-warning",
  "server-error": "border-destructive/40 bg-destructive/15 text-destructive",
  unknown: "border-muted-foreground/30 bg-muted text-muted-foreground",
};

/**
 * The HTTP status code, coloured by family.
 *
 * This reports what the target returned — it is not a security verdict. A 200
 * here says the page loaded, nothing about whether it is safe.
 */
export function HttpStatusBadge({ code }: { code: number | null }) {
  if (code === null) {
    return <span className="text-muted-foreground">—</span>;
  }

  const reason = statusCodeText(code);
  return (
    <Badge
      variant="outline"
      className={cn("gap-1.5 font-mono font-medium", FAMILY_STYLES[statusFamily(code)])}
    >
      {code}
      {reason ? <span className="font-sans font-normal opacity-80">{reason}</span> : null}
    </Badge>
  );
}
