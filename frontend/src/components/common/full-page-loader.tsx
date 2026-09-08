import { Loader2 } from "lucide-react";

export function FullPageLoader({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 text-muted-foreground">
      <Loader2 className="size-6 animate-spin text-primary" aria-hidden />
      <p className="text-sm">{label}</p>
    </div>
  );
}
