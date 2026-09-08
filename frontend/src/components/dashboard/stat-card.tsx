import type { LucideIcon } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

interface StatCardProps {
  label: string;
  value: number;
  icon: LucideIcon;
  loading?: boolean;
  accentClassName?: string;
}

export function StatCard({
  label,
  value,
  icon: Icon,
  loading = false,
  accentClassName = "bg-primary/15 text-primary",
}: StatCardProps) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4">
        <span
          className={cn("flex size-10 shrink-0 items-center justify-center rounded-md", accentClassName)}
        >
          <Icon className="size-5" aria-hidden />
        </span>
        <div className="min-w-0 space-y-1">
          <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
            {label}
          </p>
          {loading ? (
            <Skeleton className="h-7 w-12" />
          ) : (
            <p className="text-2xl leading-none font-semibold tabular-nums">{value}</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
