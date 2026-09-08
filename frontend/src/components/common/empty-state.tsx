import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description: string;
  action?: ReactNode;
}

export function EmptyState({ icon: Icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-border px-6 py-14 text-center">
      <span className="flex size-11 items-center justify-center rounded-full bg-muted">
        <Icon className="size-5 text-muted-foreground" aria-hidden />
      </span>
      <div className="space-y-1">
        <p className="font-medium">{title}</p>
        <p className="mx-auto max-w-md text-sm text-muted-foreground">{description}</p>
      </div>
      {action}
    </div>
  );
}
