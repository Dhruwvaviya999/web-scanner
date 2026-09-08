import Link from "next/link";
import { ShieldCheck } from "lucide-react";

import { cn } from "@/lib/utils";

export function Brand({ className, href = "/" }: { className?: string; href?: string }) {
  return (
    <Link href={href} className={cn("flex items-center gap-2.5 font-semibold", className)}>
      <span className="flex size-8 items-center justify-center rounded-md bg-primary/15 ring-1 ring-primary/30">
        <ShieldCheck className="size-4.5 text-primary" aria-hidden />
      </span>
      <span className="tracking-tight">Web Scanner</span>
    </Link>
  );
}
