import { Brand } from "@/components/common/brand";
import { SidebarNav } from "@/components/layout/sidebar-nav";

/** Persistent sidebar, shown from the `lg` breakpoint up. */
export function Sidebar() {
  return (
    <aside className="hidden w-64 shrink-0 flex-col border-r border-sidebar-border bg-sidebar lg:flex">
      <div className="flex h-16 items-center border-b border-sidebar-border px-5">
        <Brand href="/dashboard" />
      </div>
      <div className="flex-1 overflow-y-auto p-3">
        <SidebarNav />
      </div>
      <div className="border-t border-sidebar-border p-4">
        <p className="text-xs text-muted-foreground">
          Phase 1 · basic HTTP reconnaissance. Vulnerability detection is not enabled yet.
        </p>
      </div>
    </aside>
  );
}
