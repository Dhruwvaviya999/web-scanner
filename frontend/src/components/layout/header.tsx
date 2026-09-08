"use client";

import { usePathname } from "next/navigation";

import { MobileNav } from "@/components/layout/mobile-nav";
import { NAV_ITEMS, isNavItemActive } from "@/components/layout/nav-items";
import { UserMenu } from "@/components/layout/user-menu";

function currentSection(pathname: string): string {
  return NAV_ITEMS.find((item) => isNavItemActive(item, pathname))?.label ?? "Dashboard";
}

export function Header() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-30 flex h-16 shrink-0 items-center gap-3 border-b border-border bg-background/80 px-4 backdrop-blur sm:px-6">
      <MobileNav />
      <h2 className="flex-1 truncate text-sm font-medium text-muted-foreground">
        {currentSection(pathname)}
      </h2>
      <UserMenu />
    </header>
  );
}
