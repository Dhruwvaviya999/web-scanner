import { LayoutDashboard, ScanLine, UserRound, type LucideIcon } from "lucide-react";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Match nested routes (e.g. /dashboard/scans/<id>) as this item. */
  matchNested?: boolean;
}

export const NAV_ITEMS: NavItem[] = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/dashboard/scans", label: "Scans", icon: ScanLine, matchNested: true },
  { href: "/dashboard/profile", label: "Profile", icon: UserRound },
];

export function isNavItemActive(item: NavItem, pathname: string): boolean {
  return item.matchNested ? pathname.startsWith(item.href) : pathname === item.href;
}
