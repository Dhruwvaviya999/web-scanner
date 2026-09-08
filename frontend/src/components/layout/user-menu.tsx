"use client";

import Link from "next/link";
import { LogOut, UserRound } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "@/hooks/use-auth";

function initials(name: string): string {
  const parts = name.trim().split(/\s+/).slice(0, 2);
  return parts.map((part) => part[0]?.toUpperCase() ?? "").join("") || "U";
}

export function UserMenu() {
  const { user, logout } = useAuth();
  const [signingOut, setSigningOut] = useState(false);

  if (!user) return null;

  const handleLogout = async () => {
    setSigningOut(true);
    try {
      await logout();
      toast.success("Signed out.");
    } finally {
      setSigningOut(false);
    }
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            variant="ghost"
            className="h-10 gap-2 px-2"
            aria-label="Open account menu"
            disabled={signingOut}
          />
        }
      >
        <Avatar className="size-7">
          <AvatarFallback className="bg-primary/15 text-xs font-semibold text-primary">
            {initials(user.name)}
          </AvatarFallback>
        </Avatar>
        <span className="hidden max-w-36 truncate text-sm font-medium sm:inline">{user.name}</span>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" className="w-56">
        {/* Base UI requires a GroupLabel to sit inside a Group — it labels the
            group rather than floating in the popup. The account details and the
            profile link are that group. */}
        <DropdownMenuGroup>
          <DropdownMenuLabel className="py-2">
            <span className="block truncate text-sm font-medium text-foreground">{user.name}</span>
            <span className="block truncate text-xs text-muted-foreground">{user.email}</span>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem render={<Link href="/dashboard/profile" />}>
            <UserRound aria-hidden />
            Profile
          </DropdownMenuItem>
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuItem variant="destructive" onClick={handleLogout} disabled={signingOut}>
          <LogOut aria-hidden />
          {signingOut ? "Signing out…" : "Sign out"}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
