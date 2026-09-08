"use client";

import { Menu } from "lucide-react";
import { useState } from "react";

import { Brand } from "@/components/common/brand";
import { SidebarNav } from "@/components/layout/sidebar-nav";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";

export function MobileNav() {
  const [open, setOpen] = useState(false);

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger
        render={
          <Button variant="ghost" size="icon" className="lg:hidden" aria-label="Open navigation">
            <Menu className="size-5" aria-hidden />
          </Button>
        }
      />
      <SheetContent side="left" className="w-72 bg-sidebar p-0">
        <div className="flex h-16 items-center border-b border-sidebar-border px-5">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <Brand href="/dashboard" />
        </div>
        <div className="p-3">
          <SidebarNav onNavigate={() => setOpen(false)} />
        </div>
      </SheetContent>
    </Sheet>
  );
}
