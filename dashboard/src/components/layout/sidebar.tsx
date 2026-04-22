"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  ScanSearch,
  AlertTriangle,
  GitCompare,
  Terminal,
  FileText,
  Network,
  Settings,
  Menu,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/", label: "Dashboard", icon: Shield },
  { href: "/scans", label: "Scans", icon: ScanSearch },
  { href: "/findings", label: "Findings", icon: AlertTriangle },
  { href: "/comparison", label: "Comparison", icon: GitCompare },
  { href: "/attack-surface", label: "Attack Surface", icon: Network },
  { href: "/replay", label: "Replay", icon: Terminal },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  const nav = (
    <nav className="flex flex-col gap-0.5 p-2">
      <div className="flex items-center gap-2 px-2.5 py-3 mb-1">
        <Shield className="h-4 w-4 text-primary" />
        <span className="font-semibold text-sm tracking-tight">
          Singularity
        </span>
      </div>

      <div className="h-px bg-border mb-1.5" />

      {navItems.map(({ href, label, icon: Icon }) => {
        const active = pathname === href || (href !== "/" && pathname.startsWith(href));
        return (
          <Link
            key={href}
            href={href}
            onClick={() => setMobileOpen(false)}
            className={cn(
              "flex items-center gap-2 rounded px-2.5 py-1.5 text-[13px] font-medium transition-colors",
              active
                ? "bg-primary/10 text-primary"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/50",
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </Link>
        );
      })}
    </nav>
  );

  return (
    <>
      <button
        className="fixed top-3 left-3 z-50 md:hidden bg-card border border-border rounded p-1.5"
        onClick={() => setMobileOpen(!mobileOpen)}
        aria-label="Toggle menu"
      >
        {mobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
      </button>

      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-background/80 backdrop-blur-sm md:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={cn(
          "fixed top-0 left-0 z-40 h-full w-52 bg-card border-r border-border transition-transform md:translate-x-0",
          mobileOpen ? "translate-x-0" : "-translate-x-full",
        )}
      >
        {nav}
      </aside>
    </>
  );
}