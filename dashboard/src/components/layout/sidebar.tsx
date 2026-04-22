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
    <nav className="flex flex-col gap-1 p-3">
      {/* Logo */}
      <div className="flex items-center gap-2 px-3 py-4 mb-2">
        <Shield className="h-7 w-7 text-primary" />
        <span className="font-mono font-bold text-lg tracking-tight">
          SGL
        </span>
      </div>

      <div className="h-px bg-border mb-2" />

      {navItems.map(({ href, label, icon: Icon }) => {
        const active = pathname === href || (href !== "/" && pathname.startsWith(href));
        return (
          <Link
            key={href}
            href={href}
            onClick={() => setMobileOpen(false)}
            className={cn(
              "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-mono transition-colors",
              active
                ? "bg-primary/10 text-primary glow-green"
                : "text-muted-foreground hover:text-foreground hover:bg-muted",
            )}
          >
            <Icon className="h-4 w-4" />
            {label}
          </Link>
        );
      })}
    </nav>
  );

  return (
    <>
      {/* Mobile toggle */}
      <button
        className="fixed top-4 left-4 z-50 md:hidden bg-card border border-border rounded-md p-2"
        onClick={() => setMobileOpen(!mobileOpen)}
        aria-label="Toggle menu"
      >
        {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
      </button>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-background/80 md:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          "fixed top-0 left-0 z-40 h-full w-56 bg-card border-r border-border transition-transform md:translate-x-0",
          mobileOpen ? "translate-x-0" : "-translate-x-full",
        )}
      >
        {nav}
      </aside>
    </>
  );
}