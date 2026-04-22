"use client";

import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";
import { severityBgClass } from "@/lib/types";

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

const DOT_CLASS: Record<string, string> = {
  CRITICAL: "severity-dot-critical",
  HIGH: "severity-dot-high",
  MEDIUM: "severity-dot-medium",
  LOW: "severity-dot-low",
  INFO: "severity-dot-info",
};

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-1.5 py-px text-[11px] font-medium uppercase tracking-wider",
        severityBgClass(severity),
        className,
      )}
    >
      <span className={cn("severity-dot", DOT_CLASS[severity])} />
      {severity}
    </span>
  );
}