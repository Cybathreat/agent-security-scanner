"use client";

import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";
import { severityBgClass } from "@/lib/types";

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-mono font-semibold uppercase",
        severityBgClass(severity),
        className,
      )}
    >
      {severity}
    </span>
  );
}