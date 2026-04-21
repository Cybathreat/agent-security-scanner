"use client";

import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/findings/severity-badge";
import type { AttackSurfaceNode } from "@/lib/types";
import { cn } from "@/lib/utils";

const NODE_COLORS: Record<string, string> = {
  endpoint: "border-blue-500 bg-blue-950/50",
  tool: "border-green-500 bg-green-950/50",
  data_flow: "border-amber-500 bg-amber-950/50",
  agent: "border-purple-500 bg-purple-950/50",
  external: "border-red-500 bg-red-950/50",
};

const GLOW_CLASSES: Record<string, string> = {
  CRITICAL: "glow-red",
  HIGH: "glow-amber",
  MEDIUM: "glow-blue",
  LOW: "",
  INFO: "",
};

export function AttackNode({ data }: NodeProps) {
  const node = data as unknown as AttackSurfaceNode;
  const colorClass = NODE_COLORS[node.type] || "border-border bg-card";
  const glowClass = node.max_severity ? GLOW_CLASSES[node.max_severity] || "" : "";

  return (
    <div className={cn("rounded-md border-2 p-3 min-w-[120px] text-center", colorClass, glowClass)}>
      <Handle type="target" position={Position.Top} className="!bg-primary" />
      <div className="text-xs text-muted-foreground uppercase">{node.type}</div>
      <div className="text-sm font-medium truncate">{node.label}</div>
      {node.findings_count > 0 && (
        <div className="mt-1 flex items-center justify-center gap-1">
          <Badge variant="destructive" className="text-xs">{node.findings_count}</Badge>
          {node.max_severity && <SeverityBadge severity={node.max_severity} />}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} className="!bg-primary" />
    </div>
  );
}