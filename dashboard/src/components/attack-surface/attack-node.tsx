"use client";

import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/findings/severity-badge";
import type { AttackSurfaceNode } from "@/lib/types";
import { cn } from "@/lib/utils";

const NODE_COLORS: Record<string, string> = {
  endpoint: "border-blue-500/40 bg-blue-950/30",
  tool: "border-primary/40 bg-blue-950/30",
  data_flow: "border-amber-500/40 bg-amber-950/30",
  agent: "border-purple-500/40 bg-purple-950/30",
  external: "border-red-500/40 bg-red-950/30",
};

export function AttackNode({ data }: NodeProps) {
  const node = data as unknown as AttackSurfaceNode;
  const colorClass = NODE_COLORS[node.type] || "border-border bg-card";

  return (
    <div className={cn("rounded border-2 p-2 min-w-[110px] text-center", colorClass)}>
      <Handle type="target" position={Position.Top} className="!bg-border !w-1.5 !h-1.5" />
      <div className="text-[10px] text-muted-foreground uppercase tracking-widest">{node.type}</div>
      <div className="text-xs font-medium truncate">{node.label}</div>
      {node.findings_count > 0 && (
        <div className="mt-1 flex items-center justify-center gap-1">
          <Badge variant="destructive" className="text-[10px]">{node.findings_count}</Badge>
          {node.max_severity && <SeverityBadge severity={node.max_severity} />}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} className="!bg-border !w-1.5 !h-1.5" />
    </div>
  );
}