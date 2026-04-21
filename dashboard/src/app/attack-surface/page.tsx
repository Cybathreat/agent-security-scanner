"use client";

import { useState, useMemo, useCallback } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  type NodeTypes,
  type NodeMouseHandler,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useScans } from "@/hooks/use-scans";
import { useQuery } from "@tanstack/react-query";
import { getAttackSurface, listFindings } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { FindingDetail } from "@/components/findings/finding-detail";
import { AttackNode } from "@/components/attack-surface/attack-node";
import { Network } from "lucide-react";
import type { AttackSurfaceNode as AttackSurfaceNodeType, FindingResponse } from "@/lib/types";

const nodeTypes: NodeTypes = { attackNode: AttackNode };

const NODE_POSITIONS: Record<string, { x: number; y: number }> = {
  endpoint: { x: 250, y: 0 },
  agent: { x: 250, y: 150 },
  tool: { x: 0, y: 300 },
  data_flow: { x: 500, y: 300 },
  external: { x: 250, y: 450 },
};

export default function AttackSurfacePage() {
  const { data: scansList } = useScans(50, 0);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>([]);

  const { data: surface, isLoading } = useQuery({
    queryKey: ["attack-surface", selectedScanId],
    queryFn: () => getAttackSurface(selectedScanId),
    enabled: !!selectedScanId,
  });

  const { data: selectedFindings } = useQuery({
    queryKey: ["findings", { scan_id: selectedScanId, limit: 200 }],
    queryFn: async () => {
      const all = await listFindings({ scan_id: selectedScanId, limit: 200 });
      return all.filter((f: FindingResponse) => selectedFindingIds.includes(f.id));
    },
    enabled: selectedFindingIds.length > 0,
  });

  const nodes: Node[] = useMemo(() => {
    if (!surface) return [];
    let typeIndex: Record<string, number> = {};
    return surface.nodes.map((node) => {
      const pos = NODE_POSITIONS[node.type] || { x: 0, y: 0 };
      const offset = typeIndex[node.type] || 0;
      typeIndex[node.type] = offset + 1;
      return {
        id: node.id,
        type: "attackNode",
        position: { x: pos.x + offset * 250, y: pos.y },
        data: node as unknown as Record<string, unknown>,
      };
    });
  }, [surface]);

  const edges: Edge[] = useMemo(() => {
    if (!surface) return [];
    return surface.edges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: `${edge.label} (${edge.finding_count})`,
      animated: true,
      style: { stroke: "#22c55e" },
    }));
  }, [surface]);

  const onNodeClick: NodeMouseHandler = useCallback((_: React.MouseEvent, node: Node) => {
    const surfaceNode = surface?.nodes.find((n) => n.id === node.id);
    if (surfaceNode) {
      setSelectedFindingIds(surfaceNode.finding_ids);
    }
  }, [surface]);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Network className="h-6 w-6 text-primary" />
        <h1 className="text-2xl font-bold">Attack Surface Map</h1>
      </div>

      {/* Scan selector */}
      <select
        value={selectedScanId}
        onChange={(e) => {
          setSelectedScanId(e.target.value);
          setSelectedFindingIds([]);
        }}
        className="w-full bg-muted border border-border rounded px-3 py-2 text-sm"
      >
        <option value="">Select a scan...</option>
        {scansList?.map((scan) => (
          <option key={scan.scan_id} value={scan.scan_id}>
            {scan.target} — {scan.status}
          </option>
        ))}
      </select>

      {/* Legend */}
      <div className="flex gap-4 text-xs text-muted-foreground flex-wrap">
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded border-2 border-blue-500 bg-blue-950/50 inline-block" /> Endpoint</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded border-2 border-green-500 bg-green-950/50 inline-block" /> Tool</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded border-2 border-amber-500 bg-amber-950/50 inline-block" /> Data Flow</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded border-2 border-purple-500 bg-purple-950/50 inline-block" /> Agent</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded border-2 border-red-500 bg-red-950/50 inline-block" /> External</span>
      </div>

      {isLoading && <Skeleton className="h-[500px]" />}

      {surface && (
        <div className="grid grid-cols-[1fr_300px] gap-4">
          <div className="h-[500px] border border-border rounded bg-background">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={nodeTypes}
              onNodeClick={onNodeClick}
              fitView
            >
              <Background />
              <Controls />
              <MiniMap />
            </ReactFlow>
          </div>

          <div className="space-y-4 overflow-auto max-h-[500px]">
            {selectedFindings && selectedFindings.length > 0 ? (
              <>
                <h3 className="text-sm font-medium">Node Findings</h3>
                {selectedFindings.map((f: FindingResponse) => (
                  <FindingDetail key={f.id} finding={f} />
                ))}
              </>
            ) : (
              <p className="text-sm text-muted-foreground">Click a node to view its findings</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}