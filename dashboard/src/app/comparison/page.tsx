"use client";

import { useState } from "react";
import { useScans } from "@/hooks/use-scans";
import { useQuery } from "@tanstack/react-query";
import { getScan } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDate } from "@/lib/utils";
import { GitCompare } from "lucide-react";

export default function ComparisonPage() {
  const { data: scansList } = useScans(50, 0);
  const [leftScanId, setLeftScanId] = useState("");
  const [rightScanId, setRightScanId] = useState("");

  const { data: leftScan, isLoading: leftLoading } = useQuery({
    queryKey: ["scan", leftScanId],
    queryFn: () => getScan(leftScanId),
    enabled: !!leftScanId,
  });

  const { data: rightScan, isLoading: rightLoading } = useQuery({
    queryKey: ["scan", rightScanId],
    queryFn: () => getScan(rightScanId),
    enabled: !!rightScanId,
  });

  const scans = scansList ?? [];
  const completedScans = scans.filter((s) => s.status === "completed");

  const selectClass = "mt-0.5 flex h-8 w-full rounded border border-border bg-input px-2.5 py-1.5 text-xs text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1";

  return (
    <div className="space-y-4">
      <h1 className="text-sm font-semibold">Comparison</h1>

      <Card>
        <CardHeader>
          <CardTitle>Select Scans</CardTitle>
          <CardDescription>Compare two completed scans side-by-side</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] text-muted-foreground">Scan A</label>
              <select value={leftScanId} onChange={(e) => setLeftScanId(e.target.value)} className={selectClass}>
                <option value="">Select a scan...</option>
                {completedScans.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>{s.target} ({s.scan_id.slice(0, 8)})</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-[11px] text-muted-foreground">Scan B</label>
              <select value={rightScanId} onChange={(e) => setRightScanId(e.target.value)} className={selectClass}>
                <option value="">Select a scan...</option>
                {completedScans.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>{s.target} ({s.scan_id.slice(0, 8)})</option>
                ))}
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {leftScanId && rightScanId && (
        <div className="grid grid-cols-2 gap-4">
          {leftLoading ? <Skeleton className="h-48 w-full" /> : leftScan ? <ScanCard label="A" scan={leftScan} /> : null}
          {rightLoading ? <Skeleton className="h-48 w-full" /> : rightScan ? <ScanCard label="B" scan={rightScan} /> : null}
        </div>
      )}

      {leftScan && rightScan && (
        <Card>
          <CardHeader>
            <CardTitle>Diff Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <DiffTable left={leftScan} right={rightScan} />
          </CardContent>
        </Card>
      )}

      {!leftScanId && !rightScanId && (
        <div className="text-center py-10">
          <GitCompare className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
          <p className="text-xs text-muted-foreground">Select two scans to compare</p>
        </div>
      )}
    </div>
  );
}

function ScanCard({ label, scan }: { label: string; scan: import("@/lib/types").ScanDetailResponse }) {
  return (
    <Card>
      <CardHeader><CardTitle>Scan {label}</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <div>
          <p className="text-xs font-medium">{scan.target}</p>
          <p className="text-[11px] text-muted-foreground">{formatDate(scan.started_at)}</p>
        </div>
        <div className="space-y-1.5">
          {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
            <div key={sev} className="flex items-center gap-2">
              <span className="text-[11px] uppercase w-14 text-muted-foreground">{sev}</span>
              <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${
                    sev === "critical" ? "bg-severity-critical" :
                    sev === "high" ? "bg-severity-high" :
                    sev === "medium" ? "bg-severity-medium" :
                    sev === "low" ? "bg-severity-low" : "bg-severity-info"
                  }`}
                  style={{ width: `${Math.min(100, (scan.summary[sev] / Math.max(scan.summary.total, 1)) * 100)}%` }}
                />
              </div>
              <span className="text-xs tabular-nums w-6 text-right">{scan.summary[sev]}</span>
            </div>
          ))}
        </div>
        <div className="flex items-center justify-between pt-2 border-t border-border">
          <span className="text-[11px] text-muted-foreground">Gate</span>
          <Badge variant={scan.gate_passed ? "success" : "destructive"}>{scan.gate_passed ? "PASS" : "FAIL"}</Badge>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[11px] text-muted-foreground">Risk</span>
          <span className="text-xs font-semibold tabular-nums">{scan.summary.risk_score}</span>
        </div>
      </CardContent>
    </Card>
  );
}

function DiffTable({ left, right }: { left: import("@/lib/types").ScanDetailResponse; right: import("@/lib/types").ScanDetailResponse }) {
  const leftIds = new Set(left.findings.map((f) => f.id));
  const rightIds = new Set(right.findings.map((f) => f.id));
  const newFindings = right.findings.filter((f) => !leftIds.has(f.id));
  const resolvedFindings = left.findings.filter((f) => !rightIds.has(f.id));
  const unchanged = left.findings.filter((f) => rightIds.has(f.id));

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-2">
        <Card><CardContent className="pt-2.5 pb-2 text-center"><p className="text-base font-semibold text-primary tabular-nums">{resolvedFindings.length}</p><p className="text-[11px] text-muted-foreground">Resolved</p></CardContent></Card>
        <Card><CardContent className="pt-2.5 pb-2 text-center"><p className="text-base font-semibold tabular-nums">{unchanged.length}</p><p className="text-[11px] text-muted-foreground">Unchanged</p></CardContent></Card>
        <Card><CardContent className="pt-2.5 pb-2 text-center"><p className="text-base font-semibold text-destructive tabular-nums">{newFindings.length}</p><p className="text-[11px] text-muted-foreground">New</p></CardContent></Card>
      </div>
      {newFindings.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-destructive mb-1">New Findings</p>
          {newFindings.map((f) => (
            <div key={f.id} className="flex items-center gap-1.5 py-1 text-xs">
              <Badge variant="destructive" className="text-[10px]">NEW</Badge>
              <span className="truncate">{f.title}</span>
              <span className="text-[11px] text-muted-foreground ml-auto shrink-0">{f.severity}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}