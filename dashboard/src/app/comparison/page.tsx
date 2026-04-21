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

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-mono font-bold">Scan Comparison</h1>

      {/* Scan Selection */}
      <Card>
        <CardHeader>
          <CardTitle>Select Scans</CardTitle>
          <CardDescription>Compare two completed scans side-by-side</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-mono text-muted-foreground">Scan A</label>
              <select
                value={leftScanId}
                onChange={(e) => setLeftScanId(e.target.value)}
                className="mt-1 flex h-10 w-full rounded-md border border-border bg-input px-3 py-2 text-sm font-mono text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <option value="">Select a scan...</option>
                {completedScans.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>
                    {s.target} ({s.scan_id.slice(0, 8)})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-sm font-mono text-muted-foreground">Scan B</label>
              <select
                value={rightScanId}
                onChange={(e) => setRightScanId(e.target.value)}
                className="mt-1 flex h-10 w-full rounded-md border border-border bg-input px-3 py-2 text-sm font-mono text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <option value="">Select a scan...</option>
                {completedScans.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>
                    {s.target} ({s.scan_id.slice(0, 8)})
                  </option>
                ))}
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Comparison Results */}
      {leftScanId && rightScanId && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Left Scan */}
          {leftLoading ? (
            <Skeleton className="h-64 w-full" />
          ) : leftScan ? (
            <ScanComparisonCard label="Scan A" scan={leftScan} />
          ) : null}

          {/* Right Scan */}
          {rightLoading ? (
            <Skeleton className="h-64 w-full" />
          ) : rightScan ? (
            <ScanComparisonCard label="Scan B" scan={rightScan} />
          ) : null}
        </div>
      )}

      {/* Diff Summary */}
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

      {/* Empty State */}
      {!leftScanId && !rightScanId && (
        <div className="text-center py-12">
          <GitCompare className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-muted-foreground font-mono">Select two scans to compare</p>
        </div>
      )}
    </div>
  );
}

function ScanComparisonCard({
  label,
  scan,
}: {
  label: string;
  scan: import("@/lib/types").ScanDetailResponse;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{label}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <p className="text-sm font-mono font-medium">{scan.target}</p>
          <p className="text-xs text-muted-foreground">{formatDate(scan.started_at)}</p>
        </div>

        {/* Severity Breakdown */}
        <div className="space-y-2">
          {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
            <div key={sev} className="flex items-center gap-2">
              <span className="text-xs font-mono uppercase w-20 text-muted-foreground">{sev}</span>
              <div className="flex-1 h-3 bg-muted rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${
                    sev === "critical" ? "bg-severity-critical" :
                    sev === "high" ? "bg-severity-high" :
                    sev === "medium" ? "bg-severity-medium" :
                    sev === "low" ? "bg-severity-low" :
                    "bg-severity-info"
                  }`}
                  style={{ width: `${Math.min(100, (scan.summary[sev] / Math.max(scan.summary.total, 1)) * 100)}%` }}
                />
              </div>
              <span className="text-sm font-mono w-8 text-right">{scan.summary[sev]}</span>
            </div>
          ))}
        </div>

        {/* Gate Status */}
        <div className="flex items-center justify-between pt-2 border-t border-border">
          <span className="text-sm text-muted-foreground">Quality Gate</span>
          <Badge variant={scan.gate_passed ? "success" : "destructive"}>
            {scan.gate_passed ? "PASS" : "FAIL"}
          </Badge>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Risk Score</span>
          <span className="font-mono font-bold">{scan.summary.risk_score}</span>
        </div>
      </CardContent>
    </Card>
  );
}

function DiffTable({
  left,
  right,
}: {
  left: import("@/lib/types").ScanDetailResponse;
  right: import("@/lib/types").ScanDetailResponse;
}) {
  const leftIds = new Set(left.findings.map((f) => f.id));
  const rightIds = new Set(right.findings.map((f) => f.id));

  const newFindings = right.findings.filter((f) => !leftIds.has(f.id));
  const resolvedFindings = left.findings.filter((f) => !rightIds.has(f.id));
  const unchanged = left.findings.filter((f) => rightIds.has(f.id));

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-6 text-center">
            <p className="text-2xl font-mono font-bold text-primary">{resolvedFindings.length}</p>
            <p className="text-xs text-muted-foreground">Resolved</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6 text-center">
            <p className="text-2xl font-mono font-bold text-foreground">{unchanged.length}</p>
            <p className="text-xs text-muted-foreground">Unchanged</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6 text-center">
            <p className="text-2xl font-mono font-bold text-destructive">{newFindings.length}</p>
            <p className="text-xs text-muted-foreground">New</p>
          </CardContent>
        </Card>
      </div>

      {newFindings.length > 0 && (
        <div>
          <h3 className="text-sm font-mono font-semibold text-destructive mb-2">New Findings</h3>
          {newFindings.map((f) => (
            <div key={f.id} className="flex items-center gap-2 p-2 text-sm">
              <Badge variant="destructive" className="text-xs">NEW</Badge>
              <span className="font-mono">{f.title}</span>
              <span className="text-xs text-muted-foreground ml-auto">{f.severity}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}