"use client";

import { use } from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { useScan } from "@/hooks/use-scans";
import { useScanProgress } from "@/hooks/use-scan-progress";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDate, formatDuration } from "@/lib/utils";
import { deleteScan } from "@/lib/api";
import type { ScanEvent } from "@/lib/types";
import {
  CheckCircle,
  XCircle,
  Clock,
  Loader2,
  AlertTriangle,
  FileJson,
  FileText,
  Trash2,
} from "lucide-react";

export default function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const { data: scan, isLoading } = useScan(id);
  const { events } = useScanProgress(scan?.status === "running" || scan?.status === "pending" ? id : null);

  const deleteMutation = useMutation({
    mutationFn: () => deleteScan(id),
    onSuccess: () => router.push("/scans"),
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-12">
        <p className="text-muted-foreground font-mono">Scan not found</p>
      </div>
    );
  }

  const isRunning = scan.status === "running" || scan.status === "pending";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold">{scan.target}</h1>
          <p className="text-sm text-muted-foreground font-mono mt-1">
            Scan {scan.scan_id.slice(0, 8)}... &middot; {formatDate(scan.started_at)}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge
            variant={
              scan.status === "completed" ? "success" :
              scan.status === "failed" ? "destructive" :
              scan.status === "running" ? "info" :
              "default"
            }
          >
            {isRunning && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
            {scan.status.toUpperCase()}
          </Badge>
          <Button
            variant="destructive"
            size="sm"
            onClick={() => { if (confirm("Delete this scan?")) deleteMutation.mutate(); }}
            disabled={deleteMutation.isPending}
          >
            <Trash2 className="h-4 w-4 mr-1" /> Delete
          </Button>
        </div>
      </div>

      {/* Summary KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
          const count = scan.summary[sev];
          return (
            <Card key={sev}>
              <CardContent className="pt-4 pb-3 text-center">
                <p className={`text-2xl font-mono font-bold ${
                  sev === "critical" ? "text-severity-critical" :
                  sev === "high" ? "text-severity-high" :
                  sev === "medium" ? "text-severity-medium" :
                  sev === "low" ? "text-severity-low" :
                  "text-severity-info"
                }`}>
                  {count}
                </p>
                <p className="text-xs text-muted-foreground uppercase font-mono">{sev}</p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Quality Gate Result */}
      {scan.gate_passed !== null && (
        <Card className={scan.gate_passed ? "glow-green" : "glow-red"}>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              {scan.gate_passed ? (
                <CheckCircle className="h-6 w-6 text-primary" />
              ) : (
                <XCircle className="h-6 w-6 text-destructive" />
              )}
              <div>
                <p className="text-lg font-mono font-bold">
                  Quality Gate: {scan.gate_passed ? "PASSED" : "FAILED"}
                </p>
                {scan.gate_reason && (
                  <p className="text-sm text-muted-foreground">{scan.gate_reason}</p>
                )}
              </div>
              <div className="ml-auto text-right">
                <p className="text-sm font-mono">Risk Score</p>
                <p className="text-2xl font-mono font-bold">{scan.summary.risk_score}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Duration */}
      {scan.completed_at && (
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Clock className="h-5 w-5 text-muted-foreground" />
              <span className="font-mono text-sm">
                Duration: {formatDuration(scan.duration_ms)}
              </span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Module Progress - shown when scan is active */}
      {(scan.status === "running" || scan.status === "pending") &&
       scan.module_statuses && scan.module_statuses.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Module Progress</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {scan.module_statuses.map((mod) => (
                <div key={mod.module_name} className="flex items-center justify-between text-sm">
                  <span>{mod.module_name}</span>
                  <Badge
                    variant={
                      mod.status === "completed" ? "success" :
                      mod.status === "failed" ? "destructive" :
                      "info"
                    }
                  >
                    {mod.status}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Live Progress Events */}
      {events.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Live Progress</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="terminal-output text-xs max-h-64 overflow-y-auto">
              {events.map((event, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-muted-foreground">[{new Date(event.timestamp).toLocaleTimeString()}]</span>
                  <span className={
                    event.event === "finding_discovered" ? "text-warning" :
                    event.event === "scan_completed" ? "text-primary" :
                    event.event === "scan_error" ? "text-destructive" :
                    "text-foreground"
                  }>
                    {event.event}
                  </span>
                  {event.data && Object.keys(event.data).length > 0 && (
                    <span className="text-muted-foreground">
                      {JSON.stringify(event.data)}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Findings List */}
      <Card>
        <CardHeader>
          <CardTitle>Findings ({scan.findings?.length ?? 0})</CardTitle>
        </CardHeader>
        <CardContent>
          {!scan.findings || scan.findings.length === 0 ? (
            <p className="text-sm text-muted-foreground">No findings</p>
          ) : (
            <div className="space-y-3">
              {scan.findings.map((f) => (
                <div
                  key={f.id}
                  className="flex items-start justify-between p-3 rounded-md border border-border hover:bg-muted transition-colors"
                >
                  <div className="flex items-start gap-3">
                    <SeverityBadge severity={f.severity} />
                    <div>
                      <p className="text-sm font-mono font-medium">{f.title}</p>
                      <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">
                        {f.description}
                      </p>
                    </div>
                  </div>
                  <span className="text-xs text-muted-foreground font-mono shrink-0">
                    {f.category}
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}