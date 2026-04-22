"use client";

import { use } from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { useScan } from "@/hooks/use-scans";
import { useScanProgress } from "@/hooks/use-scan-progress";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDate, formatDuration } from "@/lib/utils";
import { deleteScan } from "@/lib/api";
import {
  CheckCircle,
  XCircle,
  Clock,
  Loader2,
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
      <div className="space-y-3">
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-36 w-full" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-12">
        <p className="text-xs text-muted-foreground">Scan not found</p>
      </div>
    );
  }

  const isRunning = scan.status === "running" || scan.status === "pending";

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-sm font-semibold">{scan.target}</h1>
          <p className="text-[11px] text-muted-foreground">
            {scan.scan_id.slice(0, 8)} &middot; {formatDate(scan.started_at)}
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <Badge
            variant={
              scan.status === "completed" ? "success" :
              scan.status === "failed" ? "destructive" :
              scan.status === "running" ? "info" :
              "default"
            }
          >
            {isRunning && <Loader2 className="h-3 w-3 mr-0.5 animate-spin" />}
            {scan.status.toUpperCase()}
          </Badge>
          <Button
            variant="destructive"
            size="sm"
            onClick={() => { if (confirm("Delete this scan?")) deleteMutation.mutate(); }}
            disabled={deleteMutation.isPending}
          >
            <Trash2 className="h-3 w-3" />
          </Button>
        </div>
      </div>

      {/* Severity summary */}
      <div className="grid grid-cols-5 gap-2">
        {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
          const count = scan.summary[sev];
          return (
            <Card key={sev}>
              <CardContent className="pt-2 pb-2 px-2.5 text-center">
                <p className={`text-base font-semibold tabular-nums leading-none ${
                  sev === "critical" ? "text-severity-critical" :
                  sev === "high" ? "text-severity-high" :
                  sev === "medium" ? "text-severity-medium" :
                  sev === "low" ? "text-severity-low" :
                  "text-severity-info"
                }`}>
                  {count}
                </p>
                <p className="text-[10px] text-muted-foreground uppercase mt-0.5">{sev}</p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Quality Gate */}
      {scan.gate_passed !== null && (
        <Card className={scan.gate_passed ? "border-primary/30" : "border-destructive/30"}>
          <CardContent className="py-2.5">
            <div className="flex items-center gap-2">
              {scan.gate_passed ? (
                <CheckCircle className="h-4 w-4 text-primary" />
              ) : (
                <XCircle className="h-4 w-4 text-destructive" />
              )}
              <span className="text-xs font-semibold">
                Quality Gate: {scan.gate_passed ? "PASSED" : "FAILED"}
              </span>
              {scan.gate_reason && (
                <span className="text-[11px] text-muted-foreground">&middot; {scan.gate_reason}</span>
              )}
              <span className="ml-auto text-xs font-semibold tabular-nums">Risk: {scan.summary.risk_score}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Duration */}
      {scan.completed_at && (
        <Card>
          <CardContent className="py-2.5">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Clock className="h-3.5 w-3.5" />
              Duration: {formatDuration(scan.duration_ms)}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Module Progress */}
      {(scan.status === "running" || scan.status === "pending") &&
       scan.module_statuses && scan.module_statuses.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Module Progress</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {scan.module_statuses.map((mod) => (
                <div key={mod.module_name} className="flex items-center justify-between text-xs">
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

      {/* Live Progress */}
      {events.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Live Progress</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="terminal-output text-[11px] max-h-48 overflow-y-auto">
              {events.map((event, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-muted-foreground">[{new Date(event.timestamp).toLocaleTimeString()}]</span>
                  <span className={
                    event.event === "finding_discovered" ? "text-warning" :
                    event.event === "scan_completed" ? "text-primary" :
                    event.event === "scan_error" ? "text-destructive" :
                    ""
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

      {/* Findings */}
      <Card>
        <CardHeader>
          <CardTitle>Findings ({scan.findings?.length ?? 0})</CardTitle>
        </CardHeader>
        <CardContent>
          {!scan.findings || scan.findings.length === 0 ? (
            <p className="text-xs text-muted-foreground">No findings</p>
          ) : (
            <div className="space-y-1">
              {scan.findings.map((f) => (
                <div
                  key={f.id}
                  className="flex items-start justify-between p-2 rounded border border-border hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-start gap-2">
                    <SeverityBadge severity={f.severity} />
                    <div>
                      <p className="text-xs font-medium">{f.title}</p>
                      <p className="text-[11px] text-muted-foreground line-clamp-1">{f.description}</p>
                    </div>
                  </div>
                  <span className="text-[11px] text-muted-foreground shrink-0 ml-2">{f.category}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}