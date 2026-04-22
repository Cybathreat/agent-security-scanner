"use client";

import { useQuery } from "@tanstack/react-query";
import { listScans, listFindings } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { Skeleton } from "@/components/ui/skeleton";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  ArrowRight,
} from "lucide-react";
import { formatDate } from "@/lib/utils";

export default function DashboardPage() {
  const { data: scans, isLoading: scansLoading } = useQuery({
    queryKey: ["scans", 10, 0],
    queryFn: () => listScans(10, 0),
  });

  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ["findings", { limit: 5 }],
    queryFn: () => listFindings({ limit: 5 }),
  });

  const recentScans = scans ?? [];
  const recentFindings = findings ?? [];

  const totalScans = recentScans.length;
  const criticalCount = recentFindings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = recentFindings.filter((f) => f.severity === "HIGH").length;
  const completedWithGate = recentScans.filter((s) => s.gate_passed !== null);
  const passRate = completedWithGate.length > 0
    ? Math.round((completedWithGate.filter((s) => s.gate_passed === true).length / completedWithGate.length) * 100)
    : 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold">Dashboard</h1>
        <Link
          href="/scans"
          className="flex items-center gap-1 text-xs text-primary hover:underline underline-offset-2"
        >
          New scan <ArrowRight className="h-3 w-3" />
        </Link>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Card>
          <CardContent className="pt-3 pb-3 px-3.5">
            <div className="flex items-center gap-2">
              <Activity className="h-3.5 w-3.5 text-muted-foreground" />
              <div>
                <p className="text-lg font-semibold tabular-nums leading-none">{totalScans}</p>
                <p className="text-[11px] text-muted-foreground mt-0.5">Scans</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-3 pb-3 px-3.5">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-3.5 w-3.5 text-destructive" />
              <div>
                <p className="text-lg font-semibold text-destructive tabular-nums leading-none">{criticalCount}</p>
                <p className="text-[11px] text-muted-foreground mt-0.5">Critical</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-3 pb-3 px-3.5">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-3.5 w-3.5 text-warning" />
              <div>
                <p className="text-lg font-semibold text-warning tabular-nums leading-none">{highCount}</p>
                <p className="text-[11px] text-muted-foreground mt-0.5">High</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-3 pb-3 px-3.5">
            <div className="flex items-center gap-2">
              <CheckCircle className="h-3.5 w-3.5 text-primary" />
              <div>
                <p className="text-lg font-semibold tabular-nums leading-none">{passRate}%</p>
                <p className="text-[11px] text-muted-foreground mt-0.5">Pass rate</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Scans */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Scans</CardTitle>
        </CardHeader>
        <CardContent>
          {scansLoading ? (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-9 w-full" />
              ))}
            </div>
          ) : recentScans.length === 0 ? (
            <p className="text-xs text-muted-foreground">No scans yet.</p>
          ) : (
            <div className="space-y-0.5">
              {recentScans.slice(0, 5).map((scan) => (
                <Link
                  key={scan.scan_id}
                  href={`/scans/${scan.scan_id}`}
                  className="flex items-center justify-between p-2 rounded hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <div className={`severity-dot ${
                      scan.status === "completed" ? "severity-dot-low" :
                      scan.status === "running" ? "severity-dot-medium" :
                      scan.status === "failed" ? "severity-dot-critical" :
                      "severity-dot-info"
                    }`} />
                    <div>
                      <p className="text-xs font-medium">{scan.target}</p>
                      <p className="text-[11px] text-muted-foreground">{formatDate(scan.started_at)}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-muted-foreground tabular-nums">
                      {scan.summary.total} findings
                    </span>
                    {scan.gate_passed !== null && (
                      <Badge variant={scan.gate_passed ? "success" : "destructive"}>
                        {scan.gate_passed ? "PASS" : "FAIL"}
                      </Badge>
                    )}
                  </div>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Recent Findings */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Findings</CardTitle>
        </CardHeader>
        <CardContent>
          {findingsLoading ? (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-8 w-full" />
              ))}
            </div>
          ) : recentFindings.length === 0 ? (
            <p className="text-xs text-muted-foreground">No findings yet.</p>
          ) : (
            <div className="space-y-0.5">
              {recentFindings.slice(0, 5).map((f) => (
                <Link
                  key={f.id}
                  href={`/findings?search=${f.id}`}
                  className="flex items-center justify-between p-2 rounded hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <span className="text-xs">{f.title}</span>
                  </div>
                  <span className="text-[11px] text-muted-foreground">{f.category}</span>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}