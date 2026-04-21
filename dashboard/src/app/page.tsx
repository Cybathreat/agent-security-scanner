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
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-mono font-bold">Dashboard</h1>
        <Link
          href="/scans"
          className="flex items-center gap-1 text-sm font-mono text-primary hover:underline"
        >
          New Scan <ArrowRight className="h-4 w-4" />
        </Link>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-primary/10">
                <Activity className="h-5 w-5 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-mono font-bold">{totalScans}</p>
                <p className="text-xs text-muted-foreground">Total Scans</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-destructive/10">
                <AlertTriangle className="h-5 w-5 text-destructive" />
              </div>
              <div>
                <p className="text-2xl font-mono font-bold text-destructive">{criticalCount}</p>
                <p className="text-xs text-muted-foreground">Critical Findings</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-warning/10">
                <AlertTriangle className="h-5 w-5 text-warning" />
              </div>
              <div>
                <p className="text-2xl font-mono font-bold text-warning">{highCount}</p>
                <p className="text-xs text-muted-foreground">High Findings</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-primary/10">
                <CheckCircle className="h-5 w-5 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-mono font-bold">{passRate}%</p>
                <p className="text-xs text-muted-foreground">Gate Pass Rate</p>
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
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : recentScans.length === 0 ? (
            <p className="text-sm text-muted-foreground">No scans yet. Start your first scan!</p>
          ) : (
            <div className="space-y-2">
              {recentScans.slice(0, 5).map((scan) => (
                <Link
                  key={scan.scan_id}
                  href={`/scans/${scan.scan_id}`}
                  className="flex items-center justify-between p-3 rounded-md hover:bg-muted transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div className={`h-2 w-2 rounded-full ${
                      scan.status === "completed" ? "bg-primary" :
                      scan.status === "running" ? "bg-info" :
                      scan.status === "failed" ? "bg-destructive" :
                      "bg-muted-foreground"
                    }`} />
                    <div>
                      <p className="text-sm font-mono">{scan.target}</p>
                      <p className="text-xs text-muted-foreground">
                        {formatDate(scan.started_at)}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-muted-foreground">
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
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : recentFindings.length === 0 ? (
            <p className="text-sm text-muted-foreground">No findings yet.</p>
          ) : (
            <div className="space-y-2">
              {recentFindings.slice(0, 5).map((f) => (
                <Link
                  key={f.id}
                  href={`/findings?search=${f.id}`}
                  className="flex items-center justify-between p-3 rounded-md hover:bg-muted transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={f.severity} />
                    <span className="text-sm font-mono">{f.title}</span>
                  </div>
                  <span className="text-xs text-muted-foreground font-mono">{f.category}</span>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}