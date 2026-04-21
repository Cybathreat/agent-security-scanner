"use client";

import { useState } from "react";
import { useScans } from "@/hooks/use-scans";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { startScan, listFindings } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { FindingDetail } from "@/components/findings/finding-detail";
import { Skeleton } from "@/components/ui/skeleton";
import type { FindingResponse } from "@/lib/types";
import { Terminal, Play } from "lucide-react";
import { useRouter } from "next/navigation";

export default function ReplayPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const { data: scansList } = useScans(50, 0);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<FindingResponse | null>(null);
  const [replayTarget, setReplayTarget] = useState("");

  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ["findings", { scan_id: selectedScanId }],
    queryFn: () => listFindings({ scan_id: selectedScanId }),
    enabled: !!selectedScanId,
  });

  const replayMutation = useMutation({
    mutationFn: startScan,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      router.push(`/scans/${data.scan_id}`);
    },
  });

  const scans = scansList ?? [];
  const completedScans = scans.filter((s) => s.status === "completed");
  const scanFindings = findings ?? [];

  const handleReplay = (finding: FindingResponse) => {
    const target = replayTarget || finding.location || "";
    if (!target) return;
    replayMutation.mutate({
      target,
      modules: [finding.category],
    });
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-mono font-bold flex items-center gap-2">
        <Terminal className="h-6 w-6" />
        Replay Console
      </h1>

      {/* Scan Selection */}
      <Card>
        <CardHeader>
          <CardTitle>Select a Scan</CardTitle>
          <CardDescription>Browse findings and re-test them</CardDescription>
        </CardHeader>
        <CardContent>
          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            className="flex h-10 w-full rounded-md border border-border bg-input px-3 py-2 text-sm font-mono text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <option value="">Select a completed scan...</option>
            {completedScans.map((s) => (
              <option key={s.scan_id} value={s.scan_id}>
                {s.target} ({s.scan_id.slice(0, 8)}) &mdash; {s.summary.total} findings
              </option>
            ))}
          </select>
        </CardContent>
      </Card>

      {/* Findings List */}
      {selectedScanId && (
        <div className="flex gap-6">
          <div className="flex-1">
            <Card>
              <CardHeader>
                <CardTitle>Findings ({scanFindings.length})</CardTitle>
              </CardHeader>
              <CardContent>
                {findingsLoading ? (
                  <div className="space-y-3">
                    {[1, 2, 3].map((i) => (
                      <Skeleton key={i} className="h-14 w-full" />
                    ))}
                  </div>
                ) : scanFindings.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No findings for this scan.</p>
                ) : (
                  <div className="space-y-2">
                    {scanFindings.map((f) => (
                      <div
                        key={f.id}
                        className={`flex items-center justify-between p-3 rounded-md border transition-colors cursor-pointer ${
                          selectedFinding?.id === f.id
                            ? "border-primary bg-primary/5"
                            : "border-border hover:bg-muted"
                        }`}
                        onClick={() => setSelectedFinding(f)}
                      >
                        <div className="flex items-center gap-3">
                          <SeverityBadge severity={f.severity} />
                          <span className="text-sm font-mono">{f.title}</span>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleReplay(f);
                          }}
                          disabled={replayMutation.isPending}
                        >
                          <Play className="h-3 w-3 mr-1" />
                          Re-test
                        </Button>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Detail + Replay Panel */}
          {selectedFinding && (
            <div className="w-96 shrink-0 space-y-4">
              <Card className="sticky top-6">
                <CardHeader>
                  <CardTitle>Finding Detail</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <FindingDetail finding={selectedFinding} />

                  <div className="border-t border-border pt-4">
                    <p className="text-sm font-mono font-medium mb-2">Re-test Target</p>
                    <Input
                      placeholder={selectedFinding.location || "Enter target URL..."}
                      value={replayTarget}
                      onChange={(e) => setReplayTarget(e.target.value)}
                    />
                    <Button
                      className="w-full mt-2"
                      onClick={() => handleReplay(selectedFinding)}
                      disabled={replayMutation.isPending}
                    >
                      <Play className="h-4 w-4 mr-2" />
                      {replayMutation.isPending ? "Starting..." : "Re-test Finding"}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {!selectedScanId && (
        <div className="text-center py-12">
          <Terminal className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-muted-foreground font-mono">Select a scan to browse findings</p>
        </div>
      )}
    </div>
  );
}