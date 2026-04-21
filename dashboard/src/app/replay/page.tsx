"use client";

import { useState, useEffect } from "react";
import { useScans } from "@/hooks/use-scans";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listFindings, replayFinding, getScan } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { FindingDetail } from "@/components/findings/finding-detail";
import { Skeleton } from "@/components/ui/skeleton";
import type { FindingResponse, ScanEvent } from "@/lib/types";
import { ScanProgressWS } from "@/lib/ws";
import { Terminal, Play, Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";

export default function ReplayPage() {
  const router = useRouter();
  const { data: scansList } = useScans(50, 0);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<FindingResponse | null>(null);
  const [replayParams, setReplayParams] = useState<Record<string, string>>({});
  const [replayScanId, setReplayScanId] = useState<string | null>(null);
  const [replayEvents, setReplayEvents] = useState<ScanEvent[]>([]);
  const [replayComplete, setReplayComplete] = useState(false);

  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ["findings", { scan_id: selectedScanId }],
    queryFn: () => listFindings({ scan_id: selectedScanId }),
    enabled: !!selectedScanId,
  });

  const { data: replayScan } = useQuery({
    queryKey: ["scan", replayScanId],
    queryFn: () => getScan(replayScanId!),
    enabled: !!replayScanId && replayComplete,
  });

  const replayMutation = useMutation({
    mutationFn: (findingId: string) => replayFinding(findingId, replayParams),
    onSuccess: (data) => {
      setReplayScanId(data.scan_id);
      setReplayComplete(false);
      setReplayEvents([]);
      const ws = new ScanProgressWS(data.scan_id);
      ws.on("*", (event: ScanEvent) => {
        setReplayEvents((prev) => [...prev, event]);
        if (event.event === "scan_completed" || event.event === "scan_error") {
          setReplayComplete(true);
          ws.disconnect();
        }
      });
      ws.connect();
    },
  });

  const handleSelectFinding = (finding: FindingResponse) => {
    setSelectedFinding(finding);
    const params: Record<string, string> = {};
    // evidence is string[] — try to extract key/value pairs from each entry
    for (const entry of finding.evidence) {
      try {
        const parsed = JSON.parse(entry);
        for (const [key, value] of Object.entries(parsed)) {
          if (typeof value === "string" || typeof value === "number") {
            params[key] = String(value);
          }
        }
      } catch {
        // Not JSON — use the raw string as a param if it looks like key=value
        if (entry.includes("=")) {
          const [key, ...rest] = entry.split("=");
          params[key.trim()] = rest.join("=").trim();
        }
      }
    }
    // Fallback: if no params were extracted, provide location as a param
    if (Object.keys(params).length === 0 && finding.location) {
      params.target = finding.location;
    }
    setReplayParams(params);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Terminal className="h-6 w-6 text-primary" />
        <h1 className="text-2xl font-bold">Replay Console</h1>
      </div>

      {/* Scan selector */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Select a Scan</CardTitle>
        </CardHeader>
        <CardContent>
          <select
            value={selectedScanId}
            onChange={(e) => {
              setSelectedScanId(e.target.value);
              setSelectedFinding(null);
              setReplayScanId(null);
              setReplayEvents([]);
              setReplayComplete(false);
            }}
            className="w-full bg-muted border border-border rounded px-3 py-2 text-sm"
          >
            <option value="">Select a completed scan...</option>
            {scansList?.filter((s) => s.status === "completed").map((scan) => (
              <option key={scan.scan_id} value={scan.scan_id}>
                {scan.target} — {new Date(scan.started_at).toLocaleDateString()}
              </option>
            ))}
          </select>
        </CardContent>
      </Card>

      {/* Findings list */}
      {findingsLoading && <Skeleton className="h-40" />}
      {findings && findings.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Findings ({findings.length})</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 max-h-60 overflow-auto">
            {findings.map((f) => (
              <button
                key={f.id}
                onClick={() => handleSelectFinding(f)}
                className={`w-full text-left p-2 rounded border border-border hover:border-primary text-sm ${
                  selectedFinding?.id === f.id ? "border-primary bg-primary/5" : ""
                }`}
              >
                <SeverityBadge severity={f.severity} />
                <span className="ml-2">{f.title}</span>
              </button>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Replay panel */}
      {selectedFinding && (
        <Card>
          <CardHeader>
            <CardTitle>Replay: {selectedFinding.title}</CardTitle>
            <CardDescription>Modify parameters and re-test this attack</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <FindingDetail finding={selectedFinding} />

            {/* Editable parameters */}
            <div className="space-y-2">
              <h3 className="text-sm font-medium text-muted-foreground">Parameters (editable)</h3>
              {Object.entries(replayParams).map(([key, value]) => (
                <div key={key} className="flex gap-2 items-center">
                  <span className="text-sm text-muted-foreground w-32">{key}</span>
                  <Input
                    value={value}
                    onChange={(e) => setReplayParams({ ...replayParams, [key]: e.target.value })}
                    className="flex-1"
                  />
                </div>
              ))}
            </div>

            <Button
              onClick={() => replayMutation.mutate(selectedFinding.id)}
              disabled={replayMutation.isPending}
            >
              {replayMutation.isPending ? (
                <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Replaying...</>
              ) : (
                <><Play className="h-4 w-4 mr-2" />Replay Attack</>
              )}
            </Button>

            {/* Live replay results */}
            {replayEvents.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-sm font-medium text-muted-foreground">Live Replay Output</h3>
                <div className="terminal-output p-3 rounded text-xs max-h-60 overflow-auto">
                  {replayEvents.map((event, i) => (
                    <div key={i} className="text-green-400">
                      [{event.event}] {JSON.stringify(event.data)}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Comparison after completion */}
            {replayComplete && replayScan && (
              <div className="space-y-2">
                <h3 className="text-sm font-medium text-muted-foreground">Replay Results</h3>
                <div className="grid grid-cols-2 gap-4">
                  <Card>
                    <CardHeader><CardTitle className="text-sm">Original</CardTitle></CardHeader>
                    <CardContent>
                      <SeverityBadge severity={selectedFinding.severity} />
                      <p className="text-xs mt-1">{selectedFinding.evidence.join("; ")}</p>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle className="text-sm">Replay</CardTitle></CardHeader>
                    <CardContent>
                      <p className="text-xs">{replayScan.findings?.length} finding(s) in replay scan</p>
                      <Button variant="outline" size="sm" className="mt-2" onClick={() => router.push(`/scans/${replayScanId}`)}>
                        View Replay Scan
                      </Button>
                    </CardContent>
                  </Card>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}