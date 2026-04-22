"use client";

import { useState } from "react";
import { useScans } from "@/hooks/use-scans";
import { useMutation, useQuery } from "@tanstack/react-query";
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
    for (const entry of finding.evidence) {
      try {
        const parsed = JSON.parse(entry);
        for (const [key, value] of Object.entries(parsed)) {
          if (typeof value === "string" || typeof value === "number") {
            params[key] = String(value);
          }
        }
      } catch {
        if (entry.includes("=")) {
          const [key, ...rest] = entry.split("=");
          params[key.trim()] = rest.join("=").trim();
        }
      }
    }
    if (Object.keys(params).length === 0 && finding.location) {
      params.target = finding.location;
    }
    setReplayParams(params);
  };

  const selectClass = "w-full bg-input border border-border rounded px-2.5 py-1.5 text-xs text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1";

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-1.5">
        <Terminal className="h-4 w-4 text-muted-foreground" />
        <h1 className="text-sm font-semibold">Replay</h1>
      </div>

      <Card>
        <CardHeader><CardTitle>Select Scan</CardTitle></CardHeader>
        <CardContent>
          <select
            value={selectedScanId}
            onChange={(e) => { setSelectedScanId(e.target.value); setSelectedFinding(null); setReplayScanId(null); setReplayEvents([]); setReplayComplete(false); }}
            className={selectClass}
          >
            <option value="">Select a completed scan...</option>
            {scansList?.filter((s) => s.status === "completed").map((scan) => (
              <option key={scan.scan_id} value={scan.scan_id}>{scan.target} — {new Date(scan.started_at).toLocaleDateString()}</option>
            ))}
          </select>
        </CardContent>
      </Card>

      {findingsLoading && <Skeleton className="h-32" />}
      {findings && findings.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Findings ({findings.length})</CardTitle></CardHeader>
          <CardContent className="space-y-0.5 max-h-48 overflow-auto">
            {findings.map((f) => (
              <button
                key={f.id}
                onClick={() => handleSelectFinding(f)}
                className={`w-full text-left flex items-center gap-2 p-2 rounded border transition-colors text-xs ${
                  selectedFinding?.id === f.id ? "border-primary/30 bg-primary/5" : "border-transparent hover:bg-muted/50"
                }`}
              >
                <SeverityBadge severity={f.severity} />
                <span className="truncate">{f.title}</span>
              </button>
            ))}
          </CardContent>
        </Card>
      )}

      {selectedFinding && (
        <Card>
          <CardHeader>
            <CardTitle>Replay: {selectedFinding.title}</CardTitle>
            <CardDescription>Modify parameters and re-test this attack</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <FindingDetail finding={selectedFinding} />
            <div className="space-y-1.5">
              <p className="text-[11px] text-muted-foreground font-medium">Parameters</p>
              {Object.entries(replayParams).map(([key, value]) => (
                <div key={key} className="flex gap-2 items-center">
                  <span className="text-[11px] text-muted-foreground w-28">{key}</span>
                  <Input value={value} onChange={(e) => setReplayParams({ ...replayParams, [key]: e.target.value })} className="flex-1" />
                </div>
              ))}
            </div>
            <Button onClick={() => replayMutation.mutate(selectedFinding.id)} disabled={replayMutation.isPending} size="sm">
              {replayMutation.isPending ? <><Loader2 className="h-3 w-3 mr-1 animate-spin" />Running...</> : <><Play className="h-3 w-3 mr-1" />Replay</>}
            </Button>
            {replayEvents.length > 0 && (
              <div>
                <p className="text-[11px] text-muted-foreground font-medium mb-1">Output</p>
                <div className="terminal-output text-[11px] max-h-40 overflow-auto">
                  {replayEvents.map((event, i) => (
                    <div key={i}><span className="text-muted-foreground">[{event.event}]</span> {JSON.stringify(event.data)}</div>
                  ))}
                </div>
              </div>
            )}
            {replayComplete && replayScan && (
              <div className="grid grid-cols-2 gap-3">
                <Card>
                  <CardHeader><CardTitle className="text-xs">Original</CardTitle></CardHeader>
                  <CardContent><SeverityBadge severity={selectedFinding.severity} /></CardContent>
                </Card>
                <Card>
                  <CardHeader><CardTitle className="text-xs">Replay</CardTitle></CardHeader>
                  <CardContent>
                    <p className="text-[11px]">{replayScan.findings?.length} finding(s)</p>
                    <Button variant="outline" size="sm" className="mt-1.5" onClick={() => router.push(`/scans/${replayScanId}`)}>View</Button>
                  </CardContent>
                </Card>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}