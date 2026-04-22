"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { annotateFinding } from "@/lib/api";
import type { FindingResponse } from "@/lib/types";

interface FindingDetailProps {
  finding: FindingResponse;
}

export function FindingDetail({ finding }: FindingDetailProps) {
  const queryClient = useQueryClient();
  const [notes, setNotes] = useState(finding.notes || "");
  const [assignedTo, setAssignedTo] = useState(finding.assigned_to || "");
  const [status, setStatus] = useState(finding.status || "open");
  const [isFalsePositive, setIsFalsePositive] = useState(finding.is_false_positive || false);

  const annotateMutation = useMutation({
    mutationFn: () =>
      annotateFinding(finding.id, {
        is_false_positive: isFalsePositive,
        notes,
        assigned_to: assignedTo,
        status,
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["findings"] }),
  });

  return (
    <div className="space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <SeverityBadge severity={finding.severity} />
          <p className="mt-1 text-xs font-semibold">{finding.title}</p>
          <p className="text-[11px] text-muted-foreground mt-0.5">{finding.description}</p>
        </div>
        <Badge variant="outline">{finding.category}</Badge>
      </div>

      {finding.cwe || finding.owasp_ref || finding.mitre_ref ? (
        <div className="flex gap-4">
          {finding.cwe && <div><p className="text-[10px] text-muted-foreground">CWE</p><p className="text-xs font-medium">{finding.cwe}</p></div>}
          {finding.owasp_ref && <div><p className="text-[10px] text-muted-foreground">OWASP</p><p className="text-xs font-medium">{finding.owasp_ref}</p></div>}
          {finding.mitre_ref && <div><p className="text-[10px] text-muted-foreground">MITRE</p><p className="text-xs font-medium">{finding.mitre_ref}</p></div>}
        </div>
      ) : null}

      {finding.evidence && finding.evidence.length > 0 && (
        <div className="terminal-output">
          {finding.evidence.map((e, i) => (
            <div key={i}>{e}</div>
          ))}
        </div>
      )}

      {finding.recommendation && (
        <p className="text-xs text-muted-foreground">{finding.recommendation}</p>
      )}

      <div className="flex gap-3 text-[11px] text-muted-foreground">
        {finding.location && <span>{finding.location}</span>}
        <span>Confidence: {finding.confidence}</span>
      </div>

      <div className="border-t border-border pt-3 space-y-2">
        <p className="text-[11px] font-medium text-muted-foreground">Annotations</p>
        <label className="flex items-center gap-1.5 text-xs cursor-pointer">
          <input type="checkbox" checked={isFalsePositive} onChange={(e) => setIsFalsePositive(e.target.checked)} className="accent-primary h-3 w-3" />
          False Positive
        </label>
        <div className="flex gap-1.5">
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as "open" | "confirmed" | "resolved" | "accepted")}
            className="bg-input text-xs rounded border border-border px-2 py-1"
          >
            <option value="open">Open</option>
            <option value="confirmed">Confirmed</option>
            <option value="resolved">Resolved</option>
            <option value="accepted">Accepted</option>
          </select>
          <Input placeholder="Assign to..." value={assignedTo} onChange={(e) => setAssignedTo(e.target.value)} className="flex-1" />
        </div>
        <textarea
          placeholder="Notes..."
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          className="w-full bg-input text-xs rounded border border-border p-1.5 min-h-[40px] resize-y placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        />
        <Button size="sm" onClick={() => annotateMutation.mutate()} disabled={annotateMutation.isPending}>
          Save
        </Button>
      </div>
    </div>
  );
}