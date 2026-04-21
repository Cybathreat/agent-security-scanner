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
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <SeverityBadge severity={finding.severity} />
          <h2 className="mt-2 text-lg font-mono font-semibold">{finding.title}</h2>
          <p className="text-sm text-muted-foreground mt-1">{finding.description}</p>
        </div>
        <Badge variant="outline">{finding.category}</Badge>
      </div>

      {/* Framework Mappings */}
      <Card>
        <CardHeader>
          <CardTitle>Framework Mappings</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {finding.cwe && (
              <div>
                <p className="text-xs text-muted-foreground font-mono">CWE</p>
                <p className="font-mono text-sm">{finding.cwe}</p>
              </div>
            )}
            {finding.owasp_ref && (
              <div>
                <p className="text-xs text-muted-foreground font-mono">OWASP</p>
                <p className="font-mono text-sm">{finding.owasp_ref}</p>
              </div>
            )}
            {finding.mitre_ref && (
              <div>
                <p className="text-xs text-muted-foreground font-mono">MITRE ATLAS</p>
                <p className="font-mono text-sm">{finding.mitre_ref}</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Evidence */}
      {finding.evidence && finding.evidence.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Evidence</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="terminal-output text-xs">
              {finding.evidence.map((e, i) => (
                <div key={i}>{e}</div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Recommendation */}
      {finding.recommendation && (
        <Card>
          <CardHeader>
            <CardTitle>Recommendation</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm">{finding.recommendation}</p>
          </CardContent>
        </Card>
      )}

      {/* Meta */}
      <div className="flex gap-4 text-xs text-muted-foreground font-mono">
        {finding.location && <span>Location: {finding.location}</span>}
        <span>Confidence: {finding.confidence}</span>
        {finding.timestamp && <span>{finding.timestamp}</span>}
      </div>

      {/* Annotations */}
      <div className="border-t border-border pt-4 space-y-3">
        <h3 className="text-sm font-medium">Annotations</h3>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1 text-sm cursor-pointer">
            <input
              type="checkbox"
              checked={isFalsePositive}
              onChange={(e) => setIsFalsePositive(e.target.checked)}
              className="accent-primary"
            />
            False Positive
          </label>
        </div>
        <div className="flex gap-2">
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as "open" | "confirmed" | "resolved" | "accepted")}
            className="bg-muted text-sm rounded px-2 py-1 border border-border"
          >
            <option value="open">Open</option>
            <option value="confirmed">Confirmed</option>
            <option value="resolved">Resolved</option>
            <option value="accepted">Accepted</option>
          </select>
          <Input
            placeholder="Assign to..."
            value={assignedTo}
            onChange={(e) => setAssignedTo(e.target.value)}
            className="flex-1"
          />
        </div>
        <textarea
          placeholder="Add notes..."
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          className="w-full bg-muted text-sm rounded p-2 border border-border min-h-[60px]"
        />
        <Button size="sm" onClick={() => annotateMutation.mutate()} disabled={annotateMutation.isPending}>
          Save Annotation
        </Button>
      </div>
    </div>
  );
}