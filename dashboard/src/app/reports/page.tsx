"use client";

import { useState } from "react";
import { useScans } from "@/hooks/use-scans";
import { useQuery } from "@tanstack/react-query";
import { getScan } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDate } from "@/lib/utils";
import { FileText, Download, GripVertical } from "lucide-react";
import type { ScanDetailResponse } from "@/lib/types";
import { DndContext, closestCenter, type DragEndEvent } from "@dnd-kit/core";
import { SortableContext, verticalListSortingStrategy, useSortable, arrayMove } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import html2pdf from "html2pdf.js";

interface Section {
  id: string;
  label: string;
  enabled: boolean;
}

const DEFAULT_SECTIONS: Section[] = [
  { id: "summary", label: "Executive Summary", enabled: true },
  { id: "findings", label: "Findings Table", enabled: true },
  { id: "modules", label: "Module Status", enabled: true },
  { id: "frameworks", label: "Framework Mappings", enabled: true },
  { id: "quality_gate", label: "Quality Gate", enabled: true },
];

function SortableSection({ section, onToggle }: { section: Section; onToggle: (id: string) => void }) {
  const { attributes, listeners, setNodeRef, transform, transition } = useSortable({ id: section.id });
  const style = { transform: CSS.Transform.toString(transform), transition };

  return (
    <div ref={setNodeRef} style={style} className="flex items-center gap-2 p-2 border border-border rounded bg-card">
      <span {...attributes} {...listeners} className="cursor-grab text-muted-foreground hover:text-foreground">
        <GripVertical className="h-4 w-4" />
      </span>
      <input
        type="checkbox"
        checked={section.enabled}
        onChange={() => onToggle(section.id)}
        className="accent-primary"
      />
      <span className="text-sm">{section.label}</span>
    </div>
  );
}

export default function ReportsPage() {
  const { data: scansList } = useScans(50, 0);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [sections, setSections] = useState(DEFAULT_SECTIONS);
  const [reportText, setReportText] = useState("");

  const { data: scan, isLoading } = useQuery({
    queryKey: ["scan", selectedScanId],
    queryFn: () => getScan(selectedScanId),
    enabled: !!selectedScanId,
  });

  const scans = scansList ?? [];
  const completedScans = scans.filter((s) => s.status === "completed");

  const toggleSection = (id: string) => {
    setSections((prev) =>
      prev.map((s) => (s.id === id ? { ...s, enabled: !s.enabled } : s)),
    );
  };

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    if (over && active.id !== over.id) {
      setSections((prev) => {
        const oldIndex = prev.findIndex((s) => s.id === active.id as string);
        const newIndex = prev.findIndex((s) => s.id === over.id as string);
        return arrayMove(prev, oldIndex, newIndex);
      });
    }
  };

  const downloadPdf = () => {
    const element = document.getElementById("report-preview");
    if (!element) return;
    html2pdf()
      .set({
        margin: 10,
        filename: `security-report-${selectedScanId}.pdf`,
        html2canvas: { scale: 2 },
        jsPDF: { unit: "mm" as const, format: "a4" as const, orientation: "portrait" as const },
      })
      .from(element)
      .save();
  };

  const downloadHtml = () => {
    const element = document.getElementById("report-preview");
    if (!element) return;
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Security Report</title><style>body{font-family:system-ui,sans-serif;max-width:800px;margin:0 auto;padding:20px;color:#e0e0e0;background:#0a0a0a;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #333;padding:8px;text-align:left;}th{background:#1a1a1a;}</style></head><body>${element.innerHTML}</body></html>`;
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security-report-${selectedScanId}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const generateExecutiveSummary = (scan: ScanDetailResponse): string => {
    const findings = scan.findings || [];
    const total = findings.length;
    const critical = findings.filter((f) => f.severity === "CRITICAL").length;
    const high = findings.filter((f) => f.severity === "HIGH").length;
    const categories = [...new Set(findings.map((f) => f.category))];
    const topCategory = categories.length
      ? categories.reduce((a, b) =>
          findings.filter((f) => f.category === a).length >=
          findings.filter((f) => f.category === b).length ? a : b
        )
      : "N/A";
    const gateStatus = scan.gate_passed ? "PASSED" : "FAILED";

    return `## Executive Summary\n\n**Scan Target:** ${scan.target}\n**Quality Gate:** ${gateStatus}\n**Total Findings:** ${total} (${critical} Critical, ${high} High)\n**Risk Score:** ${scan.summary?.risk_score ?? "N/A"}\n**Top Category:** ${topCategory}\n\n${total === 0 ? "No security findings were identified during this scan." : `This scan identified ${total} security finding(s), with ${critical} critical and ${high} high severity issues. The most affected category is ${topCategory}. The quality gate ${gateStatus.toLowerCase()}.`}`;
  };

  const generateReport = () => {
    if (!scan) return;
    const enabled = sections.filter((s) => s.enabled);
    const lines: string[] = [];

    lines.push(`# Agent Security Scanner Report`);
    lines.push(``);
    lines.push(`**Target:** ${scan.target}`);
    lines.push(`**Date:** ${formatDate(scan.started_at)}`);
    lines.push(`**Scan ID:** ${scan.scan_id}`);
    lines.push(``);

    for (const section of enabled) {
      switch (section.id) {
        case "summary":
          lines.push(generateExecutiveSummary(scan));
          lines.push(``);
          break;

        case "findings":
          lines.push(`## Findings`);
          lines.push(``);
          if (scan.findings.length === 0) {
            lines.push(`No findings discovered.`);
          } else {
            lines.push(`| Severity | Category | Title | CWE |`);
            lines.push(`|----------|----------|-------|-----|`);
            for (const f of scan.findings) {
              lines.push(`| ${f.severity} | ${f.category} | ${f.title} | ${f.cwe || "-"} |`);
            }
          }
          lines.push(``);
          break;

        case "modules":
          lines.push(`## Module Status`);
          lines.push(``);
          lines.push(`Modules: ${scan.modules.join(", ")}`);
          lines.push(``);
          break;

        case "frameworks":
          lines.push(`## Framework Mappings`);
          lines.push(``);
          for (const f of scan.findings) {
            if (f.cwe || f.owasp_ref || f.mitre_ref) {
              lines.push(`### ${f.title}`);
              if (f.cwe) lines.push(`- CWE: ${f.cwe}`);
              if (f.owasp_ref) lines.push(`- OWASP: ${f.owasp_ref}`);
              if (f.mitre_ref) lines.push(`- MITRE: ${f.mitre_ref}`);
              lines.push(``);
            }
          }
          break;

        case "quality_gate":
          lines.push(`## Quality Gate`);
          lines.push(``);
          lines.push(`Result: **${scan.gate_passed ? "PASSED" : "FAILED"}**`);
          if (scan.gate_reason) lines.push(`Reason: ${scan.gate_reason}`);
          lines.push(`Risk Score: ${scan.summary.risk_score}`);
          lines.push(``);
          break;
      }
    }

    setReportText(lines.join("\n"));
  };

  const downloadReport = (format: "md" | "json") => {
    const content = format === "json"
      ? JSON.stringify(scan, null, 2)
      : reportText;
    const blob = new Blob([content], { type: format === "json" ? "application/json" : "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security-report-${selectedScanId.slice(0, 8)}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-mono font-bold">Report Builder</h1>

      {/* Scan Selection */}
      <Card>
        <CardHeader>
          <CardTitle>Select Scan</CardTitle>
          <CardDescription>Choose a scan to generate a report</CardDescription>
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
                {s.target} ({s.scan_id.slice(0, 8)})
              </option>
            ))}
          </select>
        </CardContent>
      </Card>

      {scan && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Section Config */}
          <Card>
            <CardHeader>
              <CardTitle>Report Sections</CardTitle>
              <CardDescription>Toggle and arrange sections</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <DndContext collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
                <SortableContext items={sections.map((s) => s.id)} strategy={verticalListSortingStrategy}>
                  {sections.map((section) => (
                    <SortableSection key={section.id} section={section} onToggle={toggleSection} />
                  ))}
                </SortableContext>
              </DndContext>
              <Button className="w-full mt-4" onClick={generateReport}>
                Generate Preview
              </Button>
            </CardContent>
          </Card>

          {/* Preview */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Preview</CardTitle>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => downloadReport("md")} disabled={!reportText}>
                  <Download className="h-3 w-3 mr-1" />
                  .md
                </Button>
                <Button variant="outline" size="sm" onClick={() => downloadReport("json")} disabled={!scan}>
                  <Download className="h-3 w-3 mr-1" />
                  .json
                </Button>
                <Button size="sm" variant="outline" onClick={downloadPdf} disabled={!reportText}>
                  <Download className="h-3 w-3 mr-1" /> PDF
                </Button>
                <Button size="sm" variant="outline" onClick={downloadHtml} disabled={!reportText}>
                  <Download className="h-3 w-3 mr-1" /> HTML
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {reportText ? (
                <div id="report-preview" className="terminal-output text-xs max-h-96 overflow-y-auto">
                  {reportText}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  Click &quot;Generate Preview&quot; to see the report
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Empty State */}
      {!selectedScanId && (
        <div className="text-center py-12">
          <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-muted-foreground font-mono">Select a scan to build a report</p>
        </div>
      )}
    </div>
  );
}