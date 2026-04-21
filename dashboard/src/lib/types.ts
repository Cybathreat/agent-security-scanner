/**
 * TypeScript interfaces matching the FastAPI backend Pydantic models.
 */

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type ModuleStatus = "pending" | "running" | "completed" | "failed";
export type Confidence = "high" | "medium" | "low";

// ---------------------------------------------------------------------------
// API Response Types
// ---------------------------------------------------------------------------

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  risk_score: number;
}

export interface ScanListItem {
  scan_id: string;
  target: string;
  status: ScanStatus;
  started_at: string;
  completed_at: string | null;
  duration_ms: number;
  summary: ScanSummary;
  modules: string[];
  gate_passed: boolean | null;
}

export interface FindingResponse {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  cwe: string | null;
  owasp_ref: string | null;
  mitre_ref: string | null;
  location: string | null;
  evidence: string[];
  recommendation: string;
  confidence: Confidence;
  timestamp: string;
  is_false_positive: boolean;
  notes: string;
  assigned_to: string;
  status: "open" | "confirmed" | "resolved" | "accepted";
}

export interface ModuleStatusInfo {
  module_name: string;
  status: ModuleStatus;
  findings_count: number;
  duration_ms: number;
  errors: string[];
}

export interface ScanDetailResponse {
  scan_id: string;
  target: string;
  status: ScanStatus;
  started_at: string;
  completed_at: string | null;
  duration_ms: number;
  summary: ScanSummary;
  modules: string[];
  findings: FindingResponse[];
  gate_passed: boolean | null;
  gate_reason: string | null;
  gate_exit_code: number | null;
  module_statuses: ModuleStatusInfo[];
}

export interface ModuleInfo {
  name: string;
  display_name: string;
  description: string;
  category: string;
  enabled: boolean;
}

export interface QualityGateRequest {
  scan_id: string;
  fail_on_severity: string;
  max_findings?: number;
  max_risk_score?: number;
}

export interface QualityGateResponse {
  passed: boolean;
  exit_code: number;
  reason: string;
  summary: Record<string, number>;
  risk_score: number;
}

export interface ConfigResponse {
  scanner: Record<string, unknown>;
  quality_gate: Record<string, unknown>;
  modules: Record<string, unknown>;
}

export interface ScanRequest {
  target: string;
  modules?: string[];
  timeout?: number;
  fail_on_severity?: string;
  max_findings?: number;
  max_risk_score?: number;
}

// ---------------------------------------------------------------------------
// Replay & Attack Surface
// ---------------------------------------------------------------------------

export interface ReplayResponse {
  replay_id: string;
  scan_id: string;
  status: ScanStatus;
  message: string;
}

export interface AttackSurfaceNode {
  id: string;
  type: "endpoint" | "tool" | "data_flow" | "agent" | "external";
  label: string;
  findings_count: number;
  max_severity: Severity | null;
  finding_ids: string[];
}

export interface AttackSurfaceEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  finding_count: number;
}

export interface AttackSurfaceResponse {
  scan_id: string;
  nodes: AttackSurfaceNode[];
  edges: AttackSurfaceEdge[];
}

// ---------------------------------------------------------------------------
// WebSocket Event Types
// ---------------------------------------------------------------------------

export type ScanEventType =
  | "connected"
  | "module_started"
  | "module_completed"
  | "finding_discovered"
  | "scan_completed"
  | "scan_error"
  | "heartbeat"
  | "error";

export interface ScanEvent {
  event: ScanEventType;
  scan_id: string;
  data: Record<string, unknown>;
  timestamp: string;
}

// ---------------------------------------------------------------------------
// Health Check
// ---------------------------------------------------------------------------

export interface HealthResponse {
  status: string;
  version: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function severityColor(severity: Severity): string {
  switch (severity) {
    case "CRITICAL": return "var(--severity-critical)";
    case "HIGH": return "var(--severity-high)";
    case "MEDIUM": return "var(--severity-medium)";
    case "LOW": return "var(--severity-low)";
    case "INFO": return "var(--severity-info)";
  }
}

export function severityBgClass(severity: Severity): string {
  switch (severity) {
    case "CRITICAL": return "bg-severity-critical/20 text-severity-critical border-severity-critical/30";
    case "HIGH": return "bg-severity-high/20 text-severity-high border-severity-high/30";
    case "MEDIUM": return "bg-severity-medium/20 text-severity-medium border-severity-medium/30";
    case "LOW": return "bg-severity-low/20 text-severity-low border-severity-low/30";
    case "INFO": return "bg-severity-info/20 text-severity-info border-severity-info/30";
  }
}

export function statusColor(status: ScanStatus): string {
  switch (status) {
    case "completed": return "text-primary";
    case "running": return "text-info";
    case "failed": return "text-destructive";
    case "cancelled": return "text-muted-foreground";
    case "pending": return "text-warning";
  }
}