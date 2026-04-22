/**
 * API client for the Singularity backend.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    ...options,
  });

  if (!res.ok) {
    const detail = await res.json().catch(() => ({ detail: res.statusText }));
    throw new ApiError(res.status, detail.detail || res.statusText);
  }

  // 204 No Content
  if (res.status === 204) return undefined as T;

  return res.json();
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

export async function getHealth() {
  return request<{ status: string; version: string }>("/api/health");
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export async function startScan(body: {
  target: string;
  modules?: string[];
  timeout?: number;
  fail_on_severity?: string;
  max_findings?: number;
  max_risk_score?: number;
}) {
  return request<{ scan_id: string }>("/api/scans", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function listScans(limit = 20, offset = 0) {
  return request<import("./types").ScanListItem[]>(
    `/api/scans?limit=${limit}&offset=${offset}`,
  );
}

export async function getScan(scanId: string) {
  return request<import("./types").ScanDetailResponse>(`/api/scans/${scanId}`);
}

export async function deleteScan(scanId: string) {
  return request<void>(`/api/scans/${scanId}`, { method: "DELETE" });
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export async function listFindings(params: {
  scan_id?: string;
  severity?: string;
  category?: string;
  search?: string;
  limit?: number;
  offset?: number;
} = {}) {
  const qs = new URLSearchParams();
  if (params.scan_id) qs.set("scan_id", params.scan_id);
  if (params.severity) qs.set("severity", params.severity);
  if (params.category) qs.set("category", params.category);
  if (params.search) qs.set("search", params.search);
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.offset) qs.set("offset", String(params.offset));
  const query = qs.toString();
  return request<import("./types").FindingResponse[]>(
    `/api/findings${query ? `?${query}` : ""}`,
  );
}

export async function getFinding(findingId: string) {
  return request<import("./types").FindingResponse>(
    `/api/findings/${findingId}`,
  );
}

export async function annotateFinding(
  findingId: string,
  data: {
    is_false_positive?: boolean;
    notes?: string;
    assigned_to?: string;
    status?: string;
  },
) {
  return request<import("./types").FindingResponse>(
    `/api/findings/${findingId}`,
    {
      method: "PATCH",
      body: JSON.stringify(data),
    },
  );
}

export async function replayFinding(
  findingId: string,
  params: Record<string, unknown> = {},
) {
  return request<import("./types").ReplayResponse>(
    `/api/findings/${findingId}/replay`,
    {
      method: "POST",
      body: JSON.stringify({ params }),
    },
  );
}

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------

export async function listModules() {
  return request<import("./types").ModuleInfo[]>("/api/modules");
}

export async function getModule(name: string) {
  return request<import("./types").ModuleInfo>(`/api/modules/${name}`);
}

// ---------------------------------------------------------------------------
// Quality Gate
// ---------------------------------------------------------------------------

export async function evaluateQualityGate(body: {
  scan_id: string;
  fail_on_severity: string;
  max_findings?: number;
  max_risk_score?: number;
}) {
  return request<import("./types").QualityGateResponse>(
    "/api/quality-gate/evaluate",
    {
      method: "POST",
      body: JSON.stringify(body),
    },
  );
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export async function getConfig() {
  return request<import("./types").ConfigResponse>("/api/config");
}

export async function updateConfig(updates: Record<string, unknown>) {
  return request<import("./types").ConfigResponse>("/api/config", {
    method: "PATCH",
    body: JSON.stringify(updates),
  });
}

// ---------------------------------------------------------------------------
// Attack Surface
// ---------------------------------------------------------------------------

export async function getAttackSurface(scanId: string) {
  return request<import("./types").AttackSurfaceResponse>(
    `/api/scans/${scanId}/attack-surface`,
  );
}

export { ApiError };