# Dashboard Completion Design

## Overview

Complete the Singularity web dashboard (ROADMAP #28, Phase 3/4). Strategy: fix all existing bugs first, complete all partial features, then add the missing Attack Surface Map. Approach: parallel frontend + backend work after bug fixes are in place.

---

## Section 1: Backend Bug Fixes

Fix all 10 identified bugs plus one missing implementation:

1. **Scan cancellation is non-functional** — `ScanManager._run_scan()` never checks the cancelled flag. Fix: check `self._active_scans[scan_id]["status"]` between module executions; abort early if cancelled.
2. **DELETE endpoint conflates cancel and delete** — `DELETE /api/scans/{id}` cancels active scans but returns 204 without deleting from DB. Fix: cancel if active, then always delete from DB.
3. **Active scan response missing module_statuses and modules** — `GET /api/scans/{id}` fallback for running scans omits `module_statuses` and `modules` from the in-memory dict. Fix: populate both fields from `_active_scans[scan_id]`.
4. **`datetime.utcnow()` deprecated** — 6 occurrences across `scan_manager.py`, `ws/scan_progress.py`, `models.py`. Fix: replace with `datetime.now(timezone.utc)`.
5. **SQL f-string in `update_scan_status`** — `db.py:170` uses f-string for column names. Fix: use parameterized column allowlist pattern.
6. **Quality gate wraps single aggregate ScanResult** — `quality_gate.py` creates one synthetic `ScanResult(module_name="aggregate")` instead of per-module results. Fix: reconstruct per-module ScanResult objects from stored JSON.
7. **Missing timestamp on reconstructed Findings** — `quality_gate.py` discards the `timestamp` field from stored finding JSON when reconstructing Finding objects. Fix: pass `timestamp` through to Finding constructor.
8. **WebSocket no catch-up** — clients connecting mid-scan miss earlier events. Fix: on connect, query DB for existing scan events/modules and replay them before subscribing to the live queue.
9. **CORS hardcoded to localhost:3000** — `app.py` only allows `http://localhost:3000` and `http://127.0.0.1:3000`. Fix: read allowed origins from `SINGULARITY_CORS_ORIGINS` env var (comma-separated), fallback to localhost defaults.
10. **DB path is relative** — `db.py` uses `Path("data")` which is CWD-dependent. Fix: resolve to absolute path using package directory or `SINGULARITY_DATA_DIR` env var.
11. **PATCH /api/config is a no-op** — endpoint accepts Dict but ignores input entirely. Fix: implement full config update — apply changes to running config and persist to YAML file.

---

## Section 2: Frontend Fixes + Partial Page Completion

### Build fix
Run `npm install` in `dashboard/` to resolve missing Tailwind Linux native binary.

### Settings page
- Fix config save mutation to include `fail_on_severity`
- Add module toggle switches that update config via PATCH /api/config
- Wire CI/CD panel to set quality gates via API

### Replay Console
- New endpoint: `POST /api/findings/{id}/replay` — request body: `{"params": Dict[str, Any]}` to override payload parameters from the original finding. If `params` is empty, replays with original values. Re-sends to target, streams results via the existing WebSocket progress channel.
- Frontend: show original payload with editable parameter fields, send replay request, stream results via WebSocket, display response comparison (original vs replay)

### Report Builder
- Integrate `@dnd-kit/core` + `@dnd-kit/sortable` for drag-and-drop section reordering
- Add PDF export via `html2pdf.js`
- Add HTML export (serialize rendered report to standalone HTML with inline styles)
- Add executive summary auto-generation — computed client-side from scan data (not LLM): total findings by severity, top categories, gate result, risk score trend
- Wire section toggle state to report output in real-time

### Scan Detail page
- Fix missing modules list when scan is active (consumes backend fix #3)

### Finding Explorer
- Add annotation support via `PATCH /api/findings/{id}` — false_positive, notes, assigned_to, status
- Frontend: annotation panel in the finding detail slide-out

### Delete scan UI
- Add delete button to scan list and scan detail pages, wired to `DELETE /api/scans/{id}`

---

## Section 3: Attack Surface Map

### Backend
- New endpoint `GET /api/scans/{id}/attack-surface`
- Computes a graph from scan findings:
  - **Nodes**: target endpoints, agent tools, data flows (RAG sources, APIs), each tagged with finding count and max severity
  - **Edges**: inferred from module category — `prompt_injection` findings create endpoint→tool edges, `rag_security` findings create data_flow→external edges, `tool_boundaries` findings create endpoint→tool edges, `agent` findings create agent→tool/endpoint edges, `infrastructure` findings create endpoint→external edges
  - **Node types**: `endpoint`, `tool`, `data_flow`, `agent` — color-coded by risk level
  - Each node includes `findings: [...]` for drill-down into Finding Explorer

### Frontend
- New route `/attack-surface` with sidebar nav entry
- Graph library: **React Flow** (`@xyflow/react`) — most mature React graph library, handles interactive node/edge rendering, zoom/pan, click events, and custom node components
- Custom node components matching the cyberpunk theme (neon glow on high-severity nodes, severity badges)
- Click node → side panel showing that node's findings (reuse FindingDetail component)
- Click edge → show the attack flow description
- Legend showing node type colors and severity scale
- Works for completed scans (from DB) and active scans (from WebSocket events as modules complete)

---

## Section 4: Data Model Changes and API Summary

### New endpoints
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/scans/{id}/attack-surface` | Graph structure for Attack Surface Map |
| POST | `/api/findings/{id}/replay` | Replay a finding's payload with optional parameter modifications |
| PATCH | `/api/findings/{id}` | Annotate findings (false_positive, notes, assigned_to, status) |

### Modified endpoints
| Method | Path | Change |
|--------|------|--------|
| PATCH | `/api/config` | Actually applies updates and persists to YAML |
| DELETE | `/api/scans/{id}` | Cancel then delete, not either/or |
| GET | `/api/scans/{id}` | Populate module_statuses for active scans |

### New DB fields (findings table)
| Column | Type | Default | Purpose |
|--------|------|---------|---------|
| `is_false_positive` | BOOLEAN | FALSE | Mark finding as false positive |
| `notes` | TEXT | '' | Team annotation notes |
| `assigned_to` | TEXT | '' | Team member assignment |
| `status` | TEXT | 'open' | open / confirmed / resolved / accepted |

### New frontend dependencies
| Package | Purpose |
|---------|---------|
| `@xyflow/react` | Attack Surface Map graph visualization |
| `@dnd-kit/core` | Report Builder drag-and-drop |
| `@dnd-kit/sortable` | Report Builder drag-and-drop sortable |
| `html2pdf.js` | PDF export in Report Builder |

### No new backend dependencies
Everything uses the existing FastAPI + aiosqlite stack.

---

## Execution Order

1. **Backend bug fixes** (all 10 bugs + PATCH config implementation) — block everything else
2. **Frontend build fix** (`npm install`) — unblocks all frontend work
3. **Parallel track A — Frontend partial page completion**: Settings fixes, Replay Console, Report Builder, Finding annotations UI, Delete scan UI, Scan Detail fix
4. **Parallel track B — New backend endpoints**: PATCH findings, POST replay, GET attack-surface
5. **Attack Surface Map frontend** — depends on both tracks (needs backend endpoint + working build)
6. **Integration testing** — end-to-end across all views