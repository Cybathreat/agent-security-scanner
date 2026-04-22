# Dashboard Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all backend bugs, complete all partial frontend features, and add the missing Attack Surface Map to deliver the ROADMAP #28 web dashboard.

**Architecture:** Fix backend bugs first (they block everything), then parallelize frontend completion and new backend endpoints, then build the Attack Surface Map frontend. All backend changes use existing FastAPI + aiosqlite stack. Frontend uses Next.js + Tailwind + React Query + React Flow.

**Tech Stack:** Python 3.10+ / FastAPI / aiosqlite / Next.js 16 / React 19 / Tailwind CSS 4 / React Query 5 / React Flow / dnd-kit / html2pdf.js

---

## File Structure

### Backend files modified
- `singularity/web/app.py` — CORS config from env var
- `singularity/web/db.py` — absolute DB path, SQL allowlist, new annotation columns
- `singularity/web/scan_manager.py` — cancel check, datetime fix
- `singularity/web/models.py` — new annotation fields, new replay/attack-surface models, datetime fix
- `singularity/web/api/scans.py` — fix delete logic, fix active scan response
- `singularity/web/api/findings.py` — add PATCH endpoint, add POST replay endpoint
- `singularity/web/api/config.py` — implement PATCH persistence
- `singularity/web/api/quality_gate.py` — fix ScanResult reconstruction, fix timestamp
- `singularity/web/ws/scan_progress.py` — catch-up replay, datetime fix
- `singularity/web/api/attack_surface.py` — new file: attack surface graph endpoint
- `singularity/web/api/__init__.py` — register new routers

### Frontend files modified
- `dashboard/package.json` — add @xyflow/react, @dnd-kit/core, @dnd-kit/sortable, html2pdf.js
- `dashboard/src/lib/types.ts` — add annotation, replay, attack-surface types
- `dashboard/src/lib/api.ts` — add PATCH finding, POST replay, GET attack-surface, DELETE scan
- `dashboard/src/app/settings/page.tsx` — fix config save, add module toggles, wire CI/CD
- `dashboard/src/app/replay/page.tsx` — full replay with parameter editing and WebSocket results
- `dashboard/src/app/reports/page.tsx` — dnd-kit reorder, PDF/HTML export, executive summary
- `dashboard/src/app/scans/page.tsx` — add delete button
- `dashboard/src/app/scans/[id]/page.tsx` — fix missing modules display
- `dashboard/src/app/findings/page.tsx` — add annotation panel in slide-out
- `dashboard/src/components/findings/finding-detail.tsx` — add annotation section
- `dashboard/src/components/layout/sidebar.tsx` — add Attack Surface nav item
- `dashboard/src/app/attack-surface/page.tsx` — new file: Attack Surface Map page

### Test files created
- `tests/unit/test_web_api.py` — update existing tests for new endpoints
- `tests/unit/test_web_bugfixes.py` — new test file for bug fix verification

---

## Task 1: Fix backend — datetime.utcnow() and DB path

**Files:**
- Modify: `singularity/web/scan_manager.py:14`
- Modify: `singularity/web/ws/scan_progress.py:12`
- Modify: `singularity/web/models.py:9`
- Modify: `singularity/web/db.py:11,18-19`
- Test: `tests/unit/test_web_bugfixes.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_web_bugfixes.py
import os
from pathlib import Path
from unittest.mock import patch

import pytest


def test_db_path_is_absolute():
    """DB path should resolve to an absolute path, not relative."""
    from singularity.web.db import DB_PATH

    assert DB_PATH.is_absolute(), f"DB_PATH is relative: {DB_PATH}"


def test_db_path_uses_env_var():
    """DB_PATH should use SINGULARITY_DATA_DIR env var when set."""
    with patch.dict(os.environ, {"SINGULARITY_DATA_DIR": "/tmp/test-data"}):
        # Re-import to pick up env var
        import importlib
        from singularity import web
        importlib.reload(web.db)
        assert web.db.DB_PATH == Path("/tmp/test-data/scan_history.db")


def test_scan_manager_uses_timezone_utc():
    """ScanManager should use datetime.now(timezone.utc) not utcnow()."""
    import inspect
    from singularity.web import scan_manager

    source = inspect.getsource(scan_manager)
    assert "utcnow" not in source, "scan_manager.py still uses deprecated utcnow()"


def test_ws_scan_progress_uses_timezone_utc():
    """WebSocket handler should use datetime.now(timezone.utc) not utcnow()."""
    import inspect
    from singularity.web.ws import scan_progress

    source = inspect.getsource(scan_progress)
    assert "utcnow" not in source, "scan_progress.py still uses deprecated utcnow()"


def test_models_uses_timezone_utc():
    """Models should use datetime.now(timezone.utc) not utcnow()."""
    import inspect
    from singularity.web import models

    source = inspect.getsource(models)
    assert "utcnow" not in source, "models.py still uses deprecated utcnow()"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_web_bugfixes.py -v -k "db_path_is_absolute or utcnow or timezone_utc"`
Expected: FAIL — DB_PATH is relative and utcnow() is still in source.

- [ ] **Step 3: Fix db.py — absolute path and env var**

In `singularity/web/db.py`, replace lines 11-19:

```python
# Replace:
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiosqlite
from loguru import logger

DB_DIR = Path("data")
DB_PATH = DB_DIR / "scan_history.db"

# With:
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiosqlite
from loguru import logger

_SINGULARITY_DATA_DIR = os.environ.get("SINGULARITY_DATA_DIR")
DB_DIR = Path(_SINGULARITY_DATA_DIR) if _SINGULARITY_DATA_DIR else Path(__file__).resolve().parent.parent.parent.parent / "data"
DB_PATH = DB_DIR / "scan_history.db"
```

- [ ] **Step 4: Fix scan_manager.py — replace datetime.utcnow()**

In `singularity/web/scan_manager.py`, replace line 14:

```python
# Replace:
from datetime import datetime

# With:
from datetime import datetime, timezone
```

Then replace all `datetime.utcnow()` calls (lines 52, 166) with `datetime.now(timezone.utc)`.

- [ ] **Step 5: Fix ws/scan_progress.py — replace datetime.utcnow()**

In `singularity/web/ws/scan_progress.py`, replace line 12:

```python
# Replace:
from datetime import datetime

# With:
from datetime import datetime, timezone
```

Then replace all `datetime.utcnow()` calls (lines 41, 54, 68, 87) with `datetime.now(timezone.utc)`.

- [ ] **Step 6: Fix models.py — replace datetime.utcnow()**

In `singularity/web/models.py`, replace line 9:

```python
# Replace:
from datetime import datetime

# With:
from datetime import datetime, timezone
```

Then replace `datetime.utcnow()` in the ScanEvent model (line 206) with `datetime.now(timezone.utc)`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/unit/test_web_bugfixes.py -v`
Expected: All 5 tests PASS.

- [ ] **Step 8: Commit**

```bash
git add singularity/web/db.py singularity/web/scan_manager.py singularity/web/ws/scan_progress.py singularity/web/models.py tests/unit/test_web_bugfixes.py
git commit -m "fix: replace deprecated datetime.utcnow() and resolve DB path to absolute"
```

---

## Task 2: Fix backend — CORS from env var and SQL f-string

**Files:**
- Modify: `singularity/web/app.py:50-59`
- Modify: `singularity/web/db.py:170`
- Test: `tests/unit/test_web_bugfixes.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_web_bugfixes.py`:

```python
def test_cors_uses_env_var():
    """CORS origins should be configurable via SINGULARITY_CORS_ORIGINS env var."""
    import os
    with patch.dict(os.environ, {"SINGULARITY_CORS_ORIGINS": "https://prod.example.com,https://staging.example.com"}):
        from singularity.web.app import create_app
        app = create_app()
        # Find CORSMiddleware in app middleware stack
        for mw in app.user_middleware:
            if hasattr(mw, 'cls') and 'CORS' in str(mw.cls):
                origins = mw.kwargs.get("allow_origins", [])
                assert "https://prod.example.com" in origins
                break
        else:
            # Check the middleware stack differently
            middleware_found = any("CORSMiddleware" in str(type(mw)) for mw in app.middleware_stack.__dict__.get("stack", []))
            assert middleware_found, "CORS middleware not found"


def test_db_update_scan_status_no_fstring_sql():
    """update_scan_status should not use f-string SQL construction."""
    import inspect
    from singularity.web import db

    source = inspect.getsource(db.update_scan_status)
    # Should not have f"UPDATE scans SET {', '.join(sets)}"
    assert 'f"UPDATE' not in source, "db.py still uses f-string SQL in update_scan_status"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_web_bugfixes.py -v -k "cors_uses or fstring_sql"`
Expected: FAIL.

- [ ] **Step 3: Fix app.py — CORS from env var**

In `singularity/web/app.py`, replace lines 50-59:

```python
# Replace:
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# With:
import os

_cors_env = os.environ.get("SINGULARITY_CORS_ORIGINS", "")
if _cors_env:
    _allowed_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
else:
    _allowed_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Move the `import os` to the top-level imports section (after line 7).

- [ ] **Step 4: Fix db.py — SQL allowlist pattern**

In `singularity/web/db.py`, replace the `update_scan_status` function body (lines 129-172):

```python
async def update_scan_status(
    scan_id: str,
    status: str,
    completed_at: Optional[str] = None,
    duration_ms: int = 0,
    result_json: Optional[str] = None,
    summary_json: Optional[str] = None,
    gate_passed: Optional[bool] = None,
    gate_reason: Optional[str] = None,
    gate_exit_code: Optional[int] = None,
    db_path: Optional[Path] = None,
) -> None:
    _ALLOWED_FIELDS = {
        "status", "completed_at", "duration_ms", "result_json",
        "summary_json", "gate_passed", "gate_reason", "gate_exit_code",
    }
    updates: Dict[str, Any] = {"status": status}
    if completed_at is not None:
        updates["completed_at"] = completed_at
    if duration_ms is not None:
        updates["duration_ms"] = duration_ms
    if result_json is not None:
        updates["result_json"] = result_json
    if summary_json is not None:
        updates["summary_json"] = summary_json
    if gate_passed is not None:
        updates["gate_passed"] = gate_passed
    if gate_reason is not None:
        updates["gate_reason"] = gate_reason
    if gate_exit_code is not None:
        updates["gate_exit_code"] = gate_exit_code

    # Validate all field names against allowlist
    for field in updates:
        if field not in _ALLOWED_FIELDS:
            raise ValueError(f"Invalid field name: {field}")

    sets = [f"{k} = ?" for k in updates]
    vals = list(updates.values())
    vals.append(scan_id)

    async with aiosqlite.connect(db_path or DB_PATH) as db:
        await db.execute(
            f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", vals
        )
        await db.commit()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/test_web_bugfixes.py -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add singularity/web/app.py singularity/web/db.py tests/unit/test_web_bugfixes.py
git commit -m "fix: configurable CORS origins and safe SQL construction in update_scan_status"
```

---

## Task 3: Fix backend — scan cancellation and delete logic

**Files:**
- Modify: `singularity/web/scan_manager.py:103-200,298-305`
- Modify: `singularity/web/api/scans.py:137-146`
- Test: `tests/unit/test_web_bugfixes.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_web_bugfixes.py`:

```python
@pytest.mark.asyncio
async def test_cancel_scan_aborts_running_scan():
    """Cancelling a scan should stop the _run_scan thread."""
    from singularity.web.scan_manager import ScanManager

    mgr = ScanManager()
    scan_id = "test-cancel-123"

    # Simulate an active scan
    mgr._active_scans[scan_id] = {
        "status": "running",
        "target": "https://example.com",
        "modules": ["prompt_injection"],
        "started_at": "2026-01-01T00:00:00Z",
    }

    result = await mgr.cancel_scan(scan_id)
    assert result is True
    assert mgr._active_scans[scan_id]["status"] == "cancelled"


@pytest.mark.asyncio
async def test_delete_scan_removes_from_db_even_if_active():
    """DELETE should cancel active scans AND remove from DB."""
    from singularity.web.scan_manager import ScanManager

    mgr = ScanManager()
    scan_id = "test-delete-456"

    mgr._active_scans[scan_id] = {
        "status": "running",
        "target": "https://example.com",
        "modules": [],
        "started_at": "2026-01-01T00:00:00Z",
    }

    # cancel_scan should return True since scan is active
    cancelled = await mgr.cancel_scan(scan_id)
    assert cancelled is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_web_bugfixes.py -v -k "cancel_scan or delete_scan"`
Expected: PASS (cancel_scan already sets status, but _run_scan doesn't check it). The real test is in the _run_scan behavior.

- [ ] **Step 3: Fix scan_manager.py — add cancellation check in _run_scan**

In `singularity/web/scan_manager.py`, inside the `_run_scan` method, add a cancellation check after each module completes. Insert after the existing module completion loop (around line 163):

```python
# Add at the start of _run_scan, after the try block begins:
def _run_scan(self, scan_id, target, modules, timeout, gate_threshold):
    try:
        engine = ScanEngine(config=self._config)
        results = []
        for module_name in modules:
            # Check if scan was cancelled
            if scan_id in self._active_scans and \
               self._active_scans[scan_id].get("status") == "cancelled":
                logger.info(f"Scan {scan_id} cancelled, aborting")
                break

            result = engine.run_module(module_name, target, timeout=timeout)
            results.append(result)
            # ... rest of existing module completion logic
```

Also update `cancel_scan()` to properly signal cancellation:

```python
async def cancel_scan(self, scan_id: str) -> bool:
    if scan_id in self._active_scans:
        self._active_scans[scan_id]["status"] = "cancelled"
        await db.update_scan_status(scan_id, "cancelled")
        await self._publish_event(scan_id, "scan_error", {"reason": "cancelled"})
        return True
    return False
```

- [ ] **Step 4: Fix scans.py — delete logic: cancel then delete**

In `singularity/web/api/scans.py`, replace the `delete_scan` endpoint (lines 137-146):

```python
@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: str) -> None:
    # Cancel if active
    await scan_manager.cancel_scan(scan_id)
    # Always attempt DB deletion
    deleted = await db.delete_scan(scan_id)
    if not deleted and scan_id not in scan_manager._active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/test_web_bugfixes.py -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add singularity/web/scan_manager.py singularity/web/api/scans.py tests/unit/test_web_bugfixes.py
git commit -m "fix: scan cancellation aborts running scan and delete always removes from DB"
```

---

## Task 4: Fix backend — active scan response and module_statuses

**Files:**
- Modify: `singularity/web/api/scans.py:76-134`
- Test: `tests/unit/test_web_bugfixes.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_web_bugfixes.py`:

```python
@pytest.mark.asyncio
async def test_get_active_scan_includes_modules():
    """GET /api/scans/{id} for a running scan should include modules list."""
    from singularity.web.scan_manager import ScanManager

    mgr = ScanManager()
    scan_id = "test-active-789"

    mgr._active_scans[scan_id] = {
        "status": "running",
        "target": "https://example.com",
        "modules": ["prompt_injection", "tool_boundaries"],
        "module_statuses": [
            {"module_name": "prompt_injection", "status": "completed", "findings_count": 3, "duration_ms": 500, "errors": []},
            {"module_name": "tool_boundaries", "status": "running", "findings_count": 0, "duration_ms": 0, "errors": []},
        ],
        "started_at": "2026-01-01T00:00:00Z",
        "findings_count": 3,
    }

    status = await mgr.get_scan_status(scan_id)
    assert status is not None
    assert status.get("modules") == ["prompt_injection", "tool_boundaries"]
    assert len(status.get("module_statuses", [])) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_web_bugfixes.py -v -k "active_scan_includes_modules"`
Expected: FAIL — `get_scan_status` returns the raw dict but the `get_scan` endpoint doesn't use modules/module_statuses from it.

- [ ] **Step 3: Fix scans.py — populate modules and module_statuses for active scans**

In `singularity/web/api/scans.py`, replace the `get_scan` endpoint fallback section (around lines 110-134). The key change is using `scan_status` data to populate the response when the DB result isn't available yet:

```python
@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: str) -> ScanDetailResponse:
    # Try to get completed result from DB
    result = await scan_manager.get_scan_result(scan_id)

    if result:
        # Build response from stored result
        # ... (existing code for completed scans stays the same)
        pass

    # Fallback to active scan status
    scan_status = await scan_manager.get_scan_status(scan_id)
    if not scan_status:
        raise HTTPException(status_code=404, detail="Scan not found")

    modules_list = scan_status.get("modules", [])
    module_statuses_list = scan_status.get("module_statuses", [])
    findings_count = scan_status.get("findings_count", 0)

    return ScanDetailResponse(
        scan_id=scan_id,
        target=scan_status.get("target", ""),
        status=scan_status.get("status", "pending"),
        started_at=scan_status.get("started_at", ""),
        completed_at=scan_status.get("completed_at"),
        duration_ms=scan_status.get("duration_ms", 0),
        summary=ScanSummary() if not scan_status.get("summary") else ScanSummary(**scan_status["summary"]),
        modules=modules_list,
        module_statuses=module_statuses_list,
        findings=[],  # Findings come from DB for completed scans
        gate_passed=scan_status.get("gate_passed"),
        gate_reason=scan_status.get("gate_reason"),
        gate_exit_code=scan_status.get("gate_exit_code"),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_web_bugfixes.py -v -k "active_scan_includes_modules"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add singularity/web/api/scans.py tests/unit/test_web_bugfixes.py
git commit -m "fix: populate modules and module_statuses in active scan API response"
```

---

## Task 5: Fix backend — quality gate reconstruction and WebSocket catch-up

**Files:**
- Modify: `singularity/web/api/quality_gate.py:59-85`
- Modify: `singularity/web/ws/scan_progress.py:22-97`
- Test: `tests/unit/test_web_bugfixes.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_web_bugfixes.py`:

```python
def test_quality_gate_preserves_timestamp():
    """Reconstructed Findings should include the timestamp field."""
    import inspect
    from singularity.web.api import quality_gate

    source = inspect.getsource(quality_gate)
    # The Finding constructor call should include timestamp
    assert "timestamp" in source, "quality_gate.py doesn't pass timestamp to Finding"


def test_ws_handler_has_catchup():
    """WebSocket handler should replay past events on connect."""
    import inspect
    from singularity.web.ws import scan_progress

    source = inspect.getsource(scan_progress)
    # Should reference catching up on past events
    assert "catchup" in source.lower() or "replay" in source.lower() or "past_events" in source.lower(), \
        "WebSocket handler doesn't implement event catch-up"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_web_bugfixes.py -v -k "timestamp or catchup"`
Expected: FAIL.

- [ ] **Step 3: Fix quality_gate.py — per-module ScanResult with timestamp**

In `singularity/web/api/quality_gate.py`, replace the finding reconstruction (around lines 59-85):

```python
# Group findings by module_name
from ...modules.base import ScanResult as ScanResultClass

findings_by_module: Dict[str, List[Finding]] = {}
for f in stored_findings:
    finding_obj = Finding(
        finding_id=f.get("id", ""),
        severity=severity_map.get(f.get("severity", "low"), Severity.LOW),
        category=f.get("category", "unknown"),
        title=f.get("title", ""),
        description=f.get("description", ""),
        cwe=f.get("cwe"),
        owasp_ref=f.get("owasp_ref"),
        mitre_ref=f.get("mitre_ref"),
        location=f.get("location"),
        evidence=f.get("evidence", ""),
        recommendation=f.get("recommendation", ""),
        confidence=f.get("confidence", "medium"),
        timestamp=f.get("timestamp", ""),
    )
    module_name = f.get("category", "unknown")
    if module_name not in findings_by_module:
        findings_by_module[module_name] = []
    findings_by_module[module_name].append(finding_obj)

scan_results = [
    ScanResultClass(module_name=name, findings=module_findings, errors=[])
    for name, module_findings in findings_by_module.items()
]

if not scan_results:
    scan_results = [ScanResultClass(module_name="aggregate", findings=[], errors=[])]

gate_result = evaluate_gate(scan_results, threshold)
```

- [ ] **Step 4: Fix ws/scan_progress.py — catch-up on connect**

In `singularity/web/ws/scan_progress.py`, add catch-up logic after accepting the WebSocket and before subscribing. Insert after line 32 (subscribe):

```python
@router.websocket("/scans/{scan_id}/progress")
async def scan_progress(websocket: WebSocket, scan_id: str) -> None:
    await websocket.accept()
    queue = scan_manager.subscribe(scan_id)

    try:
        # Catch-up: send existing findings and module completions from DB
        scan_result = await scan_manager.get_scan_result(scan_id)
        scan_status = await scan_manager.get_scan_status(scan_id)

        if scan_result and scan_result.get("result_json"):
            import json as _json
            report = _json.loads(scan_result["result_json"]) if isinstance(scan_result["result_json"], str) else scan_result["result_json"]
            # Replay module completions
            for module_name, module_data in report.get("modules", {}).items():
                await websocket.send_json({
                    "event": "module_completed",
                    "scan_id": scan_id,
                    "data": {
                        "module_name": module_name,
                        "status": module_data.get("status", "completed"),
                        "findings_count": len(module_data.get("findings", [])),
                    },
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            # Replay individual findings
            for finding in report.get("findings", []):
                await websocket.send_json({
                    "event": "finding_discovered",
                    "scan_id": scan_id,
                    "data": finding,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        # Send connected event after catch-up
        await websocket.send_json({
            "event": "connected",
            "scan_id": scan_id,
            "data": {"message": "Subscribed to scan progress"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Main event loop (existing code)
        while True:
            # ... existing queue.get() loop
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/test_web_bugfixes.py -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add singularity/web/api/quality_gate.py singularity/web/ws/scan_progress.py tests/unit/test_web_bugfixes.py
git commit -m "fix: per-module ScanResult in quality gate and WebSocket catch-up on connect"
```

---

## Task 6: Implement PATCH /api/config persistence

**Files:**
- Modify: `singularity/web/api/config.py:33-44`
- Test: `tests/unit/test_web_bugfixes.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_web_bugfixes.py`:

```python
def test_config_patch_persists_changes():
    """PATCH /api/config should apply and persist config updates."""
    import inspect
    from singularity.web.api import config

    source = inspect.getsource(config)
    # Should not have the stub comment about "full implementation"
    assert "full implementation would" not in source.lower(), "config.py PATCH is still a stub"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_web_bugfixes.py -v -k "config_patch"`
Expected: FAIL.

- [ ] **Step 3: Implement PATCH config persistence**

Replace the `update_config` endpoint in `singularity/web/api/config.py`:

```python
import os
from pathlib import Path
import yaml
from ...core.config import Config, load_config


@router.patch("", response_model=ConfigResponse)
async def update_config(updates: Dict[str, Any]) -> ConfigResponse:
    config = load_config()

    # Apply scanner updates
    if "scanner" in updates and isinstance(updates["scanner"], dict):
        for key, value in updates["scanner"].items():
            if hasattr(config.scanner, key):
                setattr(config.scanner, key, value)

    # Apply quality_gate updates
    if "quality_gate" in updates and isinstance(updates["quality_gate"], dict):
        for key, value in updates["quality_gate"].items():
            if hasattr(config.quality_gate, key):
                setattr(config.quality_gate, key, value)

    # Apply module-specific updates
    if "modules" in updates and isinstance(updates["modules"], dict):
        for mod_name, mod_updates in updates["modules"].items():
            if hasattr(config.modules, mod_name) and isinstance(mod_updates, dict):
                mod_config = getattr(config.modules, mod_name)
                for key, value in mod_updates.items():
                    if hasattr(mod_config, key):
                        setattr(mod_config, key, value)

    # Persist to YAML
    config_path = os.environ.get("SINGULARITY_CONFIG_PATH", "config/config.yaml")
    config_path_resolved = Path(config_path)
    config_path_resolved.parent.mkdir(parents=True, exist_ok=True)

    with open(config_path_resolved, "w") as f:
        yaml.dump(config.to_dict(), f, default_flow_style=False)

    return ConfigResponse(
        scanner=config.to_dict().get("scanner", {}),
        quality_gate=config.to_dict().get("quality_gate", {}),
        modules=config.to_dict().get("modules", {}),
    )
```

Add `import yaml` and `import os` to the imports section. Update the `from ...core.config import load_config` to also import `Config`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_web_bugfixes.py -v -k "config_patch"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add singularity/web/api/config.py tests/unit/test_web_bugfixes.py
git commit -m "feat: implement PATCH /api/config with persistence to YAML"
```

---

## Task 7: Add DB annotation columns and PATCH findings endpoint

**Files:**
- Modify: `singularity/web/db.py` — SCHEMA and new functions
- Modify: `singularity/web/models.py` — new models
- Modify: `singularity/web/api/findings.py` — PATCH endpoint
- Test: `tests/unit/test_web_api.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_web_api.py` (or create if not existing):

```python
@pytest.mark.asyncio
async def test_patch_finding_annotation():
    """PATCH /api/findings/{id} should update annotation fields."""
    from singularity.web.db import init_db, save_scan, save_findings, update_finding_annotation, get_finding

    await init_db()
    scan_id = "test-annotation-scan"
    await save_scan(scan_id, "https://example.com", [], "completed")
    await save_findings(scan_id, [
        {"id": "find-001", "severity": "HIGH", "category": "prompt_injection",
         "title": "Test Finding", "description": "desc", "evidence": "ev",
         "recommendation": "rec", "confidence": "high", "timestamp": "2026-01-01T00:00:00Z"}
    ])

    await update_finding_annotation("find-001", is_false_positive=True, notes="Not a real issue", assigned_to="alice", status="resolved")
    finding = await get_finding("find-001")
    assert finding["is_false_positive"] is True
    assert finding["notes"] == "Not a real issue"
    assert finding["assigned_to"] == "alice"
    assert finding["status"] == "resolved"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_web_api.py -v -k "patch_finding_annotation"`
Expected: FAIL — `update_finding_annotation` doesn't exist yet.

- [ ] **Step 3: Add annotation columns to DB schema**

In `singularity/web/db.py`, add to the SCHEMA `findings` table definition:

```sql
-- Add these columns to the findings CREATE TABLE:
is_false_positive BOOLEAN DEFAULT FALSE,
notes TEXT DEFAULT '',
assigned_to TEXT DEFAULT '',
status TEXT DEFAULT 'open'
```

Add a migration function:

```python
async def _migrate_annotations(db_path: Optional[Path] = None) -> None:
    """Add annotation columns to findings table if they don't exist."""
    path = db_path or DB_PATH
    async with aiosqlite.connect(path) as db:
        cursor = await db.execute("PRAGMA table_info(findings)")
        columns = {row[1] for row in await cursor.fetchall()}
        if "is_false_positive" not in columns:
            await db.execute("ALTER TABLE findings ADD COLUMN is_false_positive BOOLEAN DEFAULT FALSE")
        if "notes" not in columns:
            await db.execute("ALTER TABLE findings ADD COLUMN notes TEXT DEFAULT ''")
        if "assigned_to" not in columns:
            await db.execute("ALTER TABLE findings ADD COLUMN assigned_to TEXT DEFAULT ''")
        if "status" not in columns:
            await db.execute("ALTER TABLE findings ADD COLUMN status TEXT DEFAULT 'open'")
        await db.commit()
```

Call `_migrate_annotations()` from `init_db()` after creating tables.

Add the `update_finding_annotation` function:

```python
async def update_finding_annotation(
    finding_id: str,
    is_false_positive: Optional[bool] = None,
    notes: Optional[str] = None,
    assigned_to: Optional[str] = None,
    status: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> bool:
    _ALLOWED_STATUSES = {"open", "confirmed", "resolved", "accepted"}
    if status is not None and status not in _ALLOWED_STATUSES:
        raise ValueError(f"Invalid status: {status}. Must be one of {_ALLOWED_STATUSES}")

    updates: Dict[str, Any] = {}
    if is_false_positive is not None:
        updates["is_false_positive"] = is_false_positive
    if notes is not None:
        updates["notes"] = notes
    if assigned_to is not None:
        updates["assigned_to"] = assigned_to
    if status is not None:
        updates["status"] = status

    if not updates:
        return False

    sets = ", ".join(f"{k} = ?" for k in updates)
    vals = list(updates.values()) + [finding_id]

    async with aiosqlite.connect(db_path or DB_PATH) as db:
        cursor = await db.execute(f"UPDATE findings SET {sets} WHERE id = ?", vals)
        await db.commit()
        return cursor.rowcount > 0
```

Also update `get_finding` to include the new columns in SELECT.

- [ ] **Step 4: Add FindingAnnotationRequest model and PATCH endpoint**

In `singularity/web/models.py`, add:

```python
class FindingAnnotationRequest(BaseModel):
    is_false_positive: Optional[bool] = None
    notes: Optional[str] = None
    assigned_to: Optional[str] = None
    status: Optional[str] = None
```

Update `FindingResponse` to include the new fields:

```python
class FindingResponse(BaseModel):
    # ... existing fields ...
    is_false_positive: bool = False
    notes: str = ""
    assigned_to: str = ""
    status: str = "open"
```

In `singularity/web/api/findings.py`, add:

```python
from ..models import FindingAnnotationRequest
from .. import db

@router.patch("/{finding_id}", response_model=FindingResponse)
async def annotate_finding(finding_id: str, request: FindingAnnotationRequest) -> FindingResponse:
    updated = await db.update_finding_annotation(
        finding_id,
        is_false_positive=request.is_false_positive,
        notes=request.notes,
        assigned_to=request.assigned_to,
        status=request.status,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding = await db.get_finding(finding_id)
    return FindingResponse(**finding)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/unit/test_web_api.py -v -k "patch_finding_annotation"`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add singularity/web/db.py singularity/web/models.py singularity/web/api/findings.py tests/unit/test_web_api.py
git commit -m "feat: add finding annotations (false_positive, notes, assigned_to, status)"
```

---

## Task 8: Add POST /api/findings/{id}/replay endpoint

**Files:**
- Create: `singularity/web/api/replay.py`
- Modify: `singularity/web/api/__init__.py`
- Modify: `singularity/web/models.py`
- Modify: `singularity/web/app.py`
- Test: `tests/unit/test_web_api.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_web_api.py`:

```python
@pytest.mark.asyncio
async def test_replay_endpoint_exists():
    """POST /api/findings/{id}/replay should be a registered route."""
    from singularity.web.app import create_app

    app = create_app()
    routes = [r.path for r in app.routes]
    assert any("replay" in str(r) for r in routes), "Replay route not registered"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_web_api.py -v -k "replay_endpoint"`
Expected: FAIL.

- [ ] **Step 3: Add replay models**

In `singularity/web/models.py`, add:

```python
class ReplayRequest(BaseModel):
    params: Dict[str, Any] = Field(default_factory=dict)

class ReplayResponse(BaseModel):
    replay_id: str
    scan_id: str
    status: ScanStatus
    message: str
```

- [ ] **Step 4: Create replay.py endpoint**

Create `singularity/web/api/replay.py`:

```python
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .. import db
from ..models import ReplayRequest, ReplayResponse
from ..scan_manager import scan_manager

router = APIRouter(prefix="/findings", tags=["replay"])


@router.post("/{finding_id}/replay", response_model=ReplayResponse)
async def replay_finding(finding_id: str, request: ReplayRequest) -> ReplayResponse:
    finding = await db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get the scan to find the target
    scan = await db.get_scan(finding.get("scan_id", ""))
    if not scan:
        raise HTTPException(status_code=404, detail="Associated scan not found")

    target = scan.get("target", "")
    category = finding.get("category", "")

    # Start a new scan with the same target and just the finding's category module
    scan_id = await scan_manager.start_scan(
        target=target,
        modules=[category],
        timeout=30,
    )

    return ReplayResponse(
        replay_id=finding_id,
        scan_id=scan_id,
        status="pending",
        message=f"Replay scan started for finding {finding_id} against {target}",
    )
```

- [ ] **Step 5: Register the router**

In `singularity/web/api/__init__.py`, add `from . import replay` and include it in the router list.

In `singularity/web/app.py`, add `from .api import replay` and `app.include_router(replay.router, prefix="/api")`.

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/unit/test_web_api.py -v -k "replay_endpoint"`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add singularity/web/api/replay.py singularity/web/api/__init__.py singularity/web/models.py singularity/web/app.py tests/unit/test_web_api.py
git commit -m "feat: add POST /api/findings/{id}/replay endpoint"
```

---

## Task 9: Add GET /api/scans/{id}/attack-surface endpoint

**Files:**
- Create: `singularity/web/api/attack_surface.py`
- Modify: `singularity/web/models.py`
- Modify: `singularity/web/app.py`
- Test: `tests/unit/test_web_api.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_web_api.py`:

```python
@pytest.mark.asyncio
async def test_attack_surface_endpoint():
    """GET /api/scans/{id}/attack-surface should return graph structure."""
    from singularity.web.app import create_app

    app = create_app()
    routes = [r.path for r in app.routes]
    assert any("attack-surface" in str(r) for r in routes), "Attack surface route not registered"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_web_api.py -v -k "attack_surface"`
Expected: FAIL.

- [ ] **Step 3: Add attack surface models**

In `singularity/web/models.py`, add:

```python
class AttackSurfaceNode(BaseModel):
    id: str
    type: str  # endpoint, tool, data_flow, agent
    label: str
    findings_count: int = 0
    max_severity: Optional[str] = None
    finding_ids: List[str] = Field(default_factory=list)

class AttackSurfaceEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    finding_count: int = 0

class AttackSurfaceResponse(BaseModel):
    scan_id: str
    nodes: List[AttackSurfaceNode]
    edges: List[AttackSurfaceEdge]
```

- [ ] **Step 4: Create attack_surface.py endpoint**

Create `singularity/web/api/attack_surface.py`:

```python
from __future__ import annotations

from typing import List

from fastapi import APIRouter, HTTPException

from .. import db
from ..models import AttackSurfaceEdge, AttackSurfaceNode, AttackSurfaceResponse

router = APIRouter(prefix="/scans", tags=["attack-surface"])

# Module category -> (source_node_type, target_node_type) edge mapping
_CATEGORY_EDGES = {
    "prompt_injection": ("endpoint", "tool"),
    "tool_boundaries": ("endpoint", "tool"),
    "rag_security": ("data_flow", "external"),
    "tool_hijacking": ("agent", "tool"),
    "recursive_agents": ("agent", "agent"),
    "memory_poisoning": ("agent", "data_flow"),
    "planning_attacks": ("agent", "tool"),
    "secret_scanner": ("endpoint", "external"),
    "dependency_audit": ("endpoint", "external"),
    "plugin_security": ("endpoint", "tool"),
    "misconfigurations": ("endpoint", "external"),
}

_NODE_TYPE_LABELS = {
    "endpoint": "Target Endpoint",
    "tool": "Agent Tool",
    "data_flow": "Data Flow",
    "agent": "Agent",
    "external": "External",
}


@router.get("/{scan_id}/attack-surface", response_model=AttackSurfaceResponse)
async def get_attack_surface(scan_id: str) -> AttackSurfaceResponse:
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = await db.get_findings(scan_id=scan_id, limit=500)

    # Build nodes grouped by type + category
    nodes: dict[str, AttackSurfaceNode] = {}
    edges: dict[str, AttackSurfaceEdge] = {}

    target = scan.get("target", "unknown")

    # Always include the target endpoint node
    nodes["endpoint:target"] = AttackSurfaceNode(
        id="endpoint:target",
        type="endpoint",
        label=target,
        findings_count=0,
        max_severity=None,
        finding_ids=[],
    )

    for finding in findings:
        category = finding.get("category", "unknown")
        finding_id = finding.get("id", "")
        severity = finding.get("severity", "INFO")

        # Determine source and target node types from category
        src_type, tgt_type = _CATEGORY_EDGES.get(category, ("endpoint", "external"))

        # Create source node if not exists
        src_key = f"{src_type}:{category}_src"
        if src_key not in nodes:
            nodes[src_key] = AttackSurfaceNode(
                id=src_key,
                type=src_type,
                label=f"{_NODE_TYPE_LABELS.get(src_type, src_type)} ({category})",
                findings_count=0,
                max_severity=None,
                finding_ids=[],
            )

        # Create target node if not exists
        tgt_key = f"{tgt_type}:{category}_tgt"
        if tgt_key not in nodes:
            nodes[tgt_key] = AttackSurfaceNode(
                id=tgt_key,
                type=tgt_type,
                label=f"{_NODE_TYPE_LABELS.get(tgt_type, tgt_type)} ({category})",
                findings_count=0,
                max_severity=None,
                finding_ids=[],
            )

        # Update node counts
        nodes[src_key].findings_count += 1
        nodes[src_key].finding_ids.append(finding_id)
        nodes[src_key].max_severity = _max_severity(nodes[src_key].max_severity, severity)

        # Create or update edge
        edge_key = f"{src_key}->{tgt_key}"
        if edge_key not in edges:
            edges[edge_key] = AttackSurfaceEdge(
                id=edge_key,
                source=src_key,
                target=tgt_key,
                label=category,
                finding_count=0,
            )
        edges[edge_key].finding_count += 1

    return AttackSurfaceResponse(
        scan_id=scan_id,
        nodes=list(nodes.values()),
        edges=list(edges.values()),
    )


def _max_severity(current: str | None, new: str) -> str:
    """Return the higher of two severity levels."""
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    if current is None:
        return new
    return new if order.get(new, 0) > order.get(current, 0) else current
```

- [ ] **Step 5: Register the router**

In `singularity/web/app.py`, add:
```python
from .api import attack_surface
app.include_router(attack_surface.router, prefix="/api")
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/unit/test_web_api.py -v -k "attack_surface"`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add singularity/web/api/attack_surface.py singularity/web/models.py singularity/web/app.py tests/unit/test_web_api.py
git commit -m "feat: add GET /api/scans/{id}/attack-surface endpoint"
```

---

## Task 10: Frontend build fix and new dependencies

**Files:**
- Modify: `dashboard/package.json`

- [ ] **Step 1: Install missing Linux Tailwind binary**

Run: `cd /home/cybathreat/Projects/singularity/dashboard && npm install`

Expected: installs `@tailwindcss/oxide-linux-x64-gnu` and resolves the build error.

- [ ] **Step 2: Add new frontend dependencies**

Run: `cd /home/cybathreat/Projects/singularity/dashboard && npm install @xyflow/react @dnd-kit/core @dnd-kit/sortable html2pdf.js`

- [ ] **Step 3: Verify build works**

Run: `cd /home/cybathreat/Projects/singularity/dashboard && npm run build`

Expected: Build succeeds with no errors.

- [ ] **Step 4: Commit**

```bash
cd /home/cybathreat/Projects/singularity/dashboard
git add package.json package-lock.json
git commit -m "fix: resolve Tailwind Linux binary and add @xyflow/react, @dnd-kit, html2pdf.js"
```

---

## Task 11: Frontend — update types and API layer

**Files:**
- Modify: `dashboard/src/lib/types.ts`
- Modify: `dashboard/src/lib/api.ts`

- [ ] **Step 1: Add new types to types.ts**

In `dashboard/src/lib/types.ts`, add these interfaces after the existing ones:

```typescript
export interface FindingAnnotation {
  is_false_positive: boolean;
  notes: string;
  assigned_to: string;
  status: "open" | "confirmed" | "resolved" | "accepted";
}

// Update FindingResponse to include annotation fields
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
  evidence: string;
  recommendation: string;
  confidence: Confidence;
  timestamp: string;
  is_false_positive: boolean;
  notes: string;
  assigned_to: string;
  status: "open" | "confirmed" | "resolved" | "accepted";
}

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

// Update ScanDetailResponse to include module_statuses
export interface ScanDetailResponse {
  scan_id: string;
  target: string;
  status: ScanStatus;
  started_at: string;
  completed_at: string | null;
  duration_ms: number;
  summary: ScanSummary;
  modules: string[];
  module_statuses: ModuleStatusInfo[];
  findings: FindingResponse[];
  gate_passed: boolean | null;
  gate_reason: string | null;
  gate_exit_code: number | null;
}

export interface ModuleStatusInfo {
  module_name: string;
  status: ModuleStatus;
  findings_count: number;
  duration_ms: number;
  errors: string[];
}
```

- [ ] **Step 2: Add new API functions to api.ts**

In `dashboard/src/lib/api.ts`, add these functions:

```typescript
export async function annotateFinding(
  findingId: string,
  data: {
    is_false_positive?: boolean;
    notes?: string;
    assigned_to?: string;
    status?: string;
  }
): Promise<FindingResponse> {
  return request<FindingResponse>(`/api/findings/${findingId}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function replayFinding(
  findingId: string,
  params: Record<string, unknown> = {}
): Promise<ReplayResponse> {
  return request<ReplayResponse>(`/api/findings/${findingId}/replay`, {
    method: "POST",
    body: JSON.stringify({ params }),
  });
}

export async function getAttackSurface(
  scanId: string
): Promise<AttackSurfaceResponse> {
  return request<AttackSurfaceResponse>(
    `/api/scans/${scanId}/attack-surface`
  );
}
```

Add the corresponding type imports at the top of api.ts.

- [ ] **Step 3: Verify TypeScript compiles**

Run: `cd /home/cybathreat/Projects/singularity/dashboard && npx tsc --noEmit`

Expected: No type errors.

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/lib/types.ts dashboard/src/lib/api.ts
git commit -m "feat: add annotation, replay, and attack-surface types and API functions"
```

---

## Task 12: Frontend — fix Settings page

**Files:**
- Modify: `dashboard/src/app/settings/page.tsx`

- [ ] **Step 1: Fix config save to include fail_on_severity**

In `dashboard/src/app/settings/page.tsx`, update the `handleSave` function (around line 35):

```typescript
const handleSave = () => {
  const updates: Record<string, unknown> = {
    quality_gate: {
      fail_on_severity: failOn,
      ...(maxFindings ? { max_findings: parseInt(maxFindings) } : {}),
      ...(maxRiskScore ? { max_risk_score: parseInt(maxRiskScore) } : {}),
    },
  };
  updateConfigMutation.mutate(updates);
};
```

- [ ] **Step 2: Initialize state from config data**

Update the useEffect or component initialization to read values from the fetched config:

```typescript
// After useQuery for config:
const configData = configQuery.data;

// Initialize from config when it loads
useEffect(() => {
  if (configData?.quality_gate) {
    setFailOn(configData.quality_gate.fail_on_severity as string || "critical");
    setMaxFindings(
      configData.quality_gate.max_findings?.toString() || ""
    );
    setMaxRiskScore(
      configData.quality_gate.max_risk_score?.toString() || ""
    );
  }
}, [configData]);
```

Add `useEffect` import from React.

- [ ] **Step 3: Add module toggle switches**

Add toggle functionality using PATCH config. Replace the static module badges section with interactive toggles:

```typescript
const handleModuleToggle = (moduleName: string, enabled: boolean) => {
  const updates = {
    modules: {
      [moduleName]: { enabled },
    },
  };
  updateConfigMutation.mutate(updates);
};
```

Render each module with a toggle switch:

```tsx
<div className="flex items-center justify-between">
  <span className="text-sm">{mod.display_name}</span>
  <button
    onClick={() => handleModuleToggle(mod.name, !mod.enabled)}
    className={`px-2 py-1 text-xs rounded ${
      mod.enabled ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"
    }`}
  >
    {mod.enabled ? "ON" : "OFF"}
  </button>
</div>
```

- [ ] **Step 4: Wire CI/CD panel to set quality gates via API**

The CI/CD section already shows copy-paste snippets. Add a "Apply to Config" button that calls the config PATCH:

```tsx
<Button
  onClick={() =>
    updateConfigMutation.mutate({
      quality_gate: {
        fail_on_severity: failOn,
        max_findings: maxFindings ? parseInt(maxFindings) : undefined,
        max_risk_score: maxRiskScore ? parseInt(maxRiskScore) : undefined,
      },
    })
  }
  size="sm"
>
  Apply Gate Settings
</Button>
```

- [ ] **Step 5: Verify TypeScript compiles**

Run: `cd /home/cybathreat/Projects/singularity/dashboard && npx tsc --noEmit`

- [ ] **Step 6: Commit**

```bash
git add dashboard/src/app/settings/page.tsx
git commit -m "fix: Settings page saves fail_on_severity, module toggles, CI/CD gate wiring"
```

---

## Task 13: Frontend — complete Replay Console

**Files:**
- Modify: `dashboard/src/app/replay/page.tsx`

- [ ] **Step 1: Add editable parameter fields and replay with WebSocket**

Replace the Replay page with a full implementation that:

1. Shows the original finding details (existing)
2. Extracts editable parameters from the finding's evidence/evidence JSON
3. Has a "Replay with Modifications" form
4. Calls `replayFinding()` API
5. Connects to WebSocket for the new scan
6. Shows original vs replay response comparison

```tsx
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
import { FindingResponse, ScanStatus } from "@/lib/types";
import { ScanProgressWS } from "@/lib/ws";
import { ScanEvent } from "@/lib/types";
import { Terminal, Play, Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";

export default function ReplayPage() {
  const router = useRouter();
  const { data: scansData } = useScans(50, 0);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<FindingResponse | null>(null);
  const [replayParams, setReplayParams] = useState<Record<string, string>>({});
  const [replayScanId, setReplayScanId] = useState<string | null>(null);
  const [replayEvents, setReplayEvents] = useState<ScanEvent[]>([]);
  const [replayComplete, setReplayComplete] = useState(false);

  const { data: findings } = useQuery({
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
      // Connect WebSocket for the new replay scan
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
    // Extract editable parameters from evidence
    try {
      const evidence = JSON.parse(finding.evidence);
      const params: Record<string, string> = {};
      for (const [key, value] of Object.entries(evidence)) {
        if (typeof value === "string" || typeof value === "number") {
          params[key] = String(value);
        }
      }
      setReplayParams(params);
    } catch {
      setReplayParams({ target: finding.evidence });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Terminal className="h-6 w-6 text-primary" />
        <h1 className="text-2xl font-bold">Replay Console</h1>
      </div>

      {/* Scan selector and finding browser — same as existing */}
      {/* ... (keep existing scan selector and findings list) */}

      {selectedFinding && (
        <Card>
          <CardHeader>
            <CardTitle>Replay: {selectedFinding.title}</CardTitle>
            <CardDescription>Modify parameters and re-test this attack</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Original finding detail */}
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
                      <p className="text-xs mt-1">{selectedFinding.evidence}</p>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle className="text-sm">Replay</CardTitle></CardHeader>
                    <CardContent>
                      <p className="text-xs">
                        {replayScan.findings?.length} finding(s) in replay scan
                      </p>
                      <Button
                        variant="outline"
                        size="sm"
                        className="mt-2"
                        onClick={() => router.push(`/scans/${replayScanId}`)}
                      >
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
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd /home/cybathreat/Projects/singularity/dashboard && npx tsc --noEmit`

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/app/replay/page.tsx
git commit -m "feat: complete Replay Console with editable params and live WebSocket results"
```

---

## Task 14: Frontend — complete Report Builder

**Files:**
- Modify: `dashboard/src/app/reports/page.tsx`

- [ ] **Step 1: Add dnd-kit sortable section reordering**

In `dashboard/src/app/reports/page.tsx`:

Add imports:
```typescript
import { DndContext, closestCenter } from "@dnd-kit/core";
import { SortableContext, verticalListSortingStrategy, useSortable, arrayMove } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import html2pdf from "html2pdf.js";
```

Create a sortable section wrapper:
```typescript
function SortableSection({ section, onToggle }: { section: Section; onToggle: (id: string) => void }) {
  const { attributes, listeners, setNodeRef, transform, transition } = useSortable({ id: section.id });
  const style = { transform: CSS.Transform.toString(transform), transition };

  return (
    <div ref={setNodeRef} style={style} className="flex items-center gap-2 p-2 border border-border rounded">
      <span {...attributes} {...listeners} className="cursor-grab text-muted-foreground">
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
```

Add drag handler in the main component:
```typescript
const handleDragEnd = (event: any) => {
  const { active, over } = event;
  if (active.id !== over?.id) {
    setSections((prev) => {
      const oldIndex = prev.findIndex((s) => s.id === active.id);
      const newIndex = prev.findIndex((s) => s.id === over.id);
      return arrayMove(prev, oldIndex, newIndex);
    });
  }
};
```

Wrap the sections list in DndContext + SortableContext:
```tsx
<DndContext collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
  <SortableContext items={sections.map((s) => s.id)} strategy={verticalListSortingStrategy}>
    {sections.map((section) => (
      <SortableSection key={section.id} section={section} onToggle={toggleSection} />
    ))}
  </SortableContext>
</DndContext>
```

- [ ] **Step 2: Add PDF export**

Add a PDF download handler:
```typescript
const downloadPdf = () => {
  const element = document.getElementById("report-preview");
  if (!element) return;
  html2pdf()
    .set({
      margin: 10,
      filename: `security-report-${selectedScanId}.pdf`,
      html2canvas: { scale: 2 },
      jsPDF: { unit: "mm", format: "a4", orientation: "portrait" },
    })
    .from(element)
    .save();
};
```

Add a "Download PDF" button next to the existing MD/JSON buttons.

- [ ] **Step 3: Add HTML export**

```typescript
const downloadHtml = () => {
  const element = document.getElementById("report-preview");
  if (!element) return;
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Security Report</title><style>body{font-family:system-ui;max-width:800px;margin:0 auto;padding:20px;color:#e0e0e0;background:#0a0a0a;}</style></head><body>${element.innerHTML}</body></html>`;
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `security-report-${selectedScanId}.html`;
  a.click();
  URL.revokeObjectURL(url);
};
```

- [ ] **Step 4: Add executive summary generation**

Add an executive summary section to `generateReport()`:

```typescript
const generateExecutiveSummary = (scan: ScanDetailResponse): string => {
  const findings = scan.findings || [];
  const total = findings.length;
  const critical = findings.filter((f) => f.severity === "CRITICAL").length;
  const high = findings.filter((f) => f.severity === "HIGH").length;
  const categories = [...new Set(findings.map((f) => f.category))];
  const topCategory = categories.length
    ? categories.reduce((a, b) =>
        findings.filter((f) => f.category === a).length >=
        findings.filter((f) => f.category === b).length
          ? a
          : b
      )
    : "N/A";
  const gateStatus = scan.gate_passed ? "PASSED" : "FAILED";

  return `## Executive Summary

**Scan Target:** ${scan.target}
**Status:** ${gateStatus}
**Total Findings:** ${total} (${critical} Critical, ${high} High)
**Risk Score:** ${scan.summary?.risk_score ?? "N/A"}
**Top Category:** ${topCategory}

${total === 0 ? "No security findings were identified during this scan." : `This scan identified ${total} security finding(s), with ${critical} critical and ${high} high severity issues. The most affected category is ${topCategory}. The quality gate ${gateStatus.toLowerCase()}.`}`;
};
```

Prepend the executive summary to the report output when the section is enabled.

- [ ] **Step 5: Verify build**

Run: `cd /home/cybathreat/Projects/singularity/dashboard && npm run build`

- [ ] **Step 6: Commit**

```bash
git add dashboard/src/app/reports/page.tsx
git commit -m "feat: complete Report Builder with dnd-kit, PDF/HTML export, executive summary"
```

---

## Task 15: Frontend — Finding annotations and delete scan UI

**Files:**
- Modify: `dashboard/src/components/findings/finding-detail.tsx`
- Modify: `dashboard/src/app/findings/page.tsx`
- Modify: `dashboard/src/app/scans/page.tsx`
- Modify: `dashboard/src/app/scans/[id]/page.tsx`

- [ ] **Step 1: Add annotation section to FindingDetail component**

In `dashboard/src/components/findings/finding-detail.tsx`, add annotation UI after the recommendation section:

```tsx
import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { annotateFinding } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

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
    <Card>
      {/* ... existing finding detail content ... */}

      {/* Annotation section */}
      <div className="border-t border-border pt-4 space-y-3">
        <h3 className="text-sm font-medium">Annotations</h3>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1 text-sm">
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
            onChange={(e) => setStatus(e.target.value)}
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
    </Card>
  );
}
```

- [ ] **Step 2: Add delete scan button to scan list**

In `dashboard/src/app/scans/page.tsx`, add a delete mutation and button. Add to the imports:

```typescript
import { deleteScan } from "@/lib/api";
import { Trash2 } from "lucide-react";
```

Add mutation:
```typescript
const deleteMutation = useMutation({
  mutationFn: deleteScan,
  onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scans"] }),
});
```

- [ ] **Step 3: Add delete button to scan detail page**

In `dashboard/src/app/scans/[id]/page.tsx`, add:

```typescript
import { deleteScan } from "@/lib/api";
import { Trash2 } from "lucide-react";

// Inside component:
const deleteMutation = useMutation({
  mutationFn: () => deleteScan(id),
  onSuccess: () => router.push("/scans"),
});

// Add button in the header area:
<Button
  variant="destructive"
  size="sm"
  onClick={() => { if (confirm("Delete this scan?")) deleteMutation.mutate(); }}
>
  <Trash2 className="h-4 w-4 mr-1" /> Delete
</Button>
```

- [ ] **Step 4: Verify build**

Run: `cd /home/cybathreat/Projects/singularity/dashboard && npm run build`

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/findings/finding-detail.tsx dashboard/src/app/findings/page.tsx dashboard/src/app/scans/page.tsx dashboard/src/app/scans/\[id\]/page.tsx
git commit -m "feat: finding annotations UI, delete scan button on list and detail"
```

---

## Task 16: Frontend — Attack Surface Map page

**Files:**
- Create: `dashboard/src/app/attack-surface/page.tsx`
- Modify: `dashboard/src/components/layout/sidebar.tsx`
- Create: `dashboard/src/components/attack-surface/attack-node.tsx`

- [ ] **Step 1: Add Attack Surface to sidebar navigation**

In `dashboard/src/components/layout/sidebar.tsx`, update `navItems` to include:

```typescript
import { Network } from "lucide-react";

// Add to navItems array:
{ label: "Attack Surface", href: "/attack-surface", icon: Network },
```

- [ ] **Step 2: Create custom AttackNode component**

Create `dashboard/src/components/attack-surface/attack-node.tsx`:

```tsx
"use client";

import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/findings/severity-badge";
import type { AttackSurfaceNode } from "@/lib/types";
import { cn } from "@/lib/utils";

const NODE_COLORS: Record<string, string> = {
  endpoint: "border-blue-500 bg-blue-950/50",
  tool: "border-green-500 bg-green-950/50",
  data_flow: "border-amber-500 bg-amber-950/50",
  agent: "border-purple-500 bg-purple-950/50",
  external: "border-red-500 bg-red-950/50",
};

const GLOW_CLASSES: Record<string, string> = {
  CRITICAL: "glow-red",
  HIGH: "glow-amber",
  MEDIUM: "glow-blue",
  LOW: "",
  INFO: "",
};

export function AttackNode({ data }: NodeProps) {
  const node = data as unknown as AttackSurfaceNode;
  const colorClass = NODE_COLORS[node.type] || "border-border bg-card";
  const glowClass = node.max_severity ? GLOW_CLASSES[node.max_severity] || "" : "";

  return (
    <div className={cn("rounded-md border-2 p-3 min-w-[120px] text-center", colorClass, glowClass)}>
      <Handle type="target" position={Position.Top} className="!bg-primary" />
      <div className="text-xs text-muted-foreground uppercase">{node.type}</div>
      <div className="text-sm font-medium truncate">{node.label}</div>
      {node.findings_count > 0 && (
        <div className="mt-1 flex items-center justify-center gap-1">
          <Badge variant="destructive" className="text-xs">{node.findings_count}</Badge>
          {node.max_severity && <SeverityBadge severity={node.max_severity} />}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} className="!bg-primary" />
    </div>
  );
}
```

- [ ] **Step 3: Create the Attack Surface Map page**

Create `dashboard/src/app/attack-surface/page.tsx`:

```tsx
"use client";

import { useState, useMemo, useCallback } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  useNodesState,
  useEdgesState,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useScans } from "@/hooks/use-scans";
import { useQuery } from "@tanstack/react-query";
import { getAttackSurface } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { FindingDetail } from "@/components/findings/finding-detail";
import { AttackNode } from "@/components/attack-surface/attack-node";
import { listFindings } from "@/lib/api";
import { Network } from "lucide-react";

const nodeTypes: NodeTypes = { attackNode: AttackNode };

const NODE_POSITIONS: Record<string, { x: number; y: number }> = {
  endpoint: { x: 250, y: 0 },
  agent: { x: 250, y: 150 },
  tool: { x: 0, y: 300 },
  data_flow: { x: 500, y: 300 },
  external: { x: 250, y: 450 },
};

export default function AttackSurfacePage() {
  const { data: scansData } = useScans(50, 0);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const { data: surface, isLoading } = useQuery({
    queryKey: ["attack-surface", selectedScanId],
    queryFn: () => getAttackSurface(selectedScanId),
    enabled: !!selectedScanId,
  });

  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>([]);

  const { data: selectedFindings } = useQuery({
    queryKey: ["findings", { ids: selectedFindingIds }],
    queryFn: async () => {
      const all = await listFindings({ scan_id: selectedScanId, limit: 200 });
      return all.filter((f) => selectedFindingIds.includes(f.id));
    },
    enabled: selectedFindingIds.length > 0,
  });

  const nodes: Node[] = useMemo(() => {
    if (!surface) return [];
    return surface.nodes.map((node, i) => {
      const pos = NODE_POSITIONS[node.type] || { x: (i % 3) * 250, y: Math.floor(i / 3) * 150 };
      return {
        id: node.id,
        type: "attackNode",
        position: pos,
        data: node,
      };
    });
  }, [surface]);

  const edges: Edge[] = useMemo(() => {
    if (!surface) return [];
    return surface.edges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: `${edge.label} (${edge.finding_count})`,
      animated: true,
      style: { stroke: "#22c55e" },
    }));
  }, [surface]);

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNodeId(node.id);
    const surfaceNode = surface?.nodes.find((n) => n.id === node.id);
    if (surfaceNode) {
      setSelectedFindingIds(surfaceNode.finding_ids);
    }
  }, [surface]);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Network className="h-6 w-6 text-primary" />
        <h1 className="text-2xl font-bold">Attack Surface Map</h1>
      </div>

      {/* Scan selector */}
      <div className="flex gap-2">
        <select
          value={selectedScanId}
          onChange={(e) => {
            setSelectedScanId(e.target.value);
            setSelectedNodeId(null);
            setSelectedFindingIds([]);
          }}
          className="bg-muted border border-border rounded px-3 py-2 text-sm flex-1"
        >
          <option value="">Select a scan...</option>
          {scansData?.map((scan) => (
            <option key={scan.scan_id} value={scan.scan_id}>
              {scan.target} — {scan.status}
            </option>
          ))}
        </select>
      </div>

      {/* Legend */}
      <div className="flex gap-4 text-xs text-muted-foreground">
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded border-2 border-blue-500 bg-blue-950/50" /> Endpoint</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded border-2 border-green-500 bg-green-950/50" /> Tool</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded border-2 border-amber-500 bg-amber-950/50" /> Data Flow</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded border-2 border-purple-500 bg-purple-950/50" /> Agent</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded border-2 border-red-500 bg-red-950/50" /> External</span>
      </div>

      {isLoading && <Skeleton className="h-[500px]" />}

      {surface && (
        <div className="grid grid-cols-[1fr_300px] gap-4">
          {/* Graph */}
          <div className="h-[500px] border border-border rounded bg-background">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={nodeTypes}
              onNodeClick={onNodeClick}
              fitView
            >
              <Background />
              <Controls />
              <MiniMap />
            </ReactFlow>
          </div>

          {/* Side panel */}
          <div className="space-y-4">
            {selectedNodeId && selectedFindings && selectedFindings.length > 0 ? (
              <>
                <h3 className="text-sm font-medium">Node Findings</h3>
                {selectedFindings.map((f) => (
                  <FindingDetail key={f.id} finding={f} />
                ))}
              </>
            ) : (
              <p className="text-sm text-muted-foreground">Click a node to view its findings</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Verify build**

Run: `cd /home/cybathreat/Projects/singularity/dashboard && npm run build`

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/app/attack-surface/ dashboard/src/components/attack-surface/ dashboard/src/components/layout/sidebar.tsx
git commit -m "feat: add Attack Surface Map with React Flow interactive graph"
```

---

## Task 17: Frontend — fix Scan Detail missing modules display

**Files:**
- Modify: `dashboard/src/app/scans/[id]/page.tsx`

- [ ] **Step 1: Add module statuses display for active scans**

In `dashboard/src/app/scans/[id]/page.tsx`, add a module status section that shows when the scan is active. The backend fix from Task 4 now returns `module_statuses` — display it:

```tsx
{/* Module Status Section - shown when scan is running/pending */}
{(scan?.status === "running" || scan?.status === "pending") && scan?.module_statuses && scan.module_statuses.length > 0 && (
  <Card>
    <CardHeader>
      <CardTitle className="text-sm">Module Progress</CardTitle>
    </CardHeader>
    <CardContent>
      <div className="space-y-2">
        {scan.module_statuses.map((mod) => (
          <div key={mod.module_name} className="flex items-center justify-between text-sm">
            <span>{mod.module_name}</span>
            <Badge
              variant={mod.status === "completed" ? "success" : mod.status === "failed" ? "destructive" : "info"}
            >
              {mod.status}
            </Badge>
          </div>
        ))}
      </div>
    </CardContent>
  </Card>
)}
```

Add `ModuleStatusInfo` to the types import. This is already in the updated `types.ts` from Task 11.

- [ ] **Step 2: Verify build**

Run: `cd /home/cybathreat/Projects/singularity/dashboard && npm run build`

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/app/scans/\[id\]/page.tsx
git commit -m "fix: show module statuses on active scan detail page"
```

---

## Task 18: Integration testing and final verification

**Files:** None (testing only)

- [ ] **Step 1: Run backend unit tests**

Run: `cd /home/cybathreat/Projects/singularity && pytest tests/unit/ -v`

Expected: All tests pass.

- [ ] **Step 2: Run backend lint and type check**

Run: `cd /home/cybathreat/Projects/singularity && ruff check singularity/ && mypy singularity/`

Expected: Clean.

- [ ] **Step 3: Verify frontend builds**

Run: `cd /home/cybathreat/Projects/singularity/dashboard && npm run build`

Expected: Build succeeds.

- [ ] **Step 4: Manual smoke test — start both servers**

Run backend:
```bash
cd /home/cybathreat/Projects/singularity && python -m singularity.web.app
```

Run frontend:
```bash
cd /home/cybathreat/Projects/singularity/dashboard && npm run dev
```

Verify in browser:
1. Dashboard loads at http://localhost:3000
2. Sidebar shows all 8 nav items including Attack Surface
3. Settings page saves config
4. Findings page shows annotation panel
5. Report Builder has drag-and-drop and PDF export
6. Attack Surface Map renders with React Flow

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "chore: final integration verification for dashboard completion"
```