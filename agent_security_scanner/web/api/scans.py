"""
Scan API endpoints.

POST /api/scans         — Start a new scan
GET  /api/scans         — List scan history
GET  /api/scans/{id}    — Get scan detail
DELETE /api/scans/{id}  — Delete scan
"""

from __future__ import annotations

import json
from typing import Dict, List

from fastapi import APIRouter, HTTPException

from ..models import (
    ModuleStatus,
    ModuleStatusInfo,
    ScanDetailResponse,
    ScanListItem,
    ScanRequest,
    ScanStatus,
    ScanSummary,
)
from .. import db
from ..scan_manager import scan_manager

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=Dict[str, str], status_code=201)
async def start_scan(request: ScanRequest) -> Dict[str, str]:
    """Start a new security scan."""
    scan_id = await scan_manager.start_scan(
        target=request.target,
        modules=request.modules,
        timeout=request.timeout,
        fail_on_severity=request.fail_on_severity,
        max_findings=request.max_findings,
        max_risk_score=request.max_risk_score,
    )
    return {"scan_id": scan_id}


@router.get("", response_model=List[ScanListItem])
async def list_scans(limit: int = 20, offset: int = 0) -> List[ScanListItem]:
    """List scan history."""
    scans = await scan_manager.list_scans(limit=limit, offset=offset)
    result = []
    for scan in scans:
        summary = ScanSummary()
        if scan.get("summary_json"):
            try:
                summary = ScanSummary(**json.loads(scan["summary_json"]))
            except (json.JSONDecodeError, Exception):
                pass

        gate_passed = None
        if scan.get("gate_passed") is not None:
            gate_passed = bool(scan["gate_passed"])

        result.append(
            ScanListItem(
                scan_id=scan["id"],
                target=scan["target"],
                status=ScanStatus(scan.get("status", "pending")),
                started_at=scan["started_at"],
                completed_at=scan.get("completed_at"),
                duration_ms=scan.get("duration_ms", 0),
                summary=summary,
                modules=json.loads(scan.get("modules", "[]")),
                gate_passed=gate_passed,
            )
        )
    return result


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: str) -> ScanDetailResponse:
    """Get full scan detail with all findings."""
    scan = await scan_manager.get_scan_status(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Try to get full result from DB
    result_data = await scan_manager.get_scan_result(scan_id)

    if result_data:
        summary = ScanSummary(**result_data.get("summary", {}))
        findings = []
        for f in result_data.get("findings", []):
            findings.append(
                {
                    "id": f["id"],
                    "severity": f["severity"],
                    "category": f["category"],
                    "title": f["title"],
                    "description": f["description"],
                    "cwe": f.get("cwe"),
                    "owasp_ref": f.get("owasp_ref"),
                    "mitre_ref": f.get("mitre_ref"),
                    "location": f.get("location"),
                    "evidence": f.get("evidence", []),
                    "recommendation": f.get("recommendation", ""),
                    "confidence": f.get("confidence", "high"),
                    "timestamp": f.get("timestamp", ""),
                }
            )

        gate_data = result_data.get("quality_gate", {})
        gate_passed = gate_data.get("passed") if gate_data else None
        gate_reason = gate_data.get("reason") if gate_data else None
        gate_exit_code = gate_data.get("exit_code") if gate_data else None

        return ScanDetailResponse(
            scan_id=scan_id,
            target=scan.get("target", ""),
            status=ScanStatus(scan.get("status", "completed")),
            started_at=scan.get("started_at", ""),
            completed_at=scan.get("completed_at"),
            duration_ms=scan.get("duration_ms", 0),
            summary=summary,
            modules=json.loads(scan.get("modules", "[]")),
            findings=findings,
            gate_passed=gate_passed,
            gate_reason=gate_reason,
            gate_exit_code=gate_exit_code,
        )

    # Active scan (not yet in DB)
    return ScanDetailResponse(
        scan_id=scan_id,
        target=scan.get("target", ""),
        status=ScanStatus(scan.get("status", "running")),
        started_at=scan.get("started_at", ""),
        modules=scan.get("modules", []),
        module_statuses=[
            ModuleStatusInfo(
                module_name=ms.get("module_name", ""),
                status=ModuleStatus(ms.get("status", "pending")),
                findings_count=ms.get("findings_count", 0),
                duration_ms=ms.get("duration_ms", 0),
                errors=ms.get("errors", []),
            )
            for ms in scan.get("module_statuses", [])
            if isinstance(ms, dict)
        ],
    )


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: str) -> None:
    """Delete a scan from history. Cancels if active, then removes from DB."""
    # Cancel if active
    await scan_manager.cancel_scan(scan_id)
    # Always attempt DB deletion
    deleted = await db.delete_scan(scan_id)
    if not deleted and scan_id not in scan_manager._active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")