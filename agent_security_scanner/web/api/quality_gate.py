"""
Quality gate API endpoints.

POST /api/quality-gate/evaluate — Evaluate quality gate against scan results
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException

from ...core.quality_gate import GateThreshold, evaluate as evaluate_gate
from ...modules.base import Finding, Severity
from .. import db
from ..models import QualityGateRequest, QualityGateResponse, ScanSummary

router = APIRouter(prefix="/quality-gate", tags=["quality-gate"])


@router.post("/evaluate", response_model=QualityGateResponse)
async def evaluate_quality_gate(request: QualityGateRequest) -> QualityGateResponse:
    """Evaluate quality gate against a completed scan's results."""
    scan = await db.get_scan(request.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    result_json = scan.get("result_json")
    if not result_json:
        raise HTTPException(status_code=400, detail="Scan has no results yet")

    try:
        result_data = json.loads(result_json)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Corrupted scan results")

    # Build threshold
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    # Reconstruct findings from JSON, grouped by module/category
    findings_by_module: Dict[str, List[Finding]] = {}
    for f in result_data.get("findings", []):
        finding_obj = Finding(
            id=f.get("id", ""),
            severity=severity_map.get(f.get("severity", "low"), Severity.LOW),
            category=f.get("category", "unknown"),
            title=f.get("title", ""),
            description=f.get("description", ""),
            cwe=f.get("cwe"),
            owasp_ref=f.get("owasp_ref"),
            mitre_ref=f.get("mitre_ref"),
            location=f.get("location"),
            evidence=f.get("evidence", []),
            recommendation=f.get("recommendation", ""),
            confidence=f.get("confidence", "high"),
            timestamp=f.get("timestamp", ""),
        )
        module_name = f.get("category", "unknown")
        if module_name not in findings_by_module:
            findings_by_module[module_name] = []
        findings_by_module[module_name].append(finding_obj)

    threshold = GateThreshold(
        fail_on_severity=severity_map.get(
            request.fail_on_severity.lower(), Severity.CRITICAL
        ),
        max_findings=request.max_findings,
        max_risk_score=request.max_risk_score,
    )

    # Create per-module ScanResult objects for evaluate()
    from ...modules.base import ScanResult as ScanResultClass

    scan_results = [
        ScanResultClass(
            module_name=name,
            target=scan.get("target", ""),
            findings=module_findings,
        )
        for name, module_findings in findings_by_module.items()
    ]

    if not scan_results:
        scan_results = [ScanResultClass(module_name="aggregate", target=scan.get("target", ""), findings=[], errors=[])]

    for sr in scan_results:
        sr.status = "success"

    gate_result = evaluate_gate(scan_results, threshold)

    return QualityGateResponse(
        passed=gate_result.passed,
        exit_code=gate_result.exit_code,
        reason=gate_result.reason,
        summary=ScanSummary(**gate_result.summary),
        risk_score=gate_result.risk_score,
    )