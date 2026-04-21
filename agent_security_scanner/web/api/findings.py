"""
Finding API endpoints.

GET    /api/findings          — List findings with filters
GET    /api/findings/{id}     — Get single finding detail
PATCH  /api/findings/{id}     — Annotate a finding
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from .. import db
from ..models import FindingAnnotationRequest, FindingResponse

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=List[FindingResponse])
async def list_findings(
    scan_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[FindingResponse]:
    """List findings with optional filters."""
    rows = await db.get_findings(
        scan_id=scan_id,
        severity=severity,
        category=category,
        search=search,
        limit=limit,
        offset=offset,
    )
    findings = []
    for row in rows:
        evidence = []
        if row.get("evidence"):
            try:
                evidence = json.loads(row["evidence"])
            except (json.JSONDecodeError, TypeError):
                evidence = [str(row["evidence"])]

        findings.append(
            FindingResponse(
                id=row["id"],
                severity=row["severity"],
                category=row["category"],
                title=row["title"],
                description=row["description"],
                cwe=row.get("cwe"),
                owasp_ref=row.get("owasp_ref"),
                mitre_ref=row.get("mitre_ref"),
                location=row.get("location"),
                evidence=evidence,
                recommendation=row.get("recommendation", ""),
                confidence=row.get("confidence", "high"),
                timestamp=row.get("timestamp", ""),
                is_false_positive=bool(row.get("is_false_positive", False)),
                notes=row.get("notes", ""),
                assigned_to=row.get("assigned_to", ""),
                status=row.get("status", "open"),
            )
        )
    return findings


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str) -> FindingResponse:
    """Get a single finding by ID."""
    row = await db.get_finding(finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    evidence = []
    if row.get("evidence"):
        try:
            evidence = json.loads(row["evidence"])
        except (json.JSONDecodeError, TypeError):
            evidence = [str(row["evidence"])]

    return FindingResponse(
        id=row["id"],
        severity=row["severity"],
        category=row["category"],
        title=row["title"],
        description=row["description"],
        cwe=row.get("cwe"),
        owasp_ref=row.get("owasp_ref"),
        mitre_ref=row.get("mitre_ref"),
        location=row.get("location"),
        evidence=evidence,
        recommendation=row.get("recommendation", ""),
        confidence=row.get("confidence", "high"),
        timestamp=row.get("timestamp", ""),
        is_false_positive=bool(row.get("is_false_positive", False)),
        notes=row.get("notes", ""),
        assigned_to=row.get("assigned_to", ""),
        status=row.get("status", "open"),
    )


@router.patch("/{finding_id}", response_model=FindingResponse)
async def annotate_finding(
    finding_id: str, request: FindingAnnotationRequest
) -> FindingResponse:
    """Annotate a finding (mark false positive, add notes, assign, change status)."""
    updated = await db.update_finding_annotation(
        finding_id,
        is_false_positive=request.is_false_positive,
        notes=request.notes,
        assigned_to=request.assigned_to,
        status=request.status,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")

    row = await db.get_finding(finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    evidence = []
    if row.get("evidence"):
        try:
            evidence = json.loads(row["evidence"])
        except (json.JSONDecodeError, TypeError):
            evidence = [str(row["evidence"])]

    return FindingResponse(
        id=row["id"],
        severity=row["severity"],
        category=row["category"],
        title=row["title"],
        description=row["description"],
        cwe=row.get("cwe"),
        owasp_ref=row.get("owasp_ref"),
        mitre_ref=row.get("mitre_ref"),
        location=row.get("location"),
        evidence=evidence,
        recommendation=row.get("recommendation", ""),
        confidence=row.get("confidence", "high"),
        timestamp=row.get("timestamp", ""),
        is_false_positive=bool(row.get("is_false_positive", False)),
        notes=row.get("notes", ""),
        assigned_to=row.get("assigned_to", ""),
        status=row.get("status", "open"),
    )