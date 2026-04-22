"""
Replay API endpoint.

POST /api/findings/{finding_id}/replay — Replay a finding's scan module
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException
from loguru import logger

from .. import db
from ..models import ReplayRequest, ReplayResponse
from ..scan_manager import scan_manager

router = APIRouter(prefix="/findings", tags=["replay"])


@router.post("/{finding_id}/replay", response_model=ReplayResponse)
async def replay_finding(finding_id: str, request: ReplayRequest) -> ReplayResponse:
    """Replay a finding by starting a new scan with just the finding's category module."""
    # Look up the finding
    finding = await db.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Look up the associated scan to get the target URL
    scan_id = finding.get("scan_id")
    if not scan_id:
        raise HTTPException(
            status_code=400,
            detail="Finding has no associated scan",
        )

    scan = await db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Associated scan not found",
        )

    target = scan.get("target")
    if not target:
        raise HTTPException(
            status_code=400,
            detail="Associated scan has no target URL",
        )

    # The finding's category maps to the module to replay
    category = finding.get("category")
    if not category:
        raise HTTPException(
            status_code=400,
            detail="Finding has no category to replay",
        )

    # Start a new scan with just the finding's category module
    new_scan_id = await scan_manager.start_scan(
        target=target,
        modules=[category],
    )

    replay_id = str(uuid.uuid4())

    logger.info(
        f"Replay {replay_id}: finding={finding_id}, "
        f"category={category}, new_scan={new_scan_id}, target={target}"
    )

    return ReplayResponse(
        replay_id=replay_id,
        scan_id=new_scan_id,
        status="pending",
        message=f"Replaying finding '{finding_id}' with module '{category}' against {target}",
    )