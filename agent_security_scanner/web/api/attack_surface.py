"""
Attack surface API endpoint.

GET /api/scans/{scan_id}/attack-surface  — Compute attack surface graph from scan findings
"""

from __future__ import annotations

from typing import Optional

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

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _max_severity(current: Optional[str], new: str) -> str:
    if current is None:
        return new
    return new if _SEVERITY_ORDER.get(new, 0) > _SEVERITY_ORDER.get(current, 0) else current


@router.get("/{scan_id}/attack-surface", response_model=AttackSurfaceResponse)
async def get_attack_surface(scan_id: str) -> AttackSurfaceResponse:
    """Compute an attack surface graph from scan findings."""
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = await db.get_findings(scan_id=scan_id, limit=500)

    nodes = {}
    edges = {}

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

        src_type, tgt_type = _CATEGORY_EDGES.get(category, ("endpoint", "external"))

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

        nodes[src_key].findings_count += 1
        nodes[src_key].finding_ids.append(finding_id)
        nodes[src_key].max_severity = _max_severity(nodes[src_key].max_severity, severity)

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