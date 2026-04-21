"""
Pydantic models for the web dashboard API.

Type-safe request/response schemas mirroring the scanner's dataclasses.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ModuleStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# Finding models
# ---------------------------------------------------------------------------


class FindingResponse(BaseModel):
    """Single security finding."""

    id: str
    severity: Severity
    category: str
    title: str
    description: str
    cwe: Optional[str] = None
    owasp_ref: Optional[str] = None
    mitre_ref: Optional[str] = None
    location: Optional[str] = None
    evidence: List[str] = Field(default_factory=list)
    recommendation: str = "Review and remediate according to security best practices."
    confidence: Confidence = Confidence.HIGH
    timestamp: str


# ---------------------------------------------------------------------------
# Scan models
# ---------------------------------------------------------------------------


class ModuleStatusInfo(BaseModel):
    """Status of a single module within a scan."""

    module_name: str
    status: ModuleStatus = ModuleStatus.PENDING
    findings_count: int = 0
    duration_ms: int = 0
    errors: List[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    """Request to start a new scan."""

    target: str
    modules: Optional[List[str]] = None  # None = all modules
    timeout: int = 30
    fail_on_severity: str = "critical"
    max_findings: Optional[int] = None
    max_risk_score: Optional[int] = None


class ScanSummary(BaseModel):
    """Severity counts for a scan."""

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    risk_score: int = 0


class ScanListItem(BaseModel):
    """Scan item in the list view."""

    scan_id: str
    target: str
    status: ScanStatus
    started_at: str
    completed_at: Optional[str] = None
    duration_ms: int = 0
    summary: ScanSummary = Field(default_factory=ScanSummary)
    modules: List[str] = Field(default_factory=list)
    gate_passed: Optional[bool] = None


class ScanDetailResponse(BaseModel):
    """Full scan detail with all findings."""

    scan_id: str
    target: str
    status: ScanStatus
    started_at: str
    completed_at: Optional[str] = None
    duration_ms: int = 0
    summary: ScanSummary = Field(default_factory=ScanSummary)
    modules: List[str] = Field(default_factory=list)
    module_statuses: List[ModuleStatusInfo] = Field(default_factory=list)
    findings: List[FindingResponse] = Field(default_factory=list)
    gate_passed: Optional[bool] = None
    gate_reason: Optional[str] = None
    gate_exit_code: Optional[int] = None


# ---------------------------------------------------------------------------
# Quality gate models
# ---------------------------------------------------------------------------


class QualityGateRequest(BaseModel):
    """Request to evaluate quality gate."""

    scan_id: str
    fail_on_severity: str = "critical"
    max_findings: Optional[int] = None
    max_risk_score: Optional[int] = None


class QualityGateResponse(BaseModel):
    """Quality gate evaluation result."""

    passed: bool
    exit_code: int
    reason: str
    summary: ScanSummary = Field(default_factory=ScanSummary)
    risk_score: int = 0


# ---------------------------------------------------------------------------
# Module info models
# ---------------------------------------------------------------------------


class ModuleInfo(BaseModel):
    """Information about a scanner module."""

    name: str
    display_name: str
    category: str
    description: str
    supported_targets: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Config models
# ---------------------------------------------------------------------------


class ConfigResponse(BaseModel):
    """Current scanner configuration."""

    scanner: Dict[str, Any] = Field(default_factory=dict)
    quality_gate: Dict[str, Any] = Field(default_factory=dict)
    modules: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# WebSocket event models
# ---------------------------------------------------------------------------


class ScanEvent(BaseModel):
    """WebSocket event for scan progress."""

    event: str  # module_started, module_completed, finding_discovered, scan_completed, scan_error
    scan_id: str
    data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")