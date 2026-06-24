# singularity/agent/findings.py
"""
Agent finding data model, in-memory store, and report generators.

Intentionally kept separate from the existing ScanResult / Finding system
in singularity/modules/base.py so the agent layer has no circular imports
into the scanner module tree.  Reports generated here are independent of
JSONReport / MarkdownReport in singularity/output/.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# AgentFinding dataclass
# ---------------------------------------------------------------------------

@dataclass
class AgentFinding:
    """
    A single vulnerability finding discovered by the agent.

    Fields
    ------
    id            : UUID string, auto-generated if not supplied.
    severity      : One of "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO".
    title         : Short title (< 120 chars).
    description   : Full human-readable description.
    category      : OWASP LLM Top 10 category or custom label
                    (e.g. "LLM01:2025 Prompt Injection").
    recommendation: Remediation advice.
    cwe           : Optional CWE identifier string (e.g. "CWE-285").
    owasp_ref     : Optional OWASP ref (e.g. "LLM01:2025").
    evidence      : List of evidence strings (request/response excerpts).
    timestamp     : UTC datetime of discovery (auto-set).
    source_tool   : Name of the tool that produced the evidence (optional).
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: str = "INFO"
    title: str = ""
    description: str = ""
    category: str = ""
    recommendation: str = ""
    cwe: Optional[str] = None
    owasp_ref: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source_tool: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Return a JSON-serialisable dict representation.

        timestamp is serialised as ISO-8601 string via .isoformat().
        All fields are included; None values are kept (not stripped).
        """
        return {
            "id":             self.id,
            "severity":       self.severity,
            "title":          self.title,
            "description":    self.description,
            "category":       self.category,
            "recommendation": self.recommendation,
            "cwe":            self.cwe,
            "owasp_ref":      self.owasp_ref,
            "evidence":       self.evidence,
            "timestamp":      self.timestamp.isoformat(),
            "source_tool":    self.source_tool,
        }


# ---------------------------------------------------------------------------
# FindingsStore
# ---------------------------------------------------------------------------

class FindingsStore:
    """
    Thread-safe* in-memory list of AgentFinding objects.

    (* safe for asyncio single-threaded use; no asyncio.Lock needed because
    the event loop is single-threaded.  If threaded access is ever needed,
    add a threading.Lock.)
    """

    def __init__(self) -> None:
        self._findings: List[AgentFinding] = []

    # -- Mutation ------------------------------------------------------------

    def add(self, finding: AgentFinding) -> None:
        """Add a single AgentFinding to the store."""
        self._findings.append(finding)

    def clear(self) -> None:
        """Remove all findings (called at the start of each run)."""
        self._findings = []

    # -- Query ---------------------------------------------------------------

    def by_severity(self, severity: str) -> List[AgentFinding]:
        """Return findings filtered by exact severity string."""
        return [f for f in self._findings if f.severity == severity]

    def summary(self) -> Dict[str, int]:
        """
        Return a dict with counts per severity level.

        Returns
        -------
        {
            "CRITICAL": int,
            "HIGH":     int,
            "MEDIUM":   int,
            "LOW":      int,
            "INFO":     int,
            "total":    int,
        }
        """
        counts: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH":     0,
            "MEDIUM":   0,
            "LOW":      0,
            "INFO":     0,
            "total":    0,
        }
        for f in self._findings:
            key = f.severity.upper()
            if key in counts:
                counts[key] += 1
            counts["total"] += 1
        return counts

    # -- Properties ----------------------------------------------------------

    @property
    def findings(self) -> List[AgentFinding]:
        """Read-only view — returns a shallow copy."""
        return list(self._findings)

    # -- Dunder --------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._findings)

    def __iter__(self):
        return iter(self._findings)


# ---------------------------------------------------------------------------
# Module-level singleton — imported by tools.py and loop.py
# ---------------------------------------------------------------------------

GLOBAL_STORE: FindingsStore = FindingsStore()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHT: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH":     4,
    "MEDIUM":   3,
    "LOW":      2,
    "INFO":     1,
}

_SEVERITY_ORDER: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _sort_findings(findings: List[AgentFinding]) -> List[AgentFinding]:
    """Return findings sorted by severity weight, highest first."""
    return sorted(
        findings,
        key=lambda f: _SEVERITY_WEIGHT.get(f.severity.upper(), 0),
        reverse=True,
    )


def _build_summary(findings: List[AgentFinding]) -> Dict[str, int]:
    """Build a severity-count summary dict from a list of findings."""
    summary: Dict[str, int] = {
        "CRITICAL": 0,
        "HIGH":     0,
        "MEDIUM":   0,
        "LOW":      0,
        "INFO":     0,
        "total":    len(findings),
    }
    for f in findings:
        key = f.severity.upper()
        if key in summary:
            summary[key] += 1
    return summary


# ---------------------------------------------------------------------------
# Report generators
# ---------------------------------------------------------------------------

def generate_json_report(
    findings: List[AgentFinding],
    target: str,
    model: str,
    scan_start: datetime,
    scan_end: datetime,
) -> str:
    """
    Generate a JSON string report from a list of AgentFinding objects.

    Parameters
    ----------
    findings   : List of AgentFinding instances to include.
    target     : Target URL that was scanned.
    model      : LLM model string used by the agent.
    scan_start : UTC datetime when the scan started.
    scan_end   : UTC datetime when the scan ended.

    Returns
    -------
    str
        Pretty-printed JSON string (indent=2) with structure:
        {
            "schema_version": "1.0",
            "scanner": "Singularity Agent",
            "target": str,
            "model": str,
            "scan_start": str (ISO-8601),
            "scan_end": str (ISO-8601),
            "duration_seconds": float,
            "summary": { ... },
            "findings": [ ... ]   # sorted by severity weight
        }

    Severity sort order (highest first): CRITICAL > HIGH > MEDIUM > LOW > INFO
    """
    duration = (scan_end - scan_start).total_seconds()
    sorted_findings = _sort_findings(findings)
    summary = _build_summary(findings)

    report: Dict[str, Any] = {
        "schema_version": "1.0",
        "scanner": "Singularity Agent",
        "target": target,
        "model": model,
        "scan_start": scan_start.isoformat(),
        "scan_end": scan_end.isoformat(),
        "duration_seconds": duration,
        "summary": summary,
        "findings": [f.to_dict() for f in sorted_findings],
    }

    return json.dumps(report, indent=2, default=str)


def generate_markdown_report(
    findings: List[AgentFinding],
    target: str,
    model: str,
    scan_start: datetime,
    scan_end: datetime,
) -> str:
    """
    Generate a Markdown string report from a list of AgentFinding objects.

    Parameters
    ----------
    findings   : List of AgentFinding instances to include.
    target     : Target URL that was scanned.
    model      : LLM model string used by the agent.
    scan_start : UTC datetime when the scan started.
    scan_end   : UTC datetime when the scan ended.

    Returns
    -------
    str
        Markdown document with the following sections.
    """
    duration = (scan_end - scan_start).total_seconds()
    sorted_findings = _sort_findings(findings)
    summary = _build_summary(findings)

    lines: List[str] = []

    # -- Title ---------------------------------------------------------------
    lines.append("# Singularity Agent Security Report")
    lines.append("")

    # -- Scan Metadata -------------------------------------------------------
    lines.append("## Scan Metadata")
    lines.append(f"- Target: {target}")
    lines.append(f"- Model: {model}")
    lines.append(f"- Start: {scan_start.isoformat()}")
    lines.append(f"- End: {scan_end.isoformat()}")
    lines.append(f"- Duration: {duration} seconds")
    lines.append("")

    # -- Summary table -------------------------------------------------------
    lines.append("## Summary")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in _SEVERITY_ORDER:
        lines.append(f"| {sev} | {summary[sev]} |")
    lines.append(f"| **Total** | {summary['total']} |")
    lines.append("")

    # -- Findings ------------------------------------------------------------
    lines.append("## Findings")
    lines.append("")

    if not sorted_findings:
        lines.append("*No findings recorded.*")
        lines.append("")
    else:
        for f in sorted_findings:
            lines.append(f"### [{f.severity}] {f.title}")
            lines.append("")
            lines.append(f"- **Category:** {f.category}")
            lines.append(f"- **CWE:** {f.cwe if f.cwe else 'N/A'}")
            lines.append(f"- **OWASP Ref:** {f.owasp_ref if f.owasp_ref else 'N/A'}")
            lines.append(f"- **Tool:** {f.source_tool if f.source_tool else 'agent'}")
            lines.append(f"- **Timestamp:** {f.timestamp.isoformat()}")
            lines.append("")
            lines.append("**Description:**")
            lines.append(f.description)
            lines.append("")
            lines.append("**Recommendation:**")
            lines.append(f.recommendation)
            lines.append("")
            lines.append("**Evidence:**")
            lines.append("```")
            if f.evidence:
                for ev in f.evidence:
                    lines.append(ev)
            else:
                lines.append("None")
            lines.append("```")
            lines.append("")
            lines.append("---")
            lines.append("")

    return "\n".join(lines)
