"""
Markdown Report Generator for Singularity.

Generates human-readable Markdown reports from scan results.

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from ..modules.base import ScanResult, Severity


# Severity display order (most critical first)
_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_RISK_LABEL = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH: "🟠 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🔵 LOW",
    Severity.INFO: "⚪ INFO",
}

_STATUS_EMOJI = {
    "success": "✅ success",
    "partial": "⚠️ partial",
    "failed": "❌ failed",
}


class MarkdownReport:
    """
    Markdown report generator.

    Produces human-readable reports for security review, GitHub issues,
    or direct developer consumption.
    """

    SEVERITY_EMOJI: Dict[Severity, str] = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "⚪",
    }

    def __init__(
        self,
        include_timestamp: bool = True,
        verbose: bool = False,
    ) -> None:
        """
        Initialize Markdown report generator.

        Args:
            include_timestamp: Include generation timestamp in report.
            verbose: Include full evidence details per finding.
        """
        self.include_timestamp = include_timestamp
        self.verbose = verbose

    def generate(self, results: List[ScanResult], target: str) -> str:
        """
        Generate Markdown report from scan results.

        Args:
            results: List of scan results from all modules.
            target: Scanned target URL/identifier.

        Returns:
            str: Rendered Markdown report.
        """
        lines: List[str] = []

        all_findings = [f for r in results for f in r.findings]

        # Severity counts
        counts: Dict[Severity, int] = {sev: 0 for sev in _SEVERITY_ORDER}
        for finding in all_findings:
            counts[finding.severity] += 1

        # Overall risk level = highest severity with at least one finding
        overall_risk = "⚪ INFO"
        for sev in _SEVERITY_ORDER:
            if counts[sev] > 0:
                overall_risk = _RISK_LABEL[sev]
                break

        # ── Header ──────────────────────────────────────────────────────────
        lines.append("# 🔒 Agent Security Scan Report")
        lines.append("")
        if self.include_timestamp:
            lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"**Target:** `{target}`")
        lines.append(f"**Risk Level:** {overall_risk}")
        lines.append(f"**Modules Run:** {', '.join(r.module_name for r in results)}")
        lines.append("")

        # ── Executive Summary ────────────────────────────────────────────────
        lines.append("## 📊 Executive Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        sev_label = {
            Severity.CRITICAL: "🔴 Critical",
            Severity.HIGH: "🟠 High",
            Severity.MEDIUM: "🟡 Medium",
            Severity.LOW: "🔵 Low",
            Severity.INFO: "⚪ Info",
        }
        for sev in _SEVERITY_ORDER:
            lines.append(f"| {sev_label[sev]} | {counts[sev]} |")
        lines.append(f"| **Total** | **{len(all_findings)}** |")
        lines.append("")

        # ── Findings Overview (table) ────────────────────────────────────────
        lines.append("## 📋 Findings Overview")
        lines.append("")
        lines.append("| ID | Severity | Category | Title | CWE |")
        lines.append("|----|----------|----------|-------|-----|")
        sorted_findings = sorted(
            all_findings,
            key=lambda f: _SEVERITY_ORDER.index(f.severity),
        )
        for finding in sorted_findings:
            emoji = self.SEVERITY_EMOJI[finding.severity]
            cwe = finding.cwe or "—"
            lines.append(
                f"| `{finding.id}` | {emoji} {finding.severity.value} "
                f"| {finding.category} | {finding.title} | {cwe} |"
            )
        lines.append("")

        # ── Detailed Findings ────────────────────────────────────────────────
        lines.append("## 🔍 Detailed Findings")
        lines.append("")

        for finding in sorted_findings:
            emoji = self.SEVERITY_EMOJI[finding.severity]
            lines.append(f"### {emoji} {finding.id}: {finding.title}")
            lines.append("")
            lines.append(f"**Severity:** {finding.severity.value}")
            lines.append(f"**Category:** {finding.category}")
            lines.append(f"**Confidence:** {finding.confidence}")
            if finding.location:
                lines.append(f"**Location:** `{finding.location}`")
            if finding.cwe:
                lines.append(f"**CWE:** {finding.cwe}")
            if finding.owasp_ref:
                lines.append(f"**OWASP:** {finding.owasp_ref}")
            if finding.mitre_ref:
                lines.append(f"**MITRE:** {finding.mitre_ref}")
            lines.append("")
            lines.append(f"**Description:** {finding.description}")
            lines.append("")
            if self.verbose and finding.evidence:
                lines.append("**Evidence:**")
                for ev in finding.evidence:
                    lines.append(f"- `{ev}`")
                lines.append("")
            lines.append(f"**Recommendation:** {finding.recommendation}")
            lines.append("")
            lines.append("---")
            lines.append("")

        # ── Module Results ────────────────────────────────────────────────────
        lines.append("## 🧩 Module Results")
        lines.append("")
        lines.append("| Module | Status | Findings | Duration | Errors |")
        lines.append("|--------|--------|----------|----------|--------|")
        for result in results:
            status_display = _STATUS_EMOJI.get(result.status, result.status)
            lines.append(
                f"| {result.module_name} | {status_display} "
                f"| {len(result.findings)} | {result.duration_ms}ms "
                f"| {len(result.errors)} |"
            )
        lines.append("")

        # ── Remediation Guidance ─────────────────────────────────────────────
        lines.append("## 🛠️ Remediation Guidance")
        lines.append("")
        priority_labels = [
            (Severity.CRITICAL, "Priority 1: Critical"),
            (Severity.HIGH, "Priority 2: High"),
            (Severity.MEDIUM, "Priority 3: Medium"),
            (Severity.LOW, "Priority 4: Low"),
            (Severity.INFO, "Priority 5: Informational"),
        ]
        for sev, label in priority_labels:
            sev_findings = [f for f in all_findings if f.severity == sev]
            lines.append(f"### {label}")
            lines.append("")
            if sev_findings:
                for finding in sev_findings:
                    lines.append(f"- **{finding.title}** (`{finding.id}`): {finding.recommendation}")
            else:
                lines.append("_No findings at this severity level._")
            lines.append("")

        return "\n".join(lines)

    def save(
        self,
        report: str,
        output_dir: str,
        filename: Optional[str] = None,
    ) -> str:
        """
        Save Markdown report to file.

        Args:
            report: Rendered Markdown string.
            output_dir: Directory to write report into.
            filename: Optional filename override. If omitted, a timestamped
                      name is generated.

        Returns:
            str: Path to saved report file.
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        if filename is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.md"

        output_path = Path(output_dir) / filename

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)

        logger.info(f"Markdown report saved: {output_path}")
        return str(output_path)
