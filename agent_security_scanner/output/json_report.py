"""
JSON Report Generator for Agent Security Scanner.

Generates structured JSON reports from scan results.

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from ..core.quality_gate import GateThreshold, evaluate as evaluate_gate
from ..modules.base import ScanResult, SEVERITY_WEIGHT, Severity


class JSONReport:
    """
    JSON report generator.

    Produces machine-readable JSON reports suitable for CI/CD integration,
    SIEM ingestion, or programmatic processing.
    """

    SCHEMA = "https://github.com/Cybathreat/agent-security-scanner/schema/report/v1"

    def __init__(
        self,
        pretty_print: bool = True,
        include_timestamp: bool = True,
    ) -> None:
        """
        Initialize JSON report generator.

        Args:
            pretty_print: Indent JSON output for readability.
            include_timestamp: Include generation timestamp in report.
        """
        self.pretty_print = pretty_print
        self.include_timestamp = include_timestamp

    def generate(
        self,
        results: List[ScanResult],
        gate_threshold: Optional[GateThreshold] = None,
    ) -> Dict[str, Any]:
        """
        Generate JSON report from scan results.

        Args:
            results: List of scan results from all modules.
            gate_threshold: Optional quality gate threshold to evaluate.

        Returns:
            Dict: Structured report ready for serialization.
        """
        target = results[0].target if results else "unknown"
        generated_at = datetime.utcnow().isoformat() + "Z"

        # Flat list of all findings across modules
        all_findings = [f for r in results for f in r.findings]

        # Aggregate severity counts and risk score
        summary: Dict[str, Any] = {
            "total": len(all_findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "risk_score": 0,
        }
        for finding in all_findings:
            key = finding.severity.value.lower()
            summary[key] += 1
            summary["risk_score"] += SEVERITY_WEIGHT.get(finding.severity, 0)

        # Framework mappings: category/ref -> [finding_ids]
        owasp_map: Dict[str, List[str]] = {}
        mitre_map: Dict[str, List[str]] = {}
        for finding in all_findings:
            if finding.owasp_ref:
                owasp_map.setdefault(finding.owasp_ref, []).append(finding.id)
            if finding.mitre_ref:
                mitre_map.setdefault(finding.mitre_ref, []).append(finding.id)

        report: Dict[str, Any] = {
            "$schema": self.SCHEMA,
            "report_id": str(uuid.uuid4()),
            "generated_at": generated_at,
            "scanner": {
                "name": "Agent Security Scanner",
                "version": "0.1.0",
            },
            "target": target,
            "summary": summary,
            "findings": [f.to_dict() for f in all_findings],
            "module_results": [r.to_dict() for r in results],
            "frameworks": {
                "owasp_llm_top_10": owasp_map,
                "mitre_atlas": mitre_map,
            },
        }

        # Evaluate quality gate if threshold provided
        if gate_threshold is not None:
            gate_result = evaluate_gate(results, gate_threshold)
            report["quality_gate"] = {
                "passed": gate_result.passed,
                "exit_code": gate_result.exit_code,
                "reason": gate_result.reason,
                "summary": gate_result.summary,
                "risk_score": gate_result.risk_score,
            }

        return report

    def to_json_string(self, report: Dict[str, Any]) -> str:
        """
        Serialize report dictionary to JSON string.

        Args:
            report: Generated report dictionary.

        Returns:
            str: JSON-encoded report.
        """
        indent = 2 if self.pretty_print else None
        return json.dumps(report, indent=indent, default=str)

    def save(
        self,
        report: Dict[str, Any],
        output_dir: str,
        filename: Optional[str] = None,
    ) -> str:
        """
        Save JSON report to file.

        Args:
            report: Generated report dictionary.
            output_dir: Directory to write report into.
            filename: Optional filename override. If omitted, a timestamped
                      name is generated.

        Returns:
            str: Path to saved report file.
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        if filename is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.json"

        output_path = Path(output_dir) / filename

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(self.to_json_string(report))

        logger.info(f"JSON report saved: {output_path}")
        return str(output_path)
