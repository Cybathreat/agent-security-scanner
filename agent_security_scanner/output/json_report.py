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

from ..core.validators import validate_path
from ..modules.base import ScanResult, Severity


# Severity weights for risk score calculation
_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


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

    def generate(self, results: List[ScanResult]) -> Dict[str, Any]:
        """
        Generate JSON report from scan results.

        Args:
            results: List of scan results from all modules.

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
            summary["risk_score"] += _SEVERITY_WEIGHT.get(finding.severity, 0)

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
        # Validate output directory to prevent path traversal
        is_valid, error_msg = validate_path(output_dir)
        if not is_valid:
            raise ValueError(f"Invalid output directory: {error_msg}")

        Path(output_dir).mkdir(parents=True, exist_ok=True)

        if filename is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.json"

        # Validate filename as well
        is_valid, error_msg = validate_path(filename)
        if not is_valid:
            raise ValueError(f"Invalid filename: {error_msg}")

        output_path = Path(output_dir) / filename

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(self.to_json_string(report))

        logger.info(f"JSON report saved: {output_path}")
        return str(output_path)
