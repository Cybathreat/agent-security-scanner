"""
Quality Gate Module for CI/CD Integration.

Evaluates scan results against configurable thresholds to produce
pass/fail verdicts suitable for CI/CD pipelines.

Exit codes:
    0: Scan completed, quality gate passed
    1: Scan error (exception during execution)
    2: Quality gate failed (findings exceed configured thresholds)

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..modules.base import Finding, ScanResult, Severity, SEVERITY_LEVELS, SEVERITY_WEIGHT


@dataclass
class GateThreshold:
    """
    Configuration for quality gate evaluation.

    Attributes:
        fail_on_severity: Minimum severity that triggers gate failure.
            Any finding at this severity or above causes failure.
            E.g., fail_on_severity=Severity.HIGH fails on HIGH and CRITICAL.
        max_findings: Maximum total findings allowed (None = no limit).
        max_risk_score: Maximum aggregate risk score allowed (None = no limit).
    """

    fail_on_severity: Severity = Severity.CRITICAL
    max_findings: Optional[int] = None
    max_risk_score: Optional[int] = None


@dataclass
class GateResult:
    """
    Result of quality gate evaluation.

    Attributes:
        passed: Whether the gate passed.
        exit_code: 0 for pass, 2 for fail.
        reason: Human-readable explanation of the result.
        summary: Finding counts by severity level.
        risk_score: Aggregate risk score.
        findings_by_severity: Findings grouped by severity.
    """

    passed: bool
    exit_code: int
    reason: str
    summary: Dict[str, int] = field(default_factory=dict)
    risk_score: int = 0
    findings_by_severity: Dict[Severity, List[Finding]] = field(default_factory=dict)


def evaluate(
    results: List[ScanResult],
    threshold: GateThreshold,
) -> GateResult:
    """
    Evaluate scan results against quality gate thresholds.

    Args:
        results: Scan results from all executed modules.
        threshold: Quality gate threshold configuration.

    Returns:
        GateResult with pass/fail verdict and details.
    """
    # Flatten all findings
    all_findings: List[Finding] = []
    for result in results:
        all_findings.extend(result.findings)

    # Group findings by severity
    findings_by_severity: Dict[Severity, List[Finding]] = {sev: [] for sev in SEVERITY_LEVELS}
    for finding in all_findings:
        if finding.severity in findings_by_severity:
            findings_by_severity[finding.severity].append(finding)

    # Count by severity
    summary: Dict[str, int] = {
        "total": len(all_findings),
        "critical": len(findings_by_severity[Severity.CRITICAL]),
        "high": len(findings_by_severity[Severity.HIGH]),
        "medium": len(findings_by_severity[Severity.MEDIUM]),
        "low": len(findings_by_severity[Severity.LOW]),
        "info": len(findings_by_severity[Severity.INFO]),
    }

    # Compute aggregate risk score
    risk_score = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in all_findings)

    # Determine failure threshold index
    threshold_index = SEVERITY_LEVELS.index(threshold.fail_on_severity)

    # Check severity threshold
    failing_findings: List[Finding] = []
    for severity in SEVERITY_LEVELS[: threshold_index + 1]:
        failing_findings.extend(findings_by_severity[severity])

    # Evaluate all conditions
    reasons: List[str] = []
    passed = True

    if failing_findings:
        sev_counts = []
        for severity in SEVERITY_LEVELS[: threshold_index + 1]:
            count = len(findings_by_severity[severity])
            if count > 0:
                sev_counts.append(f"{count} {severity.value}")
        reasons.append(
            f"{len(failing_findings)} findings at or above "
            f"{threshold.fail_on_severity.value} severity ({', '.join(sev_counts)})"
        )
        passed = False

    if threshold.max_findings is not None and len(all_findings) > threshold.max_findings:
        reasons.append(
            f"total findings ({len(all_findings)}) exceed max_findings ({threshold.max_findings})"
        )
        passed = False

    if threshold.max_risk_score is not None and risk_score > threshold.max_risk_score:
        reasons.append(
            f"risk score ({risk_score}) exceeds max_risk_score ({threshold.max_risk_score})"
        )
        passed = False

    # Build reason string
    if passed:
        if len(all_findings) == 0:
            reason = "Quality gate PASSED: no findings"
        else:
            reason = (
                f"Quality gate PASSED: {len(all_findings)} findings, "
                f"none at or above {threshold.fail_on_severity.value} severity"
            )
    else:
        reason = f"Quality gate FAILED: {'; '.join(reasons)}"

    return GateResult(
        passed=passed,
        exit_code=0 if passed else 2,
        reason=reason,
        summary=summary,
        risk_score=risk_score,
        findings_by_severity=findings_by_severity,
    )
