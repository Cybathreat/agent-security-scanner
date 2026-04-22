"""
Tests for core/quality_gate.py — CI/CD quality gate evaluation.

Covers: empty results, severity thresholds, max_findings, max_risk_score,
combined thresholds, severity ordering, risk score calculation.
"""

from datetime import datetime

import pytest

from singularity.core.quality_gate import (
    GateResult,
    GateThreshold,
    evaluate,
)
from singularity.modules.base import (
    Finding,
    ScanResult,
    Severity,
    SEVERITY_LEVELS,
    SEVERITY_WEIGHT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(severity: Severity, category: str = "test") -> Finding:
    """Create a minimal Finding for testing."""
    return Finding(
        id=f"FIND-test-{severity.value}",
        severity=severity,
        category=category,
        title=f"Test {severity.value} finding",
        description=f"A {severity.value} severity test finding",
    )


def _make_result(findings: list[Finding], target: str = "https://test.local") -> ScanResult:
    """Create a ScanResult wrapping the given findings."""
    result = ScanResult(module_name="test_module", target=target, findings=findings)
    result.finalize()
    return result


# ---------------------------------------------------------------------------
# GateThreshold defaults
# ---------------------------------------------------------------------------


class TestGateThreshold:
    """GateThreshold dataclass tests."""

    def test_defaults(self):
        t = GateThreshold()
        assert t.fail_on_severity == Severity.CRITICAL
        assert t.max_findings is None
        assert t.max_risk_score is None

    def test_custom_severity(self):
        t = GateThreshold(fail_on_severity=Severity.HIGH)
        assert t.fail_on_severity == Severity.HIGH

    def test_custom_max_findings(self):
        t = GateThreshold(max_findings=10)
        assert t.max_findings == 10

    def test_custom_max_risk_score(self):
        t = GateThreshold(max_risk_score=50)
        assert t.max_risk_score == 50


# ---------------------------------------------------------------------------
# evaluate() — empty results
# ---------------------------------------------------------------------------


class TestEvaluateEmpty:
    """Evaluate with empty or no findings."""

    def test_empty_results_list(self):
        gate = evaluate([], GateThreshold())
        assert gate.passed is True
        assert gate.exit_code == 0
        assert gate.reason == "Quality gate PASSED: no findings"
        assert gate.summary["total"] == 0
        assert gate.risk_score == 0

    def test_results_with_no_findings(self):
        result = _make_result([])
        gate = evaluate([result], GateThreshold())
        assert gate.passed is True
        assert gate.exit_code == 0
        assert gate.summary["total"] == 0


# ---------------------------------------------------------------------------
# evaluate() — severity thresholds
# ---------------------------------------------------------------------------


class TestEvaluateSeverityThresholds:
    """Severity threshold: fail_on_severity controls which severities trigger failure."""

    def test_critical_finding_fails_on_critical(self):
        findings = [_make_finding(Severity.CRITICAL)]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(fail_on_severity=Severity.CRITICAL))
        assert gate.passed is False
        assert gate.exit_code == 2
        assert "CRITICAL" in gate.reason

    def test_high_finding_passes_on_critical_threshold(self):
        """HIGH findings don't trigger a CRITICAL-only gate."""
        findings = [_make_finding(Severity.HIGH)]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(fail_on_severity=Severity.CRITICAL))
        assert gate.passed is True
        assert gate.exit_code == 0

    def test_high_finding_fails_on_high_threshold(self):
        findings = [_make_finding(Severity.HIGH)]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(fail_on_severity=Severity.HIGH))
        assert gate.passed is False
        assert gate.exit_code == 2

    def test_medium_finding_fails_on_medium_threshold(self):
        findings = [_make_finding(Severity.MEDIUM)]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(fail_on_severity=Severity.MEDIUM))
        assert gate.passed is False

    def test_low_finding_fails_on_low_threshold(self):
        findings = [_make_finding(Severity.LOW)]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(fail_on_severity=Severity.LOW))
        assert gate.passed is False

    def test_info_finding_fails_on_info_threshold(self):
        findings = [_make_finding(Severity.INFO)]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(fail_on_severity=Severity.INFO))
        assert gate.passed is False

    def test_info_finding_passes_on_low_threshold(self):
        """INFO findings don't trigger a LOW-or-above gate."""
        findings = [_make_finding(Severity.INFO)]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(fail_on_severity=Severity.LOW))
        assert gate.passed is True

    def test_mixed_severities_fail_on_high(self):
        """CRITICAL + HIGH + MEDIUM: fail_on_severity=HIGH → CRITICAL and HIGH count."""
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.MEDIUM),
        ]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(fail_on_severity=Severity.HIGH))
        assert gate.passed is False
        assert gate.summary["critical"] == 1
        assert gate.summary["high"] == 1
        assert gate.summary["medium"] == 1

    def test_severity_levels_ordering(self):
        """Verify SEVERITY_LEVELS is ordered highest to lowest."""
        for i in range(len(SEVERITY_LEVELS) - 1):
            assert SEVERITY_LEVELS[i] == Severity(
                ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"][i]
            )


# ---------------------------------------------------------------------------
# evaluate() — max_findings threshold
# ---------------------------------------------------------------------------


class TestEvaluateMaxFindings:
    """max_findings threshold: total findings must not exceed limit."""

    def test_below_max_findings_passes(self):
        findings = [_make_finding(Severity.LOW), _make_finding(Severity.INFO)]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(max_findings=5))
        assert gate.passed is True

    def test_at_max_findings_passes(self):
        findings = [_make_finding(Severity.LOW), _make_finding(Severity.INFO)]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(max_findings=2))
        assert gate.passed is True

    def test_above_max_findings_fails(self):
        findings = [_make_finding(Severity.LOW)] * 5
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(max_findings=3))
        assert gate.passed is False
        assert "total findings" in gate.reason.lower()

    def test_max_findings_none_no_limit(self):
        findings = [_make_finding(Severity.LOW)] * 100
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(max_findings=None))
        # No max_findings constraint → only severity matters
        assert gate.passed is True  # default fail_on_severity=CRITICAL, LOW doesn't trigger


# ---------------------------------------------------------------------------
# evaluate() — max_risk_score threshold
# ---------------------------------------------------------------------------


class TestEvaluateMaxRiskScore:
    """max_risk_score threshold: aggregate risk score must not exceed limit."""

    def test_below_risk_score_passes(self):
        findings = [_make_finding(Severity.HIGH)]  # risk = 7
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(max_risk_score=10))
        assert gate.passed is True

    def test_at_risk_score_passes(self):
        findings = [_make_finding(Severity.HIGH)]  # risk = 7
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(max_risk_score=7))
        assert gate.passed is True

    def test_above_risk_score_fails(self):
        findings = [_make_finding(Severity.HIGH)]  # risk = 7
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(max_risk_score=5))
        assert gate.passed is False
        assert "risk score" in gate.reason.lower()

    def test_risk_score_calculation(self):
        """Verify risk score sums severity weights correctly."""
        findings = [
            _make_finding(Severity.CRITICAL),  # 10
            _make_finding(Severity.HIGH),        # 7
            _make_finding(Severity.MEDIUM),      # 4
            _make_finding(Severity.LOW),         # 1
            _make_finding(Severity.INFO),        # 0
        ]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold())
        assert gate.risk_score == 22  # 10 + 7 + 4 + 1 + 0

    def test_max_risk_score_none_no_limit(self):
        findings = [_make_finding(Severity.CRITICAL)] * 20  # risk = 200
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(max_risk_score=None))
        # max_risk_score=None means no limit; fail_on_severity=CRITICAL still fails
        assert gate.passed is False
        assert "risk score" not in gate.reason.lower()


# ---------------------------------------------------------------------------
# evaluate() — combined thresholds
# ---------------------------------------------------------------------------


class TestEvaluateCombinedThresholds:
    """Multiple thresholds active simultaneously."""

    def test_severity_and_max_findings_both_fail(self):
        findings = [_make_finding(Severity.HIGH)] * 5
        result = _make_result(findings)
        gate = evaluate(
            [result],
            GateThreshold(fail_on_severity=Severity.HIGH, max_findings=3),
        )
        assert gate.passed is False
        assert "HIGH" in gate.reason
        assert "total findings" in gate.reason.lower()

    def test_severity_passes_but_max_findings_fails(self):
        findings = [_make_finding(Severity.INFO)] * 10
        result = _make_result(findings)
        gate = evaluate(
            [result],
            GateThreshold(fail_on_severity=Severity.CRITICAL, max_findings=5),
        )
        assert gate.passed is False
        assert "total findings" in gate.reason.lower()

    def test_severity_fails_but_max_findings_passes(self):
        findings = [_make_finding(Severity.CRITICAL)]
        result = _make_result(findings)
        gate = evaluate(
            [result],
            GateThreshold(fail_on_severity=Severity.CRITICAL, max_findings=10),
        )
        assert gate.passed is False
        assert "CRITICAL" in gate.reason

    def test_all_three_pass(self):
        findings = [_make_finding(Severity.LOW)]
        result = _make_result(findings)
        gate = evaluate(
            [result],
            GateThreshold(fail_on_severity=Severity.HIGH, max_findings=10, max_risk_score=50),
        )
        assert gate.passed is True
        assert gate.exit_code == 0

    def test_all_three_fail(self):
        findings = [_make_finding(Severity.CRITICAL)] * 3
        result = _make_result(findings)
        gate = evaluate(
            [result],
            GateThreshold(fail_on_severity=Severity.HIGH, max_findings=2, max_risk_score=20),
        )
        assert gate.passed is False
        assert gate.exit_code == 2
        assert "HIGH" in gate.reason
        assert "total findings" in gate.reason.lower()
        assert "risk score" in gate.reason.lower()


# ---------------------------------------------------------------------------
# evaluate() — multiple ScanResults
# ---------------------------------------------------------------------------


class TestEvaluateMultipleResults:
    """Findings aggregated across multiple ScanResult objects."""

    def test_findings_from_multiple_results(self):
        r1 = _make_result([_make_finding(Severity.HIGH)])
        r2 = _make_result([_make_finding(Severity.MEDIUM)])
        gate = evaluate([r1, r2], GateThreshold(fail_on_severity=Severity.HIGH))
        assert gate.passed is False
        assert gate.summary["total"] == 2
        assert gate.summary["high"] == 1
        assert gate.summary["medium"] == 1

    def test_risk_score_across_multiple_results(self):
        r1 = _make_result([_make_finding(Severity.CRITICAL)])  # 10
        r2 = _make_result([_make_finding(Severity.HIGH)])       # 7
        gate = evaluate([r1, r2], GateThreshold())
        assert gate.risk_score == 17


# ---------------------------------------------------------------------------
# evaluate() — GateResult structure
# ---------------------------------------------------------------------------


class TestGateResultStructure:
    """Verify GateResult fields are populated correctly."""

    def test_findings_by_severity(self):
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.HIGH),
        ]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold())
        assert len(gate.findings_by_severity[Severity.CRITICAL]) == 1
        assert len(gate.findings_by_severity[Severity.HIGH]) == 2
        assert len(gate.findings_by_severity[Severity.MEDIUM]) == 0

    def test_summary_counts(self):
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.MEDIUM),
            _make_finding(Severity.LOW),
            _make_finding(Severity.INFO),
        ]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold())
        assert gate.summary == {
            "total": 6,
            "critical": 1,
            "high": 2,
            "medium": 1,
            "low": 1,
            "info": 1,
        }

    def test_passed_reason_format(self):
        findings = [_make_finding(Severity.MEDIUM)]
        result = _make_result(findings)
        gate = evaluate([result], GateThreshold(fail_on_severity=Severity.HIGH))
        assert gate.passed is True
        assert "PASSED" in gate.reason
        assert "1 findings" in gate.reason
        assert "none at or above HIGH" in gate.reason


# ---------------------------------------------------------------------------
# SEVERITY_WEIGHT & SEVERITY_LEVELS
# ---------------------------------------------------------------------------


class TestSeverityConstants:
    """Verify severity constants used by quality gate."""

    def test_severity_weight_values(self):
        assert SEVERITY_WEIGHT[Severity.CRITICAL] == 10
        assert SEVERITY_WEIGHT[Severity.HIGH] == 7
        assert SEVERITY_WEIGHT[Severity.MEDIUM] == 4
        assert SEVERITY_WEIGHT[Severity.LOW] == 1
        assert SEVERITY_WEIGHT[Severity.INFO] == 0

    def test_severity_levels_order(self):
        assert SEVERITY_LEVELS == (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        )