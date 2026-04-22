"""
Tests for CLI quality gate integration.

Covers: arg parsing, _build_gate_threshold, exit codes (0/1/2),
quality gate output in scan summary, config precedence.
"""

from unittest.mock import MagicMock, patch

import pytest

from singularity.cli import _build_gate_threshold, main, parse_args
from singularity.core.config import QualityGateConfig
from singularity.core.quality_gate import GateThreshold
from singularity.modules.base import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(severity: Severity) -> Finding:
    return Finding(
        id=f"FIND-test-{severity.value}",
        severity=severity,
        category="test",
        title=f"Test {severity.value}",
        description="Test finding",
    )


def _make_result(findings: list[Finding], target: str = "https://test.local") -> ScanResult:
    result = ScanResult(module_name="test_module", target=target, findings=findings)
    result.finalize()
    return result


def _mock_namespace(**overrides) -> MagicMock:
    """Create a mock argparse Namespace with scan defaults."""
    ns = MagicMock()
    ns.command = "scan"
    ns.target = "https://test.local"
    ns.modules = "all"
    ns.output = "output"
    ns.format = "json"
    ns.config = None
    ns.timeout = 30
    ns.verbose = False
    ns.log_level = "WARNING"
    ns.dry_run = False
    ns.fail_on = None
    ns.max_findings = None
    ns.max_risk_score = None
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------


class TestParseArgsQualityGate:
    """Test quality gate CLI arguments."""

    def test_fail_on_critical(self):
        args = parse_args(["scan", "--target", "https://x", "--fail-on", "critical"])
        assert args.fail_on == "critical"

    def test_fail_on_high(self):
        args = parse_args(["scan", "--target", "https://x", "--fail-on", "high"])
        assert args.fail_on == "high"

    def test_fail_on_medium(self):
        args = parse_args(["scan", "--target", "https://x", "--fail-on", "medium"])
        assert args.fail_on == "medium"

    def test_fail_on_low(self):
        args = parse_args(["scan", "--target", "https://x", "--fail-on", "low"])
        assert args.fail_on == "low"

    def test_fail_on_info(self):
        args = parse_args(["scan", "--target", "https://x", "--fail-on", "info"])
        assert args.fail_on == "info"

    def test_fail_on_invalid(self):
        with pytest.raises(SystemExit):
            parse_args(["scan", "--target", "https://x", "--fail-on", "extreme"])

    def test_max_findings(self):
        args = parse_args(["scan", "--target", "https://x", "--max-findings", "10"])
        assert args.max_findings == 10

    def test_max_risk_score(self):
        args = parse_args(["scan", "--target", "https://x", "--max-risk-score", "50"])
        assert args.max_risk_score == 50

    def test_all_gate_args_combined(self):
        args = parse_args([
            "scan", "--target", "https://x",
            "--fail-on", "high",
            "--max-findings", "5",
            "--max-risk-score", "20",
        ])
        assert args.fail_on == "high"
        assert args.max_findings == 5
        assert args.max_risk_score == 20

    def test_default_none(self):
        args = parse_args(["scan", "--target", "https://x"])
        assert args.fail_on is None
        assert args.max_findings is None
        assert args.max_risk_score is None


# ---------------------------------------------------------------------------
# _build_gate_threshold
# ---------------------------------------------------------------------------


class TestBuildGateThreshold:
    """Test quality gate threshold construction from args + config."""

    def test_defaults(self):
        args = _mock_namespace(fail_on=None, max_findings=None, max_risk_score=None)
        config_qg = QualityGateConfig()
        threshold = _build_gate_threshold(args, config_qg)
        assert threshold.fail_on_severity == Severity.CRITICAL
        assert threshold.max_findings is None
        assert threshold.max_risk_score is None

    def test_cli_fail_on_overrides_config(self):
        args = _mock_namespace(fail_on="high")
        config_qg = QualityGateConfig(fail_on_severity="low")
        threshold = _build_gate_threshold(args, config_qg)
        assert threshold.fail_on_severity == Severity.HIGH

    def test_config_fail_on_when_no_cli(self):
        args = _mock_namespace(fail_on=None)
        config_qg = QualityGateConfig(fail_on_severity="medium")
        threshold = _build_gate_threshold(args, config_qg)
        assert threshold.fail_on_severity == Severity.MEDIUM

    def test_cli_max_findings_overrides_config(self):
        args = _mock_namespace(max_findings=10)
        config_qg = QualityGateConfig(max_findings=50)
        threshold = _build_gate_threshold(args, config_qg)
        assert threshold.max_findings == 10

    def test_config_max_findings_when_no_cli(self):
        args = _mock_namespace(max_findings=None)
        config_qg = QualityGateConfig(max_findings=50)
        threshold = _build_gate_threshold(args, config_qg)
        assert threshold.max_findings == 50

    def test_cli_max_risk_score_overrides_config(self):
        args = _mock_namespace(max_risk_score=20)
        config_qg = QualityGateConfig(max_risk_score=100)
        threshold = _build_gate_threshold(args, config_qg)
        assert threshold.max_risk_score == 20

    def test_config_max_risk_score_when_no_cli(self):
        args = _mock_namespace(max_risk_score=None)
        config_qg = QualityGateConfig(max_risk_score=100)
        threshold = _build_gate_threshold(args, config_qg)
        assert threshold.max_risk_score == 100

    def test_all_from_cli(self):
        args = _mock_namespace(fail_on="low", max_findings=5, max_risk_score=10)
        config_qg = QualityGateConfig()
        threshold = _build_gate_threshold(args, config_qg)
        assert threshold.fail_on_severity == Severity.LOW
        assert threshold.max_findings == 5
        assert threshold.max_risk_score == 10


# ---------------------------------------------------------------------------
# main() exit codes
# ---------------------------------------------------------------------------


class TestMainExitCodes:
    """Test main() returns correct exit codes for quality gate scenarios."""

    @patch("singularity.cli.generate_reports")
    @patch("singularity.cli.evaluate_gate")
    @patch("singularity.cli.load_config")
    @patch("singularity.cli.run_scan")
    def test_exit_0_no_findings(self, mock_scan, mock_config, mock_eval, mock_reports):
        mock_scan.return_value = []
        mock_config.return_value = MagicMock(quality_gate=QualityGateConfig())
        mock_eval.return_value = MagicMock(
            passed=True, exit_code=0, reason="Quality gate PASSED: no findings",
            summary={"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            risk_score=0,
        )
        exit_code = main(["scan", "--target", "https://x"])
        assert exit_code == 0

    @patch("singularity.cli.generate_reports")
    @patch("singularity.cli.evaluate_gate")
    @patch("singularity.cli.load_config")
    @patch("singularity.cli.run_scan")
    def test_exit_0_low_findings_default_critical_threshold(
        self, mock_scan, mock_config, mock_eval, mock_reports,
    ):
        """LOW findings with default fail_on=CRITICAL → gate passes → exit 0."""
        result = _make_result([_make_finding(Severity.LOW)])
        mock_scan.return_value = [result]
        mock_config.return_value = MagicMock(quality_gate=QualityGateConfig())
        mock_eval.return_value = MagicMock(
            passed=True, exit_code=0,
            reason="Quality gate PASSED: 1 findings, none at or above CRITICAL",
            summary={"total": 1, "critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0},
            risk_score=1,
        )
        exit_code = main(["scan", "--target", "https://x"])
        assert exit_code == 0

    @patch("singularity.cli.generate_reports")
    @patch("singularity.cli.evaluate_gate")
    @patch("singularity.cli.load_config")
    @patch("singularity.cli.run_scan")
    def test_exit_2_critical_finding(self, mock_scan, mock_config, mock_eval, mock_reports):
        """CRITICAL finding with default fail_on=CRITICAL → gate fails → exit 2."""
        result = _make_result([_make_finding(Severity.CRITICAL)])
        mock_scan.return_value = [result]
        mock_config.return_value = MagicMock(quality_gate=QualityGateConfig())
        mock_eval.return_value = MagicMock(
            passed=False, exit_code=2,
            reason="Quality gate FAILED: 1 findings at or above CRITICAL severity (1 CRITICAL)",
            summary={"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
            risk_score=10,
        )
        exit_code = main(["scan", "--target", "https://x"])
        assert exit_code == 2

    @patch("singularity.cli.generate_reports")
    @patch("singularity.cli.evaluate_gate")
    @patch("singularity.cli.load_config")
    @patch("singularity.cli.run_scan")
    def test_exit_2_high_finding_with_fail_on_high(
        self, mock_scan, mock_config, mock_eval, mock_reports,
    ):
        """HIGH finding with --fail-on high → gate fails → exit 2."""
        result = _make_result([_make_finding(Severity.HIGH)])
        mock_scan.return_value = [result]
        mock_config.return_value = MagicMock(quality_gate=QualityGateConfig())
        mock_eval.return_value = MagicMock(
            passed=False, exit_code=2,
            reason="Quality gate FAILED: 1 findings at or above HIGH severity (1 HIGH)",
            summary={"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            risk_score=7,
        )
        exit_code = main(["scan", "--target", "https://x", "--fail-on", "high"])
        assert exit_code == 2

    @patch("singularity.cli.generate_reports")
    @patch("singularity.cli.evaluate_gate")
    @patch("singularity.cli.load_config")
    @patch("singularity.cli.run_scan")
    def test_exit_1_on_exception(self, mock_scan, mock_config, mock_eval, mock_reports):
        """Scan throws exception → exit 1."""
        mock_scan.side_effect = RuntimeError("connection refused")
        exit_code = main(["scan", "--target", "https://x"])
        assert exit_code == 1

    @patch("singularity.cli.generate_reports")
    @patch("singularity.cli.evaluate_gate")
    @patch("singularity.cli.load_config")
    @patch("singularity.cli.run_scan")
    def test_exit_2_max_findings_exceeded(
        self, mock_scan, mock_config, mock_eval, mock_reports,
    ):
        """Total findings exceed --max-findings → exit 2."""
        findings = [_make_finding(Severity.INFO)] * 5
        result = _make_result(findings)
        mock_scan.return_value = [result]
        mock_config.return_value = MagicMock(quality_gate=QualityGateConfig())
        mock_eval.return_value = MagicMock(
            passed=False, exit_code=2,
            reason="Quality gate FAILED: total findings (5) exceed max_findings (3)",
            summary={"total": 5, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 5},
            risk_score=0,
        )
        exit_code = main(["scan", "--target", "https://x", "--max-findings", "3"])
        assert exit_code == 2


# ---------------------------------------------------------------------------
# Generated config includes quality_gate
# ---------------------------------------------------------------------------


class TestGeneratedConfig:
    """Verify generated config YAML includes quality_gate section."""

    def test_config_generate_includes_quality_gate(self, tmp_path):
        output_path = str(tmp_path / "config.yaml")
        exit_code = main(["config", "--generate", "--output", output_path])
        assert exit_code == 0

        with open(output_path) as f:
            content = f.read()

        assert "quality_gate:" in content
        assert "fail_on_severity" in content