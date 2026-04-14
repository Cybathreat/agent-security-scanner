"""
Unit tests for output/reporting modules.

Tests JSONReport and MarkdownReport generators.

Run: pytest tests/unit/test_output.py -v
"""

import pytest
import json
import tempfile
from pathlib import Path

from agent_security_scanner.modules.base import Finding, ScanResult, Severity
from agent_security_scanner.output.json_report import JSONReport
from agent_security_scanner.output.markdown_report import MarkdownReport


class TestJSONReport:
    """Test JSON report generator."""

    @pytest.fixture
    def sample_results(self):
        """Create sample scan results for testing."""
        results = []

        # Prompt injection result
        pi_result = ScanResult(
            module_name="prompt_injection",
            target="https://api.example.com",
        )
        pi_result.add_finding(Finding(
            id="FIND-pi-001",
            severity=Severity.HIGH,
            category="prompt_injection",
            title="Direct Prompt Injection",
            description="Agent accepts injected instructions",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            mitre_ref="MITRE ATLAS - TA0045 - LLM Attack",
        ))
        pi_result.finalize()
        results.append(pi_result)

        # Misconfigurations result
        mc_result = ScanResult(
            module_name="misconfigurations",
            target="https://api.example.com",
        )
        mc_result.add_finding(Finding(
            id="FIND-mc-001",
            severity=Severity.MEDIUM,
            category="misconfigurations",
            title="Missing Rate Limiting",
            description="No rate limit headers",
            cwe="CWE-770",
        ))
        mc_result.finalize()
        results.append(mc_result)

        return results

    def test_generate_report_structure(self, sample_results):
        """Test JSON report structure."""
        reporter = JSONReport()
        report = reporter.generate(sample_results)

        assert "$schema" in report
        assert "report_id" in report
        assert "generated_at" in report
        assert "scanner" in report
        assert "target" in report
        assert "summary" in report
        assert "findings" in report
        assert "module_results" in report
        assert "frameworks" in report

    def test_generate_report_summary(self, sample_results):
        """Test summary calculation."""
        reporter = JSONReport()
        report = reporter.generate(sample_results)

        summary = report["summary"]
        assert summary["total"] == 2
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert "risk_score" in summary

    def test_generate_report_findings(self, sample_results):
        """Test findings serialization."""
        reporter = JSONReport()
        report = reporter.generate(sample_results)

        assert len(report["findings"]) == 2
        assert report["findings"][0]["id"] == "FIND-pi-001"
        assert report["findings"][0]["severity"] == "HIGH"
        assert report["findings"][0]["cwe"] == "CWE-94"

    def test_generate_report_owasp_mapping(self, sample_results):
        """Test OWASP mapping."""
        reporter = JSONReport()
        report = reporter.generate(sample_results)

        assert "owasp_llm_top_10" in report["frameworks"]
        owasp = report["frameworks"]["owasp_llm_top_10"]
        # Check that the OWASP ref is mapped (key should match finding's owasp_ref)
        assert len(owasp) >= 1  # At least one category has findings
        # Find the category that contains our finding
        found = False
        for category, finding_ids in owasp.items():
            if "FIND-pi-001" in finding_ids:
                found = True
                break
        assert found

    def test_generate_report_mitre_mapping(self, sample_results):
        """Test MITRE mapping."""
        reporter = JSONReport()
        report = reporter.generate(sample_results)

        assert "mitre_atlas" in report["frameworks"]
        mitre = report["frameworks"]["mitre_atlas"]
        # Check that MITRE ref is mapped
        found = False
        for category, finding_ids in mitre.items():
            if "FIND-pi-001" in finding_ids:
                found = True
                break
        assert found

    def test_save_report(self, sample_results):
        """Test saving JSON report to file."""
        reporter = JSONReport()
        report = reporter.generate(sample_results)

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = reporter.save(report, tmpdir, "test_report.json")

            assert Path(filepath).exists()
            assert filepath.endswith("test_report.json")

            with open(filepath, "r") as f:
                loaded = json.load(f)

            assert loaded["report_id"] == report["report_id"]
            assert len(loaded["findings"]) == 2

    def test_pretty_print_option(self, sample_results):
        """Test pretty print formatting."""
        reporter_pretty = JSONReport(pretty_print=True)
        reporter_compact = JSONReport(pretty_print=False)

        report = reporter_pretty.generate(sample_results)

        pretty_json = reporter_pretty.to_json_string(report)
        compact_json = reporter_compact.to_json_string(report)

        assert len(pretty_json) > len(compact_json)
        assert "\n" in pretty_json

    def test_include_timestamp_option(self, sample_results):
        """Test timestamp in filename."""
        reporter = JSONReport(include_timestamp=True)
        report = reporter.generate(sample_results)

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = reporter.save(report, tmpdir)
            # Filename should contain timestamp
            assert "_" in Path(filepath).name


class TestMarkdownReport:
    """Test Markdown report generator."""

    @pytest.fixture
    def sample_results(self):
        """Create sample scan results for testing."""
        results = []

        result = ScanResult(module_name="prompt_injection", target="https://api.example.com")
        result.add_finding(Finding(
            id="FIND-pi-002",
            severity=Severity.CRITICAL,
            category="prompt_injection",
            title="Critical Injection",
            description="Critical vulnerability",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024",
        ))
        result.add_finding(Finding(
            id="FIND-pi-003",
            severity=Severity.HIGH,
            category="prompt_injection",
            title="High Issue",
            description="High severity issue",
        ))
        result.add_finding(Finding(
            id="FIND-pi-004",
            severity=Severity.LOW,
            category="prompt_injection",
            title="Low Issue",
            description="Low severity issue",
        ))
        result.finalize()
        results.append(result)

        return results

    def test_generate_report_structure(self, sample_results):
        """Test Markdown report structure."""
        reporter = MarkdownReport()
        report = reporter.generate(sample_results, "https://api.example.com")

        assert "# 🔒 Agent Security Scan Report" in report
        assert "## 📊 Executive Summary" in report
        assert "## 📋 Findings Overview" in report
        assert "## 🔍 Detailed Findings" in report
        assert "## 🧩 Module Results" in report
        assert "## 🛠️ Remediation Guidance" in report

    def test_generate_executive_summary(self, sample_results):
        """Test executive summary section."""
        reporter = MarkdownReport()
        report = reporter.generate(sample_results, "https://api.example.com")

        assert "🔴 CRITICAL" in report  # Risk level
        assert "| Severity | Count |" in report
        assert "🔴 Critical | 1 |" in report
        assert "🟠 High | 1 |" in report
        assert "🔵 Low | 1 |" in report

    def test_generate_findings_table(self, sample_results):
        """Test findings table."""
        reporter = MarkdownReport()
        report = reporter.generate(sample_results, "https://api.example.com")

        assert "| ID | Severity | Category | Title | CWE |" in report
        assert "FIND-pi-002" in report
        assert "FIND-pi-003" in report
        assert "FIND-pi-004" in report

    def test_generate_detailed_findings(self, sample_results):
        """Test detailed findings section."""
        reporter = MarkdownReport()
        report = reporter.generate(sample_results, "https://api.example.com")

        assert "### 🔴 FIND-pi-002: Critical Injection" in report
        assert "**Severity:** CRITICAL" in report
        assert "**Description:**" in report
        assert "**Recommendation:**" in report

    def test_generate_module_summary(self, sample_results):
        """Test module results table."""
        reporter = MarkdownReport()
        report = reporter.generate(sample_results, "https://api.example.com")

        assert "| Module | Status | Findings | Duration | Errors |" in report
        assert "prompt_injection" in report
        assert "✅ success" in report

    def test_generate_remediation_guidance(self, sample_results):
        """Test remediation guidance section."""
        reporter = MarkdownReport()
        report = reporter.generate(sample_results, "https://api.example.com")

        assert "## 🛠️ Remediation Guidance" in report
        assert "Priority 1: Critical" in report
        assert "Priority 2: High" in report
        assert "Priority 3: Medium" in report

    def test_save_report(self, sample_results):
        """Test saving Markdown report to file."""
        reporter = MarkdownReport()
        report = reporter.generate(sample_results, "https://api.example.com")

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = reporter.save(report, tmpdir, "test_summary.md")

            assert Path(filepath).exists()
            assert filepath.endswith("test_summary.md")

            with open(filepath, "r") as f:
                content = f.read()

            assert "# 🔒 Agent Security Scan Report" in content

    def test_verbose_option(self, sample_results):
        """Test verbose mode."""
        reporter_quiet = MarkdownReport(verbose=False)
        reporter_verbose = MarkdownReport(verbose=True)

        report_quiet = reporter_quiet.generate(sample_results, "https://api.example.com")
        report_verbose = reporter_verbose.generate(sample_results, "https://api.example.com")

        # Both should have same structure (verbose is for future expansion)
        assert len(report_quiet) > 0
        assert len(report_verbose) > 0

    def test_severity_emoji_mapping(self):
        """Test severity emoji mapping."""
        emoji_map = MarkdownReport.SEVERITY_EMOJI

        assert emoji_map[Severity.CRITICAL] == "🔴"
        assert emoji_map[Severity.HIGH] == "🟠"
        assert emoji_map[Severity.MEDIUM] == "🟡"
        assert emoji_map[Severity.LOW] == "🔵"
        assert emoji_map[Severity.INFO] == "⚪"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
