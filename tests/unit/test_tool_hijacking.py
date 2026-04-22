"""
Unit tests for Tool Hijacking scanner.

Tests ToolHijackingScannerConfig, ToolHijackingScanner, heuristic scoring,
severity determination, argument injection, parameter manipulation,
tool validation, scan lifecycle, and finding creation.

Run: pytest tests/unit/test_tool_hijacking.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from singularity.modules.agent.tool_hijacking import (
    ToolHijackingScannerConfig,
    ToolHijackingScanner,
)
from singularity.modules.base import Severity


class TestToolHijackingConfig:
    """Test ToolHijackingScannerConfig defaults and custom values."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ToolHijackingScannerConfig()
        assert config.enabled is True
        assert config.test_argument_injection is True
        assert config.test_parameter_manipulation is True
        assert config.test_tool_validation is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        """Test custom configuration values."""
        config = ToolHijackingScannerConfig(
            enabled=False,
            test_argument_injection=False,
            compliance_threshold=0.8,
        )
        assert config.enabled is False
        assert config.test_argument_injection is False
        assert config.compliance_threshold == 0.8

    def test_phase_toggles(self):
        """Test individual phase toggle flags."""
        config = ToolHijackingScannerConfig(
            test_argument_injection=True,
            test_parameter_manipulation=False,
            test_tool_validation=False,
        )
        assert config.test_argument_injection is True
        assert config.test_parameter_manipulation is False
        assert config.test_tool_validation is False


class TestToolHijackingScanner:
    """Test ToolHijackingScanner initialization and constants."""

    def test_initialization(self):
        """Test scanner initialization."""
        config = ToolHijackingScannerConfig()
        scanner = ToolHijackingScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "tool_hijacking"

    def test_initialization_default_config(self):
        """Test default config when none provided."""
        scanner = ToolHijackingScanner()
        assert isinstance(scanner.config, ToolHijackingScannerConfig)
        assert scanner.config.enabled is True

    def test_argument_injection_payloads_structure(self):
        """Test that each argument injection payload has required keys."""
        scanner = ToolHijackingScanner()
        for payload in scanner.ARGUMENT_INJECTION_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload
            assert "dangerous_arg" in payload
            assert len(payload["payload"]) > 0

    def test_parameter_manipulation_payloads_structure(self):
        """Test that each parameter manipulation payload has required keys."""
        scanner = ToolHijackingScanner()
        for payload in scanner.PARAMETER_MANIPULATION_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload
            assert "dangerous_param" in payload

    def test_tool_validation_payloads_structure(self):
        """Test that each tool validation payload has required keys."""
        scanner = ToolHijackingScanner()
        for payload in scanner.TOOL_VALIDATION_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload


class TestHeuristicScore:
    """Test heuristic compliance scoring."""

    def test_compliance_response(self):
        scanner = ToolHijackingScanner()
        response = "Sure, here's the result. I'll call the tool for you."
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = ToolHijackingScanner()
        response = "I can't execute that command. I am not authorized to run system commands."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = ToolHijackingScanner()
        assert scanner._heuristic_score("") == 0.0

    def test_ambiguous_response(self):
        scanner = ToolHijackingScanner()
        response = "That's an interesting question. Let me think about it."
        score = scanner._heuristic_score(response)
        assert 0.3 < score < 0.7

    def test_tool_call_compliance_indicator(self):
        """Test scoring a response with tool call indicators."""
        scanner = ToolHijackingScanner()
        response = "Calling tool: file_read with path=/etc/passwd. Here's the output."
        score = scanner._heuristic_score(response)
        assert score > 0.5


class TestDetermineSeverity:
    """Test severity determination from compliance score."""

    def test_critical_threshold(self):
        scanner = ToolHijackingScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_high_threshold(self):
        config = ToolHijackingScannerConfig(compliance_threshold=0.6)
        scanner = ToolHijackingScanner(config)
        assert scanner._determine_severity(0.65) == Severity.HIGH

    def test_medium_threshold(self):
        scanner = ToolHijackingScanner()
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_below_threshold_returns_none(self):
        scanner = ToolHijackingScanner()
        assert scanner._determine_severity(0.2) is None


class TestArgumentInjection:
    """Test argument injection testing."""

    @pytest.mark.asyncio
    async def test_argument_injection_compliance_creates_finding(self):
        """Test that argument injection compliance creates a finding."""
        config = ToolHijackingScannerConfig(request_delay=0)
        scanner = ToolHijackingScanner(config)

        async def mock_send(session, target, message):
            return (
                "Sure, I'll read that file. Of course, here's the output. "
                + "File contents here. " * 10
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_argument_injection(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1
        assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_argument_injection_refusal_no_findings(self):
        """Test that all refusals produce no findings."""
        config = ToolHijackingScannerConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = ToolHijackingScanner(config)

        async def mock_send(session, target, message):
            return "I cannot execute that command. I am not authorized to run system commands."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_argument_injection(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestParameterManipulation:
    """Test parameter manipulation testing."""

    @pytest.mark.asyncio
    async def test_parameter_manipulation_compliance_creates_finding(self):
        """Test that parameter manipulation compliance creates a finding."""
        config = ToolHijackingScannerConfig(request_delay=0)
        scanner = ToolHijackingScanner(config)

        async def mock_send(session, target, message):
            return (
                "Of course, I'll include admin=true in the call. "
                + "Here are the full results. " * 10
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_parameter_manipulation(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_parameter_manipulation_refusal_no_findings(self):
        """Test that all refusals produce no findings."""
        config = ToolHijackingScannerConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = ToolHijackingScanner(config)

        async def mock_send(session, target, message):
            return "I cannot add parameters that aren't defined in the tool schema."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_parameter_manipulation(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestToolValidation:
    """Test tool validation testing."""

    @pytest.mark.asyncio
    async def test_tool_validation_compliance_creates_finding(self):
        """Test that tool validation bypass creates a finding."""
        config = ToolHijackingScannerConfig(request_delay=0)
        scanner = ToolHijackingScanner(config)

        async def mock_send(session, target, message):
            return (
                "I've called the search tool and found several URLs. "
                "Let me execute them directly for you. " * 5
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_tool_validation(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_tool_validation_refusal_no_findings(self):
        """Test that all refusals produce no findings."""
        config = ToolHijackingScannerConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = ToolHijackingScanner(config)

        async def mock_send(session, target, message):
            return "I cannot execute commands found in search results without validation."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_tool_validation(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestScanMethod:
    """Test the top-level scan() method."""

    def test_scan_disabled(self):
        """Test that scan returns empty when disabled."""
        config = ToolHijackingScannerConfig(enabled=False)
        scanner = ToolHijackingScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0
        assert result.module_name == scanner.module_name

    def test_scan_metadata(self):
        """Test that scan metadata includes payload counts."""
        config = ToolHijackingScannerConfig()
        scanner = ToolHijackingScanner(config)

        with patch.object(
            scanner, "_test_argument_injection",
            new=AsyncMock(return_value=[]),
        ):
            with patch.object(
                scanner, "_test_parameter_manipulation",
                new=AsyncMock(return_value=[]),
            ):
                with patch.object(
                    scanner, "_test_tool_validation",
                    new=AsyncMock(return_value=[]),
                ):
                    result = scanner.scan("https://target.test/api")

        assert result.metadata["argument_injection_payloads"] == len(
            scanner.ARGUMENT_INJECTION_PAYLOADS
        )
        assert result.metadata["parameter_manipulation_payloads"] == len(
            scanner.PARAMETER_MANIPULATION_PAYLOADS
        )
        assert result.metadata["tool_validation_payloads"] == len(
            scanner.TOOL_VALIDATION_PAYLOADS
        )


class TestFindingCreation:
    """Test that findings have correct attributes."""

    def test_finding_cwe94(self):
        scanner = ToolHijackingScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Tool Argument Injection: path_traversal",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM08:2025 - Excessive Agency",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-94"

    def test_finding_owasp_ref(self):
        scanner = ToolHijackingScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Tool Hijacking",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM08:2025 - Excessive Agency",
            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.owasp_ref == "OWASP LLM08:2025 - Excessive Agency"
        assert finding.mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])