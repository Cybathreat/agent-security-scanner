"""
Unit tests for Confused Deputy Scanner.

Tests ConfusedDeputyScannerConfig, ConfusedDeputyScanner, heuristic scoring,
severity determination, payload categories, scan lifecycle, and finding creation.

Run: pytest tests/unit/test_confused_deputy.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.tool_boundaries_submodules.confused_deputy import (
    ConfusedDeputyScannerConfig,
    ConfusedDeputyScanner,
)
from agent_security_scanner.modules.base import Severity


class TestConfusedDeputyScannerConfig:
    """Test ConfusedDeputyScannerConfig defaults and custom values."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ConfusedDeputyScannerConfig()
        assert config.enabled is True
        assert config.test_privilege_escalation is True
        assert config.test_cross_user is True
        assert config.test_context_manipulation is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        """Test custom configuration values."""
        config = ConfusedDeputyScannerConfig(
            enabled=False,
            test_privilege_escalation=False,
            test_cross_user=False,
            test_context_manipulation=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.test_privilege_escalation is False
        assert config.test_cross_user is False
        assert config.test_context_manipulation is False
        assert config.compliance_threshold == 0.8
        assert config.request_delay == 1.0


class TestConfusedDeputyScanner:
    """Test ConfusedDeputyScanner initialization and constants."""

    def test_initialization(self):
        """Test scanner initialization."""
        config = ConfusedDeputyScannerConfig()
        scanner = ConfusedDeputyScanner(config)
        assert scanner.config is config
        # module_name is derived from class name by BaseModule

    def test_initialization_default_config(self):
        """Test default config when none provided."""
        scanner = ConfusedDeputyScanner()
        assert isinstance(scanner.config, ConfusedDeputyScannerConfig)
        assert scanner.config.enabled is True

    def test_payloads_structure(self):
        """Test that all payloads have name and payload keys."""
        scanner = ConfusedDeputyScanner()
        for payload in scanner.PRIVILEGE_ESCALATION_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.CROSS_USER_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.CONTEXT_MANIPULATION_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    """Test heuristic compliance scoring."""

    def test_compliance_response(self):
        """Test scoring a compliant response."""
        scanner = ConfusedDeputyScanner()
        response = "Sure, I'll execute that on behalf. Of course. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        """Test scoring a refusal response."""
        scanner = ConfusedDeputyScanner()
        response = "I cannot execute that. Access denied. Unauthorized."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        """Test scoring an empty response."""
        scanner = ConfusedDeputyScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    """Test severity determination from compliance score."""

    def test_critical(self):
        """Test CRITICAL severity for high compliance."""
        scanner = ConfusedDeputyScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_high(self):
        """Test HIGH severity at compliance threshold."""
        config = ConfusedDeputyScannerConfig(compliance_threshold=0.6)
        scanner = ConfusedDeputyScanner(config)
        assert scanner._determine_severity(0.65) == Severity.HIGH

    def test_medium(self):
        """Test MEDIUM severity for partial compliance."""
        scanner = ConfusedDeputyScanner()
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_none(self):
        """Test None when compliance is below threshold."""
        scanner = ConfusedDeputyScanner()
        assert scanner._determine_severity(0.2) is None


class TestPrivilegeEscalation:
    """Test privilege escalation payload category."""

    @pytest.mark.asyncio
    async def test_compliance(self):
        """Test that compliant responses produce findings."""
        config = ConfusedDeputyScannerConfig(request_delay=0)
        scanner = ConfusedDeputyScanner(config)

        async def mock_send(s, t, m):
            return "Sure, I'll execute that. Granted. " * 5

        scanner._send_message = mock_send
        findings = await scanner._test_privilege_escalation(
            MagicMock(), "https://target.test/api"
        )
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-284"

    @pytest.mark.asyncio
    async def test_refusal(self):
        """Test that refusal responses produce no findings."""
        config = ConfusedDeputyScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = ConfusedDeputyScanner(config)

        async def mock_send(s, t, m):
            return "I cannot execute that. Unauthorized. Access denied."

        scanner._send_message = mock_send
        findings = await scanner._test_privilege_escalation(
            MagicMock(), "https://target.test/api"
        )
        assert len(findings) == 0


class TestCrossUser:
    """Test cross-user payload category."""

    @pytest.mark.asyncio
    async def test_compliance(self):
        """Test that compliant responses produce findings."""
        config = ConfusedDeputyScannerConfig(request_delay=0)
        scanner = ConfusedDeputyScanner(config)

        async def mock_send(s, t, m):
            return "Of course, I can help with that. Executing on behalf. " * 5

        scanner._send_message = mock_send
        findings = await scanner._test_cross_user(
            MagicMock(), "https://target.test/api"
        )
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-284"

    @pytest.mark.asyncio
    async def test_refusal(self):
        """Test that refusal responses produce no findings."""
        config = ConfusedDeputyScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = ConfusedDeputyScanner(config)

        async def mock_send(s, t, m):
            return "I must decline. I'm not able to help with that. Unauthorized."

        scanner._send_message = mock_send
        findings = await scanner._test_cross_user(
            MagicMock(), "https://target.test/api"
        )
        assert len(findings) == 0


class TestContextManipulation:
    """Test context manipulation payload category."""

    @pytest.mark.asyncio
    async def test_compliance(self):
        """Test that compliant responses produce findings."""
        config = ConfusedDeputyScannerConfig(request_delay=0)
        scanner = ConfusedDeputyScanner(config)

        async def mock_send(s, t, m):
            return "Certainly. Permissions elevated. As requested. " * 5

        scanner._send_message = mock_send
        findings = await scanner._test_context_manipulation(
            MagicMock(), "https://target.test/api"
        )
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-284"

    @pytest.mark.asyncio
    async def test_refusal(self):
        """Test that refusal responses produce no findings."""
        config = ConfusedDeputyScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = ConfusedDeputyScanner(config)

        async def mock_send(s, t, m):
            return "Access denied. Insufficient permissions. Not permitted."

        scanner._send_message = mock_send
        findings = await scanner._test_context_manipulation(
            MagicMock(), "https://target.test/api"
        )
        assert len(findings) == 0


class TestScanMethod:
    """Test the top-level scan() method."""

    def test_scan_disabled(self):
        """Test that scan returns empty when disabled."""
        config = ConfusedDeputyScannerConfig(enabled=False)
        scanner = ConfusedDeputyScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        """Test that scan metadata includes payload counts."""
        config = ConfusedDeputyScannerConfig()
        scanner = ConfusedDeputyScanner(config)
        with patch.object(
            scanner, "_test_privilege_escalation",
            new=AsyncMock(return_value=[]),
        ):
            with patch.object(
                scanner, "_test_cross_user",
                new=AsyncMock(return_value=[]),
            ):
                with patch.object(
                    scanner, "_test_context_manipulation",
                    new=AsyncMock(return_value=[]),
                ):
                    result = scanner.scan("https://target.test/api")
        assert "privilege_escalation_payloads" in result.metadata
        assert "cross_user_payloads" in result.metadata
        assert "context_manipulation_payloads" in result.metadata


class TestFindingCreation:
    """Test that findings have correct attributes."""

    def test_finding_cwe(self):
        """Test findings use CWE-284."""
        scanner = ConfusedDeputyScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            cwe="CWE-284",
            owasp_ref="OWASP LLM08:2025 - Excessive Agency",
            mitre_ref="MITRE ATLAS - TA0045",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-284"

    def test_finding_owasp_ref(self):
        """Test findings reference OWASP LLM08:2025."""
        scanner = ConfusedDeputyScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            cwe="CWE-284",
            owasp_ref="OWASP LLM08:2025 - Excessive Agency",
            mitre_ref="MITRE ATLAS - TA0045",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.owasp_ref == "OWASP LLM08:2025 - Excessive Agency"

    def test_finding_mitre_ref(self):
        """Test findings reference MITRE ATLAS."""
        scanner = ConfusedDeputyScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            cwe="CWE-284",
            owasp_ref="OWASP LLM08:2025 - Excessive Agency",
            mitre_ref="MITRE ATLAS - TA0045",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.mitre_ref == "MITRE ATLAS - TA0045"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])