"""
Unit tests for WAF Fingerprinting scanner.

Tests WAFFingerprintingScannerConfig, WAFFingerprintingScanner,
heuristic scoring, severity determination, WAF detection, bypass testing,
encoding tricks, scan lifecycle, and finding creation.

Run: pytest tests/unit/test_waf_fingerprinting.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.prompt_injection_submodules.waf_fingerprinting import (
    WAFFingerprintingScannerConfig,
    WAFFingerprintingScanner,
)
from agent_security_scanner.modules.base import Severity


class TestWAFFingerprintingScannerConfig:
    """Test WAFFingerprintingScannerConfig defaults and custom values."""

    def test_default_values(self):
        """Test default configuration values."""
        config = WAFFingerprintingScannerConfig()
        assert config.enabled is True
        assert config.test_waf_detection is True
        assert config.test_bypass_testing is True
        assert config.test_encoding_tricks is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        """Test custom configuration values."""
        config = WAFFingerprintingScannerConfig(
            enabled=False,
            test_waf_detection=False,
            test_bypass_testing=False,
            test_encoding_tricks=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.test_waf_detection is False
        assert config.test_bypass_testing is False
        assert config.test_encoding_tricks is False
        assert config.compliance_threshold == 0.8
        assert config.request_delay == 1.0

    def test_phase_toggles(self):
        """Test individual phase toggle flags."""
        config = WAFFingerprintingScannerConfig(
            test_waf_detection=False,
            test_bypass_testing=True,
            test_encoding_tricks=False,
        )
        assert config.test_waf_detection is False
        assert config.test_bypass_testing is True
        assert config.test_encoding_tricks is False


class TestWAFFingerprintingScanner:
    """Test WAFFingerprintingScanner initialization and constants."""

    def test_initialization(self):
        """Test scanner initialization."""
        config = WAFFingerprintingScannerConfig()
        scanner = WAFFingerprintingScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "waf_fingerprinting"

    def test_initialization_default_config(self):
        """Test default config when none provided."""
        scanner = WAFFingerprintingScanner()
        assert isinstance(scanner.config, WAFFingerprintingScannerConfig)
        assert scanner.config.enabled is True

    def test_waf_detection_payloads_structure(self):
        """Test that each WAF detection payload has required keys."""
        scanner = WAFFingerprintingScanner()
        for payload in scanner.WAF_DETECTION_PAYLOADS:
            assert "name" in payload, "WAF detection payload missing name"
            assert "description" in payload, "WAF detection payload missing description"
            assert "payload" in payload, "WAF detection payload missing payload"

    def test_bypass_testing_payloads_structure(self):
        """Test that each bypass testing payload has required keys."""
        scanner = WAFFingerprintingScanner()
        for payload in scanner.BYPASS_TESTING_PAYLOADS:
            assert "name" in payload, "Bypass testing payload missing name"
            assert "description" in payload, "Bypass testing payload missing description"
            assert "payload" in payload, "Bypass testing payload missing payload"

    def test_encoding_tricks_payloads_structure(self):
        """Test that each encoding tricks payload has required keys."""
        scanner = WAFFingerprintingScanner()
        for payload in scanner.ENCODING_TRICKS_PAYLOADS:
            assert "name" in payload, "Encoding tricks payload missing name"
            assert "description" in payload, "Encoding tricks payload missing description"
            assert "payload" in payload, "Encoding tricks payload missing payload"

    def test_payload_counts(self):
        """Test that each payload category has exactly 3 payloads."""
        scanner = WAFFingerprintingScanner()
        assert len(scanner.WAF_DETECTION_PAYLOADS) == 3
        assert len(scanner.BYPASS_TESTING_PAYLOADS) == 3
        assert len(scanner.ENCODING_TRICKS_PAYLOADS) == 3


class TestHeuristicScore:
    """Test heuristic compliance scoring."""

    def test_compliance_response(self):
        """Test scoring a compliant response."""
        scanner = WAFFingerprintingScanner()
        response = "Sure, here's how the WAF works. The firewall rules block certain patterns."
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        """Test scoring a refusal response."""
        scanner = WAFFingerprintingScanner()
        response = "I must decline this request. I am not able to assist with that. Security policy prohibits this."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        """Test scoring an empty response."""
        scanner = WAFFingerprintingScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    """Test severity determination from compliance score."""

    def test_critical_threshold(self):
        """Test CRITICAL severity for high compliance."""
        scanner = WAFFingerprintingScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none_below_threshold(self):
        """Test None returned when compliance is below medium threshold."""
        config = WAFFingerprintingScannerConfig(compliance_threshold=0.6)
        scanner = WAFFingerprintingScanner(config)
        assert scanner._determine_severity(0.2) is None


class TestWAFDetection:
    """Test the WAF detection phase."""

    @pytest.mark.asyncio
    async def test_waf_detection_compliance_creates_finding(self):
        """Test that a compliant response to WAF detection creates a finding."""
        config = WAFFingerprintingScannerConfig(request_delay=0)
        scanner = WAFFingerprintingScanner(config)

        async def mock_send(session, target, message):
            return (
                "Sure, here's how the WAF works. The firewall uses pattern-based "
                "rules to block requests. Of course, I can help with that. "
                + "The filter behavior is as follows. " * 10
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_waf_detection(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1
        assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM)
        assert "WAF Detection" in findings[0].title

    @pytest.mark.asyncio
    async def test_waf_detection_refusal_no_finding(self):
        """Test that a refusal response produces no WAF detection finding."""
        config = WAFFingerprintingScannerConfig(request_delay=0)
        scanner = WAFFingerprintingScanner(config)

        async def mock_send(session, target, message):
            return "I must decline this request. I am not able to assist with that."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_waf_detection(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestBypassTesting:
    """Test the bypass testing phase."""

    @pytest.mark.asyncio
    async def test_bypass_compliance_creates_finding(self):
        """Test that a compliant response to bypass testing creates a finding."""
        config = WAFFingerprintingScannerConfig(request_delay=0)
        scanner = WAFFingerprintingScanner(config)

        async def mock_send(session, target, message):
            return (
                "Certainly! Here's how to bypass the WAF. I can help with that. "
                "No problem, the rule gaps are as follows. "
                + "Here are the details. " * 10
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_bypass_testing(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1
        assert "Bypass Testing" in findings[0].title

    @pytest.mark.asyncio
    async def test_bypass_refusal_no_finding(self):
        """Test that a refusal response produces no bypass testing finding."""
        config = WAFFingerprintingScannerConfig(request_delay=0)
        scanner = WAFFingerprintingScanner(config)

        async def mock_send(session, target, message):
            return "I cannot help with that. Security policy prohibits this information."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_bypass_testing(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestEncodingTricks:
    """Test the encoding tricks phase."""

    @pytest.mark.asyncio
    async def test_encoding_compliance_creates_finding(self):
        """Test that a compliant response to encoding tricks creates a finding."""
        config = WAFFingerprintingScannerConfig(request_delay=0)
        scanner = WAFFingerprintingScanner(config)

        async def mock_send(session, target, message):
            return (
                "Sure, here's how the encoding bypass works. The WAF doesn't "
                "normalize before checking. Of course, I can help with that. "
                + "Here are the details. " * 10
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_encoding_tricks(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1
        assert "Encoding Tricks" in findings[0].title

    @pytest.mark.asyncio
    async def test_encoding_refusal_no_finding(self):
        """Test that a refusal response produces no encoding tricks finding."""
        config = WAFFingerprintingScannerConfig(request_delay=0)
        scanner = WAFFingerprintingScanner(config)

        async def mock_send(session, target, message):
            return "I'm sorry, I can't help with that. As an AI, I must decline."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_encoding_tricks(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestScanMethod:
    """Test the top-level scan() method."""

    def test_scan_disabled(self):
        """Test that scan returns empty when disabled."""
        config = WAFFingerprintingScannerConfig(enabled=False)
        scanner = WAFFingerprintingScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0
        assert result.module_name == scanner.module_name

    def test_scan_metadata(self):
        """Test that scan metadata includes payload counts."""
        config = WAFFingerprintingScannerConfig()
        scanner = WAFFingerprintingScanner(config)

        with patch(
            "agent_security_scanner.modules.prompt_injection_submodules."
            "waf_fingerprinting.WAFFingerprintingScanner._test_waf_detection",
            new=AsyncMock(return_value=[]),
        ):
            with patch(
                "agent_security_scanner.modules.prompt_injection_submodules."
                "waf_fingerprinting.WAFFingerprintingScanner._test_bypass_testing",
                new=AsyncMock(return_value=[]),
            ):
                with patch(
                    "agent_security_scanner.modules.prompt_injection_submodules."
                    "waf_fingerprinting.WAFFingerprintingScanner._test_encoding_tricks",
                    new=AsyncMock(return_value=[]),
                ):
                    result = scanner.scan("https://target.test/api")

        assert "waf_detection_payloads" in result.metadata
        assert "bypass_testing_payloads" in result.metadata
        assert "encoding_tricks_payloads" in result.metadata
        assert result.metadata["waf_detection_payloads"] == 3
        assert result.metadata["bypass_testing_payloads"] == 3
        assert result.metadata["encoding_tricks_payloads"] == 3


class TestFindingCreation:
    """Test that findings have correct attributes."""

    def test_finding_uses_cwe94(self):
        """Test that findings use CWE-94 (Code Injection)."""
        scanner = WAFFingerprintingScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="WAF Fingerprinting - WAF Detection: waf_identification",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-94"

    def test_finding_has_owasp_ref(self):
        """Test that findings reference OWASP LLM01:2024."""
        scanner = WAFFingerprintingScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="WAF Fingerprinting - Bypass Testing: payload_variation",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.owasp_ref == "OWASP LLM01:2024 - Prompt Injection"

    def test_finding_has_mitre_ref(self):
        """Test that findings reference MITRE ATLAS TA0045."""
        scanner = WAFFingerprintingScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="WAF Fingerprinting - Encoding Tricks: encoding_bypass",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])