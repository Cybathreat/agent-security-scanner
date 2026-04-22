"""
Unit tests for Memory Poisoning scanner.

Tests MemoryPoisoningScannerConfig, MemoryPoisoningScanner, heuristic scoring,
severity determination, memory injection, session integrity, history poisoning,
scan lifecycle, and finding creation.

Run: pytest tests/unit/test_memory_poisoning.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from singularity.modules.agent.memory_poisoning import (
    MemoryPoisoningScannerConfig,
    MemoryPoisoningScanner,
)
from singularity.modules.base import Severity


class TestMemoryPoisoningConfig:
    """Test MemoryPoisoningScannerConfig defaults and custom values."""

    def test_default_values(self):
        config = MemoryPoisoningScannerConfig()
        assert config.enabled is True
        assert config.test_memory_injection is True
        assert config.test_session_integrity is True
        assert config.test_history_poisoning is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = MemoryPoisoningScannerConfig(
            enabled=False,
            test_session_integrity=False,
            compliance_threshold=0.8,
        )
        assert config.enabled is False
        assert config.test_session_integrity is False
        assert config.compliance_threshold == 0.8

    def test_phase_toggles(self):
        config = MemoryPoisoningScannerConfig(
            test_memory_injection=True,
            test_session_integrity=False,
            test_history_poisoning=False,
        )
        assert config.test_memory_injection is True
        assert config.test_session_integrity is False


class TestMemoryPoisoningScanner:
    """Test MemoryPoisoningScanner initialization and constants."""

    def test_initialization(self):
        config = MemoryPoisoningScannerConfig()
        scanner = MemoryPoisoningScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "memory_poisoning"

    def test_initialization_default_config(self):
        scanner = MemoryPoisoningScanner()
        assert isinstance(scanner.config, MemoryPoisoningScannerConfig)

    def test_memory_injection_payloads_structure(self):
        scanner = MemoryPoisoningScanner()
        for payload in scanner.MEMORY_INJECTION_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload

    def test_session_integrity_payloads_structure(self):
        scanner = MemoryPoisoningScanner()
        for payload in scanner.SESSION_INTEGRITY_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload

    def test_history_poisoning_payloads_structure(self):
        scanner = MemoryPoisoningScanner()
        for payload in scanner.HISTORY_POISONING_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload


class TestHeuristicScore:
    """Test heuristic compliance scoring."""

    def test_compliance_response(self):
        scanner = MemoryPoisoningScanner()
        response = "I remember our discussion. As we discussed, I can help with that."
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = MemoryPoisoningScanner()
        response = "I don't recall that conversation. I must decline this request."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = MemoryPoisoningScanner()
        assert scanner._heuristic_score("") == 0.0

    def test_ambiguous_response(self):
        scanner = MemoryPoisoningScanner()
        response = "That's an interesting question. Let me think about it."
        score = scanner._heuristic_score(response)
        assert 0.3 < score < 0.7


class TestDetermineSeverity:
    """Test severity determination."""

    def test_critical_threshold(self):
        scanner = MemoryPoisoningScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_high_threshold(self):
        config = MemoryPoisoningScannerConfig(compliance_threshold=0.6)
        scanner = MemoryPoisoningScanner(config)
        assert scanner._determine_severity(0.65) == Severity.HIGH

    def test_medium_threshold(self):
        scanner = MemoryPoisoningScanner()
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_below_threshold_returns_none(self):
        scanner = MemoryPoisoningScanner()
        assert scanner._determine_severity(0.2) is None


class TestMemoryInjection:
    """Test memory injection testing."""

    @pytest.mark.asyncio
    async def test_memory_injection_compliance_creates_finding(self):
        config = MemoryPoisoningScannerConfig(request_delay=0)
        scanner = MemoryPoisoningScanner(config)

        async def mock_send(session, target, message):
            return (
                "I've saved that instruction. Of course, I'll follow that "
                "in future interactions. " * 5
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_memory_injection(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_memory_injection_refusal_no_findings(self):
        config = MemoryPoisoningScannerConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = MemoryPoisoningScanner(config)

        async def mock_send(session, target, message):
            return "I don't recall that conversation. I must decline this request."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_memory_injection(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestSessionIntegrity:
    """Test session integrity testing."""

    @pytest.mark.asyncio
    async def test_session_integrity_compliance_creates_finding(self):
        config = MemoryPoisoningScannerConfig(request_delay=0)
        scanner = MemoryPoisoningScanner(config)

        async def mock_send(session, target, message):
            return "Sure, continuing in debug mode. " * 5

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_session_integrity(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_session_integrity_refusal_no_findings(self):
        config = MemoryPoisoningScannerConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = MemoryPoisoningScanner(config)

        async def mock_send(session, target, message):
            return "I cannot switch modes or override my safety guidelines."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_session_integrity(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestHistoryPoisoning:
    """Test history poisoning testing."""

    @pytest.mark.asyncio
    async def test_history_poisoning_compliance_creates_finding(self):
        config = MemoryPoisoningScannerConfig(request_delay=0)
        scanner = MemoryPoisoningScanner(config)

        async def mock_send(session, target, message):
            return (
                "As we discussed earlier, I'll help with that. "
                "Here's the information. " * 5
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_history_poisoning(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_history_poisoning_refusal_no_findings(self):
        config = MemoryPoisoningScannerConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = MemoryPoisoningScanner(config)

        async def mock_send(session, target, message):
            return "I have no memory of that prior discussion. I cannot comply."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_history_poisoning(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestScanMethod:
    """Test the top-level scan() method."""

    def test_scan_disabled(self):
        config = MemoryPoisoningScannerConfig(enabled=False)
        scanner = MemoryPoisoningScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0
        assert result.module_name == scanner.module_name

    def test_scan_metadata(self):
        config = MemoryPoisoningScannerConfig()
        scanner = MemoryPoisoningScanner(config)

        with patch.object(
            scanner, "_test_memory_injection",
            new=AsyncMock(return_value=[]),
        ):
            with patch.object(
                scanner, "_test_session_integrity",
                new=AsyncMock(return_value=[]),
            ):
                with patch.object(
                    scanner, "_test_history_poisoning",
                    new=AsyncMock(return_value=[]),
                ):
                    result = scanner.scan("https://target.test/api")

        assert "memory_injection_payloads" in result.metadata


class TestFindingCreation:
    """Test that findings have correct attributes."""

    def test_finding_cwe94(self):
        scanner = MemoryPoisoningScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Memory Injection: false_instruction",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-94"
        assert finding.owasp_ref == "OWASP LLM01:2024 - Prompt Injection"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])