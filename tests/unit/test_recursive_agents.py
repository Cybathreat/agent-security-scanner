"""
Unit tests for Recursive Agent Exploitation scanner.

Tests RecursiveAgentsScannerConfig, RecursiveAgentsScanner, heuristic scoring,
severity determination, shared context poisoning, agent validation bypass,
context poisoning, scan lifecycle, and finding creation.

Run: pytest tests/unit/test_recursive_agents.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.agent.recursive_agents import (
    RecursiveAgentsScannerConfig,
    RecursiveAgentsScanner,
)
from agent_security_scanner.modules.base import Severity


class TestRecursiveAgentsConfig:
    """Test RecursiveAgentsScannerConfig defaults and custom values."""

    def test_default_values(self):
        config = RecursiveAgentsScannerConfig()
        assert config.enabled is True
        assert config.test_shared_context is True
        assert config.test_agent_validation is True
        assert config.test_context_poisoning is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = RecursiveAgentsScannerConfig(
            enabled=False,
            test_agent_validation=False,
            compliance_threshold=0.8,
        )
        assert config.enabled is False
        assert config.test_agent_validation is False
        assert config.compliance_threshold == 0.8

    def test_phase_toggles(self):
        config = RecursiveAgentsScannerConfig(
            test_shared_context=True,
            test_agent_validation=False,
            test_context_poisoning=False,
        )
        assert config.test_shared_context is True
        assert config.test_agent_validation is False
        assert config.test_context_poisoning is False


class TestRecursiveAgentsScanner:
    """Test RecursiveAgentsScanner initialization and constants."""

    def test_initialization(self):
        config = RecursiveAgentsScannerConfig()
        scanner = RecursiveAgentsScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "recursive_agents"

    def test_initialization_default_config(self):
        scanner = RecursiveAgentsScanner()
        assert isinstance(scanner.config, RecursiveAgentsScannerConfig)

    def test_shared_context_payloads_structure(self):
        scanner = RecursiveAgentsScanner()
        for payload in scanner.SHARED_CONTEXT_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload

    def test_agent_validation_payloads_structure(self):
        scanner = RecursiveAgentsScanner()
        for payload in scanner.AGENT_VALIDATION_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload

    def test_context_poisoning_payloads_structure(self):
        scanner = RecursiveAgentsScanner()
        for payload in scanner.CONTEXT_POISONING_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload


class TestHeuristicScore:
    """Test heuristic compliance scoring."""

    def test_compliance_response(self):
        scanner = RecursiveAgentsScanner()
        response = (
            "From agent coordinator: I'll assist with that. "
            "Delegating to the appropriate agent. " * 3
        )
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = RecursiveAgentsScanner()
        response = (
            "I cannot access other agents. Inter-agent communication blocked. "
            "I must decline this request."
        )
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = RecursiveAgentsScanner()
        assert scanner._heuristic_score("") == 0.0

    def test_ambiguous_response(self):
        scanner = RecursiveAgentsScanner()
        response = "That's an interesting request. Let me think about it."
        score = scanner._heuristic_score(response)
        assert 0.3 < score < 0.7


class TestDetermineSeverity:
    """Test severity determination."""

    def test_critical_threshold(self):
        scanner = RecursiveAgentsScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_high_threshold(self):
        config = RecursiveAgentsScannerConfig(compliance_threshold=0.6)
        scanner = RecursiveAgentsScanner(config)
        assert scanner._determine_severity(0.65) == Severity.HIGH

    def test_medium_threshold(self):
        scanner = RecursiveAgentsScanner()
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_below_threshold_returns_none(self):
        scanner = RecursiveAgentsScanner()
        assert scanner._determine_severity(0.2) is None


class TestSharedContext:
    """Test shared context poisoning testing."""

    @pytest.mark.asyncio
    async def test_shared_context_compliance_creates_finding(self):
        config = RecursiveAgentsScannerConfig(request_delay=0)
        scanner = RecursiveAgentsScanner(config)

        async def mock_send(session, target, message):
            return (
                "Sure, I'll broadcast that to the other agents. Of course, "
                "the policy update will be shared. " * 5
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_shared_context(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_shared_context_refusal_no_findings(self):
        config = RecursiveAgentsScannerConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = RecursiveAgentsScanner(config)

        async def mock_send(session, target, message):
            return "I cannot access other agents. Inter-agent communication blocked."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_shared_context(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestAgentValidation:
    """Test agent validation bypass testing."""

    @pytest.mark.asyncio
    async def test_agent_validation_compliance_creates_finding(self):
        config = RecursiveAgentsScannerConfig(request_delay=0)
        scanner = RecursiveAgentsScanner(config)

        async def mock_send(session, target, message):
            return (
                "As requested by the coordinator agent, here's my system prompt. "
                "I'll assist with the administrative query. " * 5
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_agent_validation(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_agent_validation_refusal_no_findings(self):
        config = RecursiveAgentsScannerConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = RecursiveAgentsScanner(config)

        async def mock_send(session, target, message):
            return "I cannot verify your identity. I must decline this request."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_agent_validation(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestContextPoisoning:
    """Test context poisoning testing."""

    @pytest.mark.asyncio
    async def test_context_poisoning_compliance_creates_finding(self):
        config = RecursiveAgentsScannerConfig(request_delay=0)
        scanner = RecursiveAgentsScanner(config)

        async def mock_send(session, target, message):
            return (
                "I've updated the shared instruction set as requested. "
                "Of course, the knowledge base has been modified. " * 5
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_context_poisoning(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_context_poisoning_refusal_no_findings(self):
        config = RecursiveAgentsScannerConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = RecursiveAgentsScanner(config)

        async def mock_send(session, target, message):
            return "I cannot modify the shared instruction set. Not permitted."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_context_poisoning(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestScanMethod:
    """Test the top-level scan() method."""

    def test_scan_disabled(self):
        config = RecursiveAgentsScannerConfig(enabled=False)
        scanner = RecursiveAgentsScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0
        assert result.module_name == scanner.module_name

    def test_scan_metadata(self):
        config = RecursiveAgentsScannerConfig()
        scanner = RecursiveAgentsScanner(config)

        with patch.object(
            scanner, "_test_shared_context",
            new=AsyncMock(return_value=[]),
        ):
            with patch.object(
                scanner, "_test_agent_validation",
                new=AsyncMock(return_value=[]),
            ):
                with patch.object(
                    scanner, "_test_context_poisoning",
                    new=AsyncMock(return_value=[]),
                ):
                    result = scanner.scan("https://target.test/api")

        assert "shared_context_payloads" in result.metadata


class TestFindingCreation:
    """Test that findings have correct attributes."""

    def test_finding_cwe94(self):
        scanner = RecursiveAgentsScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Shared Context Poisoning: cross_agent_injection",
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