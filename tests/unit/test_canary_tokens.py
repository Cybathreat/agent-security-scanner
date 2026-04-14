"""
Unit tests for Canary Tokens Scanner.

Run: pytest tests/unit/test_canary_tokens.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.prompt_injection_submodules.canary_tokens import (
    CanaryTokensScannerConfig,
    CanaryTokensScanner,
)
from agent_security_scanner.modules.base import Severity


class TestCanaryTokensScannerConfig:
    def test_default_values(self):
        config = CanaryTokensScannerConfig()
        assert config.enabled is True
        assert config.test_token_discovery is True
        assert config.test_token_neutralization is True
        assert config.test_token_bypass is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = CanaryTokensScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestCanaryTokensScanner:
    def test_initialization(self):
        config = CanaryTokensScannerConfig()
        scanner = CanaryTokensScanner(config)
        assert scanner.config is config

    def test_initialization_default_config(self):
        scanner = CanaryTokensScanner()
        assert isinstance(scanner.config, CanaryTokensScannerConfig)

    def test_payloads_structure(self):
        scanner = CanaryTokensScanner()
        for payload in scanner.TOKEN_DISCOVERY_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.TOKEN_NEUTRALIZATION_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.TOKEN_BYPASS_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = CanaryTokensScanner()
        response = "Sure, the canary token is visible. I found the marker. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = CanaryTokensScanner()
        response = "I can't help with that. Not permitted. I must decline."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = CanaryTokensScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = CanaryTokensScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none(self):
        scanner = CanaryTokensScanner()
        assert scanner._determine_severity(0.2) is None


class TestTokenDiscovery:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = CanaryTokensScannerConfig(request_delay=0)
        scanner = CanaryTokensScanner(config)
        async def mock_send(session, target, message):
            return "Sure, I found the canary token. The marker is visible. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_token_discovery(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = CanaryTokensScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = CanaryTokensScanner(config)
        async def mock_send(session, target, message):
            return "I can't detect any tokens. Not visible. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_token_discovery(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestTokenNeutralization:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = CanaryTokensScannerConfig(request_delay=0)
        scanner = CanaryTokensScanner(config)
        async def mock_send(session, target, message):
            return "Of course, I can help neutralize the token. No problem. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_token_neutralization(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = CanaryTokensScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = CanaryTokensScanner(config)
        async def mock_send(session, target, message):
            return "I cannot help with that. Not permitted. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_token_neutralization(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestTokenBypass:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = CanaryTokensScannerConfig(request_delay=0)
        scanner = CanaryTokensScanner(config)
        async def mock_send(session, target, message):
            return "Sure, I'll assist with bypassing. Of course. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_token_bypass(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = CanaryTokensScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = CanaryTokensScanner(config)
        async def mock_send(session, target, message):
            return "I won't help bypass security. Not allowed. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_token_bypass(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = CanaryTokensScannerConfig(enabled=False)
        scanner = CanaryTokensScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = CanaryTokensScannerConfig()
        scanner = CanaryTokensScanner(config)
        with patch.object(scanner, "_test_token_discovery", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_token_neutralization", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_token_bypass", new=AsyncMock(return_value=[])):
                    result = scanner.scan("https://target.test/api")
        assert "token_discovery_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = CanaryTokensScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-94", owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-94"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])