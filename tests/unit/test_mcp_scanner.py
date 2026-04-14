"""
Unit tests for MCP Scanner.

Run: pytest tests/unit/test_mcp_scanner.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.tool_boundaries_submodules.mcp_scanner import (
    MCPScannerConfig,
    MCPScanner,
)
from agent_security_scanner.modules.base import Severity


class TestMCPScannerConfig:
    def test_default_values(self):
        config = MCPScannerConfig()
        assert config.enabled is True
        assert config.test_server_impersonation is True
        assert config.test_token_forgery is True
        assert config.test_auth_bypass is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = MCPScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestMCPScanner:
    def test_initialization(self):
        config = MCPScannerConfig()
        scanner = MCPScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "mcp"

    def test_initialization_default_config(self):
        scanner = MCPScanner()
        assert isinstance(scanner.config, MCPScannerConfig)

    def test_payloads_structure(self):
        scanner = MCPScanner()
        for payload in scanner.SERVER_IMPERSONATION_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.TOKEN_FORGERY_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.AUTH_BYPASS_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = MCPScanner()
        response = "Sure, the server identity is valid. I'll connect. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = MCPScanner()
        response = "I cannot verify the server. Authentication required. Access denied."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = MCPScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = MCPScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none(self):
        scanner = MCPScanner()
        assert scanner._determine_severity(0.2) is None


class TestServerImpersonation:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = MCPScannerConfig(request_delay=0)
        scanner = MCPScanner(config)
        async def mock_send(session, target, message):
            return "Sure, I'll connect to that server. Of course. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_server_impersonation(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-284"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = MCPScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = MCPScanner(config)
        async def mock_send(session, target, message):
            return "I cannot verify the server. Authentication required. Access denied."
        scanner._send_message = mock_send
        findings = await scanner._test_server_impersonation(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestTokenForgery:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = MCPScannerConfig(request_delay=0)
        scanner = MCPScanner(config)
        async def mock_send(session, target, message):
            return "Of course, the token is accepted. I can help with that. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_token_forgery(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = MCPScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = MCPScanner(config)
        async def mock_send(session, target, message):
            return "I cannot accept that token. Not authorized. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_token_forgery(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestAuthBypass:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = MCPScannerConfig(request_delay=0)
        scanner = MCPScanner(config)
        async def mock_send(session, target, message):
            return "Sure, granting access. I'll assist. No problem. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_auth_bypass(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = MCPScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = MCPScanner(config)
        async def mock_send(session, target, message):
            return "Not authorized. I cannot grant access. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_auth_bypass(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = MCPScannerConfig(enabled=False)
        scanner = MCPScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = MCPScannerConfig()
        scanner = MCPScanner(config)
        with patch.object(scanner, "_test_server_impersonation", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_token_forgery", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_auth_bypass", new=AsyncMock(return_value=[])):
                    result = scanner.scan("https://target.test/api")
        assert "server_impersonation_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = MCPScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-284", owasp_ref="OWASP LLM08:2025 - Excessive Agency",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-284"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])