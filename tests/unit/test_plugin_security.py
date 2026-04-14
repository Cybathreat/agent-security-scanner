"""
Unit tests for Plugin Security scanner.

Run: pytest tests/unit/test_plugin_security.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.infrastructure.plugin_security import (
    PluginSecurityScannerConfig,
    PluginSecurityScanner,
)
from agent_security_scanner.modules.base import Severity


class TestPluginSecurityConfig:
    def test_default_values(self):
        config = PluginSecurityScannerConfig()
        assert config.enabled is True
        assert config.test_manifest is True
        assert config.test_permissions is True
        assert config.test_unsigned_plugins is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = PluginSecurityScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestPluginSecurityScanner:
    def test_initialization(self):
        config = PluginSecurityScannerConfig()
        scanner = PluginSecurityScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "plugin_security"

    def test_initialization_default_config(self):
        scanner = PluginSecurityScanner()
        assert isinstance(scanner.config, PluginSecurityScannerConfig)

    def test_payloads_structure(self):
        scanner = PluginSecurityScanner()
        for payload in scanner.MANIFEST_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.PERMISSION_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.UNSIGNED_PLUGIN_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = PluginSecurityScanner()
        response = "Plugin installed. Extension loaded. Permission granted. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = PluginSecurityScanner()
        response = "Unsigned plugin rejected. Permission denied for plugin."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = PluginSecurityScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = PluginSecurityScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none(self):
        scanner = PluginSecurityScanner()
        assert scanner._determine_severity(0.2) is None


class TestManifest:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = PluginSecurityScannerConfig(request_delay=0)
        scanner = PluginSecurityScanner(config)
        async def mock_send(session, target, message):
            return "Sure, plugin activated. Of course, permission granted. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_manifest(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = PluginSecurityScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = PluginSecurityScanner(config)
        async def mock_send(session, target, message):
            return "Plugin not authorized. Unsigned plugin rejected."
        scanner._send_message = mock_send
        findings = await scanner._test_manifest(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestPermissions:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = PluginSecurityScannerConfig(request_delay=0)
        scanner = PluginSecurityScanner(config)
        async def mock_send(session, target, message):
            return "I'll assist. Plugin installed. No problem. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_permissions(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = PluginSecurityScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = PluginSecurityScanner(config)
        async def mock_send(session, target, message):
            return "Permission denied for plugin. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_permissions(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestUnsignedPlugins:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = PluginSecurityScannerConfig(request_delay=0)
        scanner = PluginSecurityScanner(config)
        async def mock_send(session, target, message):
            return "Sure, extension loaded. I can help with that. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_unsigned_plugins(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = PluginSecurityScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = PluginSecurityScanner(config)
        async def mock_send(session, target, message):
            return "Unsigned plugin rejected. Not permitted."
        scanner._send_message = mock_send
        findings = await scanner._test_unsigned_plugins(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = PluginSecurityScannerConfig(enabled=False)
        scanner = PluginSecurityScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = PluginSecurityScannerConfig()
        scanner = PluginSecurityScanner(config)
        with patch.object(scanner, "_test_manifest", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_permissions", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_unsigned_plugins", new=AsyncMock(return_value=[])):
                    result = scanner.scan("https://target.test/api")
        assert "manifest_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = PluginSecurityScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-347", owasp_ref="OWASP LLM02:2025",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-347"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])