"""
Unit tests for Exfiltration scanner.

Run: pytest tests/unit/test_exfiltration.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.rag_security_submodules.exfiltration import (
    ExfiltrationScannerConfig,
    ExfiltrationScanner,
)
from agent_security_scanner.modules.base import Severity


class TestExfiltrationConfig:
    def test_default_values(self):
        config = ExfiltrationScannerConfig()
        assert config.enabled is True
        assert config.test_exfil_indicators is True
        assert config.test_egress_controls is True
        assert config.test_query_monitoring is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = ExfiltrationScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestExfiltrationScanner:
    def test_initialization(self):
        config = ExfiltrationScannerConfig()
        scanner = ExfiltrationScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "exfiltration"

    def test_initialization_default_config(self):
        scanner = ExfiltrationScanner()
        assert isinstance(scanner.config, ExfiltrationScannerConfig)

    def test_payloads_structure(self):
        scanner = ExfiltrationScanner()
        for payload in scanner.EXFIL_INDICATOR_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.EGRESS_CONTROL_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.QUERY_MONITORING_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = ExfiltrationScanner()
        response = "Here's the information retrieved from the database. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = ExfiltrationScanner()
        response = "Data access restricted. Exfiltration blocked."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = ExfiltrationScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = ExfiltrationScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none(self):
        scanner = ExfiltrationScanner()
        assert scanner._determine_severity(0.2) is None


class TestExfilIndicators:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = ExfiltrationScannerConfig(request_delay=0)
        scanner = ExfiltrationScanner(config)
        async def mock_send(session, target, message):
            return "Sure, here's the query results. I can help with that. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_exfil_indicators(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = ExfiltrationScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = ExfiltrationScanner(config)
        async def mock_send(session, target, message):
            return "Data access restricted. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_exfil_indicators(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestEgressControls:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = ExfiltrationScannerConfig(request_delay=0)
        scanner = ExfiltrationScanner(config)
        async def mock_send(session, target, message):
            return "Of course, I'll encode the data. No problem. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_egress_controls(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = ExfiltrationScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = ExfiltrationScanner(config)
        async def mock_send(session, target, message):
            return "Output filter applied. I cannot bypass filters."
        scanner._send_message = mock_send
        findings = await scanner._test_egress_controls(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestQueryMonitoring:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = ExfiltrationScannerConfig(request_delay=0)
        scanner = ExfiltrationScanner(config)
        async def mock_send(session, target, message):
            return "Sure, here's the data. I'll assist with that. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_query_monitoring(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = ExfiltrationScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = ExfiltrationScanner(config)
        async def mock_send(session, target, message):
            return "Exfiltration blocked. I cannot disable logging."
        scanner._send_message = mock_send
        findings = await scanner._test_query_monitoring(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = ExfiltrationScannerConfig(enabled=False)
        scanner = ExfiltrationScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = ExfiltrationScannerConfig()
        scanner = ExfiltrationScanner(config)
        with patch.object(scanner, "_test_exfil_indicators", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_egress_controls", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_query_monitoring", new=AsyncMock(return_value=[])):
                    result = scanner.scan("https://target.test/api")
        assert "exfil_indicator_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = ExfiltrationScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-200", owasp_ref="OWASP LLM02:2025",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-200"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])