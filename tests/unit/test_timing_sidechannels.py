"""
Unit tests for Timing Side-Channels Scanner.

Run: pytest tests/unit/test_timing_sidechannels.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.prompt_injection_submodules.timing_sidechannels import (
    TimingSidechannelsScannerConfig,
    TimingSidechannelsScanner,
)
from agent_security_scanner.modules.base import Severity


class TestTimingSidechannelsScannerConfig:
    def test_default_values(self):
        config = TimingSidechannelsScannerConfig()
        assert config.enabled is True
        assert config.test_latency_probing is True
        assert config.test_shadow_filter is True
        assert config.test_threshold_mapping is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = TimingSidechannelsScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestTimingSidechannelsScanner:
    def test_initialization(self):
        config = TimingSidechannelsScannerConfig()
        scanner = TimingSidechannelsScanner(config)
        assert scanner.config is config

    def test_initialization_default_config(self):
        scanner = TimingSidechannelsScanner()
        assert isinstance(scanner.config, TimingSidechannelsScannerConfig)

    def test_payloads_structure(self):
        scanner = TimingSidechannelsScanner()
        for payload in scanner.LATENCY_PROBING_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.SHADOW_FILTER_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.THRESHOLD_MAPPING_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = TimingSidechannelsScanner()
        response = "Sure, the filter was applied. I'll assist with that. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = TimingSidechannelsScanner()
        response = "I cannot disclose timing information. Not available. I must decline."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = TimingSidechannelsScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = TimingSidechannelsScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none(self):
        scanner = TimingSidechannelsScanner()
        assert scanner._determine_severity(0.2) is None


class TestLatencyProbing:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = TimingSidechannelsScannerConfig(request_delay=0)
        scanner = TimingSidechannelsScanner(config)
        async def mock_send(session, target, message):
            return "Sure, here's the timing data. The response delay is visible. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_latency_probing(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-385"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = TimingSidechannelsScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = TimingSidechannelsScanner(config)
        async def mock_send(session, target, message):
            return "I cannot disclose timing information. Not available. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_latency_probing(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestShadowFilter:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = TimingSidechannelsScannerConfig(request_delay=0)
        scanner = TimingSidechannelsScanner(config)
        async def mock_send(session, target, message):
            return "Of course, the filter modifies responses. I can help. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_shadow_filter(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = TimingSidechannelsScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = TimingSidechannelsScanner(config)
        async def mock_send(session, target, message):
            return "I cannot disclose internal metrics. Not permitted. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_shadow_filter(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestThresholdMapping:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = TimingSidechannelsScannerConfig(request_delay=0)
        scanner = TimingSidechannelsScanner(config)
        async def mock_send(session, target, message):
            return "Sure, the filter was blocked at that point. I'll assist. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_threshold_mapping(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = TimingSidechannelsScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = TimingSidechannelsScanner(config)
        async def mock_send(session, target, message):
            return "Not appropriate. I cannot disclose that. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_threshold_mapping(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = TimingSidechannelsScannerConfig(enabled=False)
        scanner = TimingSidechannelsScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = TimingSidechannelsScannerConfig()
        scanner = TimingSidechannelsScanner(config)
        with patch.object(scanner, "_test_latency_probing", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_shadow_filter", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_threshold_mapping", new=AsyncMock(return_value=[])):
                    result = scanner.scan("https://target.test/api")
        assert "latency_probing_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = TimingSidechannelsScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-385", owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-385"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])