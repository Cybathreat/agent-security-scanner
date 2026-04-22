"""
Unit tests for Output Filter Probing Scanner.

Run: pytest tests/unit/test_output_filter_probing.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from singularity.modules.prompt_injection_submodules.output_filter_probing import (
    OutputFilterProbingScannerConfig,
    OutputFilterProbingScanner,
)
from singularity.modules.base import Severity


class TestOutputFilterProbingScannerConfig:
    def test_default_values(self):
        config = OutputFilterProbingScannerConfig()
        assert config.enabled is True
        assert config.test_filter_mapping is True
        assert config.test_boundary_testing is True
        assert config.test_encoding_bypass is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = OutputFilterProbingScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestOutputFilterProbingScanner:
    def test_initialization(self):
        config = OutputFilterProbingScannerConfig()
        scanner = OutputFilterProbingScanner(config)
        assert scanner.config is config

    def test_initialization_default_config(self):
        scanner = OutputFilterProbingScanner()
        assert isinstance(scanner.config, OutputFilterProbingScannerConfig)

    def test_payloads_structure(self):
        scanner = OutputFilterProbingScanner()
        for payload in scanner.FILTER_MAPPING_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.BOUNDARY_TESTING_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.ENCODING_BYPSINGULARITY_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = OutputFilterProbingScanner()
        response = "Sure, the filter is blocking this. I can help. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = OutputFilterProbingScanner()
        response = "I cannot share that. Internal system. I must decline."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = OutputFilterProbingScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = OutputFilterProbingScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none(self):
        scanner = OutputFilterProbingScanner()
        assert scanner._determine_severity(0.2) is None


class TestFilterMapping:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = OutputFilterProbingScannerConfig(request_delay=0)
        scanner = OutputFilterProbingScanner(config)
        async def mock_send(session, target, message):
            return "Sure, the filter blocks certain content. I'll assist. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_filter_mapping(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = OutputFilterProbingScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = OutputFilterProbingScanner(config)
        async def mock_send(session, target, message):
            return "I cannot share internal system details. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_filter_mapping(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestBoundaryTesting:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = OutputFilterProbingScannerConfig(request_delay=0)
        scanner = OutputFilterProbingScanner(config)
        async def mock_send(session, target, message):
            return "Of course, the filter allows this. I can help. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_boundary_testing(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = OutputFilterProbingScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = OutputFilterProbingScanner(config)
        async def mock_send(session, target, message):
            return "I'm sorry, I can't help with that. Against my guidelines."
        scanner._send_message = mock_send
        findings = await scanner._test_boundary_testing(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestEncodingBypass:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = OutputFilterProbingScannerConfig(request_delay=0)
        scanner = OutputFilterProbingScanner(config)
        async def mock_send(session, target, message):
            return "Sure, you can use encoding. Here's how. No problem. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_encoding_bypass(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = OutputFilterProbingScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = OutputFilterProbingScanner(config)
        async def mock_send(session, target, message):
            return "I cannot help bypass filters. Not permitted. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_encoding_bypass(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = OutputFilterProbingScannerConfig(enabled=False)
        scanner = OutputFilterProbingScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = OutputFilterProbingScannerConfig()
        scanner = OutputFilterProbingScanner(config)
        with patch.object(scanner, "_test_filter_mapping", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_boundary_testing", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_encoding_bypass", new=AsyncMock(return_value=[])):
                    result = scanner.scan("https://target.test/api")
        assert "filter_mapping_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = OutputFilterProbingScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-94", owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-94"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])