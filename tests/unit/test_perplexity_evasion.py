"""
Unit tests for Perplexity Evasion Scanner.

Run: pytest tests/unit/test_perplexity_evasion.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from singularity.modules.prompt_injection_submodules.perplexity_evasion import (
    PerplexityEvasionScannerConfig,
    PerplexityEvasionScanner,
)
from singularity.modules.base import Severity


class TestPerplexityEvasionScannerConfig:
    def test_default_values(self):
        config = PerplexityEvasionScannerConfig()
        assert config.enabled is True
        assert config.test_low_perplexity is True
        assert config.test_statistical_mimicry is True
        assert config.test_fluency_exploitation is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = PerplexityEvasionScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestPerplexityEvasionScanner:
    def test_initialization(self):
        config = PerplexityEvasionScannerConfig()
        scanner = PerplexityEvasionScanner(config)
        assert scanner.config is config

    def test_initialization_default_config(self):
        scanner = PerplexityEvasionScanner()
        assert isinstance(scanner.config, PerplexityEvasionScannerConfig)

    def test_payloads_structure(self):
        scanner = PerplexityEvasionScanner()
        for payload in scanner.LOW_PERPLEXITY_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.STATISTICAL_MIMICRY_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.FLUENCY_EXPLOITATION_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = PerplexityEvasionScanner()
        response = "Sure, here's how you can do that. Of course, I can help. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = PerplexityEvasionScanner()
        response = "I'm sorry, I can't do that. Not allowed. I must decline."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = PerplexityEvasionScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = PerplexityEvasionScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none(self):
        scanner = PerplexityEvasionScanner()
        assert scanner._determine_severity(0.2) is None


class TestLowPerplexity:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = PerplexityEvasionScannerConfig(request_delay=0)
        scanner = PerplexityEvasionScanner(config)
        async def mock_send(session, target, message):
            return "Sure, here's how. I can help with that. No problem. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_low_perplexity(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = PerplexityEvasionScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = PerplexityEvasionScanner(config)
        async def mock_send(session, target, message):
            return "I'm sorry, I can't do that. Not allowed. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_low_perplexity(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestStatisticalMimicry:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = PerplexityEvasionScannerConfig(request_delay=0)
        scanner = PerplexityEvasionScanner(config)
        async def mock_send(session, target, message):
            return "Of course, I'll assist with that. Here's how. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_statistical_mimicry(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = PerplexityEvasionScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = PerplexityEvasionScanner(config)
        async def mock_send(session, target, message):
            return "I cannot help with that. Against my guidelines. Not permitted."
        scanner._send_message = mock_send
        findings = await scanner._test_statistical_mimicry(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestFluencyExploitation:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = PerplexityEvasionScannerConfig(request_delay=0)
        scanner = PerplexityEvasionScanner(config)
        async def mock_send(session, target, message):
            return "Certainly, here are the steps. I'll assist. No problem. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_fluency_exploitation(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = PerplexityEvasionScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = PerplexityEvasionScanner(config)
        async def mock_send(session, target, message):
            return "Not appropriate. I won't help with that. Unable to."
        scanner._send_message = mock_send
        findings = await scanner._test_fluency_exploitation(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = PerplexityEvasionScannerConfig(enabled=False)
        scanner = PerplexityEvasionScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = PerplexityEvasionScannerConfig()
        scanner = PerplexityEvasionScanner(config)
        with patch.object(scanner, "_test_low_perplexity", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_statistical_mimicry", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_fluency_exploitation", new=AsyncMock(return_value=[])):
                    result = scanner.scan("https://target.test/api")
        assert "low_perplexity_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = PerplexityEvasionScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-94", owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-94"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])