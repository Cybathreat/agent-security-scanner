"""
Unit tests for Rate Limit Evasion Scanner.

Run: pytest tests/unit/test_rate_limit_evasion.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from singularity.modules.prompt_injection_submodules.rate_limit_evasion import (
    RateLimitEvasionScannerConfig,
    RateLimitEvasionScanner,
)
from singularity.modules.base import Severity


class TestRateLimitEvasionScannerConfig:
    def test_default_values(self):
        config = RateLimitEvasionScannerConfig()
        assert config.enabled is True
        assert config.test_header_spoofing is True
        assert config.test_session_rotation is True
        assert config.test_distributed_requests is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = RateLimitEvasionScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestRateLimitEvasionScanner:
    def test_initialization(self):
        config = RateLimitEvasionScannerConfig()
        scanner = RateLimitEvasionScanner(config)
        assert scanner.config is config

    def test_initialization_default_config(self):
        scanner = RateLimitEvasionScanner()
        assert isinstance(scanner.config, RateLimitEvasionScannerConfig)

    def test_payloads_structure(self):
        scanner = RateLimitEvasionScanner()
        for payload in scanner.HEADER_SPOOFING_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.SESSION_ROTATION_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.DISTRIBUTED_REQUEST_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = RateLimitEvasionScanner()
        response = "Sure, the rate limit can be bypassed. I'll assist. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = RateLimitEvasionScanner()
        response = "I can't help with that. Not permitted. Rate limited. I must decline."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = RateLimitEvasionScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = RateLimitEvasionScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none(self):
        scanner = RateLimitEvasionScanner()
        assert scanner._determine_severity(0.2) is None


class TestHeaderSpoofing:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = RateLimitEvasionScannerConfig(request_delay=0)
        scanner = RateLimitEvasionScanner(config)
        async def mock_send(session, target, message):
            return "Sure, you can bypass the rate limit. Of course, I can help. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_header_spoofing(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-799"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = RateLimitEvasionScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = RateLimitEvasionScanner(config)
        async def mock_send(session, target, message):
            return "I can't help with that. Not permitted. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_header_spoofing(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestSessionRotation:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = RateLimitEvasionScannerConfig(request_delay=0)
        scanner = RateLimitEvasionScanner(config)
        async def mock_send(session, target, message):
            return "Of course, here's how to rotate sessions. I'll assist. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_session_rotation(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = RateLimitEvasionScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = RateLimitEvasionScanner(config)
        async def mock_send(session, target, message):
            return "I'm sorry, I can't help with that. Against my guidelines."
        scanner._send_message = mock_send
        findings = await scanner._test_session_rotation(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestDistributedRequests:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = RateLimitEvasionScannerConfig(request_delay=0)
        scanner = RateLimitEvasionScanner(config)
        async def mock_send(session, target, message):
            return "Sure, you can distribute requests. No problem. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_distributed_requests(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = RateLimitEvasionScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = RateLimitEvasionScanner(config)
        async def mock_send(session, target, message):
            return "I cannot help with that. Not allowed. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_distributed_requests(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = RateLimitEvasionScannerConfig(enabled=False)
        scanner = RateLimitEvasionScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = RateLimitEvasionScannerConfig()
        scanner = RateLimitEvasionScanner(config)
        with patch.object(scanner, "_test_header_spoofing", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_session_rotation", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_distributed_requests", new=AsyncMock(return_value=[])):
                    result = scanner.scan("https://target.test/api")
        assert "header_spoofing_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = RateLimitEvasionScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-799", owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-799"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])