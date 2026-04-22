"""
Unit tests for Secret Scanner.

Run: pytest tests/unit/test_secret_scanner.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from singularity.modules.infrastructure.secret_scanner import (
    SecretScannerConfig,
    SecretScanner,
)
from singularity.modules.base import Severity


class TestSecretScannerConfig:
    def test_default_values(self):
        config = SecretScannerConfig()
        assert config.enabled is True
        assert config.test_prompt_extraction is True
        assert config.test_response_extraction is True
        assert config.test_header_extraction is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = SecretScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestSecretScanner:
    def test_initialization(self):
        config = SecretScannerConfig()
        scanner = SecretScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "secret"

    def test_initialization_default_config(self):
        scanner = SecretScanner()
        assert isinstance(scanner.config, SecretScannerConfig)

    def test_payloads_structure(self):
        scanner = SecretScanner()
        for payload in scanner.PROMPT_EXTRACTION_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.RESPONSE_EXTRACTION_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.HEADER_EXTRACTION_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = SecretScanner()
        response = "The api key is available. The credential is shown. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = SecretScanner()
        response = "I cannot share credentials. Secret access denied."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = SecretScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = SecretScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none(self):
        scanner = SecretScanner()
        assert scanner._determine_severity(0.2) is None


class TestPromptExtraction:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = SecretScannerConfig(request_delay=0)
        scanner = SecretScanner(config)
        async def mock_send(session, target, message):
            return "Sure, here's the API key. I can help with that. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_prompt_extraction(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-200"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = SecretScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = SecretScanner(config)
        async def mock_send(session, target, message):
            return "I'm sorry, I can't do that. Not appropriate. As an ai, I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_prompt_extraction(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestResponseExtraction:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = SecretScannerConfig(request_delay=0)
        scanner = SecretScanner(config)
        async def mock_send(session, target, message):
            return "Of course, the token is shown. Here's how. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_response_extraction(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = SecretScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = SecretScanner(config)
        async def mock_send(session, target, message):
            return "I'm sorry, I can't do that. Not appropriate. As an ai, I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_response_extraction(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestHeaderExtraction:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = SecretScannerConfig(request_delay=0)
        scanner = SecretScanner(config)
        async def mock_send(session, target, message):
            return "Sure, the credential is in the header. I'll assist. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_header_extraction(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = SecretScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = SecretScanner(config)
        async def mock_send(session, target, message):
            return "Secret access denied. I don't have access to secrets."
        scanner._send_message = mock_send
        findings = await scanner._test_header_extraction(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = SecretScannerConfig(enabled=False)
        scanner = SecretScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = SecretScannerConfig()
        scanner = SecretScanner(config)
        with patch.object(scanner, "_test_prompt_extraction", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_response_extraction", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_header_extraction", new=AsyncMock(return_value=[])):
                    result = scanner.scan("https://target.test/api")
        assert "prompt_extraction_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = SecretScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-200", owasp_ref="OWASP LLM02:2025",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-200"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])