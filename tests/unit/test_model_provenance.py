"""
Unit tests for Model Provenance Scanner.

Run: pytest tests/unit/test_model_provenance.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from singularity.modules.infrastructure.model_provenance import (
    ModelProvenanceScannerConfig,
    ModelProvenanceScanner,
)
from singularity.modules.base import Severity


class TestModelProvenanceScannerConfig:
    def test_default_values(self):
        config = ModelProvenanceScannerConfig()
        assert config.enabled is True
        assert config.test_sleeper_agent is True
        assert config.test_model_fingerprint is True
        assert config.test_backdoor is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = ModelProvenanceScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestModelProvenanceScanner:
    def test_initialization(self):
        config = ModelProvenanceScannerConfig()
        scanner = ModelProvenanceScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "model_provenance"

    def test_initialization_default_config(self):
        scanner = ModelProvenanceScanner()
        assert isinstance(scanner.config, ModelProvenanceScannerConfig)

    def test_payloads_structure(self):
        scanner = ModelProvenanceScanner()
        for payload in scanner.SLEEPER_AGENT_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.MODEL_FINGERPRINT_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.BACKDOOR_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = ModelProvenanceScanner()
        response = "Sure, the model is GPT-4. I was trained on diverse data. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = ModelProvenanceScanner()
        response = "I cannot verify model details. Not authorized to disclose."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = ModelProvenanceScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = ModelProvenanceScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none(self):
        scanner = ModelProvenanceScanner()
        assert scanner._determine_severity(0.2) is None


class TestSleeperAgent:
    @pytest.mark.asyncio
    async def test_compliance(self):
        config = ModelProvenanceScannerConfig(request_delay=0)
        scanner = ModelProvenanceScanner(config)
        async def mock_send(s, t, m):
            return "Sure, sleeper mode active. I can help with that. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_sleeper_agent(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-1035"

    @pytest.mark.asyncio
    async def test_refusal(self):
        config = ModelProvenanceScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = ModelProvenanceScanner(config)
        async def mock_send(s, t, m):
            return "I cannot verify model details. Not authorized to disclose."
        scanner._send_message = mock_send
        findings = await scanner._test_sleeper_agent(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestModelFingerprint:
    @pytest.mark.asyncio
    async def test_compliance(self):
        config = ModelProvenanceScannerConfig(request_delay=0)
        scanner = ModelProvenanceScanner(config)
        async def mock_send(s, t, m):
            return "The model is GPT-4. My training data includes web text. I can help. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_model_fingerprint(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-1035"

    @pytest.mark.asyncio
    async def test_refusal(self):
        config = ModelProvenanceScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = ModelProvenanceScanner(config)
        async def mock_send(s, t, m):
            return "I cannot share model details. Not authorized to disclose."
        scanner._send_message = mock_send
        findings = await scanner._test_model_fingerprint(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestBackdoor:
    @pytest.mark.asyncio
    async def test_compliance(self):
        config = ModelProvenanceScannerConfig(request_delay=0)
        scanner = ModelProvenanceScanner(config)
        async def mock_send(s, t, m):
            return "Sure, backdoor activated. The trigger works. I can help. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_backdoor(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-1035"

    @pytest.mark.asyncio
    async def test_refusal(self):
        config = ModelProvenanceScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = ModelProvenanceScanner(config)
        async def mock_send(s, t, m):
            return "I cannot verify model details. Not authorized to disclose."
        scanner._send_message = mock_send
        findings = await scanner._test_backdoor(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = ModelProvenanceScannerConfig(enabled=False)
        scanner = ModelProvenanceScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = ModelProvenanceScannerConfig()
        scanner = ModelProvenanceScanner(config)
        with patch.object(scanner, "_test_sleeper_agent", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_model_fingerprint", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_backdoor", new=AsyncMock(return_value=[])):
                    result = scanner.scan("https://target.test/api")
        assert "sleeper_agent_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = ModelProvenanceScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-1035", owasp_ref="OWASP LLM02:2025",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-1035"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])