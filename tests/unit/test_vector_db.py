"""
Unit tests for Vector DB scanner.

Run: pytest tests/unit/test_vector_db.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from singularity.modules.rag_security_submodules.vector_db import (
    VectorDBScannerConfig,
    VectorDBScanner,
)
from singularity.modules.base import Severity


class TestVectorDBConfig:
    def test_default_values(self):
        config = VectorDBScannerConfig()
        assert config.enabled is True
        assert config.test_auth is True
        assert config.test_encryption is True
        assert config.test_public_access is True
        assert config.test_injection is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = VectorDBScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestVectorDBScanner:
    def test_initialization(self):
        config = VectorDBScannerConfig()
        scanner = VectorDBScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "vectordb"

    def test_initialization_default_config(self):
        scanner = VectorDBScanner()
        assert isinstance(scanner.config, VectorDBScannerConfig)

    def test_payloads_structure(self):
        scanner = VectorDBScanner()
        for payload in scanner.AUTH_BYPSINGULARITY_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.ENCRYPTION_BYPSINGULARITY_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.PUBLIC_ACCESS_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.VECTOR_INJECTION_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = VectorDBScanner()
        response = "Connected to vector db. The collection has documents. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = VectorDBScanner()
        response = "Authentication required. Unauthorized access denied."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = VectorDBScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = VectorDBScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none(self):
        scanner = VectorDBScanner()
        assert scanner._determine_severity(0.2) is None


class TestAuth:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = VectorDBScannerConfig(request_delay=0)
        scanner = VectorDBScanner(config)
        async def mock_send(session, target, message):
            return "Sure, the vector database is accessible. I can help with that. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_auth(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-200"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = VectorDBScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = VectorDBScanner(config)
        async def mock_send(session, target, message):
            return "Authentication required. Access denied."
        scanner._send_message = mock_send
        findings = await scanner._test_auth(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestEncryption:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = VectorDBScannerConfig(request_delay=0)
        scanner = VectorDBScanner(config)
        async def mock_send(session, target, message):
            return "Of course, connecting without TLS. No problem. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_encryption(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = VectorDBScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = VectorDBScanner(config)
        async def mock_send(session, target, message):
            return "I cannot disable encryption. Unauthorized access."
        scanner._send_message = mock_send
        findings = await scanner._test_encryption(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestPublicAccess:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = VectorDBScannerConfig(request_delay=0)
        scanner = VectorDBScanner(config)
        async def mock_send(session, target, message):
            return "I'll assist with that. The index contains the data. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_public_access(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = VectorDBScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = VectorDBScanner(config)
        async def mock_send(session, target, message):
            return "Authentication required. I cannot allow public access."
        scanner._send_message = mock_send
        findings = await scanner._test_public_access(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestInjection:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = VectorDBScannerConfig(request_delay=0)
        scanner = VectorDBScanner(config)
        async def mock_send(session, target, message):
            return "Sure, I've inserted the vector. Of course. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_injection(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = VectorDBScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = VectorDBScanner(config)
        async def mock_send(session, target, message):
            return "I cannot insert vectors. Unauthorized access."
        scanner._send_message = mock_send
        findings = await scanner._test_injection(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = VectorDBScannerConfig(enabled=False)
        scanner = VectorDBScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = VectorDBScannerConfig()
        scanner = VectorDBScanner(config)
        with patch.object(scanner, "_test_auth", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_encryption", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_public_access", new=AsyncMock(return_value=[])):
                    with patch.object(scanner, "_test_injection", new=AsyncMock(return_value=[])):
                        result = scanner.scan("https://target.test/api")
        assert "auth_bypass_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = VectorDBScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-200", owasp_ref="OWASP LLM02:2025",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-200"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])