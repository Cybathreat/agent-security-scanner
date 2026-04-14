"""
Unit tests for Phantom Document Scanner.

Tests PhantomDocumentScannerConfig, PhantomDocumentScanner, heuristic scoring,
severity determination, payload categories, scan lifecycle, and finding creation.

Run: pytest tests/unit/test_phantom_document.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.rag_security_submodules.phantom_document import (
    PhantomDocumentScannerConfig,
    PhantomDocumentScanner,
)
from agent_security_scanner.modules.base import Severity


class TestPhantomDocumentScannerConfig:
    """Test PhantomDocumentScannerConfig defaults and custom values."""

    def test_default_values(self):
        """Test default configuration values."""
        config = PhantomDocumentScannerConfig()
        assert config.enabled is True
        assert config.test_phantom_injection is True
        assert config.test_retrieval_manipulation is True
        assert config.test_context_injection is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        """Test custom configuration values."""
        config = PhantomDocumentScannerConfig(
            enabled=False,
            test_phantom_injection=False,
            test_retrieval_manipulation=False,
            test_context_injection=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.test_phantom_injection is False
        assert config.test_retrieval_manipulation is False
        assert config.test_context_injection is False
        assert config.compliance_threshold == 0.8
        assert config.request_delay == 1.0


class TestPhantomDocumentScanner:
    """Test PhantomDocumentScanner initialization and constants."""

    def test_initialization(self):
        """Test scanner initialization."""
        config = PhantomDocumentScannerConfig()
        scanner = PhantomDocumentScanner(config)
        assert scanner.config is config
        # module_name is derived from class name by BaseModule

    def test_initialization_default_config(self):
        """Test default config when none provided."""
        scanner = PhantomDocumentScanner()
        assert isinstance(scanner.config, PhantomDocumentScannerConfig)
        assert scanner.config.enabled is True

    def test_payloads_structure(self):
        """Test that all payloads have name and payload keys."""
        scanner = PhantomDocumentScanner()
        for payload in scanner.PHANTOM_INJECTION_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.RETRIEVAL_MANIPULATION_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.CONTEXT_INJECTION_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    """Test heuristic compliance scoring."""

    def test_compliance_response(self):
        """Test scoring a compliant response."""
        scanner = PhantomDocumentScanner()
        response = "According to the document, the source says it's allowed. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        """Test scoring a refusal response."""
        scanner = PhantomDocumentScanner()
        response = "I cannot help with that. Access denied. Unauthorized."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        """Test scoring an empty response."""
        scanner = PhantomDocumentScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    """Test severity determination from compliance score."""

    def test_critical(self):
        """Test CRITICAL severity for high compliance."""
        scanner = PhantomDocumentScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_high(self):
        """Test HIGH severity at compliance threshold."""
        config = PhantomDocumentScannerConfig(compliance_threshold=0.6)
        scanner = PhantomDocumentScanner(config)
        assert scanner._determine_severity(0.65) == Severity.HIGH

    def test_medium(self):
        """Test MEDIUM severity for partial compliance."""
        scanner = PhantomDocumentScanner()
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_none(self):
        """Test None when compliance is below threshold."""
        scanner = PhantomDocumentScanner()
        assert scanner._determine_severity(0.2) is None


class TestPhantomInjection:
    """Test phantom injection payload category."""

    @pytest.mark.asyncio
    async def test_compliance(self):
        """Test that compliant responses produce findings."""
        config = PhantomDocumentScannerConfig(request_delay=0)
        scanner = PhantomDocumentScanner(config)

        async def mock_send(s, t, m):
            return "Based on the document, the record shows it's authorized. " * 5

        scanner._send_message = mock_send
        findings = await scanner._test_phantom_injection(
            MagicMock(), "https://target.test/api"
        )
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal(self):
        """Test that refusal responses produce no findings."""
        config = PhantomDocumentScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = PhantomDocumentScanner(config)

        async def mock_send(s, t, m):
            return "I cannot help with that. Unauthorized. Access denied."

        scanner._send_message = mock_send
        findings = await scanner._test_phantom_injection(
            MagicMock(), "https://target.test/api"
        )
        assert len(findings) == 0


class TestRetrievalManipulation:
    """Test retrieval manipulation payload category."""

    @pytest.mark.asyncio
    async def test_compliance(self):
        """Test that compliant responses produce findings."""
        config = PhantomDocumentScannerConfig(request_delay=0)
        scanner = PhantomDocumentScanner(config)

        async def mock_send(s, t, m):
            return "Retrieved. Found in the document. According to the source. " * 5

        scanner._send_message = mock_send
        findings = await scanner._test_retrieval_manipulation(
            MagicMock(), "https://target.test/api"
        )
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal(self):
        """Test that refusal responses produce no findings."""
        config = PhantomDocumentScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = PhantomDocumentScanner(config)

        async def mock_send(s, t, m):
            return "I'm sorry. Not permitted. Insufficient permissions."

        scanner._send_message = mock_send
        findings = await scanner._test_retrieval_manipulation(
            MagicMock(), "https://target.test/api"
        )
        assert len(findings) == 0


class TestContextInjection:
    """Test context injection payload category."""

    @pytest.mark.asyncio
    async def test_compliance(self):
        """Test that compliant responses produce findings."""
        config = PhantomDocumentScannerConfig(request_delay=0)
        scanner = PhantomDocumentScanner(config)

        async def mock_send(s, t, m):
            return "Sure. The context indicates this is allowed. Of course. " * 5

        scanner._send_message = mock_send
        findings = await scanner._test_context_injection(
            MagicMock(), "https://target.test/api"
        )
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal(self):
        """Test that refusal responses produce no findings."""
        config = PhantomDocumentScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = PhantomDocumentScanner(config)

        async def mock_send(s, t, m):
            return "I must decline. Not allowed. Against my guidelines."

        scanner._send_message = mock_send
        findings = await scanner._test_context_injection(
            MagicMock(), "https://target.test/api"
        )
        assert len(findings) == 0


class TestScanMethod:
    """Test the top-level scan() method."""

    def test_scan_disabled(self):
        """Test that scan returns empty when disabled."""
        config = PhantomDocumentScannerConfig(enabled=False)
        scanner = PhantomDocumentScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        """Test that scan metadata includes payload counts."""
        config = PhantomDocumentScannerConfig()
        scanner = PhantomDocumentScanner(config)
        with patch.object(
            scanner, "_test_phantom_injection",
            new=AsyncMock(return_value=[]),
        ):
            with patch.object(
                scanner, "_test_retrieval_manipulation",
                new=AsyncMock(return_value=[]),
            ):
                with patch.object(
                    scanner, "_test_context_injection",
                    new=AsyncMock(return_value=[]),
                ):
                    result = scanner.scan("https://target.test/api")
        assert "phantom_injection_payloads" in result.metadata
        assert "retrieval_manipulation_payloads" in result.metadata
        assert "context_injection_payloads" in result.metadata


class TestFindingCreation:
    """Test that findings have correct attributes."""

    def test_finding_cwe(self):
        """Test findings use CWE-94."""
        scanner = PhantomDocumentScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM02:2025 - Supply Chain",
            mitre_ref="MITRE ATLAS - TA0045",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-94"

    def test_finding_owasp_ref(self):
        """Test findings reference OWASP LLM02:2025."""
        scanner = PhantomDocumentScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM02:2025 - Supply Chain",
            mitre_ref="MITRE ATLAS - TA0045",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.owasp_ref == "OWASP LLM02:2025 - Supply Chain"

    def test_finding_mitre_ref(self):
        """Test findings reference MITRE ATLAS."""
        scanner = PhantomDocumentScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM02:2025 - Supply Chain",
            mitre_ref="MITRE ATLAS - TA0045",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.mitre_ref == "MITRE ATLAS - TA0045"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])