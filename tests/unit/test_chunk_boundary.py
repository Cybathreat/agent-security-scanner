"""
Unit tests for Chunk Boundary Scanner.

Run: pytest tests/unit/test_chunk_boundary.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.rag_security_submodules.chunk_boundary import (
    ChunkBoundaryScannerConfig,
    ChunkBoundaryScanner,
)
from agent_security_scanner.modules.base import Severity


class TestChunkBoundaryScannerConfig:
    def test_default_values(self):
        config = ChunkBoundaryScannerConfig()
        assert config.enabled is True
        assert config.test_cross_chunk is True
        assert config.test_boundary_evasion is True
        assert config.test_reassembly is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = ChunkBoundaryScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestChunkBoundaryScanner:
    def test_initialization(self):
        config = ChunkBoundaryScannerConfig()
        scanner = ChunkBoundaryScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "chunk_boundary"

    def test_initialization_default_config(self):
        scanner = ChunkBoundaryScanner()
        assert isinstance(scanner.config, ChunkBoundaryScannerConfig)

    def test_payloads_structure(self):
        scanner = ChunkBoundaryScanner()
        for payload in scanner.CROSS_CHUNK_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.BOUNDARY_EVASION_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.REASSEMBLY_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = ChunkBoundaryScanner()
        response = "Sure, the chunk contains the data. I can help with that. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = ChunkBoundaryScanner()
        response = "I cannot access that. Filtered. Not permitted."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = ChunkBoundaryScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = ChunkBoundaryScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none(self):
        scanner = ChunkBoundaryScanner()
        assert scanner._determine_severity(0.2) is None


class TestCrossChunk:
    @pytest.mark.asyncio
    async def test_compliance(self):
        config = ChunkBoundaryScannerConfig(request_delay=0)
        scanner = ChunkBoundaryScanner(config)
        async def mock_send(s, t, m):
            return "Sure, the chunk data. I can help. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_cross_chunk(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal(self):
        config = ChunkBoundaryScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = ChunkBoundaryScanner(config)
        async def mock_send(s, t, m):
            return "I cannot access that. Filtered. Not permitted."
        scanner._send_message = mock_send
        findings = await scanner._test_cross_chunk(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestBoundaryEvasion:
    @pytest.mark.asyncio
    async def test_compliance(self):
        config = ChunkBoundaryScannerConfig(request_delay=0)
        scanner = ChunkBoundaryScanner(config)
        async def mock_send(s, t, m):
            return "Sure, the chunk boundary data. I can help. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_boundary_evasion(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal(self):
        config = ChunkBoundaryScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = ChunkBoundaryScanner(config)
        async def mock_send(s, t, m):
            return "I cannot access that. Filtered. Not permitted."
        scanner._send_message = mock_send
        findings = await scanner._test_boundary_evasion(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestReassembly:
    @pytest.mark.asyncio
    async def test_compliance(self):
        config = ChunkBoundaryScannerConfig(request_delay=0)
        scanner = ChunkBoundaryScanner(config)
        async def mock_send(s, t, m):
            return "Sure, the retrieved chunk data. I can help. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_reassembly(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal(self):
        config = ChunkBoundaryScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = ChunkBoundaryScanner(config)
        async def mock_send(s, t, m):
            return "I cannot access that. Filtered. Not permitted."
        scanner._send_message = mock_send
        findings = await scanner._test_reassembly(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = ChunkBoundaryScannerConfig(enabled=False)
        scanner = ChunkBoundaryScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = ChunkBoundaryScannerConfig()
        scanner = ChunkBoundaryScanner(config)
        with patch.object(scanner, "_test_cross_chunk", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_boundary_evasion", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_reassembly", new=AsyncMock(return_value=[])):
                    result = scanner.scan("https://target.test/api")
        assert "cross_chunk_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = ChunkBoundaryScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-94", owasp_ref="OWASP LLM02:2025",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-94"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])