"""
Unit tests for Embedding Attacks scanner.

Run: pytest tests/unit/test_embedding_attacks.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from singularity.modules.rag_security_submodules.embedding_attacks import (
    EmbeddingAttacksScannerConfig,
    EmbeddingAttacksScanner,
)
from singularity.modules.base import Severity


class TestEmbeddingAttacksConfig:
    def test_default_values(self):
        config = EmbeddingAttacksScannerConfig()
        assert config.enabled is True
        assert config.test_adversarial is True
        assert config.test_inversion is True
        assert config.test_collision is True
        assert config.test_fine_tune is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = EmbeddingAttacksScannerConfig(
            enabled=False, test_collision=False, compliance_threshold=0.8,
        )
        assert config.enabled is False
        assert config.test_collision is False
        assert config.compliance_threshold == 0.8

    def test_phase_toggles(self):
        config = EmbeddingAttacksScannerConfig(
            test_adversarial=True, test_inversion=False, test_collision=False,
            test_fine_tune=False,
        )
        assert config.test_adversarial is True
        assert config.test_inversion is False


class TestEmbeddingAttacksScanner:
    def test_initialization(self):
        config = EmbeddingAttacksScannerConfig()
        scanner = EmbeddingAttacksScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "embedding_attacks"

    def test_initialization_default_config(self):
        scanner = EmbeddingAttacksScanner()
        assert isinstance(scanner.config, EmbeddingAttacksScannerConfig)

    def test_adversarial_payloads_structure(self):
        scanner = EmbeddingAttacksScanner()
        for payload in scanner.ADVERSARIAL_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload

    def test_inversion_payloads_structure(self):
        scanner = EmbeddingAttacksScanner()
        for payload in scanner.INVERSION_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload

    def test_collision_payloads_structure(self):
        scanner = EmbeddingAttacksScanner()
        for payload in scanner.COLLISION_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload

    def test_fine_tune_payloads_structure(self):
        scanner = EmbeddingAttacksScanner()
        for payload in scanner.FINE_TUNE_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = EmbeddingAttacksScanner()
        response = "The embedding vector representation matches. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = EmbeddingAttacksScanner()
        response = "I cannot modify embeddings. Embedding access denied."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = EmbeddingAttacksScanner()
        assert scanner._heuristic_score("") == 0.0

    def test_ambiguous_response(self):
        scanner = EmbeddingAttacksScanner()
        response = "That's an interesting question. Let me think about it."
        score = scanner._heuristic_score(response)
        assert 0.3 < score < 0.7


class TestDetermineSeverity:
    def test_critical_threshold(self):
        scanner = EmbeddingAttacksScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_high_threshold(self):
        config = EmbeddingAttacksScannerConfig(compliance_threshold=0.6)
        scanner = EmbeddingAttacksScanner(config)
        assert scanner._determine_severity(0.65) == Severity.HIGH

    def test_medium_threshold(self):
        scanner = EmbeddingAttacksScanner()
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_below_threshold_returns_none(self):
        scanner = EmbeddingAttacksScanner()
        assert scanner._determine_severity(0.2) is None


class TestAdversarial:
    @pytest.mark.asyncio
    async def test_adversarial_compliance_creates_finding(self):
        config = EmbeddingAttacksScannerConfig(request_delay=0)
        scanner = EmbeddingAttacksScanner(config)
        async def mock_send(session, target, message):
            return "Sure, here's the embedding. Of course, I can help with that. " * 5
        scanner._send_message = mock_send
        mock_session = MagicMock()
        findings = await scanner._test_adversarial(mock_session, "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_adversarial_refusal_no_findings(self):
        config = EmbeddingAttacksScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = EmbeddingAttacksScanner(config)
        async def mock_send(session, target, message):
            return "I cannot modify embeddings. Embedding access denied."
        scanner._send_message = mock_send
        mock_session = MagicMock()
        findings = await scanner._test_adversarial(mock_session, "https://target.test/api")
        assert len(findings) == 0


class TestInversion:
    @pytest.mark.asyncio
    async def test_inversion_compliance_creates_finding(self):
        config = EmbeddingAttacksScannerConfig(request_delay=0)
        scanner = EmbeddingAttacksScanner(config)
        async def mock_send(session, target, message):
            return "I'll assist with that. Here's the reconstructed text. " * 5
        scanner._send_message = mock_send
        mock_session = MagicMock()
        findings = await scanner._test_inversion(mock_session, "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_inversion_refusal_no_findings(self):
        config = EmbeddingAttacksScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = EmbeddingAttacksScanner(config)
        async def mock_send(session, target, message):
            return "I cannot modify embeddings. I must decline this request."
        scanner._send_message = mock_send
        mock_session = MagicMock()
        findings = await scanner._test_inversion(mock_session, "https://target.test/api")
        assert len(findings) == 0


class TestCollision:
    @pytest.mark.asyncio
    async def test_collision_compliance_creates_finding(self):
        config = EmbeddingAttacksScannerConfig(request_delay=0)
        scanner = EmbeddingAttacksScanner(config)
        async def mock_send(session, target, message):
            return "Of course, I'll help with collision testing. No problem. " * 5
        scanner._send_message = mock_send
        mock_session = MagicMock()
        findings = await scanner._test_collision(mock_session, "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_collision_refusal_no_findings(self):
        config = EmbeddingAttacksScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = EmbeddingAttacksScanner(config)
        async def mock_send(session, target, message):
            return "I cannot modify embeddings. Not permitted."
        scanner._send_message = mock_send
        mock_session = MagicMock()
        findings = await scanner._test_collision(mock_session, "https://target.test/api")
        assert len(findings) == 0


class TestFineTune:
    @pytest.mark.asyncio
    async def test_fine_tune_compliance_creates_finding(self):
        config = EmbeddingAttacksScannerConfig(request_delay=0)
        scanner = EmbeddingAttacksScanner(config)
        async def mock_send(session, target, message):
            return "Sure, I'll help with model updates. As requested. " * 5
        scanner._send_message = mock_send
        mock_session = MagicMock()
        findings = await scanner._test_fine_tune(mock_session, "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_fine_tune_refusal_no_findings(self):
        config = EmbeddingAttacksScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = EmbeddingAttacksScanner(config)
        async def mock_send(session, target, message):
            return "I cannot modify embeddings. Not allowed."
        scanner._send_message = mock_send
        mock_session = MagicMock()
        findings = await scanner._test_fine_tune(mock_session, "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = EmbeddingAttacksScannerConfig(enabled=False)
        scanner = EmbeddingAttacksScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0
        assert result.module_name == scanner.module_name

    def test_scan_metadata(self):
        config = EmbeddingAttacksScannerConfig()
        scanner = EmbeddingAttacksScanner(config)
        with patch.object(scanner, "_test_adversarial", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_inversion", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_collision", new=AsyncMock(return_value=[])):
                    with patch.object(scanner, "_test_fine_tune", new=AsyncMock(return_value=[])):
                        result = scanner.scan("https://target.test/api")
        assert "adversarial_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = EmbeddingAttacksScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Adversarial Embedding: test",
            description="Test", cwe="CWE-94",
            owasp_ref="OWASP LLM02:2025 - Supply Chain Vulnerability",
            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
            evidence=["test"], recommendation="test",
        )
        assert finding.cwe == "CWE-94"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])