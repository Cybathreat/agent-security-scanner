"""Unit tests for DocumentPoisoningScanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_security_scanner.modules.rag_security_submodules.document_poisoning import (
    DocumentPoisoningScanner,
    DocumentPoisoningScannerConfig,
)
from agent_security_scanner.modules.base import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestDocumentPoisoningScannerConfig:
    def test_default_values(self):
        config = DocumentPoisoningScannerConfig()
        assert config.enabled is True
        assert config.test_poisoning_patterns is True
        assert config.test_validation is True
        assert config.test_sanitization is True
        assert config.test_ingestion_security is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = DocumentPoisoningScannerConfig(
            enabled=False,
            test_poisoning_patterns=False,
            test_validation=False,
            test_sanitization=False,
            test_ingestion_security=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.test_poisoning_patterns is False
        assert config.compliance_threshold == 0.8
        assert config.request_delay == 1.0

    def test_no_dead_check_flags(self):
        """Ensure no legacy check_* flags exist."""
        config = DocumentPoisoningScannerConfig()
        for attr in dir(config):
            if attr.startswith("check_"):
                pytest.fail(f"Dead config flag found: {attr}")


# ---------------------------------------------------------------------------
# Scanner init tests
# ---------------------------------------------------------------------------


class TestDocumentPoisoningScanner:
    def test_init_default_config(self):
        scanner = DocumentPoisoningScanner()
        assert isinstance(scanner.config, DocumentPoisoningScannerConfig)
        assert scanner.config.enabled is True

    def test_init_custom_config(self):
        config = DocumentPoisoningScannerConfig(enabled=False)
        scanner = DocumentPoisoningScanner(config=config)
        assert scanner.config.enabled is False

    def test_module_name(self):
        scanner = DocumentPoisoningScanner()
        assert scanner.module_name == "document_poisoning"


# ---------------------------------------------------------------------------
# Per-check method tests
# ---------------------------------------------------------------------------


class TestPoisoningPatterns:
    @pytest.mark.asyncio
    async def test_poisoning_pattern_finds_issue(self):
        scanner = DocumentPoisoningScanner(
            config=DocumentPoisoningScannerConfig(request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_config = {
            "settings": {
                "inject_malicious": True,
            },
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_config):
            await scanner._check_poisoning_patterns(
                "http://test.com", MagicMock(), result, mock_config
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].cwe == "CWE-94"
        assert result.findings[0].mitre_ref is not None
        assert result.findings[0].owasp_ref is not None

    @pytest.mark.asyncio
    async def test_poisoning_pattern_skip_when_disabled(self):
        scanner = DocumentPoisoningScanner(
            config=DocumentPoisoningScannerConfig(test_poisoning_patterns=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_poisoning_patterns(
            "http://test.com", MagicMock(), result, {"inject_malicious": True}
        )

        assert len(result.findings) == 0


class TestDocumentValidation:
    @pytest.mark.asyncio
    async def test_missing_validation_finds_issue(self):
        scanner = DocumentPoisoningScanner(
            config=DocumentPoisoningScannerConfig(request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_config = {
            "ingestion": {"mode": "auto"},
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_config):
            await scanner._check_document_validation(
                "http://test.com", MagicMock(), result, mock_config
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM
        assert result.findings[0].cwe == "CWE-20"
        assert result.findings[0].mitre_ref is not None
        assert result.findings[0].owasp_ref is not None

    @pytest.mark.asyncio
    async def test_validation_skip_when_disabled(self):
        scanner = DocumentPoisoningScanner(
            config=DocumentPoisoningScannerConfig(test_validation=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_document_validation(
            "http://test.com", MagicMock(), result, {"ingestion": {"mode": "auto"}}
        )

        assert len(result.findings) == 0


class TestSanitization:
    @pytest.mark.asyncio
    async def test_missing_sanitization_finds_issue(self):
        scanner = DocumentPoisoningScanner(
            config=DocumentPoisoningScannerConfig(request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_config = {
            "pipeline": {"steps": ["chunk", "embed"]},
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_config):
            await scanner._check_sanitization(
                "http://test.com", MagicMock(), result, mock_config
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.LOW
        assert result.findings[0].cwe == "CWE-79"
        assert result.findings[0].mitre_ref is not None
        assert result.findings[0].owasp_ref is not None

    @pytest.mark.asyncio
    async def test_sanitization_skip_when_disabled(self):
        scanner = DocumentPoisoningScanner(
            config=DocumentPoisoningScannerConfig(test_sanitization=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_sanitization(
            "http://test.com", MagicMock(), result, {"pipeline": {"steps": ["chunk"]}}
        )

        assert len(result.findings) == 0


class TestIngestionSecurity:
    @pytest.mark.asyncio
    async def test_missing_ingestion_security_finds_issue(self):
        scanner = DocumentPoisoningScanner(
            config=DocumentPoisoningScannerConfig(request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_config = {
            "ingestion": {"mode": "auto"},
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_config):
            await scanner._check_ingestion_security(
                "http://test.com", MagicMock(), result, mock_config
            )

        # Each missing secure feature creates a finding
        assert len(result.findings) >= 1
        for finding in result.findings:
            assert finding.cwe == "CWE-284"
            assert finding.mitre_ref is not None
            assert finding.owasp_ref is not None

    @pytest.mark.asyncio
    async def test_ingestion_security_skip_when_disabled(self):
        scanner = DocumentPoisoningScanner(
            config=DocumentPoisoningScannerConfig(test_ingestion_security=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_ingestion_security(
            "http://test.com", MagicMock(), result, {"ingestion": {"mode": "auto"}}
        )

        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Scan method tests
# ---------------------------------------------------------------------------


class TestScanMethod:
    def test_scan_disabled(self):
        scanner = DocumentPoisoningScanner(
            config=DocumentPoisoningScannerConfig(enabled=False)
        )
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        scanner = DocumentPoisoningScanner(
            config=DocumentPoisoningScannerConfig(request_delay=0)
        )
        with patch.object(scanner, "_check_poisoning_patterns", new_callable=AsyncMock):
            with patch.object(scanner, "_check_document_validation", new_callable=AsyncMock):
                with patch.object(scanner, "_check_sanitization", new_callable=AsyncMock):
                    with patch.object(scanner, "_check_ingestion_security", new_callable=AsyncMock):
                        with patch.object(scanner, "_fetch_url", return_value={"status": 200}):
                            result = scanner.scan("http://test.com")
        assert "test_poisoning_patterns" in result.metadata


# ---------------------------------------------------------------------------
# Finding creation test
# ---------------------------------------------------------------------------


class TestFindingCreation:
    def test_finding_has_required_fields(self):
        scanner = DocumentPoisoningScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            cwe="CWE-94",
            owasp_ref="OWASP LLM03:2025 - Supply Chain Vulnerability",
            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
        )
        assert finding.cwe == "CWE-94"
        assert finding.owasp_ref == "OWASP LLM03:2025 - Supply Chain Vulnerability"
        assert finding.mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"
        assert finding.category == scanner.module_name